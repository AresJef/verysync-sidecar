//! Explicit kernel upgrade calls. No automatic selection, download or retry.
use super::Client;
use crate::{Error, KernelUpgradeCheck, OfficialProgram, ResponseDiagnostic, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek},
    path::{Path, PathBuf},
};

impl Client {
    /// Check the kernel's own release provider once. Managed instances disable
    /// this by default; explicitly select ManagedUpgradeChecks::Manual to allow
    /// checks while keeping periodic upgrade checks off. A 501 is retained as
    /// an HTTP error rather than interpreted as a license requirement.
    pub async fn check_kernel_upgrade(&self) -> Result<KernelUpgradeCheck> {
        self.system_status().await?;
        let operation = "check kernel upgrade";
        let (status, body) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection.management_url("rest/system/upgrade", &[])?,
                None,
                false,
            )
            .await?;
        let value: KernelUpgradeCheck =
            serde_json::from_slice(&body).map_err(|_| Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(status, body.clone()),
            })?;
        if value.running.is_empty() || value.latest.is_empty() {
            return Err(Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(status, body),
            });
        }
        Ok(value)
    }

    /// Ask the kernel to install the release chosen by its own provider once.
    /// This can overwrite its executable and stop the process. It is NOT a
    /// version-pinned SDK download: a previous check cannot prevent a changing
    /// provider feed. Explicitly coordinate release policy/network access.
    /// Ok only acknowledges the kernel's restarting response; independently verify
    /// executable identity, owned-process exit and readiness after restarting.
    /// Cancellation or a transport error can leave an unknown mutation outcome.
    pub async fn request_server_selected_upgrade(&self) -> Result<()> {
        let operation = "request server-selected upgrade";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let (status, body) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::POST,
                self.connection.management_url("rest/system/upgrade", &[])?,
                None,
                true,
            )
            .await?;
        acknowledge(operation, status, body)
    }

    /// Upload one complete, locally supplied fixed official archive. Check its
    /// full catalog size and SHA-256 before the modifying request, then stream
    /// from that same open regular file with bounded buffering. No download or
    /// extraction occurs. Keep the input immutable until this future ends;
    /// an open handle does not prevent another writer changing its contents.
    ///
    /// The kernel checks target compatibility. Ok is an acknowledgement, not
    /// installation/readiness. Never retry an unknown outcome automatically.
    /// Dropping this future stops the request; read-only hash preparation may
    /// finish in the runtime's blocking pool after cancellation.
    pub async fn upload_kernel_upgrade(
        &self,
        archive: impl Into<PathBuf>,
        program: &OfficialProgram,
    ) -> Result<()> {
        let operation = "upload fixed kernel upgrade";
        if program.archive_bytes() > 128 * 1024 * 1024 {
            return Err(Error::ProgramRejected {
                reason: "archive exceeds the kernel upload bound",
            });
        }
        let path = archive.into();
        if !path.is_absolute() {
            return Err(Error::InvalidPath {
                reason: "upgrade archive must be an absolute local path",
            });
        }
        let expected_len = program.archive_bytes();
        let expected_sha = program.archive_sha256();
        let file =
            tokio::task::spawn_blocking(move || prepare_archive(&path, expected_len, expected_sha))
                .await
                .map_err(|_| Error::ManagedFailure {
                    reason: "archive verification worker did not complete",
                })??;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let part = reqwest::multipart::Part::stream_with_length(
            reqwest::Body::from(tokio::fs::File::from_std(file)),
            expected_len,
        )
        .file_name(program.archive_filename().to_owned());
        let request = self
            .connection
            .http
            .post(
                self.connection
                    .management_url("rest/system/upgrade/upload", &[])?,
            )
            .header("X-API-Key", self.connection.key.header())
            .multipart(reqwest::multipart::Form::new().part("file", part));
        let (status, body) = self
            .connection
            .request_prepared(operation, request, true)
            .await?;
        acknowledge(operation, status, body)
    }
}

fn acknowledge(operation: &'static str, status: u16, body: Vec<u8>) -> Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Acknowledgement {
        ok: String,
    }
    if !serde_json::from_slice::<Acknowledgement>(&body).is_ok_and(|value| value.ok == "restarting")
    {
        return Err(Error::MutationOutcomeUnknown {
            operation,
            source: Box::new(Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(status, body),
            }),
        });
    }
    Ok(())
}

fn prepare_archive(path: &Path, len: u64, sha: [u8; 32]) -> Result<File> {
    let io = |source| Error::LocalIo {
        operation: "verify local upgrade archive",
        source,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path).map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    let admissible = metadata.is_file() && metadata.len() == len;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let admissible = admissible
            && metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                == 0;
        if !admissible {
            return Err(Error::ProgramRejected {
                reason: "upgrade input is not a matching regular archive",
            });
        }
    }
    if !admissible {
        return Err(Error::ProgramRejected {
            reason: "upgrade input is not a matching regular archive",
        });
    }
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0; 65536];
    loop {
        let read = file.read(&mut buffer).map_err(io)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > len {
            break;
        }
        hash.update(&buffer[..read]);
    }
    if total != len || <[u8; 32]>::from(hash.finalize()) != sha {
        return Err(Error::ProgramRejected {
            reason: "upgrade archive does not match its fixed SHA-256",
        });
    }
    file.rewind().map_err(io)?;
    Ok(file)
}
