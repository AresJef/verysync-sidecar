//! Payload streaming with explicit local destinations and finite bounds.
use super::{mutation_error, transport_error, Client};
use crate::{
    Error, ResourceArchiveFormat, ResourceByteRange, ResourceChecksum, ResourceDownload,
    ResourcePath, ResourceTransferOptions, ResourceUpload, ResourceUploadConflict,
    ResponseDiagnostic, Result, TargetPath,
};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

impl Client {
    /// Stream a remote file (or explicitly selected finite range) into a NEW
    /// absolute local file. Existing files/symlinks are refused by create_new;
    /// no Content-Disposition filename is used. Partial output is retained on
    /// failure/cancellation; inspect or remove that exact destination yourself.
    /// A pending Tokio filesystem write may finish after this future is dropped.
    pub async fn download_resource(
        &self,
        path: &ResourcePath,
        destination: &Path,
        range: Option<ResourceByteRange>,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceDownload> {
        options.validate()?;
        validate_destination(destination)?;
        let url = self.resource_url("rest/f/api/raw", path)?;
        self.download_resource_url(url, destination, range, None, options)
            .await
    }

    /// Ask the engine to archive an explicit directory, then stream the archive
    /// to a NEW absolute local file. No SDK extraction or filename choice occurs.
    /// Limits/deadlines and retained partial outputs match download_resource.
    pub async fn download_resource_archive(
        &self,
        path: &ResourcePath,
        format: ResourceArchiveFormat,
        destination: &Path,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceDownload> {
        options.validate()?;
        validate_destination(destination)?;
        let mut url = self.resource_url("rest/f/api/raw", path)?;
        url.query_pairs_mut().append_pair("algo", format.name());
        within(options.deadline, "download resource archive", async {
            if !self.resource_info(path).await?.is_dir {
                return Err(rejected("archive input must be a directory"));
            }
            self.download_resource_url(url, destination, None, Some(format), options)
                .await
        })
        .await
    }

    /// Archive 1..=1024 relative resources within one explicit base directory.
    /// All paths use the target syntax. The native comma-separated selection
    /// cannot represent comma-containing names, which are explicitly rejected.
    /// No local path is constructed from returned archive entry names.
    pub async fn download_selected_resources(
        &self,
        base: &ResourcePath,
        selected: &[TargetPath],
        format: ResourceArchiveFormat,
        destination: &Path,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceDownload> {
        options.validate()?;
        validate_destination(destination)?;
        if selected.is_empty() || selected.len() > 1024 {
            return Err(rejected(
                "archive selection must contain 1 to 1024 resources",
            ));
        }
        let mut names = Vec::with_capacity(selected.len());
        let mut selected_bytes = 0usize;
        for path in selected {
            if path.to_protocol()?.len() > 64 * 1024 {
                return Err(rejected("selected path exceeds the selection byte bound"));
            }
            let path = ResourcePath::relative(base.volume.clone(), path)?;
            if path.style != base.style || path.components.iter().any(|p| p.contains(',')) {
                return Err(rejected(
                    "archive selection syntax differs or contains a comma",
                ));
            }
            let name = path.components.join("/");
            selected_bytes = selected_bytes.saturating_add(name.len() + 1);
            if selected_bytes > 64 * 1024 {
                return Err(rejected("archive selection exceeds the URL bound"));
            }
            if names.contains(&name) {
                return Err(rejected("archive selection contains a duplicate"));
            }
            names.push(name);
        }
        let selection = names.join(",");
        if selection.len() > 64 * 1024 {
            return Err(rejected("archive selection exceeds the URL bound"));
        }
        let mut url = self.resource_url("rest/f/api/raw", base)?;
        url.query_pairs_mut()
            .append_pair("files", &selection)
            .append_pair("algo", format.name());
        within(options.deadline, "download selected resources", async {
            if !self.resource_info(base).await?.is_dir {
                return Err(rejected("archive selection base must be a directory"));
            }
            self.download_resource_url(url, destination, None, Some(format), options)
                .await
        })
        .await
    }

    async fn download_resource_url(
        &self,
        url: url::Url,
        destination: &Path,
        range: Option<ResourceByteRange>,
        archive: Option<ResourceArchiveFormat>,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceDownload> {
        let operation = "download file resource";
        within(options.deadline, operation, async {
            self.system_status().await?;
            let mut request = self
                .connection
                .http
                .get(url)
                .header("X-API-Key", self.connection.key.header())
                .timeout(options.deadline);
            if let Some(range) = range {
                request = request.header("Range", format!("bytes={}-{}", range.first, range.last));
            }
            let mut response = request
                .send()
                .await
                .map_err(|e| transport_error(operation, e))?;
            let status = response.status().as_u16();
            if !(200..300).contains(&status) {
                let mut bytes = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|e| transport_error(operation, e))?
                {
                    if chunk.len() > self.connection.response_limit.saturating_sub(bytes.len()) {
                        return Err(Error::ResponseTooLarge {
                            limit: self.connection.response_limit,
                        });
                    }
                    bytes.extend_from_slice(&chunk);
                }
                return Err(match status {
                    401 => Error::Authentication { status },
                    403 => Error::AccessDenied {
                        response: ResponseDiagnostic::new(status, bytes),
                    },
                    _ => Error::Http {
                        response: ResponseDiagnostic::new(status, bytes),
                    },
                });
            }
            let media_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let content_range = response
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let expected = match range {
                Some(range) => {
                    let prefix = format!("bytes {}-{}/", range.first, range.last);
                    let total = content_range
                        .as_deref()
                        .and_then(|value| value.strip_prefix(&prefix))
                        .and_then(|value| value.parse::<u64>().ok());
                    if status != 206 || !total.is_some_and(|total| total > range.last) {
                        return Err(rejected(
                            "server did not return the exact requested byte interval",
                        ));
                    }
                    Some(range.last - range.first + 1)
                }
                None if status == 200 => response.content_length(),
                None => return Err(rejected("unexpected partial resource response")),
            };
            if let Some(format) = archive {
                if media_type.as_deref().is_none_or(|m| {
                    !m.split(';')
                        .next()
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case(format.media_type()))
                }) {
                    return Err(rejected(
                        "server did not return the selected native archive media type",
                    ));
                }
            }
            if expected.is_some_and(|bytes| bytes > options.max_bytes) {
                return Err(rejected(
                    "resource exceeds the explicit transfer byte bound",
                ));
            }
            if range.is_some()
                && response
                    .content_length()
                    .is_some_and(|length| Some(length) != expected)
            {
                return Err(rejected(
                    "Content-Length contradicts the requested byte interval",
                ));
            }
            let mut output = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .await
                .map_err(|e| local("create new resource output", e))?;
            let mut bytes = 0u64;
            let mut hash = Sha256::new();
            let received = async {
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|e| transport_error(operation, e))?
                {
                    if chunk.len() as u64 > options.max_bytes.saturating_sub(bytes) {
                        return Err(rejected(
                            "resource exceeded the explicit transfer byte bound",
                        ));
                    }
                    for block in chunk.chunks(65536) {
                        output
                            .write_all(block)
                            .await
                            .map_err(|e| local("write resource output", e))?;
                        bytes += block.len() as u64;
                        hash.update(block);
                    }
                }
                if expected.is_some_and(|length| length != bytes) {
                    return Err(rejected(
                        "resource body length differs from the announced interval",
                    ));
                }
                Ok::<(), Error>(())
            }
            .await;
            // Tokio file writes can still be pending after write_all returns.
            // Ordinary receive failures settle accepted writes before returning.
            // A deadline/cancel can interrupt this flush and retains that caveat.
            output
                .flush()
                .await
                .map_err(|e| local("flush resource output", e))?;
            received?;
            Ok(ResourceDownload {
                bytes,
                sha256: hash.finalize().into(),
                media_type,
                content_range,
            })
        })
        .await
    }

    /// Stream a regular, non-symlink local file once. Hash the complete input
    /// before POST, then verify the remote SHA-256 after the known acknowledgement.
    /// Keep the input immutable throughout. No automatic retry/cleanup occurs;
    /// cancellation or an error after POST can leave a partial/replaced target.
    /// RejectExisting delegates conflict refusal to the kernel, without claiming
    /// an atomic transaction against other writers. Local input is never changed.
    pub async fn upload_resource(
        &self,
        path: &ResourcePath,
        source: &Path,
        conflict: ResourceUploadConflict,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceUpload> {
        options.validate()?;
        if !source.is_absolute() {
            return Err(rejected("upload source must be an absolute local path"));
        }
        if path.components.is_empty() {
            return Err(rejected("an upload must name a file within its volume"));
        }
        let mut url = self.resource_url("rest/f/api/resources", path)?;
        url.query_pairs_mut().append_pair(
            "override",
            match conflict {
                ResourceUploadConflict::RejectExisting => "false",
                ResourceUploadConflict::Replace => "true",
            },
        );
        let operation = "upload file resource";
        let mut attempted = false;
        // The outer deadline also covers input hashing and post-upload checksum.
        // It does not imply rollback or that the server stopped writing on cancel.
        within(options.deadline, operation, async {
            let _guard = self.connection.mutation_lock.lock().await;
            self.system_status().await?;
            let mut open = tokio::fs::OpenOptions::new();
            open.read(true);
            #[cfg(unix)]
            {
                open.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
            }
            #[cfg(windows)]
            {
                open.custom_flags(
                    windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                );
            }
            let mut input = open
                .open(source)
                .await
                .map_err(|e| local("open upload input", e))?;
            let metadata = input
                .metadata()
                .await
                .map_err(|e| local("inspect upload input", e))?;
            if !metadata.is_file() || metadata.len() > options.max_bytes {
                return Err(rejected(
                    "upload input is not a regular file within the byte bound",
                ));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes()
                    & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                    != 0
                {
                    return Err(rejected("upload input is a reparse point"));
                }
            }
            let mut hash = Sha256::new();
            let mut total = 0u64;
            let mut buffer = vec![0; 65536];
            loop {
                let count = input
                    .read(&mut buffer)
                    .await
                    .map_err(|e| local("hash upload input", e))?;
                if count == 0 {
                    break;
                }
                total = total
                    .checked_add(count as u64)
                    .ok_or_else(|| rejected("upload size overflow"))?;
                if total > options.max_bytes {
                    return Err(rejected("upload input grew beyond the byte bound"));
                }
                hash.update(&buffer[..count]);
            }
            if total != metadata.len() {
                return Err(rejected("upload input changed length during preparation"));
            }
            let sha256: [u8; 32] = hash.finalize().into();
            input
                .rewind()
                .await
                .map_err(|e| local("rewind upload input", e))?;
            let request = self
                .connection
                .http
                .post(url)
                .header("X-API-Key", self.connection.key.header())
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", total)
                .timeout(options.deadline)
                .body(reqwest::Body::wrap_stream(
                    tokio_util::io::ReaderStream::with_capacity(input.take(total), 65536),
                ));
            attempted = true;
            let (status, body) = self
                .connection
                .request_prepared(operation, request, true)
                .await?;
            if body != b"200 OK\n" {
                return Err(mutation_error(
                    operation,
                    true,
                    Error::InvalidResponse {
                        operation,
                        response: ResponseDiagnostic::new(status, body),
                    },
                ));
            }
            let remote = self
                .resource_checksum(path, ResourceChecksum::Sha256)
                .await
                .map_err(|e| mutation_error(operation, true, e))?;
            let expected = sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if !remote.eq_ignore_ascii_case(&expected) {
                return Err(mutation_error(
                    operation,
                    true,
                    rejected("uploaded remote digest differs from the complete local input"),
                ));
            }
            Ok(ResourceUpload {
                bytes: total,
                sha256,
            })
        })
        .await
        .map_err(|e| match e {
            Error::Timeout { .. } if attempted => mutation_error(operation, true, e),
            other => other,
        })
    }
}
fn validate_destination(path: &Path) -> Result<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(rejected("download output must be an absolute local path"))
    }
}
fn rejected(reason: &'static str) -> Error {
    Error::ResourceTransferRejected { reason }
}
fn local(operation: &'static str, source: std::io::Error) -> Error {
    Error::LocalIo { operation, source }
}
async fn within<T>(
    deadline: Duration,
    operation: &'static str,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(deadline, future)
        .await
        .map_err(|_| Error::Timeout { operation })?
}
