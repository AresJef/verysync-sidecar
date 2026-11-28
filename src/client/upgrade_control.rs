//! Explicit kernel upgrade calls and opt-in retries for trusted reads.
use super::{checked_response, mutation_error, send_bounded_observing_headers, Client};
use crate::{
    operation_options::OperationContext,
    upgrade_receipt::{UpgradeAttempt, UpgradeProgress},
    Error, FailedUpgradeRead, KernelUpgradeCheck, OfficialProgram, OperationOptions,
    OperationPhase, ReadRetryDecision, ResponseDiagnostic, Result, UpgradeAction, UpgradeDispatch,
    UpgradeOperationResult, UpgradeOutcome, UpgradeQueryReport,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek},
    path::{Path, PathBuf},
    time::Duration,
};

impl Client {
    /// Read the running engine's available release and keep the request evidence.
    ///
    /// A handle configured with [Client::with_transient_read_retries] can make
    /// one extra read after an eligible timeout or connection interruption.
    /// The first attempt uses up to four fifths of the total time when enabled.
    /// Each attempt checks the selected version and device before querying the
    /// release provider. The query does not install a release.
    pub async fn query_kernel_upgrade(
        &self,
        options: OperationOptions,
    ) -> Result<UpgradeQueryReport> {
        let context = options.start()?;
        let result = self
            .query_kernel_upgrade_in(&context, context.deadline)
            .await;
        context.phase(OperationPhase::Finished);
        result
    }

    async fn query_kernel_upgrade_in(
        &self,
        context: &OperationContext,
        deadline: tokio::time::Instant,
    ) -> Result<UpgradeQueryReport> {
        let attempt = UpgradeAttempt::new(
            UpgradeAction::ManagementCheck,
            self.instance().device_id.clone(),
            deadline.duration_since(context.started),
        )?;
        let retry = context.read_retries_enabled(self.transient_read_retries);
        let first_deadline = if retry {
            context.started + deadline.duration_since(context.started).mul_f64(4.0 / 5.0)
        } else {
            deadline
        };
        let result = self
            .read_kernel_release(context, first_deadline, &attempt)
            .await;
        let delay = retry_delay(attempt.operation_id());
        let retry_decision = result
            .as_ref()
            .err()
            .map(|error| self.decide_upgrade_read_retry(retry, deadline, delay, error));
        if retry_decision != Some(ReadRetryDecision::Permitted) {
            return Ok(UpgradeQueryReport {
                first_failed_attempt: None,
                retry_decision,
                final_attempt: attempt.finish(result, |_| UpgradeOutcome::Queried),
            });
        }
        let next = attempt.repeat_read();
        let initial = attempt.finish(result, |_| UpgradeOutcome::Queried);
        let first_failed_attempt = initial.result.err().map(|source| FailedUpgradeRead {
            receipt: initial.receipt,
            source,
        });
        context.phase(OperationPhase::WaitingToRetry);
        let delay = context
            .wait(deadline, "retry the kernel release check", async {
                tokio::time::sleep(delay).await;
                Ok(())
            })
            .await;
        let result = match delay {
            Ok(()) => self.read_kernel_release(context, deadline, &next).await,
            Err(error) => Err(error),
        };
        Ok(UpgradeQueryReport {
            first_failed_attempt,
            retry_decision,
            final_attempt: next.finish(result, |_| UpgradeOutcome::Queried),
        })
    }

    pub(crate) fn decide_upgrade_read_retry(
        &self,
        enabled: bool,
        deadline: tokio::time::Instant,
        delay: Duration,
        error: &Error,
    ) -> ReadRetryDecision {
        if !enabled {
            ReadRetryDecision::Disabled
        } else if !retryable_read(error) {
            ReadRetryDecision::CauseNotEligible
        } else if deadline.saturating_duration_since(tokio::time::Instant::now()) <= delay {
            ReadRetryDecision::InsufficientTime
        } else if !self.read_retry_budget.take() {
            ReadRetryDecision::SharedBudgetExhausted
        } else {
            ReadRetryDecision::Permitted
        }
    }

    async fn read_kernel_release(
        &self,
        context: &OperationContext,
        deadline: tokio::time::Instant,
        attempt: &UpgradeAttempt,
    ) -> Result<KernelUpgradeCheck> {
        context
            .wait(deadline, "check the kernel release", async {
                context.phase(OperationPhase::Checking);
                self.observe_control_identity().await?;
                self.check_kernel_upgrade_response(Some(&attempt.progress))
                    .await
            })
            .await
            .map_err(super::control_identity::recovery_read_error)
    }

    /// Check the kernel's own release provider once. Managed instances disable
    /// this by default; explicitly select ManagedUpgradeChecks::Manual to allow
    /// checks while keeping periodic upgrade checks off. A 501 is retained as
    /// an HTTP error rather than interpreted as a license requirement.
    pub async fn check_kernel_upgrade(&self) -> Result<KernelUpgradeCheck> {
        self.check_kernel_upgrade_inner(None).await
    }

    /// Check once within a caller-supplied deadline and return the query receipt.
    /// A provider answer does not authorize or initiate an installation.
    pub async fn check_kernel_upgrade_with_receipt(
        &self,
        timeout: Duration,
    ) -> Result<UpgradeOperationResult<KernelUpgradeCheck>> {
        self.upgrade_with_receipt(
            UpgradeAction::ManagementCheck,
            "check kernel upgrade",
            timeout,
            |progress| self.check_kernel_upgrade_inner(Some(progress)),
        )
        .await
    }

    async fn check_kernel_upgrade_inner(
        &self,
        progress: Option<UpgradeProgress>,
    ) -> Result<KernelUpgradeCheck> {
        self.system_status().await?;
        self.check_kernel_upgrade_response(progress.as_ref()).await
    }

    async fn check_kernel_upgrade_response(
        &self,
        progress: Option<&UpgradeProgress>,
    ) -> Result<KernelUpgradeCheck> {
        let operation = "check kernel upgrade";
        let request = self.connection.authorized_request(
            reqwest::Method::GET,
            self.connection.management_url("rest/system/upgrade", &[])?,
            None,
        );
        let (status, body) = self
            .send_upgrade(operation, request, false, progress)
            .await
            .map_err(classify_release_unavailable)?;
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
        self.request_server_selected_upgrade_inner(None).await
    }

    /// Make one provider-selected installation request with a total deadline.
    /// Keep the receipt when no complete acknowledgement reaches the caller.
    pub async fn request_server_selected_upgrade_with_receipt(
        &self,
        timeout: Duration,
    ) -> Result<UpgradeOperationResult<()>> {
        self.upgrade_with_receipt(
            UpgradeAction::ManagementProvider,
            "request server-selected upgrade",
            timeout,
            |progress| self.request_server_selected_upgrade_inner(Some(progress)),
        )
        .await
    }

    async fn request_server_selected_upgrade_inner(
        &self,
        progress: Option<UpgradeProgress>,
    ) -> Result<()> {
        let operation = "request server-selected upgrade";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let request = self.connection.authorized_request(
            reqwest::Method::POST,
            self.connection.management_url("rest/system/upgrade", &[])?,
            None,
        );
        let (status, body) = self
            .send_upgrade(operation, request, true, progress.as_ref())
            .await
            .map_err(classify_release_unavailable)?;
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
        self.upload_kernel_upgrade_inner(archive.into(), program, None)
            .await
    }

    /// Verify and upload a fixed archive within a total deadline and return
    /// the receipt. The acknowledgement alone does not establish installation.
    pub async fn upload_kernel_upgrade_with_receipt(
        &self,
        archive: impl Into<PathBuf>,
        program: &OfficialProgram,
        timeout: Duration,
    ) -> Result<UpgradeOperationResult<()>> {
        let attempt = UpgradeAttempt::new(
            UpgradeAction::ManagementArchive,
            self.instance().device_id.clone(),
            timeout,
        )?;
        Ok(self
            .upload_kernel_upgrade_attempt(archive.into(), program, attempt)
            .await)
    }

    pub(crate) async fn upload_kernel_upgrade_attempt(
        &self,
        archive: PathBuf,
        program: &OfficialProgram,
        mut attempt: UpgradeAttempt,
    ) -> UpgradeOperationResult<()> {
        attempt.set_archive(program.archive_sha256());
        Self::run_upgrade_attempt(
            attempt,
            UpgradeAction::ManagementArchive,
            "upload fixed kernel upgrade",
            |progress| self.upload_kernel_upgrade_inner(archive, program, Some(progress)),
        )
        .await
    }

    async fn upload_kernel_upgrade_inner(
        &self,
        path: PathBuf,
        program: &OfficialProgram,
        progress: Option<UpgradeProgress>,
    ) -> Result<()> {
        let file = Self::prepare_kernel_archive(path, program).await?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.upload_prepared_kernel_archive(file, program, progress.as_ref(), None)
            .await
    }

    pub(crate) async fn prepare_kernel_archive(
        path: PathBuf,
        program: &OfficialProgram,
    ) -> Result<File> {
        if program.archive_bytes() > 128 * 1024 * 1024 {
            return Err(Error::ProgramRejected {
                reason: "archive exceeds the kernel upload bound",
            });
        }
        if !path.is_absolute() {
            return Err(Error::InvalidPath {
                reason: "upgrade archive must be an absolute local path",
            });
        }
        let expected_len = program.archive_bytes();
        let expected_sha = program.archive_sha256();
        tokio::task::spawn_blocking(move || prepare_archive(&path, expected_len, expected_sha))
            .await
            .map_err(|_| Error::ManagedFailure {
                reason: "archive verification worker did not complete",
            })?
    }

    pub(crate) async fn lock_for_kernel_upgrade(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.connection.mutation_lock.lock().await
    }

    pub(crate) async fn upload_prepared_kernel_archive(
        &self,
        file: File,
        program: &OfficialProgram,
        progress: Option<&UpgradeProgress>,
        context: Option<&OperationContext>,
    ) -> Result<()> {
        let operation = "upload fixed kernel upgrade";
        let part = reqwest::multipart::Part::stream_with_length(
            reqwest::Body::from(tokio::fs::File::from_std(file)),
            program.archive_bytes(),
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
        if let Some(context) = context {
            context.phase(OperationPhase::Submitting);
        }
        let (status, body) = self
            .send_upgrade(operation, request, true, progress)
            .await?;
        acknowledge(operation, status, body)
    }

    async fn send_upgrade(
        &self,
        operation: &'static str,
        request: reqwest::RequestBuilder,
        mutation: bool,
        progress: Option<&UpgradeProgress>,
    ) -> Result<(u16, Vec<u8>)> {
        let Some(progress) = progress else {
            return self
                .connection
                .request_prepared(operation, request, mutation)
                .await;
        };
        progress.dispatch(UpgradeDispatch::Http {
            status: None,
            complete: false,
        });
        let response = send_bounded_observing_headers(
            operation,
            request,
            mutation,
            self.connection.response_limit,
            |status| {
                progress.dispatch(UpgradeDispatch::Http {
                    status: Some(status),
                    complete: false,
                });
            },
        )
        .await?;
        progress.dispatch(UpgradeDispatch::Http {
            status: Some(response.status),
            complete: true,
        });
        let response = checked_response(operation, response, mutation)?;
        Ok((response.status, response.body))
    }

    async fn upgrade_with_receipt<T, F>(
        &self,
        action: UpgradeAction,
        operation: &'static str,
        timeout: Duration,
        run: impl FnOnce(UpgradeProgress) -> F,
    ) -> Result<UpgradeOperationResult<T>>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        let attempt = UpgradeAttempt::new(action, self.instance().device_id.clone(), timeout)?;
        Ok(Self::run_upgrade_attempt(attempt, action, operation, run).await)
    }

    async fn run_upgrade_attempt<T, F>(
        attempt: UpgradeAttempt,
        action: UpgradeAction,
        operation: &'static str,
        run: impl FnOnce(UpgradeProgress) -> F,
    ) -> UpgradeOperationResult<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        let deadline = tokio::time::Instant::from_std(attempt.deadline);
        let result = match tokio::time::timeout_at(deadline, run(attempt.progress.clone())).await {
            Ok(result) => result,
            Err(_) => Err(mutation_error(
                operation,
                !action.is_query() && matches!(attempt.dispatch(), UpgradeDispatch::Http { .. }),
                Error::Timeout { operation },
            )),
        };
        attempt.finish(result, |_| {
            if action.is_query() {
                UpgradeOutcome::Queried
            } else {
                UpgradeOutcome::Acknowledged
            }
        })
    }
}

pub(crate) fn retry_delay(operation_id: [u8; 16]) -> Duration {
    Duration::from_millis(5 + u64::from(operation_id[0] & 0x0f))
}

fn retryable_read(error: &Error) -> bool {
    use std::{error::Error as _, io::ErrorKind};
    match error {
        Error::Timeout { .. } => true,
        Error::Transport { source, .. } if source.is_connect() => {
            let mut cause = source.source();
            while let Some(error) = cause {
                if let Some(io) = error.downcast_ref::<std::io::Error>() {
                    return matches!(
                        io.kind(),
                        ErrorKind::ConnectionRefused
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                    );
                }
                cause = error.source();
            }
            false
        }
        _ => false,
    }
}

pub(super) fn classify_release_unavailable(error: Error) -> Error {
    match error {
        Error::Http { response } if crate::upgrades::is_missing_release(&response) => {
            Error::UpgradeReleaseUnavailable { response }
        }
        Error::MutationOutcomeUnknown { operation, source } => match *source {
            Error::Http { response } if crate::upgrades::is_missing_release(&response) => {
                Error::UpgradeReleaseUnavailable { response }
            }
            source => Error::MutationOutcomeUnknown {
                operation,
                source: Box::new(source),
            },
        },
        other => other,
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
