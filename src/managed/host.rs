//! Explicit native Linux file-watch minimum requests and independent observations.
use super::{command::CliPlan, ManagedInstance};
use crate::{Error, ProcessDiagnostic, Result};
use std::{
    io,
    time::{Duration, Instant},
};

/// Independently observed local kernel watch limit, not an invented native value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWatchLimitObservation {
    /// The actual decimal kernel value at one observation.
    Value(u64),
    /// This host has no supported Linux procfs observation.
    NotAvailableOnHost,
    /// The independent read failed; preserve its category and native OS code.
    ReadFailure {
        /// Portable I/O category.
        kind: io::ErrorKind,
        /// Actual native OS code when available.
        os_code: Option<i32>,
    },
    /// Bounded kernel data did not match the known decimal schema.
    Unrecognized,
    /// The caller's total deadline left no completed observation.
    DeadlineExceeded,
}
/// Native exit plus an independent post-command kernel observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWatchLimitOutcome {
    /// Exit zero and a post-command value at least the requested minimum.
    /// This does not attribute a change to this caller or promise persistence.
    MinimumObserved,
    /// Exit zero but the observed kernel value remains below the request.
    MinimumNotObserved,
    /// Exit zero without a usable post-command kernel observation.
    Unobservable,
    /// The native process did not exit zero, regardless of the observed value.
    NativeFailure,
}
/// Actual contained CLI exit and independently observed local host state.
#[derive(Debug)]
pub struct NativeWatchLimitExit {
    /// Exact requested minimum, not a request to lower the current value.
    pub requested_minimum: u64,
    /// Actual native process exit code.
    pub code: Option<i32>,
    /// Exact owned CLI containment and descendants have ended.
    pub tree_stopped: bool,
    /// Snapshot before the request.
    pub before: NativeWatchLimitObservation,
    /// Snapshot after the request.
    pub after: NativeWatchLimitObservation,
    /// Explicit result; zero exit alone never means the setting was applied.
    pub outcome: NativeWatchLimitOutcome,
    /// Bounded private native output.
    pub diagnostic: ProcessDiagnostic,
}
#[cfg(any(target_os = "linux", test))]
fn parse_limit(bytes: &[u8]) -> NativeWatchLimitObservation {
    if bytes.len() > 32 {
        return NativeWatchLimitObservation::Unrecognized;
    }
    match std::str::from_utf8(bytes)
        .ok()
        .map(str::trim)
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(value) => NativeWatchLimitObservation::Value(value),
        None => NativeWatchLimitObservation::Unrecognized,
    }
}
fn outcome(
    code: Option<i32>,
    minimum: u64,
    after: NativeWatchLimitObservation,
) -> NativeWatchLimitOutcome {
    if code != Some(0) {
        return NativeWatchLimitOutcome::NativeFailure;
    }
    match after {
        NativeWatchLimitObservation::Value(value) if value >= minimum => {
            NativeWatchLimitOutcome::MinimumObserved
        }
        NativeWatchLimitObservation::Value(_) => NativeWatchLimitOutcome::MinimumNotObserved,
        _ => NativeWatchLimitOutcome::Unobservable,
    }
}
async fn observe_limit(deadline: tokio::time::Instant) -> NativeWatchLimitObservation {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = deadline;
        NativeWatchLimitObservation::NotAvailableOnHost
    }
    #[cfg(target_os = "linux")]
    {
        use tokio::io::AsyncReadExt;
        let reading = async {
            let file = match tokio::fs::File::open(std::path::Path::new(
                "/proc/sys/fs/inotify/max_user_watches",
            ))
            .await
            {
                Ok(file) => file,
                Err(error) => {
                    return NativeWatchLimitObservation::ReadFailure {
                        kind: error.kind(),
                        os_code: error.raw_os_error(),
                    }
                }
            };
            let mut bytes = Vec::with_capacity(33);
            if let Err(error) = file.take(33).read_to_end(&mut bytes).await {
                return NativeWatchLimitObservation::ReadFailure {
                    kind: error.kind(),
                    os_code: error.raw_os_error(),
                };
            }
            parse_limit(&bytes)
        };
        match tokio::time::timeout_at(deadline, reading).await {
            Ok(observation) => observation,
            Err(_) => NativeWatchLimitObservation::DeadlineExceeded,
        }
    }
}
impl ManagedInstance {
    /// Explicitly request the native Linux inotify watch minimum on this
    /// confirmed stopped owner. Zero requests no increase on the fixed baseline.
    ///
    /// This is a host-wide kernel action and may need caller-supplied privilege.
    /// The library never elevates privilege, starts a serving core, installs a
    /// service, writes persistent host configuration, or automatically retries.
    /// The pinned Linux command only raises an insufficient current value; it
    /// cannot lower it and does not persist the change across host restarts.
    ///
    /// The native CLI discards its internal read/parse/write errors and can exit
    /// zero without changing the limit. Independently read at most 33 procfs
    /// bytes before/after the request and report explicit observations/outcome.
    /// These are snapshots, not a transaction with other host administrators.
    /// Other hosts have no Linux observation; inspect their actual native exit.
    ///
    /// Reuses exact executable verification, dedicated state/profile, alias
    /// checks, state leasing, bounded output and contained cancellation cleanup.
    /// A cancelled or failed request may already have changed the host limit.
    /// Prior clean-backup eligibility is invalidated like other stopped CLI
    /// commands. One total deadline covers the reads and command, with necessary
    /// owned-process cleanup allowed to finish after cancellation/deadline.
    pub async fn request_native_file_watch_limit(
        &mut self,
        minimum: u64,
        timeout: Duration,
    ) -> Result<NativeWatchLimitExit> {
        if isize::try_from(minimum).is_err() {
            return Err(Error::InvalidConfiguration {
                reason: "watch minimum exceeds the local signed native integer range",
            });
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or(Error::InvalidConfiguration {
                reason: "host configuration deadline must be positive and representable",
            })?;
        if !self.exit_snapshot().is_some_and(|exit| exit.tree_stopped) {
            return Err(Error::ManagedFailure {
                reason: "host configuration requires a confirmed stopped owned tree",
            });
        }
        let tokio_deadline = tokio::time::Instant::from_std(deadline);
        let before = observe_limit(tokio_deadline).await;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout {
                operation: "observe native file-watch limit before request",
            });
        }
        let exit = self
            .run_stopped_cli(
                CliPlan {
                    arguments: vec![
                        "configure-host".to_owned(),
                        "--watch-files".to_owned(),
                        minimum.to_string(),
                    ],
                    positional: Vec::new(),
                    operation: "request native file-watch limit",
                    may_modify: true,
                    clean_stop_required: false,
                },
                remaining,
            )
            .await?;
        let after = observe_limit(tokio_deadline).await;
        Ok(NativeWatchLimitExit {
            requested_minimum: minimum,
            code: exit.code,
            tree_stopped: exit.tree_stopped,
            before,
            after,
            outcome: outcome(exit.code, minimum, after),
            diagnostic: exit.diagnostic,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn watch_limit_observation_never_treats_zero_exit_as_applied_without_kernel_evidence() {
        use NativeWatchLimitObservation as O;
        use NativeWatchLimitOutcome as R;
        assert_eq!(outcome(Some(0), 100, O::Value(100)), R::MinimumObserved);
        assert_eq!(outcome(Some(0), 100, O::Value(99)), R::MinimumNotObserved);
        assert_eq!(
            outcome(Some(0), 100, O::NotAvailableOnHost),
            R::Unobservable
        );
        assert_eq!(outcome(Some(1), 100, O::Value(200)), R::NativeFailure);
        assert_eq!(outcome(None, 100, O::Value(200)), R::NativeFailure);
        assert_eq!(parse_limit(b"1048576\n"), O::Value(1048576));
        for bytes in [
            b"".as_slice(),
            b"-1",
            b"1 extra",
            b"+1",
            &[255],
            b"18446744073709551616",
        ] {
            assert_eq!(parse_limit(bytes), O::Unrecognized);
        }
    }
}
