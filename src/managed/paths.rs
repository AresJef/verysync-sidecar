//! Explicit native storage-location introspection for a stopped owned instance.
use super::{command::CliPlan, ManagedInstance};
use crate::{ProcessDiagnostic, Result};
use std::{fmt, path::PathBuf, time::Duration};

/// Locations reported by the local program. A reported path does not prove
/// existence, writeability, data contents, or an active listener.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeStoragePaths {
    /// Configuration file.
    pub configuration_file: PathBuf,
    /// Device identity private key.
    pub device_private_key: PathBuf,
    /// Device identity certificate.
    pub device_certificate: PathBuf,
    /// GUI/API HTTPS private key.
    pub https_private_key: PathBuf,
    /// GUI/API HTTPS certificate.
    pub https_certificate: PathBuf,
    /// Database directory.
    pub database_directory: PathBuf,
    /// Native log file.
    pub log_file: PathBuf,
    /// GUI override directory.
    pub gui_override_directory: PathBuf,
    /// Native default synchronization directory; not a registered-folder list.
    pub default_sync_directory: PathBuf,
}
impl fmt::Debug for NativeStoragePaths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeStoragePaths { [REDACTED] }")
    }
}
/// Classification of an actual contained native paths command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeStoragePathsOutcome {
    /// Exit zero and the complete recognized native report.
    Success,
    /// Native nonzero exit; inspect the private diagnostic.
    Failure,
    /// Exit zero with an unrecognized, incomplete, or ambiguous report.
    UnrecognizedOutput,
}
/// Actual native exit, typed paths when recognized, and bounded private output.
#[derive(Debug)]
pub struct NativeStoragePathsExit {
    /// Actual native process code.
    pub code: Option<i32>,
    /// Exact owned CLI containment and descendants have ended.
    pub tree_stopped: bool,
    /// Native exit and schema classification.
    pub outcome: NativeStoragePathsOutcome,
    /// Present only after exit zero and a complete recognized report.
    pub paths: Option<NativeStoragePaths>,
    /// Exact bounded private native output, potentially revealing local paths.
    pub diagnostic: ProcessDiagnostic,
}
fn parse_paths(bytes: &[u8]) -> Option<NativeStoragePaths> {
    const GROUPS: [(&str, usize); 7] = [
        ("Configuration file:", 1),
        ("Device private key & certificate files:", 2),
        ("GUI / API HTTPS private key & certificate files:", 2),
        ("Database location:", 1),
        ("Log file:", 1),
        ("GUI override directory:", 1),
        ("Default sync folder directory:", 1),
    ];
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines().filter(|line| !line.is_empty());
    let mut paths = Vec::with_capacity(9);
    for (label, count) in GROUPS {
        if lines.next()? != label {
            return None;
        }
        for _ in 0..count {
            let text = lines.next()?.strip_prefix('\t')?;
            if text.chars().any(char::is_control) {
                return None;
            }
            let path = PathBuf::from(text);
            if !path.is_absolute() {
                return None;
            }
            paths.push(path);
        }
    }
    if lines.next().is_some() {
        return None;
    }
    let mut paths = paths.into_iter();
    Some(NativeStoragePaths {
        configuration_file: paths.next()?,
        device_private_key: paths.next()?,
        device_certificate: paths.next()?,
        https_private_key: paths.next()?,
        https_certificate: paths.next()?,
        database_directory: paths.next()?,
        log_file: paths.next()?,
        gui_override_directory: paths.next()?,
        default_sync_directory: paths.next()?,
    })
}
impl ManagedInstance {
    /// Explicitly run the native paths command against a confirmed stopped owner.
    ///
    /// Verifies the last-ready executable hash, holds the private state lease
    /// through contained child cleanup, uses its dedicated profile and explicit
    /// home, and captures at most 64 KiB. Never connects to management, starts a
    /// serving core, retries, downloads, or changes the caller environment.
    /// Native helpers can initialize directories inside the owned state.
    /// As with other stopped CLI inspections, this invalidates the prior
    /// clean-generation backup eligibility. Results are local PathBuf values,
    /// distinct from the remote REST native_system_paths response.
    ///
    /// Cancellation requests exact cleanup; the worker retains its locks until
    /// cleanup ends. Nonzero exits and unknown text remain explicit outcomes.
    pub async fn inspect_native_storage_paths(
        &mut self,
        timeout: Duration,
    ) -> Result<NativeStoragePathsExit> {
        let exit = self
            .run_stopped_cli(
                CliPlan {
                    arguments: vec!["paths".to_owned()],
                    positional: Vec::new(),
                    operation: "inspect native storage paths",
                    may_modify: false,
                    clean_stop_required: false,
                },
                timeout,
            )
            .await?;
        let paths = (exit.code == Some(0))
            .then(|| parse_paths(exit.diagnostic.body_bytes()))
            .flatten();
        let outcome = if exit.code != Some(0) {
            NativeStoragePathsOutcome::Failure
        } else if paths.is_some() {
            NativeStoragePathsOutcome::Success
        } else {
            NativeStoragePathsOutcome::UnrecognizedOutput
        };
        Ok(NativeStoragePathsExit {
            code: exit.code,
            tree_stopped: exit.tree_stopped,
            outcome,
            paths,
            diagnostic: exit.diagnostic,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_paths;
    fn output() -> Vec<u8> {
        let groups = [
            ("Configuration file:", 1),
            ("Device private key & certificate files:", 2),
            ("GUI / API HTTPS private key & certificate files:", 2),
            ("Database location:", 1),
            ("Log file:", 1),
            ("GUI override directory:", 1),
            ("Default sync folder directory:", 1),
        ];
        let mut text = String::new();
        for (label, count) in groups {
            text.push_str(label);
            text.push('\n');
            for i in 0..count {
                let path = std::env::temp_dir().join(format!("owned space \u{4e8c}/{i}"));
                text.push('\t');
                text.push_str(path.to_str().unwrap());
                text.push('\n');
            }
            text.push('\n');
        }
        text.into_bytes()
    }
    #[test]
    fn complete_native_paths_keep_native_syntax_and_reject_ambiguous_or_partial_output() {
        let bytes = output();
        let paths = parse_paths(&bytes).unwrap();
        assert_eq!(
            paths.configuration_file,
            std::env::temp_dir().join("owned space \u{4e8c}/0")
        );
        assert_eq!(
            paths.device_certificate,
            std::env::temp_dir().join("owned space \u{4e8c}/1")
        );
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(parse_paths(text.replace('\n', "\r\n").as_bytes()).is_some());
        assert!(parse_paths(&bytes[..bytes.len() / 2]).is_none());
        assert!(parse_paths(
            text.replace("Configuration file:", "Unknown heading:")
                .as_bytes()
        )
        .is_none());
        assert!(parse_paths(text.replacen("\t", "", 1).as_bytes()).is_none());
        assert!(parse_paths(text.replacen("\t", "\trelative/", 1).as_bytes()).is_none());
        assert!(parse_paths(&[bytes.as_slice(), b"unknown trailer\n"].concat()).is_none());
        assert!(parse_paths(&[bytes.as_slice(), bytes.as_slice()].concat()).is_none());
        assert!(parse_paths(&[bytes.as_slice(), &[255]].concat()).is_none());
        assert!(!format!("{paths:?}").contains("owned space"));
    }
}
