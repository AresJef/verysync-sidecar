//! Explicit stopped-owner database commands through the pinned native program.
use super::{command::CliPlan, ManagedInstance};
use crate::{Error, FolderId, PathStyle, ProcessDiagnostic, Result, TargetPath};
use std::{fmt, time::Duration};

/// Whitelisted native database operation. No command stops or starts a core
/// implicitly; reset is a separate explicit choice.
#[derive(Clone)]
pub enum DatabaseCommand {
    /// Read native database size statistics.
    Statistics,
    /// Read the actual folder's native count table.
    Counts(FolderId),
    /// Read native indexed metadata for one relative target file.
    File {
        /// Exact indexed folder identifier.
        folder: FolderId,
        /// Relative indexed path in the local program's native syntax.
        path: TargetPath,
    },
    /// Explicitly remove the native synchronization database for all folders.
    /// Original files are outside this operation's index-reset scope; later
    /// startup/scans/synchronization can still change them.
    ResetAll,
}

impl fmt::Debug for DatabaseCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Statistics => "DatabaseCommand::Statistics",
            Self::Counts(_) => "DatabaseCommand::Counts([REDACTED])",
            Self::File { .. } => "DatabaseCommand::File([REDACTED])",
            Self::ResetAll => "DatabaseCommand::ResetAll",
        })
    }
}
/// Classification of the actual native CLI outcome, not a data-repair promise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseCommandOutcome {
    /// Native exit zero; inspect actual returned data and separate effects.
    Success,
    /// Only the exact known native exit-one "no such folder" diagnostic.
    FolderNotIndexed,
    /// Native command failed; inspect its bounded private diagnostic.
    Failure,
    /// Native counts exited zero but its table did not match the known schema.
    UnrecognizedCounts,
}
/// One observed native count-table row. Native flag/deletion labels are kept
/// exact instead of assigning undocumented synchronization semantics.
#[derive(Clone)]
pub struct DatabaseCountRow {
    /// Native device label or identifier.
    pub device: String,
    /// Native entry-kind label.
    pub kind: String,
    /// Exact native flags column.
    pub flags: String,
    /// Exact native deleted column, including placeholder labels.
    pub deleted: String,
    /// Reported native count.
    pub count: u64,
    /// Reported native SIZE column without undocumented conversion.
    pub size: u64,
}
impl fmt::Debug for DatabaseCountRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseCountRow")
            .field("count", &self.count)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}
/// Actual contained CLI exit with explicit private native output. Statistics
/// and file metadata retain native text; counts have the verified typed table.
#[derive(Debug)]
pub struct DatabaseCommandExit {
    /// Explicit operation, with private values omitted by Debug.
    pub command: DatabaseCommand,
    /// Actual native process code.
    pub code: Option<i32>,
    /// Exact owned CLI containment ended, including descendant cleanup.
    pub tree_stopped: bool,
    /// Native outcome classification; exit zero is not proof of repair.
    pub outcome: DatabaseCommandOutcome,
    /// Typed count rows only for a recognized successful Counts response.
    /// None is not an invented successful empty table.
    pub counts: Option<Vec<DatabaseCountRow>>,
    /// Opaque native text before a recognized counts table or known missing-folder
    /// diagnostic. Retained privately rather than treated as a count row or discarded.
    /// Other native text responses are not split into a preamble.
    pub native_preamble: Option<ProcessDiagnostic>,
    /// Bounded private native output; explicit inspection can reveal paths/data.
    pub diagnostic: ProcessDiagnostic,
}
fn parse_counts(bytes: &[u8]) -> Option<(Vec<DatabaseCountRow>, Vec<u8>)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut offset = 0;
    let mut start = None;
    for line in text.split_inclusive('\n') {
        if line.split_whitespace().collect::<Vec<_>>()
            == ["DEVICE", "TYPE", "FLAGS", "DELETED", "COUNT", "SIZE"]
        {
            start = Some((offset, offset + line.len()));
            break;
        }
        offset += line.len();
    }
    let (header, body) = start?;
    let mut rows = Vec::new();
    for line in text[body..].lines().filter(|line| !line.trim().is_empty()) {
        let cells = line.split_whitespace().collect::<Vec<_>>();
        if cells.len() != 6 || rows.len() >= 1024 {
            return None;
        }
        rows.push(DatabaseCountRow {
            device: cells[0].to_owned(),
            kind: cells[1].to_owned(),
            flags: cells[2].to_owned(),
            deleted: cells[3].to_owned(),
            count: cells[4].parse().ok()?,
            size: cells[5].parse().ok()?,
        });
    }
    Some((rows, bytes[..header].to_vec()))
}
fn missing_folder_preamble(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?.trim_end();
    if text.lines().any(|line| {
        line.split_whitespace().collect::<Vec<_>>()
            == ["DEVICE", "TYPE", "FLAGS", "DELETED", "COUNT", "SIZE"]
    }) {
        return None;
    }
    let (prefix, line) = text
        .rsplit_once('\n')
        .map(|(prefix, line)| (&bytes[..prefix.len() + 1], line))
        .unwrap_or((&bytes[..0], text));
    matches!(
        line.trim(),
        "verysync: error: no such folder" | "verysync.exe: error: no such folder"
    )
    .then(|| prefix.to_vec())
}
impl ManagedInstance {
    /// Run one whitelisted database command against this confirmed stopped
    /// owner. Verify the exact last-ready executable hash, retain the private
    /// state lease through contained child cleanup and capture at most 64 KiB.
    /// No stop/start, network activation, backup, retry or rollback is implicit.
    ///
    /// Positional values follow a native `--` separator, preventing a folder or
    /// filename from becoming a CLI flag. Cancellation requests exact helper
    /// cleanup; the worker retains locks until cleanup ends. A reset can already
    /// have changed the database when an error/cancellation occurs. Every CLI
    /// inspection invalidates a prior clean-generation backup claim: explicitly
    /// start and normally stop again before taking a fresh snapshot.
    ///
    /// ```rust,no_run
    /// # async fn inspect(core: &mut verysync_sidecar::ManagedInstance, folder: verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
    /// use std::time::Duration;
    /// use verysync_sidecar::DatabaseCommand;
    /// // Explicitly confirm the owned generation is stopped before this call.
    /// let result = core.run_database_command(
    ///     DatabaseCommand::Counts(folder), Duration::from_secs(10),
    /// ).await?;
    /// assert!(result.tree_stopped);
    /// # Ok(()) }
    /// ```
    pub async fn run_database_command(
        &mut self,
        command: DatabaseCommand,
        timeout: Duration,
    ) -> Result<DatabaseCommandExit> {
        let (subcommand, positional) = match &command {
            DatabaseCommand::Statistics => ("database-statistics", Vec::new()),
            DatabaseCommand::Counts(folder) => {
                ("database-counts", vec![folder.as_str().to_owned()])
            }
            DatabaseCommand::File { folder, path } => {
                let style = if cfg!(windows) {
                    PathStyle::Windows
                } else {
                    PathStyle::Unix
                };
                let path = crate::scans::validate_subpath(path, style)?;
                if path.len() > 32768 {
                    return Err(Error::InvalidConfiguration {
                        reason: "database file selector exceeds its bound",
                    });
                }
                (
                    "database-file",
                    vec![folder.as_str().to_owned(), path.to_owned()],
                )
            }
            DatabaseCommand::ResetAll => ("reset-database", Vec::new()),
        };
        let plan = CliPlan {
            arguments: vec!["debug".to_owned(), subcommand.to_owned()],
            positional,
            operation: "run native database command",
            may_modify: matches!(command, DatabaseCommand::ResetAll),
            clean_stop_required: false,
        };
        let exit = self.run_stopped_cli(plan, timeout).await?;
        let mut counts = None;
        let mut native_preamble = None;
        let mut outcome = if exit.code == Some(0) {
            DatabaseCommandOutcome::Success
        } else {
            DatabaseCommandOutcome::Failure
        };
        if matches!(
            command,
            DatabaseCommand::Counts(_) | DatabaseCommand::File { .. }
        ) && exit.code == Some(1)
        {
            if let Some(prefix) = missing_folder_preamble(exit.diagnostic.body_bytes()) {
                outcome = DatabaseCommandOutcome::FolderNotIndexed;
                if !prefix.is_empty() {
                    native_preamble = Some(ProcessDiagnostic::new(prefix));
                }
            }
        }
        if matches!(command, DatabaseCommand::Counts(_))
            && outcome == DatabaseCommandOutcome::Success
        {
            match parse_counts(exit.diagnostic.body_bytes()) {
                Some((rows, prefix)) => {
                    counts = Some(rows);
                    if !prefix.is_empty() {
                        native_preamble = Some(ProcessDiagnostic::new(prefix));
                    }
                }
                None => outcome = DatabaseCommandOutcome::UnrecognizedCounts,
            }
        }
        Ok(DatabaseCommandExit {
            command,
            code: exit.code,
            tree_stopped: exit.tree_stopped,
            outcome,
            counts,
            native_preamble,
            diagnostic: exit.diagnostic,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{missing_folder_preamble, parse_counts};

    #[test]
    fn counts_retain_unknown_labels_and_reject_partial_or_overflowing_tables() {
        let header = "DEVICE TYPE FLAGS DELETED COUNT SIZE\r\n";
        let table = format!("{header}native-device FUTURE --X-- future 2 67\r\n");
        let (rows, preamble) = parse_counts(table.as_bytes()).unwrap();
        assert!(preamble.is_empty());
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (&*rows[0].kind, &*rows[0].flags, &*rows[0].deleted),
            ("FUTURE", "--X--", "future")
        );
        assert_eq!((rows[0].count, rows[0].size), (2, 67));
        assert!(!format!("{:?}", rows[0]).contains("native-device"));
        for invalid in [
            Vec::new(),
            b"a different native envelope".to_vec(),
            format!("{header}local FILE flags 0 1").into_bytes(),
            format!("{header}local FILE flags 0 18446744073709551616 1").into_bytes(),
            format!("{header}local FILE flags 0 -1 1").into_bytes(),
            [header.as_bytes(), &[0xff]].concat(),
            format!("{header}{}", "local FILE flags 0 1 1\n".repeat(1025)).into_bytes(),
        ] {
            assert!(parse_counts(&invalid).is_none());
        }
        assert!(parse_counts(header.as_bytes()).unwrap().0.is_empty());
    }

    #[test]
    fn native_preamble_is_retained_while_complete_count_rows_and_missing_errors_stay_strict() {
        let prefix = b"opaque native startup text\r\n";
        let header = b"DEVICE TYPE FLAGS DELETED COUNT SIZE\r\n";
        let table = [
            prefix.as_slice(),
            header.as_slice(),
            b"local FILE flags --- 1 36\r\n",
        ]
        .concat();
        let (rows, observed) = parse_counts(&table).unwrap();
        assert_eq!(observed, prefix);
        assert_eq!((rows[0].count, rows[0].size), (1, 36));
        assert!(parse_counts(&[table.as_slice(), header.as_slice()].concat()).is_none());
        assert!(
            parse_counts(&[table.as_slice(), b"native unrecognized trailer\n"].concat()).is_none()
        );
        assert!(parse_counts(prefix).is_none());
        assert_eq!(
            missing_folder_preamble(
                &[prefix.as_slice(), b"verysync: error: no such folder\r\n"].concat()
            )
            .unwrap(),
            prefix
        );
        assert!(
            missing_folder_preamble(b"verysync: error: no such folder\nother failure\n").is_none()
        );
        assert!(missing_folder_preamble(b"verysync: error: permission denied\n").is_none());
        assert_eq!(
            missing_folder_preamble(
                &[
                    prefix.as_slice(),
                    b"verysync.exe: error: no such folder\r\n"
                ]
                .concat()
            )
            .unwrap(),
            prefix
        );
        assert!(missing_folder_preamble(b"unrelated.exe: error: no such folder\n").is_none());
        assert!(
            missing_folder_preamble(b"verysync.exe: error: no such folder\nother failure\n")
                .is_none()
        );
        assert!(missing_folder_preamble(
            &[table.as_slice(), b"verysync: error: no such folder\n"].concat()
        )
        .is_none());
    }
}
