//! Explicit native completion instructions, never evaluated as shell code.
use super::{command::CliPlan, ManagedInstance};
use crate::{ProcessDiagnostic, Result};
use std::time::Duration;

/// Exact native completion command selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCompletionAction {
    /// Invoke the native install-completions command.
    Install,
    /// Invoke it with the native uninstall flag.
    Uninstall,
}
/// Actual native exit and text classification, not shell integration status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCompletionOutcome {
    /// Exit zero with nonempty UTF-8 native instruction text.
    InstructionText,
    /// Native nonzero exit or no normal exit code.
    Failure,
    /// Exit zero with empty, non-UTF-8 or NUL-containing output.
    UnrecognizedOutput,
}
/// Bounded private native output and the actual contained CLI exit.
#[derive(Debug)]
pub struct NativeCompletionExit {
    /// Exact requested action.
    pub action: NativeCompletionAction,
    /// Actual native exit code.
    pub code: Option<i32>,
    /// Exact owned CLI containment and descendants have ended.
    pub tree_stopped: bool,
    /// Text and exit classification; never a shell installation receipt.
    pub outcome: NativeCompletionOutcome,
    /// Exact bounded private output, potentially containing executable paths.
    pub diagnostic: ProcessDiagnostic,
}
impl NativeCompletionExit {
    /// Borrow exact native text only after a recognized exit-zero response.
    /// This is untrusted shell text, not validated or quoted executable code.
    pub fn instruction_text(&self) -> Option<&str> {
        if self.outcome != NativeCompletionOutcome::InstructionText {
            return None;
        }
        std::str::from_utf8(self.diagnostic.body_bytes()).ok()
    }
}
fn classify(code: Option<i32>, bytes: &[u8]) -> NativeCompletionOutcome {
    if code != Some(0) {
        return NativeCompletionOutcome::Failure;
    }
    match std::str::from_utf8(bytes) {
        Ok(text) if !text.trim().is_empty() && !text.contains('\0') => {
            NativeCompletionOutcome::InstructionText
        }
        _ => NativeCompletionOutcome::UnrecognizedOutput,
    }
}
impl ManagedInstance {
    /// Explicitly request native completion instructions on a stopped owner.
    ///
    /// Reuses the exact program hash, private lease/profile, state alias checks,
    /// cancellation, contained cleanup and 64 KiB private capture. Does not
    /// evaluate or rewrite native text, launch a shell, change caller environment,
    /// download a program, or claim that shell integration was installed/removed.
    /// Native profile effects stay within the explicit owned-state boundary.
    ///
    /// The fixed macOS baseline prints identical instructions for both actions
    /// and leaves synthetic shell customization unchanged. Its printed executable
    /// path is retained literally, including spaces; text is not certified safe
    /// to evaluate or portable to the caller's shell. Other target effects require
    /// their own native evidence. A missing or malformed response is never
    /// invented as successful installation.
    ///
    /// As with other stopped CLI operations, clean-backup eligibility is
    /// invalidated. Cancellation requests cleanup rather than undoing an action.
    /// Failed or timed-out invocation may have changed native owned profile
    /// state and remains an uncertain mutation; no retry is automatic.
    pub async fn native_completion_instructions(
        &mut self,
        action: NativeCompletionAction,
        timeout: Duration,
    ) -> Result<NativeCompletionExit> {
        let mut arguments = vec!["install-completions".to_owned()];
        if action == NativeCompletionAction::Uninstall {
            arguments.push("--uninstall".to_owned());
        }
        let exit = self
            .run_stopped_cli(
                CliPlan {
                    arguments,
                    positional: Vec::new(),
                    operation: "request native shell completion instructions",
                    may_modify: true,
                    clean_stop_required: false,
                },
                timeout,
            )
            .await?;
        Ok(NativeCompletionExit {
            action,
            code: exit.code,
            tree_stopped: exit.tree_stopped,
            outcome: classify(exit.code, exit.diagnostic.body_bytes()),
            diagnostic: exit.diagnostic,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_text_does_not_turn_failures_empty_or_non_utf8_into_success() {
        let text = b"complete -C /owned engine verysync\r\n";
        assert_eq!(
            classify(Some(0), text),
            NativeCompletionOutcome::InstructionText
        );
        for code in [Some(1), Some(2), None] {
            assert_eq!(classify(code, text), NativeCompletionOutcome::Failure);
        }
        for bad in [b"".as_slice(), b" \r\n", &[255], b"text\0more"] {
            assert_eq!(
                classify(Some(0), bad),
                NativeCompletionOutcome::UnrecognizedOutput
            );
        }
        let exit = NativeCompletionExit {
            action: NativeCompletionAction::Install,
            code: Some(0),
            tree_stopped: true,
            outcome: classify(Some(0), text),
            diagnostic: ProcessDiagnostic::new(text.to_vec()),
        };
        assert_eq!(exit.instruction_text().unwrap().as_bytes(), text);
        assert!(!format!("{exit:?}").contains("owned engine"));
    }
}
