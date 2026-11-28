//! Bounded, authenticated logging changes with independent runtime readback.

use super::{
    maintenance_control::{core_log_level_body, verify_empty_maintenance_reply},
    workflow_write_result, Client,
};
use crate::{
    CoreErrorLog, CoreLogChange, CoreLogChangeReport, CoreLogLevels, CoreLogObservation, Error,
    OperationOptions, OperationPhase, ResponseDiagnostic, Result,
};
use reqwest::Method;
use std::collections::BTreeMap;
use tokio::time::Instant;

impl Client {
    /// Record one correlated error, clear observed errors or change selected
    /// runtime levels. Check the original reply and separate native readback.
    /// This does not log on the controller, retry writes or preserve removed logs.
    pub async fn change_core_logging_and_verify(
        &self,
        change: CoreLogChange<'_>,
        options: OperationOptions,
    ) -> Result<CoreLogChangeReport> {
        const CHANGE: &str = "change the selected engine's logging state";
        const READ: &str = "verify the selected engine's logging state";
        let (route, marker, text, body) = match &change {
            CoreLogChange::Record {
                message,
                correlation,
            } => {
                if !(1..=80).contains(&correlation.len())
                    || !correlation
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                    || message.is_empty()
                    || message.contains('\0')
                    || 8192usize.saturating_sub(correlation.len() + 11) < message.len()
                {
                    return Err(invalid(
                        "select a bounded error message and a non-secret correlation token",
                    ));
                }
                let marker = format!("[sidecar:{correlation}]");
                let text = format!("{message} {marker}");
                ("rest/system/error", Some(marker), Some(text), None)
            }
            CoreLogChange::ClearErrors => ("rest/system/error/clear", None, None, None),
            CoreLogChange::Levels(levels) => (
                "rest/system/loglevels",
                None,
                None,
                Some(serde_json::json!(core_log_level_body(levels)?)),
            ),
        };
        let url = self.connection.management_url(route, &[])?;
        let context = options.start()?;
        let mut guard = None;
        let mut write = Default::default();
        let mut chosen = None;
        let mut original_errors = None;
        let mut unchanged = None;
        let result = context
            .wait(context.dispatch_deadline(), CHANGE, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let generation =
                    self.system_status().await?.start_time.ok_or_else(|| {
                        invalid("the selected engine did not report its start time")
                    })?;
                match change {
                    CoreLogChange::Record { .. } => {
                        let before = self.core_errors().await?;
                        if count_label(
                            &before,
                            marker
                                .as_deref()
                                .ok_or_else(|| invalid("the error label is absent"))?,
                        ) != 0
                        {
                            return Err(invalid(
                                "open the existing error log entry before reusing its correlation",
                            ));
                        }
                    }
                    CoreLogChange::ClearErrors => {
                        let before = self.core_errors().await?;
                        if before.is_empty() {
                            unchanged = Some(clear_observation(&before, before.clone()));
                        }
                        original_errors = Some(before);
                    }
                    CoreLogChange::Levels(levels) => {
                        let current = self.core_log_levels().await?;
                        if levels
                            .keys()
                            .any(|package| !current.levels.contains_key(package))
                        {
                            return Err(invalid(
                                "a requested package is absent from the active log levels",
                            ));
                        }
                        let observation = level_observation(levels, current);
                        if observation.completion() == crate::OperationCompletion::Completed {
                            unchanged = Some(observation);
                        }
                    }
                }
                self.require_configuration_generation(&generation).await?;
                if unchanged.is_some() {
                    return Ok(None);
                }
                if Instant::now() >= context.dispatch_deadline() {
                    return Err(Error::Timeout { operation: CHANGE });
                }
                chosen = Some(generation);
                let request = self
                    .connection
                    .authorized_request(Method::POST, url, body.as_ref());
                let request = if let Some(text) = text {
                    request
                        .header("Content-Type", "text/plain; charset=utf-8")
                        .body(text)
                } else {
                    request
                };
                let reply = self
                    .connection
                    .send_workflow_write(CHANGE, request, &context, &mut write)
                    .await?;
                verify_empty_maintenance_reply(CHANGE, reply.status, &reply.body)?;
                Ok(Some(ResponseDiagnostic::new(reply.status, reply.body)))
            })
            .await;
        let original = workflow_write_result(CHANGE, write, result);
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        let mut report = CoreLogChangeReport {
            write,
            current: unchanged.filter(|_| original.is_ok()),
            original,
            observation_error: None,
        };
        if let Some(generation) = chosen.filter(|_| write.dispatched && !refused) {
            context.phase(OperationPhase::Verifying);
            let verified = context
                .wait(context.deadline, READ, async {
                    self.require_configuration_generation(&generation).await?;
                    let observation = match change {
                        CoreLogChange::Record { .. } => {
                            let log = self.core_errors().await?;
                            let matches = count_label(
                                &log,
                                marker
                                    .as_deref()
                                    .ok_or_else(|| invalid("the error label is absent"))?,
                            );
                            CoreLogObservation::Recorded { matches, log }
                        }
                        CoreLogChange::ClearErrors => {
                            let before = original_errors
                                .as_ref()
                                .ok_or_else(|| invalid("the original error log is absent"))?;
                            clear_observation(before, self.core_errors().await?)
                        }
                        CoreLogChange::Levels(levels) => {
                            level_observation(levels, self.core_log_levels().await?)
                        }
                    };
                    self.require_configuration_generation(&generation).await?;
                    Ok(observation)
                })
                .await;
            match verified {
                Ok(current) => report.current = Some(current),
                Err(error) => report.observation_error = Some(error),
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfiguration { reason }
}

fn count_label(log: &CoreErrorLog, marker: &str) -> usize {
    log.errors
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|entry| entry.message.contains(marker))
        .count()
}

fn log_keys(log: &CoreErrorLog) -> BTreeMap<(&str, &str, &str), usize> {
    let mut counts = BTreeMap::new();
    for entry in log.errors.as_deref().unwrap_or_default() {
        *counts
            .entry((
                entry.when.as_str(),
                entry.level.as_str(),
                entry.message.as_str(),
            ))
            .or_default() += 1;
    }
    counts
}

fn clear_observation(before: &CoreErrorLog, current: CoreErrorLog) -> CoreLogObservation {
    let original = log_keys(before);
    let after = log_keys(&current);
    let remaining = original
        .iter()
        .map(|(key, count)| (*count).min(*after.get(key).unwrap_or(&0)))
        .sum();
    CoreLogObservation::Cleared {
        previous: original.values().sum(),
        remaining,
        new_entries: after.values().sum::<usize>() - remaining,
        log: current,
    }
}

fn level_observation(
    levels: &BTreeMap<String, crate::CoreLogLevel>,
    current: CoreLogLevels,
) -> CoreLogObservation {
    let matching = levels
        .iter()
        .filter(|(package, level)| current.levels.get(*package) == Some(*level))
        .count();
    CoreLogObservation::Levels {
        selected: levels.len(),
        matching,
        current,
    }
}
