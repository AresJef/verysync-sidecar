//! Explicit ignore-file reads, replacements and restoration of engine defaults.
use super::{workflow_write_result, Client};
use crate::{
    Error, FolderId, IgnoreChange, IgnorePatterns, IgnoreReadback, IgnoreSnapshot, IgnoreUpdate,
    IgnoreWorkflowReport, OperationOptions, OperationPhase, ResponseDiagnostic, Result,
};
use reqwest::Method;
use tokio::time::Instant;

impl Client {
    /// Apply one change to the selected folder or default template. Replacing
    /// already matching rules requires no write. A folder parser failure can
    /// leave invalid text stored. The report retains the original error and
    /// any current readback. File and indexing effects have separate evidence.
    pub async fn change_ignore_patterns_and_verify(
        &self,
        change: IgnoreChange<'_>,
        options: OperationOptions,
    ) -> Result<IgnoreWorkflowReport> {
        const CHANGE: &str = "change ignore rules in the selected scope";
        const READ: &str = "verify the selected ignore rules";
        let (folder, route, method) = match change {
            IgnoreChange::Folder { folder, .. } => (Some(folder), "rest/db/ignores", Method::POST),
            IgnoreChange::RestoreFolderDefaults(folder) => {
                (Some(folder), "rest/db/resetIgnores", Method::POST)
            }
            IgnoreChange::DefaultTemplate(_) => (None, "rest/config/defaults/ignores", Method::PUT),
        };
        let query = folder.map(|id| [("folder", id.as_str())]);
        let url = self.connection.management_url(
            route,
            query.as_ref().map_or(&[], |values| values.as_slice()),
        )?;
        let context = options.start()?;
        let mut write = Default::default();
        let mut guard = None;
        let mut scope = None;
        let mut matched = None;
        let mut expected_template = None;
        let mut native_reset = None;
        let result =
            context
                .wait(context.dispatch_deadline(), CHANGE, async {
                    context.phase(OperationPhase::Checking);
                    guard = Some(self.connection.mutation_lock.lock().await);
                    self.observe_control_identity().await?;
                    let generation = self.system_status().await?.start_time.ok_or(
                        Error::InvalidConfiguration {
                            reason: "the selected instance did not report its start time",
                        },
                    )?;
                    let path = match folder {
                        Some(id) => Some(self.folder(id).await?.path),
                        None => None,
                    };
                    let body = match change {
                        IgnoreChange::Folder { folder, patterns } => {
                            let current = self.ignore_patterns(folder).await?;
                            if usable_rules(&current)
                                && current.patterns.as_deref().unwrap_or_default()
                                    == patterns.patterns()
                            {
                                matched = Some(IgnoreReadback::Folder(current));
                            }
                            Some(serde_json::json!({"ignore": patterns.patterns()}))
                        }
                        IgnoreChange::RestoreFolderDefaults(_) => None,
                        IgnoreChange::DefaultTemplate(patterns) => {
                            let mut current = self.default_ignore_patterns().await?;
                            if current.lines == patterns.patterns() {
                                matched = Some(IgnoreReadback::DefaultTemplate(current.clone()));
                            }
                            current.lines = patterns.patterns().to_owned();
                            let body = serde_json::to_value(&current).map_err(|_| {
                                Error::InvalidConfiguration {
                                    reason: "the default ignore template cannot be encoded",
                                }
                            })?;
                            expected_template = Some(current);
                            Some(body)
                        }
                    };
                    self.verify_ignore_scope(folder, path.as_ref(), &generation)
                        .await?;
                    if matched.is_some() {
                        return Ok(None);
                    }
                    if Instant::now() >= context.dispatch_deadline() {
                        return Err(Error::Timeout { operation: CHANGE });
                    }
                    scope = Some((generation, path));
                    let request = self
                        .connection
                        .authorized_request(method, url, body.as_ref());
                    let reply = self
                        .connection
                        .send_workflow_write(CHANGE, request, &context, &mut write)
                        .await?;
                    if folder.is_some() {
                        let parsed = decode_ignore_reply(reply.status, &reply.body)?;
                        if matches!(change, IgnoreChange::RestoreFolderDefaults(_)) {
                            native_reset = Some(parsed);
                        }
                    }
                    Ok(Some(ResponseDiagnostic::new(reply.status, reply.body)))
                })
                .await;
        let original = workflow_write_result(CHANGE, write, result);
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        let mut report = IgnoreWorkflowReport {
            write,
            scope_matches: (matched.is_some() && original.is_ok()).then_some(true),
            original,
            current: None,
            observation_error: None,
        };
        if report.scope_matches == Some(true) {
            report.current = matched;
        }
        if let Some((generation, path)) = scope.filter(|_| write.dispatched && !refused) {
            context.phase(OperationPhase::Verifying);
            let observed = context
                .wait(context.deadline, READ, async {
                    self.verify_ignore_scope(folder, path.as_ref(), &generation)
                        .await?;
                    let (current, matches) = match change {
                        IgnoreChange::Folder { folder, patterns } => {
                            let current = self.ignore_patterns(folder).await?;
                            let matched = usable_rules(&current)
                                && current.patterns.as_deref().unwrap_or_default()
                                    == patterns.patterns();
                            (IgnoreReadback::Folder(current), Some(matched))
                        }
                        IgnoreChange::RestoreFolderDefaults(folder) => {
                            let current = self.ignore_patterns(folder).await?;
                            let matched = if !usable_rules(&current) {
                                Some(false)
                            } else {
                                native_reset.as_ref().map(|ack| {
                                    ack.patterns == current.patterns
                                        && ack.expanded_patterns == current.expanded_patterns
                                })
                            };
                            (IgnoreReadback::Folder(current), matched)
                        }
                        IgnoreChange::DefaultTemplate(_) => {
                            let current = self.default_ignore_patterns().await?;
                            let matched = expected_template
                                .as_ref()
                                .is_some_and(|expected| *expected == current);
                            (IgnoreReadback::DefaultTemplate(current), Some(matched))
                        }
                    };
                    self.verify_ignore_scope(folder, path.as_ref(), &generation)
                        .await?;
                    Ok((current, matches))
                })
                .await;
            match observed {
                Ok((current, matches)) => {
                    report.current = Some(current);
                    report.scope_matches = matches;
                }
                Err(source) => report.observation_error = Some(source),
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn verify_ignore_scope(
        &self,
        folder: Option<&FolderId>,
        path: Option<&crate::TargetPath>,
        generation: &str,
    ) -> Result<()> {
        if let Some(folder) = folder {
            if Some(&self.folder(folder).await?.path) != path {
                return Err(Error::ConfigurationChanged);
            }
        }
        if self.system_status().await?.start_time.as_deref() != Some(generation) {
            return Err(Error::ConfigurationChanged);
        }
        Ok(())
    }

    /// Read the global default template without reading or changing ignore files.
    pub async fn default_ignore_patterns(&self) -> Result<crate::IgnoreDefaults> {
        self.system_status().await?;
        self.connection
            .get_json(
                "read default ignore patterns",
                "rest/config/defaults/ignores",
            )
            .await
    }

    /// Replace the global template once, retaining unknown native fields and
    /// returning complete actual readback. Empty explicitly selects no lines.
    /// This does not parse rules, alter existing ignore files or retry a write.
    /// Independent writers are not coordinated by the shared Client clone lock.
    pub async fn set_default_ignore_patterns(
        &self,
        patterns: &IgnorePatterns,
    ) -> Result<crate::ConfigurationSectionUpdate<crate::IgnoreDefaults>> {
        let _guard = self.connection.mutation_lock.lock().await;
        let mut desired = self.default_ignore_patterns().await?;
        desired.lines = patterns.patterns().to_owned();
        let body = serde_json::to_value(&desired).map_err(|_| Error::InvalidConfiguration {
            reason: "default ignore template cannot be encoded",
        })?;
        let url = self
            .connection
            .management_url("rest/config/defaults/ignores", &[])?;
        self.connection
            .request_bytes(
                "replace default ignore patterns",
                reqwest::Method::PUT,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration = self.default_ignore_patterns().await.map_err(|source| {
            Error::MutationOutcomeUnknown {
                operation: "read back default ignore patterns",
                source: Box::new(source),
            }
        })?;
        Ok(crate::ConfigurationSectionUpdate {
            requested_fields_match: configuration == desired,
            configuration,
        })
    }

    /// Read current rules and parser diagnostics without changing the file.
    /// A malformed stored file is an observable snapshot with parse_error set.
    pub async fn ignore_patterns(&self, folder: &FolderId) -> Result<IgnoreSnapshot> {
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .get_json_with_query(
                "read folder ignore patterns",
                "rest/db/ignores",
                &[("folder", folder.as_str())],
            )
            .await
    }
    /// Replace exact ordered rules once. The engine may store invalid syntax
    /// while returning HTTP 200; this is IgnorePatternsRejected, never success.
    pub async fn set_ignore_patterns(
        &self,
        folder: &FolderId,
        patterns: &IgnorePatterns,
    ) -> Result<IgnoreUpdate> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.change_ignore_file(
            folder,
            "rest/db/ignores",
            Some(&serde_json::json!({"ignore":patterns.patterns()})),
        )
        .await?;
        let snapshot =
            self.ignore_patterns(folder)
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back replaced ignore patterns",
                    source: Box::new(source),
                })?;
        reject_parse_error(snapshot).map(|snapshot| IgnoreUpdate {
            requested_patterns_match: snapshot.patterns.as_deref().unwrap_or_default()
                == patterns.patterns(),
            snapshot,
        })
    }
    /// Restore this engine's built-in default ignore list, rather than clearing
    /// it. The library does not embed or reconstruct the vendor's default text.
    pub async fn reset_ignore_patterns(&self, folder: &FolderId) -> Result<IgnoreSnapshot> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.change_ignore_file(folder, "rest/db/resetIgnores", None)
            .await?;
        let snapshot =
            self.ignore_patterns(folder)
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back restored ignore defaults",
                    source: Box::new(source),
                })?;
        reject_parse_error(snapshot)
    }
    async fn change_ignore_file(
        &self,
        folder: &FolderId,
        route: &'static str,
        body: Option<&serde_json::Value>,
    ) -> Result<()> {
        let url = self
            .connection
            .management_url(route, &[("folder", folder.as_str())])?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "change folder ignore patterns",
                reqwest::Method::POST,
                url,
                body,
                true,
            )
            .await?;
        decode_ignore_reply(status, &bytes).map(|_| ())
    }
}

fn decode_ignore_reply(status: u16, bytes: &[u8]) -> Result<IgnoreSnapshot> {
    let snapshot: IgnoreSnapshot =
        serde_json::from_slice(bytes).map_err(|_| Error::MutationOutcomeUnknown {
            operation: "decode changed ignore patterns",
            source: Box::new(Error::InvalidResponse {
                operation: "decode changed ignore patterns",
                response: ResponseDiagnostic::new(status, bytes.to_owned()),
            }),
        })?;
    reject_parse_error(snapshot)
}

fn usable_rules(snapshot: &IgnoreSnapshot) -> bool {
    snapshot.parse_error.as_ref().is_none_or(String::is_empty)
}
fn reject_parse_error(snapshot: IgnoreSnapshot) -> Result<IgnoreSnapshot> {
    if !usable_rules(&snapshot) {
        return Err(Error::IgnorePatternsRejected {
            snapshot: Box::new(snapshot),
        });
    }
    Ok(snapshot)
}
