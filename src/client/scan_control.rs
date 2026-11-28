//! Explicit scan scopes and partial per-folder scheduling settings.
use std::collections::BTreeMap;

use super::{workflow_write_result, Client};
use crate::operations::ScanCycle;
use crate::{
    Error, EventOptions, EventStreamItem, FolderConfig, FolderId, FolderScanConfig,
    FolderScanPatch, FolderScanUpdate, FolderState, OperationOptions, OperationPhase, Result,
    ScanFolderObservation, ScanPhase, ScanScope, ScanWorkflowReport, TargetPath,
};
use reqwest::Method;
use serde::Deserialize;

const SCAN: &str = "request the specified scan";
const WATCH: &str = "observe the specified scan";

impl Client {
    /// Read actual scan scheduling settings for an existing folder.
    pub async fn folder_scan_configuration(&self, folder: &FolderId) -> Result<FolderScanConfig> {
        #[derive(Deserialize)]
        struct Entry {
            id: FolderId,
            #[serde(flatten)]
            scan: FolderScanConfig,
        }
        #[derive(Deserialize)]
        struct Config {
            folders: Vec<Entry>,
        }
        self.system_status().await?;
        let config: Config = self
            .connection
            .get_json("read folder scan configuration", "rest/config")
            .await?;
        config
            .folders
            .into_iter()
            .find(|x| x.id == *folder)
            .map(|x| x.scan)
            .ok_or_else(|| Error::FolderNotFound { id: folder.clone() })
    }
    /// Patch selected scan settings once, without retry or automatic restart.
    /// Readback is distinct from a watcher readiness or scan completion receipt.
    pub async fn update_folder_scan_configuration(
        &self,
        folder: &FolderId,
        patch: &FolderScanPatch,
    ) -> Result<FolderScanUpdate> {
        patch.validate()?;
        let url = self.connection.folder_url(folder)?;
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "scan settings cannot be encoded",
        })?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .request_bytes(
                "update folder scan configuration",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration = self
            .folder_scan_configuration(folder)
            .await
            .map_err(|source| Error::MutationOutcomeUnknown {
                operation: "read back changed folder scan configuration",
                source: Box::new(source),
            })?;
        Ok(FolderScanUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }
    /// Request a scan of 1..=256 relative target subpaths. This acknowledgement
    /// does not correlate an observed cycle with this particular request.
    pub async fn request_scan_subpaths(
        &self,
        folder: &FolderId,
        subpaths: &[TargetPath],
    ) -> Result<()> {
        let query = self.scan_subpath_query(folder, subpaths)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        if self.folder(folder).await?.paused {
            return Err(Error::ScanNotIdle);
        }
        let url = self.connection.management_url("rest/db/scan", &query)?;
        self.connection
            .request_bytes(
                "request subpath scan",
                reqwest::Method::POST,
                url,
                None,
                true,
            )
            .await
            .map(|_| ())
    }

    fn scan_subpath_query<'a>(
        &self,
        folder: &'a FolderId,
        paths: &'a [TargetPath],
    ) -> Result<Vec<(&'static str, &'a str)>> {
        if paths.is_empty() || paths.len() > 256 {
            return Err(Error::InvalidPath {
                reason: "subpath scan requires 1 through 256 explicit subpaths",
            });
        }
        let style = self.folder_path_style()?;
        let mut query = vec![("folder", folder.as_str())];
        for path in paths {
            query.push(("sub", crate::scans::validate_subpath(path, style)?));
        }
        Ok(query)
    }
    /// Request scans for all folders handled by the engine. Paused folders are
    /// governed by the engine. This does not resume folders or await completion.
    pub async fn request_all_scans(&self) -> Result<()> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/db/scan", &[])?;
        self.connection
            .request_bytes(
                "request all folder scans",
                reqwest::Method::POST,
                url,
                None,
                true,
            )
            .await
            .map(|_| ())
    }

    /// Submit one scan while observing the selected, initially idle folders.
    /// An all-folders request includes each unpaused folder in one native
    /// request. If an unpaused folder is busy, the report refuses dispatch.
    /// Cancel and timeout end SDK waiting without stopping or resubmitting scans.
    pub async fn scan_and_observe(
        &self,
        scope: ScanScope,
        options: OperationOptions,
    ) -> Result<ScanWorkflowReport> {
        let query = match &scope {
            ScanScope::Folder(folder) => vec![("folder", folder.as_str())],
            ScanScope::Subpaths { folder, paths } => self.scan_subpath_query(folder, paths)?,
            ScanScope::All => Vec::new(),
        };
        let url = self.connection.management_url("rest/db/scan", &query)?;
        let context = options.start()?;
        let mut stream = None;
        let mut event_start = None;
        let mut write = Default::default();
        let mut pending = BTreeMap::new();
        let mut folders = BTreeMap::new();
        let submission = context
            .wait(context.dispatch_deadline(), SCAN, async {
                context.phase(OperationPhase::Checking);
                let _guard = self.connection.mutation_lock.lock().await;
                self.observe_control_identity().await?;
                let generation = self
                    .system_status()
                    .await?
                    .start_time
                    .ok_or(Error::ScanObservationLost)?;
                let initial = self.scan_configurations(&scope).await?;
                for (id, entry) in &initial {
                    if entry.paused {
                        folders.insert(id.clone(), ScanFolderObservation::Paused);
                    }
                }
                if (initial.len() == folders.len())
                    || (matches!(scope, ScanScope::Folder(_) | ScanScope::Subpaths { .. })
                        && !folders.is_empty())
                {
                    return Err(Error::ScanNotIdle);
                }
                let events = self
                    .subscribe_events(EventOptions::default().reconnect_attempts(0)?)
                    .await?;
                let start = events.cursor().clone();
                stream = Some(events);
                if start.engine_started_at.as_ref() != Some(&generation) {
                    return Err(Error::EventGenerationChanged);
                }
                event_start = Some(start);
                for (id, entry) in &initial {
                    if entry.paused {
                        continue;
                    }
                    let state = self.folder_status(id).await?.state;
                    if state != Some(FolderState::Idle) {
                        folders.insert(
                            id.clone(),
                            ScanFolderObservation::Unavailable {
                                source: Error::ScanNotIdle,
                            },
                        );
                        return Err(Error::ScanNotIdle);
                    }
                    folders.insert(
                        id.clone(),
                        ScanFolderObservation::Pending {
                            last_phase: ScanPhase::AwaitingStart,
                        },
                    );
                    pending.insert(id.clone(), (entry.path.clone(), ScanCycle::new()));
                }
                let current = self.scan_configurations(&scope).await?;
                if initial.len() != current.len()
                    || initial.iter().any(|(id, entry)| {
                        current
                            .get(id)
                            .is_none_or(|now| now.path != entry.path || now.paused != entry.paused)
                    })
                {
                    return Err(Error::ConfigurationChanged);
                }
                self.check_scan_generation(&generation).await?;
                let request = self.connection.authorized_request(Method::POST, url, None);
                self.connection
                    .send_workflow_write(SCAN, request, &context, &mut write)
                    .await
                    .map(|_| ())
            })
            .await;
        let original = workflow_write_result(SCAN, write, submission);
        let mut report = ScanWorkflowReport {
            scope,
            write,
            original,
            event_start,
            event_gap: None,
            folders,
            observation_error: None,
        };
        if let Some(mut stream) = stream {
            let refused = write.response_complete
                && matches!(
                    &report.original,
                    Err(Error::Authentication { .. } | Error::AccessDenied { .. })
                );
            if let Some(generation) = report
                .event_start
                .as_ref()
                .and_then(|cursor| cursor.engine_started_at.as_ref())
                .filter(|_| write.dispatched && !refused)
            {
                context.phase(OperationPhase::Verifying);
                report.observation_error = context
                    .wait(context.deadline, WATCH, async {
                        while !pending.is_empty() {
                            let event = match stream.next().await {
                                Some(Ok(EventStreamItem::Event(event))) => event,
                                Some(Ok(EventStreamItem::Gap(gap))) => {
                                    report.event_gap = Some(gap);
                                    return Err(Error::ScanObservationLost);
                                }
                                Some(Ok(_)) => continue,
                                Some(Err(error)) => return Err(error),
                                None => return Err(Error::ScanObservationLost),
                            };
                            let Some(id) = event.data()["folder"]
                                .as_str()
                                .and_then(|raw| FolderId::parse(raw).ok())
                            else {
                                continue;
                            };
                            let Some((path, cycle)) = pending.get_mut(&id) else {
                                continue;
                            };
                            let observed = match cycle.accept(event) {
                                Err(source) => ScanFolderObservation::Unavailable { source },
                                Ok(_) if cycle.has_ended() => {
                                    self.check_scan_generation(generation).await?;
                                    let snapshot = async {
                                        if self.folder(&id).await?.path != *path {
                                            return Err(Error::ConfigurationChanged);
                                        }
                                        self.folder_status(&id).await
                                    }
                                    .await;
                                    self.check_scan_generation(generation).await?;
                                    match snapshot.and_then(|value| cycle.finish(id.clone(), value))
                                    {
                                        Ok(value) => {
                                            ScanFolderObservation::CycleObserved(Box::new(value))
                                        }
                                        Err(source) => {
                                            ScanFolderObservation::Unavailable { source }
                                        }
                                    }
                                }
                                Ok(_) => {
                                    report.folders.insert(
                                        id,
                                        ScanFolderObservation::Pending {
                                            last_phase: cycle.phase(),
                                        },
                                    );
                                    continue;
                                }
                            };
                            pending.remove(&id);
                            report.folders.insert(id, observed);
                        }
                        Ok(())
                    })
                    .await
                    .err();
            }
            if let Err(source) = stream.close().await {
                report.observation_error.get_or_insert(source);
            }
        }
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn scan_configurations(
        &self,
        scope: &ScanScope,
    ) -> Result<BTreeMap<FolderId, FolderConfig>> {
        if let ScanScope::Folder(id) | ScanScope::Subpaths { folder: id, .. } = scope {
            return Ok(BTreeMap::from([(id.clone(), self.folder(id).await?)]));
        }
        let mut folders = BTreeMap::new();
        for folder in self.folders().await? {
            if folders.insert(folder.id.clone(), folder).is_some() {
                return Err(Error::ScanObservationLost);
            }
        }
        Ok(folders)
    }

    async fn check_scan_generation(&self, expected: &str) -> Result<()> {
        self.observe_control_identity().await?;
        if self.system_status().await?.start_time.as_deref() != Some(expected) {
            return Err(Error::EventGenerationChanged);
        }
        Ok(())
    }
}
