//! Explicit scheduling mutations and independent rate-setting readback.
use super::{workflow_write_result, Client};
use crate::{
    BandwidthPatch, BandwidthUpdate, Error, FilePriorityReport, FilePriorityState, FolderId,
    FolderPullOrder, FolderSchedulingConfig, FolderSchedulingUpdate, GlobalBandwidthConfig,
    ListPage, NeedPage, OperationOptions, OperationPhase, ResponseDiagnostic, Result, SyncFileKind,
    TargetPath,
};
use reqwest::{Method, Url};
use serde::Deserialize;
use std::time::Duration;
use tokio::time::Instant;
impl Client {
    /// Read actual global byte-rate settings, without starting a transfer.
    pub async fn bandwidth_configuration(&self) -> Result<GlobalBandwidthConfig> {
        #[derive(Deserialize)]
        struct Config {
            options: GlobalBandwidthConfig,
        }
        self.system_status().await?;
        let config: Config = self
            .connection
            .get_json("read global bandwidth configuration", "rest/config")
            .await?;
        Ok(config.options)
    }
    /// Partially update global limits once; zero removes only the selected
    /// limiter. Device limits and other bottlenecks remain independent.
    pub async fn update_bandwidth_configuration(
        &self,
        patch: &BandwidthPatch,
    ) -> Result<BandwidthUpdate> {
        patch.validate()?;
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "bandwidth settings cannot be encoded",
        })?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/config/options", &[])?;
        self.connection
            .request_bytes(
                "update global bandwidth configuration",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration = self.bandwidth_configuration().await.map_err(|source| {
            Error::MutationOutcomeUnknown {
                operation: "read back changed global bandwidth configuration",
                source: Box::new(source),
            }
        })?;
        Ok(BandwidthUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }
    /// Read the configured file pull order for an exact existing folder.
    pub async fn folder_scheduling_configuration(
        &self,
        folder: &FolderId,
    ) -> Result<FolderSchedulingConfig> {
        #[derive(Deserialize)]
        struct Entry {
            id: FolderId,
            #[serde(flatten)]
            scheduling: FolderSchedulingConfig,
        }
        #[derive(Deserialize)]
        struct Config {
            folders: Vec<Entry>,
        }
        self.system_status().await?;
        let config: Config = self
            .connection
            .get_json("read folder scheduling configuration", "rest/config")
            .await?;
        config
            .folders
            .into_iter()
            .find(|x| x.id == *folder)
            .map(|x| x.scheduling)
            .ok_or_else(|| Error::FolderNotFound { id: folder.clone() })
    }
    /// Change one known file-order value without altering block order or
    /// cancelling an already active file. Readback is not queue execution.
    pub async fn set_folder_pull_order(
        &self,
        folder: &FolderId,
        order: &FolderPullOrder,
    ) -> Result<FolderSchedulingUpdate> {
        if matches!(order, FolderPullOrder::Unknown(_)) {
            return Err(Error::InvalidConfiguration {
                reason: "unknown folder pull order cannot be submitted",
            });
        }
        let url = self.connection.folder_url(folder)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .request_bytes(
                "set folder file pull order",
                reqwest::Method::PATCH,
                url,
                Some(&serde_json::json!({"order":order})),
                true,
            )
            .await?;
        let configuration =
            self.folder_scheduling_configuration(folder)
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back changed folder pull order",
                    source: Box::new(source),
                })?;
        Ok(FolderSchedulingUpdate {
            requested_order_match: configuration.pull_order == *order,
            configuration,
        })
    }
    /// Prioritize one visible waiting file once and independently read its
    /// current queue position. Use page one with a limit that includes that
    /// file. An active or first-queued file requires no write. After a
    /// successful reply, read the queue up to four times within the original
    /// deadline while the selected file is still waiting. If it leaves the
    /// page, check its contents separately.
    pub async fn prioritize_file_and_verify(
        &self,
        folder: &FolderId,
        file: &TargetPath,
        page: ListPage,
        options: OperationOptions,
    ) -> Result<FilePriorityReport> {
        const WRITE: &str = "prioritize the selected folder file";
        const CHECK: &str = "read the selected folder file's priority";
        if page.number() != 1 {
            return Err(Error::InvalidConfiguration {
                reason: "file priority verification requires the first need page",
            });
        }
        let relative = crate::scans::validate_subpath(file, self.folder_path_style()?)?;
        let url = self.priority_url(folder, relative, page)?;
        let context = options.start()?;
        let mut write = Default::default();
        let mut guard = None;
        let mut selected = None;
        let mut before = None;
        let mut no_write = None;
        let original =
            context
                .wait(context.dispatch_deadline(), WRITE, async {
                    context.phase(OperationPhase::Checking);
                    guard = Some(self.connection.mutation_lock.lock().await);
                    self.observe_control_identity().await?;
                    let generation = self.system_status().await?.start_time.ok_or(
                        Error::InvalidConfiguration {
                            reason: "the selected instance did not report its start time",
                        },
                    )?;
                    let config = self.folder(folder).await?;
                    if config.paused {
                        return Err(Error::FolderPaused { id: folder.clone() });
                    }
                    let need = self.folder_need(folder, page).await?;
                    let state = file_priority(&need, relative, page)?;
                    self.verify_priority_scope(folder, &config.path, &generation)
                        .await?;
                    before = Some(state);
                    if state != FilePriorityState::Waiting {
                        no_write = Some((state, need));
                        return Ok(None);
                    }
                    if Instant::now() >= context.dispatch_deadline() {
                        return Err(Error::Timeout { operation: WRITE });
                    }
                    selected = Some((config.path, generation));
                    let request = self.connection.authorized_request(Method::POST, url, None);
                    let reply = self
                        .connection
                        .send_workflow_write(WRITE, request, &context, &mut write)
                        .await?;
                    decode_priority_page(reply.status, reply.body).map(Some)
                })
                .await;
        drop(guard);
        let original = workflow_write_result(WRITE, write, original);
        let later_reads = if matches!(original, Ok(Some(_))) {
            4
        } else {
            1
        };
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        let mut report = FilePriorityReport {
            write,
            original,
            before,
            current: None,
            current_need: None,
            observation_error: None,
        };
        if let Some((state, need)) = no_write {
            report.current = Some(state);
            report.current_need = Some(need);
        }
        if let Some((path, generation)) = selected.filter(|_| write.dispatched && !refused) {
            context.phase(OperationPhase::Verifying);
            let observed = context
                .wait(context.deadline, CHECK, async {
                    let interval = Duration::from_millis(250);
                    let mut remaining_reads = later_reads;
                    loop {
                        self.verify_priority_scope(folder, &path, &generation)
                            .await?;
                        let need = self.folder_need(folder, page).await?;
                        let state = file_priority(&need, relative, page)?;
                        self.verify_priority_scope(folder, &path, &generation)
                            .await?;
                        remaining_reads -= 1;
                        if state != FilePriorityState::Waiting
                            || remaining_reads == 0
                            || Instant::now() + interval >= context.deadline
                        {
                            return Ok((state, need));
                        }
                        tokio::time::sleep(interval).await;
                    }
                })
                .await;
            match observed {
                Ok((state, need)) => {
                    report.current = Some(state);
                    report.current_need = Some(need);
                }
                Err(source) => report.observation_error = Some(source),
            }
        }
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn verify_priority_scope(
        &self,
        folder: &FolderId,
        path: &TargetPath,
        generation: &str,
    ) -> Result<()> {
        let current = self.folder(folder).await?;
        if current.paused
            || &current.path != path
            || self.system_status().await?.start_time.as_deref() != Some(generation)
        {
            return Err(Error::ConfigurationChanged);
        }
        Ok(())
    }

    /// Ask the engine to prioritize a relative file and return its actual need
    /// page. An active file is not preempted; absence from this page is unknown.
    pub async fn prioritize_file(
        &self,
        folder: &FolderId,
        file: &TargetPath,
        page: ListPage,
    ) -> Result<NeedPage> {
        let file = crate::scans::validate_subpath(file, self.folder_path_style()?)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        if self.folder(folder).await?.paused {
            return Err(Error::FolderPaused { id: folder.clone() });
        }
        let url = self.priority_url(folder, file, page)?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "prioritize folder file",
                reqwest::Method::POST,
                url,
                None,
                true,
            )
            .await?;
        decode_priority_page(status, bytes)
    }

    fn priority_url(&self, folder: &FolderId, file: &str, page: ListPage) -> Result<Url> {
        let number = page.number().to_string();
        let limit = page.per_page().to_string();
        self.connection.management_url(
            "rest/db/prio",
            &[
                ("folder", folder.as_str()),
                ("file", file),
                ("page", &number),
                ("perpage", &limit),
            ],
        )
    }
}

fn decode_priority_page(status: u16, bytes: Vec<u8>) -> Result<NeedPage> {
    serde_json::from_slice(&bytes).map_err(|_| Error::MutationOutcomeUnknown {
        operation: "decode prioritized need page",
        source: Box::new(Error::InvalidResponse {
            operation: "decode prioritized need page",
            response: ResponseDiagnostic::new(status, bytes),
        }),
    })
}

fn file_priority(
    page: &NeedPage,
    relative: &str,
    requested: ListPage,
) -> Result<FilePriorityState> {
    if page.page != Some(requested.number())
        || page.per_page != Some(u32::from(requested.per_page()))
    {
        return Err(Error::InvalidConfiguration {
            reason: "the need response did not identify the selected page",
        });
    }
    let mut matches = page
        .progress
        .iter()
        .map(|file| (FilePriorityState::InProgress, file))
        .chain(page.queued.iter().enumerate().map(|(index, file)| {
            (
                if index == 0 {
                    FilePriorityState::FirstQueued
                } else {
                    FilePriorityState::Waiting
                },
                file,
            )
        }))
        .chain(
            page.rest
                .iter()
                .map(|file| (FilePriorityState::Waiting, file)),
        )
        .filter(|(_, file)| file.name == relative);
    let Some((state, file)) = matches.next() else {
        return Ok(FilePriorityState::Unobserved);
    };
    if matches.next().is_some()
        || file.kind != SyncFileKind::File
        || file.deleted == Some(true)
        || file.invalid == Some(true)
        || file.ignored == Some(true)
    {
        return Err(Error::InvalidConfiguration {
            reason: "the need response did not identify one valid waiting file",
        });
    }
    Ok(state)
}
