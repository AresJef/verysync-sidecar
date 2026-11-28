//! Explicit native resource changes, separate from sync registration changes.
use super::{mutation_error, workflow_write_result, Client};
use crate::{
    Error, OperationOptions, OperationPhase, ResourceConflictPolicy, ResourceDeleteScope,
    ResourceFileState, ResourceInfo, ResourceMutation, ResourcePath, ResourceRelocationOutcome,
    ResourceRelocationReport, ResourceRemoval, ResourceRemovalOutcome, ResourceRemovalReport,
    ResponseDiagnostic, Result,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use tokio::time::Instant;

const VERIFY_FILE: &str = "verify the current source and destination of the selected file";

impl Client {
    /// Create a directory at a non-root resource path. Refuse a currently
    /// existing resource before POST and read back an actual directory. The
    /// native operation also creates missing parents. No retry/rollback occurs;
    /// preflights do not lock against external writers.
    pub async fn create_resource_directory(&self, path: &ResourcePath) -> Result<ResourceInfo> {
        nonroot(path)?;
        let operation = "create resource directory";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        if self.optional_resource(path).await?.is_some() {
            return Err(Error::ResourceAlreadyExists);
        }
        let mut url = self.resource_url("rest/f/api/resources", path)?;
        // A directory requires native POST with a real trailing URL separator.
        // PUT is destructive file editing; an encoded slash alone is insufficient.
        let mut directory = url.path().to_owned();
        directory.push('/');
        url.set_path(&directory);
        let request = self
            .connection
            .http
            .post(url)
            .header("X-API-Key", self.connection.key.header());
        self.resource_mutation_ack(operation, request).await?;
        let info = self
            .resource_info(path)
            .await
            .map_err(|e| unknown(operation, e))?;
        if !info.is_dir {
            return Err(unknown(
                operation,
                rejected("created resource is not a directory"),
            ));
        }
        Ok(info)
    }

    /// Copy one explicit resource. OverwriteAndMerge overwrites matching files
    /// and preserves destination-only directory children; it is not whole-tree
    /// replacement. KeepBoth reconciles a unique new entry in the destination
    /// parent, otherwise returns an unknown outcome for caller reconciliation.
    /// Metadata readback is separate from recursive content verification.
    ///
    /// ```no_run
    /// use verysync_sidecar::{Client, Error, ResourceConflictPolicy, ResourcePath};
    /// # async fn copy_selected(client: &Client, source: &ResourcePath,
    /// # destination: &ResourcePath) -> Result<(), Error> {
    /// let copied = client.copy_resource(
    ///     source, destination, ResourceConflictPolicy::RejectExisting,
    /// ).await?;
    /// let observed_destination = copied.destination;
    /// # let _ = observed_destination;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn copy_resource(
        &self,
        source: &ResourcePath,
        destination: &ResourcePath,
        conflict: ResourceConflictPolicy,
    ) -> Result<ResourceMutation> {
        self.relocate_resource(source, destination, conflict, false)
            .await
    }
    /// Move/rename one explicit resource, verifying the old logical source is
    /// absent afterwards. Directory overwrite merges, retaining destination-only
    /// children. Distinct logical volume IDs are refused before requests. Within
    /// one mount, native backend behavior applies without an SDK promise of
    /// cross-filesystem atomicity, backend compatibility or rollback.
    pub async fn move_resource(
        &self,
        source: &ResourcePath,
        destination: &ResourcePath,
        conflict: ResourceConflictPolicy,
    ) -> Result<ResourceMutation> {
        self.relocate_resource(source, destination, conflict, true)
            .await
    }

    /// Copy one regular file in a native volume and verify whole-file contents
    /// at the destination and the original source. If acknowledgements are
    /// lost, the SDK reads the same paths without sending another copy.
    pub async fn copy_file_and_verify(
        &self,
        source: &ResourcePath,
        destination: &ResourcePath,
        conflict: ResourceConflictPolicy,
        options: OperationOptions,
    ) -> Result<ResourceRelocationReport> {
        self.relocate_file_and_verify(source, destination, conflict, false, options)
            .await
    }

    /// Move one regular file and verify the resulting bytes and absence at
    /// the original path. Coordinate other writers when using KeepBoth.
    pub async fn move_file_and_verify(
        &self,
        source: &ResourcePath,
        destination: &ResourcePath,
        conflict: ResourceConflictPolicy,
        options: OperationOptions,
    ) -> Result<ResourceRelocationReport> {
        self.relocate_file_and_verify(source, destination, conflict, true, options)
            .await
    }

    async fn relocate_file_and_verify(
        &self,
        source: &ResourcePath,
        destination: &ResourcePath,
        conflict: ResourceConflictPolicy,
        moving: bool,
        options: OperationOptions,
    ) -> Result<ResourceRelocationReport> {
        use ResourceFileState as File;
        use ResourceRelocationOutcome as Outcome;
        validate_relocation(source, destination)?;
        let context = options.start()?;
        let parent = destination
            .parent()
            .ok_or_else(|| rejected("destination has no parent"))?;
        let operation = if moving {
            "move the selected file"
        } else {
            "copy the selected file"
        };
        let mut guard = None;
        let mut write = Default::default();
        let mut before = None;
        let mut admission = None;
        let result = context
            .wait(context.dispatch_deadline(), operation, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let generation = self
                    .system_status()
                    .await?
                    .start_time
                    .ok_or_else(|| rejected("VerySync did not report its start time"))?;
                let file = self.resource_file_state(source).await?;
                before = Some(file);
                match file {
                    File::Present { .. } => {}
                    File::Missing => return Err(Error::ResourceNotFound),
                    File::OtherKind => return Err(rejected("the source is not a regular file")),
                }
                let target = self.resource_file_state(destination).await?;
                if conflict == ResourceConflictPolicy::RejectExisting && target != File::Missing {
                    return Err(Error::ResourceAlreadyExists);
                }
                if target == File::OtherKind {
                    return Err(rejected("the destination is not a regular file"));
                }
                let keep_both = conflict == ResourceConflictPolicy::KeepBoth;
                let names = if keep_both {
                    Some(self.resource_child_names(&parent).await?)
                } else {
                    None
                };
                let preserve = (keep_both && target != File::Missing).then_some(target);
                self.check_resource_generation(&generation).await?;
                if Instant::now() >= context.dispatch_deadline() {
                    return Err(Error::Timeout { operation });
                }
                let request =
                    self.resource_relocation_request(source, destination, conflict, moving)?;
                admission = Some((generation, names, preserve));
                let response = self
                    .connection
                    .send_workflow_write(operation, request, &context, &mut write)
                    .await?;
                verify_mutation_ack(operation, response.status, response.body)
            })
            .await;
        let original = workflow_write_result(operation, write, result);
        let refused = write.response_complete
            && matches!(
                &original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        let mut report = ResourceRelocationReport {
            outcome: if refused {
                Outcome::Rejected
            } else if write.dispatched {
                Outcome::Unconfirmed
            } else {
                Outcome::NotSubmitted
            },
            write,
            original,
            source_before: before,
            source_after: None,
            destination: None,
            destination_after: None,
            kept_target_after: None,
            observation_error: None,
        };
        if let Some((generation, names, preserve)) =
            admission.filter(|_| report.outcome == Outcome::Unconfirmed)
        {
            context.phase(OperationPhase::Verifying);
            report.observation_error = context
                .wait(context.deadline, VERIFY_FILE, async {
                    self.check_resource_generation(&generation).await?;
                    let origin = self.resource_file_state(source).await;
                    let actual = self
                        .resource_relocation_destination(destination, &parent, names.as_ref())
                        .await;
                    let (actual, observed) = match actual {
                        Ok(path) => {
                            let evidence = self.resource_file_state(&path).await;
                            (Some(path), evidence)
                        }
                        Err(error) => (None, Err(error)),
                    };
                    let kept = if preserve.is_some() {
                        Some(self.resource_file_state(destination).await)
                    } else {
                        None
                    };
                    self.check_resource_generation(&generation).await?;
                    let origin_expected = if moving { Some(File::Missing) } else { before };
                    let source_matches = origin.as_ref().ok().copied() == origin_expected;
                    let destination_matches = observed.as_ref().ok().copied() == before;
                    let kept_matches =
                        kept.as_ref().and_then(|value| value.as_ref().ok()).copied() == preserve;
                    report.outcome = if source_matches && destination_matches && kept_matches {
                        Outcome::ExpectedStateObserved
                    } else if destination_matches || (moving && source_matches) {
                        Outcome::PartiallyObserved
                    } else if origin.is_ok()
                        && observed.is_ok()
                        && kept.as_ref().is_none_or(|value| value.is_ok())
                    {
                        Outcome::CurrentStateDiffers
                    } else {
                        Outcome::Unconfirmed
                    };
                    report.source_after = Some(origin);
                    report.destination = actual;
                    report.destination_after = Some(observed);
                    report.kept_target_after = kept;
                    Ok(())
                })
                .await
                .err();
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn check_resource_generation(&self, generation: &str) -> Result<()> {
        if self.system_status().await?.start_time.as_deref() != Some(generation) {
            return Err(Error::ConfigurationChanged);
        }
        Ok(())
    }

    async fn relocate_resource(
        &self,
        source: &ResourcePath,
        destination: &ResourcePath,
        conflict: ResourceConflictPolicy,
        moving: bool,
    ) -> Result<ResourceMutation> {
        validate_relocation(source, destination)?;
        let operation = if moving {
            "move resource"
        } else {
            "copy resource"
        };
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let before = self
            .optional_resource(source)
            .await?
            .ok_or(Error::ResourceNotFound)?;
        if before.is_dir
            && source.volume == destination.volume
            && destination.components.starts_with(&source.components)
        {
            return Err(rejected(
                "a directory cannot be copied or moved inside itself",
            ));
        }
        let old_target = self.optional_resource(destination).await?;
        if conflict == ResourceConflictPolicy::RejectExisting && old_target.is_some() {
            return Err(Error::ResourceAlreadyExists);
        }
        if conflict == ResourceConflictPolicy::OverwriteAndMerge
            && old_target
                .as_ref()
                .is_some_and(|v| v.is_dir != before.is_dir)
        {
            return Err(rejected("overwrite requires matching resource kinds"));
        }
        let parent = destination
            .parent()
            .ok_or_else(|| rejected("destination has no parent"))?;
        let old_names = if conflict == ResourceConflictPolicy::KeepBoth {
            Some(self.resource_child_names(&parent).await?)
        } else {
            None
        };
        let request = self.resource_relocation_request(source, destination, conflict, moving)?;
        self.resource_mutation_ack(operation, request).await?;
        let actual = self
            .resource_relocation_destination(destination, &parent, old_names.as_ref())
            .await
            .map_err(|error| unknown(operation, error))?;
        let metadata = self
            .resource_info(&actual)
            .await
            .map_err(|e| unknown(operation, e))?;
        if metadata.is_dir != before.is_dir || (!before.is_dir && metadata.size != before.size) {
            return Err(unknown(
                operation,
                rejected("destination metadata differs from the source snapshot"),
            ));
        }
        let remaining = self
            .optional_resource(source)
            .await
            .map_err(|e| unknown(operation, e))?;
        if moving && remaining.is_some() {
            return Err(unknown(
                operation,
                rejected("move source is still observed"),
            ));
        }
        if !moving
            && remaining
                .as_ref()
                .is_none_or(|r| r.is_dir != before.is_dir || r.size != before.size)
        {
            return Err(unknown(
                operation,
                rejected("copy source changed or disappeared"),
            ));
        }
        Ok(ResourceMutation {
            generated_name: actual.components != destination.components
                || actual.volume != destination.volume,
            destination: actual,
            metadata,
        })
    }

    fn resource_relocation_request(
        &self,
        source: &ResourcePath,
        destination: &ResourcePath,
        conflict: ResourceConflictPolicy,
        moving: bool,
    ) -> Result<reqwest::RequestBuilder> {
        let mut url = self.resource_url("rest/f/api/resources", source)?;
        // Native destination is an escaped resource URI inside a query value.
        // The UI supplies encoded names before encodeURIComponent on that value.
        // Preserve both URI levels, including literal percent and C0 filenames.
        let destination_url = self.resource_url("rest/f/api/resources", destination)?;
        let route = self
            .connection
            .management_url("rest/f/api/resources", &[])?;
        let logical = destination_url
            .path()
            .strip_prefix(route.path().trim_end_matches('/'))
            .ok_or_else(|| rejected("destination URI escaped its resource route"))?;
        url.query_pairs_mut()
            .append_pair("action", if moving { "rename" } else { "copy" })
            .append_pair("destination", logical)
            .append_pair(
                "override",
                if conflict == ResourceConflictPolicy::OverwriteAndMerge {
                    "true"
                } else {
                    "false"
                },
            )
            .append_pair(
                "rename",
                if conflict == ResourceConflictPolicy::KeepBoth {
                    "true"
                } else {
                    "false"
                },
            );
        Ok(self
            .connection
            .http
            .patch(url)
            .header("X-API-Key", self.connection.key.header()))
    }

    async fn resource_relocation_destination(
        &self,
        destination: &ResourcePath,
        parent: &ResourcePath,
        previous_names: Option<&BTreeSet<String>>,
    ) -> Result<ResourcePath> {
        let Some(names) = previous_names else {
            return Ok(destination.clone());
        };
        let after = self.resource_child_names(parent).await?;
        let mut added = after.difference(names);
        let name = added
            .next()
            .ok_or_else(|| rejected("no unambiguous new destination entry was observed"))?;
        if added.next().is_some() {
            return Err(rejected(
                "multiple new entries prevent generated-name reconciliation",
            ));
        }
        parent.clone().child(name.clone())
    }

    /// Delete an explicit file or explicitly recursive directory, then observe
    /// absence. This removes filesystem data; it is not a sync detach or trash
    /// request. The SDK creates no backup and retries/rolls back nothing.
    /// A failure/cancel after DELETE can leave partial irreversible effects.
    pub async fn delete_resource(
        &self,
        path: &ResourcePath,
        scope: ResourceDeleteScope,
    ) -> Result<ResourceRemoval> {
        nonroot(path)?;
        let operation = "delete resource";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let previous = self
            .optional_resource(path)
            .await?
            .ok_or(Error::ResourceNotFound)?;
        if previous.is_dir != (scope == ResourceDeleteScope::RecursiveDirectory) {
            return Err(rejected(
                "deletion intent differs from the observed resource kind",
            ));
        }
        let request = self
            .connection
            .http
            .delete(self.resource_url("rest/f/api/resources", path)?)
            .header("X-API-Key", self.connection.key.header());
        self.resource_mutation_ack(operation, request).await?;
        if self
            .optional_resource(path)
            .await
            .map_err(|e| unknown(operation, e))?
            .is_some()
        {
            return Err(unknown(
                operation,
                rejected("deleted resource is still observed"),
            ));
        }
        Ok(ResourceRemoval { previous })
    }

    /// Ensure absence at one exact resource path with the selected deletion
    /// scope. A native 404 before dispatch completes the state goal without a
    /// DELETE. After an unanswered request, observe the same path without
    /// deleting again. A remaining folder can have lost some of its children.
    pub async fn delete_resource_and_verify(
        &self,
        path: &ResourcePath,
        scope: ResourceDeleteScope,
        options: OperationOptions,
    ) -> Result<ResourceRemovalReport> {
        use ResourceRemovalOutcome as Outcome;
        const DELETE: &str = "delete the selected resource";
        const VERIFY: &str = "check the selected path after deletion";
        nonroot(path)?;
        let context = options.start()?;
        let url = self.resource_url("rest/f/api/resources", path)?;
        let mut report = ResourceRemovalReport {
            outcome: Outcome::NotSubmitted,
            write: Default::default(),
            original: None,
            before: None,
            remaining: None,
            direct_children_removed: None,
            observation_error: None,
        };
        let mut generation = None;
        let mut guard = None;
        let attempted = context
            .wait(context.dispatch_deadline(), DELETE, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let start = self
                    .system_status()
                    .await?
                    .start_time
                    .ok_or_else(|| rejected("VerySync did not report its start time"))?;
                report.before = self.optional_resource(path).await?;
                self.check_resource_generation(&start).await?;
                let Some(current) = &report.before else {
                    report.outcome = Outcome::AlreadyAbsent;
                    return Ok(());
                };
                if current.is_dir != (scope == ResourceDeleteScope::RecursiveDirectory) {
                    return Err(rejected(
                        "deletion intent differs from the observed resource kind",
                    ));
                }
                if Instant::now() >= context.dispatch_deadline() {
                    return Err(Error::Timeout { operation: DELETE });
                }
                let request =
                    self.connection
                        .authorized_request(reqwest::Method::DELETE, url, None);
                generation = Some(start);
                let response = self
                    .connection
                    .send_workflow_write(DELETE, request, &context, &mut report.write)
                    .await?;
                verify_mutation_ack(DELETE, response.status, response.body)
            })
            .await;
        if report.outcome != Outcome::AlreadyAbsent {
            report.original = Some(workflow_write_result(DELETE, report.write, attempted));
        }
        if report.write.dispatched {
            report.outcome = if report.write.response_complete
                && matches!(
                    report.original,
                    Some(Err(
                        Error::Authentication { .. } | Error::AccessDenied { .. }
                    ))
                ) {
                Outcome::Rejected
            } else {
                Outcome::Unconfirmed
            };
        }
        if let Some(generation) = generation.filter(|_| report.outcome == Outcome::Unconfirmed) {
            context.phase(OperationPhase::Verifying);
            let observed = context
                .wait(context.deadline, VERIFY, async {
                    self.check_resource_generation(&generation).await?;
                    let remaining = self.optional_resource(path).await?;
                    self.check_resource_generation(&generation).await?;
                    Ok(remaining)
                })
                .await;
            match observed {
                Ok(None) => report.outcome = Outcome::ObservedAbsent,
                Ok(Some(remaining)) => {
                    report.direct_children_removed = report
                        .before
                        .as_ref()
                        .and_then(|previous| removed_children(previous, &remaining));
                    report.outcome = if report
                        .direct_children_removed
                        .is_some_and(|count| count > 0)
                    {
                        Outcome::PartialDirectoryChange
                    } else {
                        Outcome::StillPresent
                    };
                    report.remaining = Some(remaining);
                }
                Err(error) => report.observation_error = Some(error),
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    /// Destructively edit an existing file with at most 16 MiB of UTF-8 text.
    /// Refuse an absent resource or directory before PUT, then require actual
    /// size and native SHA-256 readback. Cancellation can truncate or remove the
    /// previous file; no backup, retry, transaction or rollback is implied.
    pub async fn write_resource_text(
        &self,
        path: &ResourcePath,
        text: &str,
    ) -> Result<ResourceInfo> {
        nonroot(path)?;
        if text.len() > 16 * 1024 * 1024 {
            return Err(rejected("text edit exceeds the explicit 16 MiB bound"));
        }
        let operation = "write existing resource text";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let before = self
            .optional_resource(path)
            .await?
            .ok_or(Error::ResourceNotFound)?;
        if before.is_dir {
            return Err(rejected("text editing requires an existing file"));
        }
        let request = self
            .connection
            .http
            .put(self.resource_url("rest/f/api/resources", path)?)
            .header("X-API-Key", self.connection.key.header())
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(text.to_owned());
        self.resource_mutation_ack(operation, request).await?;
        let info = self
            .resource_info(path)
            .await
            .map_err(|e| unknown(operation, e))?;
        let digest = self
            .resource_checksum(path, crate::ResourceChecksum::Sha256)
            .await
            .map_err(|e| unknown(operation, e))?;
        if info.is_dir
            || info.size != text.len() as u64
            || !digest.eq_ignore_ascii_case(&format!("{:x}", Sha256::digest(text.as_bytes())))
        {
            return Err(unknown(
                operation,
                rejected("edited file metadata or digest differs from requested text"),
            ));
        }
        Ok(info)
    }
    async fn optional_resource(&self, path: &ResourcePath) -> Result<Option<ResourceInfo>> {
        match self.resource_info(path).await {
            Ok(info) => Ok(Some(info)),
            Err(Error::Http { response }) if response.status() == 404 => Ok(None),
            Err(e) => Err(e),
        }
    }
    async fn resource_child_names(&self, path: &ResourcePath) -> Result<BTreeSet<String>> {
        let info = self.resource_info(path).await?;
        if !info.is_dir {
            return Err(rejected("destination parent is not a directory"));
        }
        let items = info.items.ok_or_else(|| {
            rejected("parent listing is absent rather than an observed empty directory")
        })?;
        let mut names = BTreeSet::new();
        for item in items {
            path.clone().child(item.name.clone())?;
            if !names.insert(item.name) {
                return Err(rejected("parent listing contains duplicate names"));
            }
        }
        Ok(names)
    }
    async fn resource_mutation_ack(
        &self,
        operation: &'static str,
        request: reqwest::RequestBuilder,
    ) -> Result<()> {
        let (status, body) = self
            .connection
            .request_prepared(operation, request, true)
            .await?;
        verify_mutation_ack(operation, status, body)
    }
}

fn validate_relocation(source: &ResourcePath, destination: &ResourcePath) -> Result<()> {
    nonroot(source)?;
    nonroot(destination)?;
    // The native handler resolves both paths within the source mount.
    if source.volume != destination.volume {
        return Err(rejected(
            "native mutations require a single explicit logical volume",
        ));
    }
    if source.style != destination.style {
        return Err(rejected("resource target syntax differs"));
    }
    if source.components == destination.components {
        return Err(rejected(
            "source and destination are the same logical resource",
        ));
    }
    Ok(())
}

fn removed_children(previous: &ResourceInfo, current: &ResourceInfo) -> Option<usize> {
    if !previous.is_dir || !current.is_dir {
        return None;
    }
    let before: BTreeSet<_> = previous
        .items
        .as_ref()?
        .iter()
        .map(|item| &item.name)
        .collect();
    let after: BTreeSet<_> = current
        .items
        .as_ref()?
        .iter()
        .map(|item| &item.name)
        .collect();
    Some(before.difference(&after).count())
}

fn verify_mutation_ack(operation: &'static str, status: u16, body: Vec<u8>) -> Result<()> {
    if body == b"200 OK\n" {
        Ok(())
    } else {
        Err(unknown(
            operation,
            Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(status, body),
            },
        ))
    }
}
fn nonroot(path: &ResourcePath) -> Result<()> {
    if path.components.is_empty() {
        Err(Error::InvalidPath {
            reason: "a resource mutation cannot target a volume root",
        })
    } else {
        Ok(())
    }
}
fn rejected(reason: &'static str) -> Error {
    Error::ResourceMutationRejected { reason }
}
fn unknown(operation: &'static str, error: Error) -> Error {
    mutation_error(operation, true, error)
}
