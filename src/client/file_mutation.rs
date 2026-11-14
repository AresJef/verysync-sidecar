//! Explicit native resource changes, separate from sync registration changes.
use super::{mutation_error, Client};
use crate::{
    Error, ResourceConflictPolicy, ResourceDeleteScope, ResourceInfo, ResourceMutation,
    ResourcePath, ResourceRemoval, ResponseDiagnostic, Result,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

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
    async fn relocate_resource(
        &self,
        source: &ResourcePath,
        destination: &ResourcePath,
        conflict: ResourceConflictPolicy,
        moving: bool,
    ) -> Result<ResourceMutation> {
        nonroot(source)?;
        nonroot(destination)?;
        // The fixed native handler resolves destination components within the
        // SOURCE mount even when another volume ID was supplied. Reject that
        // unsafe request before reads/writes; never guess a cross-mount mapping.
        if source.volume != destination.volume {
            return Err(rejected(
                "native mutations require a single explicit logical volume",
            ));
        }
        if source.style != destination.style {
            return Err(rejected("resource target syntax differs"));
        }
        if source.volume == destination.volume && source.components == destination.components {
            return Err(rejected(
                "source and destination are the same logical resource",
            ));
        }
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
        let request = self
            .connection
            .http
            .patch(url)
            .header("X-API-Key", self.connection.key.header());
        self.resource_mutation_ack(operation, request).await?;
        let actual = if let Some(names) = old_names {
            let after = self
                .resource_child_names(&parent)
                .await
                .map_err(|e| unknown(operation, e))?;
            let mut added = after.difference(&names);
            let name = added.next().ok_or_else(|| {
                unknown(
                    operation,
                    rejected("no unambiguous new destination entry was observed"),
                )
            })?;
            if added.next().is_some() {
                return Err(unknown(
                    operation,
                    rejected("multiple new entries prevent generated-name reconciliation"),
                ));
            }
            parent
                .child(name.clone())
                .map_err(|e| unknown(operation, e))?
        } else {
            destination.clone()
        };
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
        if body != b"200 OK\n" {
            return Err(unknown(
                operation,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, body),
                },
            ));
        }
        Ok(())
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
