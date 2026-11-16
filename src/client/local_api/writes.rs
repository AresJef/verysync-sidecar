//! Licensed native configuration proxy routes with guarded readbacks.
use super::{control::checked_control_response, LocalApiClient};
use crate::{
    CreateFolderOptions, Error, FolderConfig, FolderDefaults, FolderId, FolderPatch, FolderRemoval,
    FolderUpdate, RawMethod, RawRequest, RawResponse, RequestEffect, Result,
};
use std::collections::{BTreeMap, BTreeSet};

/// Readback after explicitly replacing the complete native folder collection.
/// Separate requests are not an atomic transaction with independent writers.
#[derive(Debug)]
pub struct LocalApiFolderCollectionUpdate {
    /// Full configurations read individually after the collection PUT.
    pub configurations: Vec<FolderConfig>,
    /// Whether the observed exact ID set matches the requested collection.
    pub configuration_ids_match: bool,
    /// Whether all full observed bodies match the explicitly requested bodies.
    pub requested_fields_match: bool,
}

impl LocalApiClient {
    /// Read a full native configuration through the licensed item proxy. This
    /// differs from the free Local-API folder projection returned by `folder`.
    pub async fn folder_configuration(&self, id: &FolderId) -> Result<FolderConfig> {
        let style = self.path_style()?;
        let wire: crate::folders::WireFolder = self
            .control_json(
                item(RawMethod::Get, id, RequestEffect::ReadOnly)?,
                "read Local-API full folder configuration",
            )
            .await?;
        wire.into_config(style)
    }

    async fn send_configuration_locked(
        &self,
        request: RawRequest,
        operation: &'static str,
        _guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> Result<RawResponse> {
        self.system_status().await?;
        let response = self.send_raw(request).await?;
        checked_control_response(operation, response, true)
    }

    /// Create one guarded folder using an explicit complete native template.
    /// Local-API registers no defaults route, so no defaults are fabricated or
    /// fetched through another authentication channel. Obtain this template
    /// explicitly from the selected core or supply its complete native values.
    /// Independent writers must coordinate: native POST remains an upsert.
    ///
    /// ```no_run
    /// # async fn example(client: &verysync_sidecar::LocalApiClient,
    /// # template: &verysync_sidecar::FolderDefaults,
    /// # id: verysync_sidecar::FolderId, path: verysync_sidecar::TargetPath)
    /// # -> verysync_sidecar::Result<()> {
    /// let options = verysync_sidecar::CreateFolderOptions::new(id, path);
    /// let actual = client.create_folder(template, &options).await?;
    /// // This is configuration readback; observe files and synchronization separately.
    /// # let _ = actual;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_folder(
        &self,
        template: &FolderDefaults,
        options: &CreateFolderOptions,
    ) -> Result<FolderConfig> {
        if options.path.style() != self.path_style()? {
            return Err(Error::InvalidPath {
                reason: "path syntax differs from the connected engine",
            });
        }
        item(RawMethod::Get, &options.id, RequestEffect::ReadOnly)?;
        let path = options.path.to_protocol()?;
        let advanced = options
            .advanced
            .as_ref()
            .map(crate::FolderAdvancedPatch::body)
            .transpose()?;
        let mut body = template
            .extra
            .clone()
            .into_iter()
            .collect::<serde_json::Map<_, _>>();
        body.insert("label".into(), serde_json::json!(template.label));
        body.insert("paused".into(), serde_json::json!(template.paused));
        body.insert(
            "rescanIntervalS".into(),
            serde_json::json!(template.rescan_interval_seconds),
        );
        body.insert(
            "fsWatcherEnabled".into(),
            serde_json::json!(template.watcher_enabled),
        );
        body.insert("id".into(), serde_json::json!(options.id.as_str()));
        body.insert("path".into(), serde_json::json!(path));
        if let Some(advanced) = advanced {
            body.extend(
                advanced
                    .as_object()
                    .ok_or(Error::InvalidConfiguration {
                        reason: "initial folder settings must be an object",
                    })?
                    .clone(),
            );
        }
        if let Some(label) = &options.label {
            body.insert("label".into(), serde_json::json!(label));
        }
        if let Some(paused) = options.paused {
            body.insert("paused".into(), serde_json::json!(paused));
        }
        let request = RawRequest::new(
            RawMethod::Post,
            ["config", "folders"],
            RequestEffect::MayModify,
        )?
        .json_body(&serde_json::Value::Object(body))?;
        let guard = self.connection.mutation_lock.lock().await;
        let current = self.folders().await?;
        if current.iter().any(|f| f.id == options.id) {
            return Err(Error::FolderAlreadyExists {
                id: options.id.clone(),
            });
        }
        if !options.allow_shared_path {
            if let Some(folder) = current
                .iter()
                .find(|f| f.path.to_protocol().is_ok_and(|value| value == path))
            {
                return Err(Error::FolderPathAlreadyConfigured {
                    id: folder.id.clone(),
                });
            }
        }
        self.send_configuration_locked(request, "create Local-API folder", &guard)
            .await?;
        self.folder_configuration(&options.id)
            .await
            .map_err(|e| unknown("read back created Local-API folder", e))
    }

    /// Patch only the selected label/pause fields, preserving other native
    /// settings. An acknowledgement is separate from matching configuration.
    pub async fn update_folder(&self, id: &FolderId, patch: &FolderPatch) -> Result<FolderUpdate> {
        if patch.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "folder patch must contain at least one field",
            });
        }
        let request = item(RawMethod::Patch, id, RequestEffect::MayModify)?.json_body(
            &serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
                reason: "folder patch cannot be encoded",
            })?,
        )?;
        let guard = self.connection.mutation_lock.lock().await;
        self.folder_configuration(id).await?;
        self.send_configuration_locked(request, "patch Local-API folder", &guard)
            .await?;
        let configuration = self
            .folder_configuration(id)
            .await
            .map_err(|e| unknown("read back patched Local-API folder", e))?;
        Ok(FolderUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }

    /// Replace one full native configuration from explicit caller values.
    /// Unknown fields are preserved from that supplied snapshot. No restart,
    /// path discovery, key generation, retry or implicit template merge occurs.
    pub async fn replace_folder_configuration(
        &self,
        configuration: &FolderConfig,
    ) -> Result<FolderUpdate> {
        let body = folder_body(configuration, self.path_style()?)?;
        let request =
            item(RawMethod::Put, &configuration.id, RequestEffect::MayModify)?.json_body(&body)?;
        let guard = self.connection.mutation_lock.lock().await;
        self.folder_configuration(&configuration.id).await?;
        self.send_configuration_locked(request, "replace Local-API folder configuration", &guard)
            .await?;
        let observed = self
            .folder_configuration(&configuration.id)
            .await
            .map_err(|e| unknown("read back replaced Local-API folder", e))?;
        let matches = folder_body(&observed, self.path_style()?)
            .map_err(|e| unknown("compare replaced Local-API folder", e))?
            == body;
        Ok(FolderUpdate {
            configuration: observed,
            requested_fields_match: matches,
        })
    }

    /// Explicitly replace the whole folder collection, including removing IDs
    /// omitted by the caller. This sends one native PUT and reads full items
    /// afterward. File retention and runtime effects require separate observation.
    pub async fn replace_folder_configurations(
        &self,
        configurations: &[FolderConfig],
    ) -> Result<LocalApiFolderCollectionUpdate> {
        let style = self.path_style()?;
        let mut desired = BTreeMap::new();
        for configuration in configurations {
            item(RawMethod::Get, &configuration.id, RequestEffect::ReadOnly)?;
            if desired
                .insert(configuration.id.clone(), folder_body(configuration, style)?)
                .is_some()
            {
                return Err(Error::InvalidConfiguration {
                    reason: "replacement collection contains duplicate folder identifiers",
                });
            }
        }
        let body: Vec<_> = configurations
            .iter()
            .map(|c| desired[&c.id].clone())
            .collect();
        let request = RawRequest::new(
            RawMethod::Put,
            ["config", "folders"],
            RequestEffect::MayModify,
        )?
        .json_body(&serde_json::Value::Array(body))?;
        let guard = self.connection.mutation_lock.lock().await;
        self.folders().await?;
        self.send_configuration_locked(request, "replace Local-API folder collection", &guard)
            .await?;
        let projected = self
            .folders()
            .await
            .map_err(|e| unknown("read back Local-API folder collection", e))?;
        let ids: BTreeSet<_> = projected.iter().map(|f| f.id.clone()).collect();
        let configuration_ids_match =
            ids.len() == projected.len() && ids == desired.keys().cloned().collect();
        let mut configurations = Vec::with_capacity(ids.len());
        let mut actual = BTreeMap::new();
        for projection in projected {
            let id = projection.id;
            let config = self
                .folder_configuration(&id)
                .await
                .map_err(|e| unknown("read back replaced Local-API collection item", e))?;
            actual.insert(
                id,
                folder_body(&config, style)
                    .map_err(|e| unknown("compare Local-API collection item", e))?,
            );
            configurations.push(config);
        }
        Ok(LocalApiFolderCollectionUpdate {
            configurations,
            configuration_ids_match,
            requested_fields_match: configuration_ids_match && actual == desired,
        })
    }

    /// Unregister one exact folder through native DELETE, with no file-deletion
    /// flag or body. Configuration absence is not a filesystem deletion receipt.
    pub async fn remove_folder_keep_files(&self, id: &FolderId) -> Result<FolderRemoval> {
        let request = item(RawMethod::Delete, id, RequestEffect::MayModify)?;
        let guard = self.connection.mutation_lock.lock().await;
        let previous_configuration = self.folder_configuration(id).await?;
        self.send_configuration_locked(request, "unregister Local-API folder", &guard)
            .await?;
        let observed = self
            .folders()
            .await
            .map_err(|e| unknown("read back unregistered Local-API folder", e))?;
        Ok(FolderRemoval {
            previous_configuration,
            configuration_absent: !observed.iter().any(|f| f.id == *id),
        })
    }
}

fn item(method: RawMethod, id: &FolderId, effect: RequestEffect) -> Result<RawRequest> {
    RawRequest::new(method, ["config", "folders", id.as_str()], effect)
}
fn folder_body(config: &FolderConfig, style: crate::PathStyle) -> Result<serde_json::Value> {
    if config.path.style() != style {
        return Err(Error::InvalidPath {
            reason: "folder configuration path syntax differs from the target",
        });
    }
    let mut body = config
        .extra
        .clone()
        .into_iter()
        .collect::<serde_json::Map<_, _>>();
    body.insert("id".into(), serde_json::json!(config.id.as_str()));
    body.insert("path".into(), serde_json::json!(config.path.to_protocol()?));
    body.insert("label".into(), serde_json::json!(config.label));
    body.insert("paused".into(), serde_json::json!(config.paused));
    Ok(serde_json::Value::Object(body))
}
fn unknown(operation: &'static str, error: Error) -> Error {
    crate::client::mutation_error(operation, true, error)
}
