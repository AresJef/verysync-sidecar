//! Create one selected directory and verify its own native namespace.

use super::{
    delivery::{native_path_parts, same_resource},
    file_mutation::{resource_directory_url, verify_mutation_ack},
    local_sync_control::decode_local_sync_json,
    workflow_write_result, Client,
};
use crate::{
    DirectoryCreationReport, DirectoryTarget, Error, OperationOptions, OperationPhase,
    ResourcePath, ResponseDiagnostic, Result, StorageEntry,
};
use reqwest::{Method, Url};
use serde_json::Value;
use tokio::time::Instant;

impl Client {
    /// Create a directory in the selected namespace, then read its exact location.
    /// An existing directory requires no write. An existing file is kept intact.
    /// Native handlers can also create parents. The report covers the exact
    /// directory, and leaves any other filesystem effects to your own checks.
    /// Native picker verification requires read access to its local volume so
    /// a missing path can be distinguished from a refused picker directory.
    pub async fn create_directory_and_verify(
        &self,
        target: DirectoryTarget<'_>,
        options: OperationOptions,
    ) -> Result<DirectoryCreationReport> {
        const CREATE: &str = "create the selected directory";
        const VERIFY: &str = "check the selected directory";
        let (url, body) = self.directory_request(&target)?;
        let context = options.start()?;
        let mut guard = None;
        let mut write = Default::default();
        let mut selected = None;
        let mut existed_before = None;
        let result = context
            .wait(context.dispatch_deadline(), CREATE, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let generation =
                    self.system_status()
                        .await?
                        .start_time
                        .ok_or(Error::InvalidConfiguration {
                            reason: "the selected engine did not report its start time",
                        })?;
                let mount = match &target {
                    DirectoryTarget::NativePicker(path) => {
                        Some(self.local_file_manager_base(path).await?)
                    }
                    _ => None,
                };
                let exists = self.directory_exists(&target, mount.as_ref()).await?;
                self.require_configuration_generation(&generation).await?;
                existed_before = Some(exists);
                if exists {
                    return Ok(None);
                }
                if Instant::now() >= context.dispatch_deadline() {
                    return Err(Error::Timeout { operation: CREATE });
                }
                selected = Some((generation, mount));
                let request = self
                    .connection
                    .authorized_request(Method::POST, url, body.as_ref());
                let reply = self
                    .connection
                    .send_workflow_write(CREATE, request, &context, &mut write)
                    .await?;
                match &target {
                    DirectoryTarget::FileManager(_) => {
                        verify_mutation_ack(CREATE, reply.status, reply.body.clone())?
                    }
                    DirectoryTarget::NativePicker(path) => {
                        let style = path.style();
                        let receipt = super::auxiliary_control::decode_target_directory_creation(
                            CREATE,
                            reply.status,
                            reply.body.clone(),
                            style,
                        )?;
                        let expected = native_path_parts(style, path.to_protocol()?);
                        let returned = native_path_parts(style, receipt.path.to_protocol()?);
                        if expected.is_none() || returned != expected {
                            return Err(super::mutation_error(
                                CREATE,
                                true,
                                Error::InvalidResponse {
                                    operation: CREATE,
                                    response: ResponseDiagnostic::new(reply.status, reply.body),
                                },
                            ));
                        }
                    }
                    DirectoryTarget::LocalSync { parent, name, .. } => {
                        let entry: StorageEntry = decode_local_sync_json(
                            CREATE,
                            reply.status,
                            reply.body.clone(),
                            true,
                            false,
                        )?;
                        if !entry.directory || entry.path != storage_path(parent, name) {
                            return Err(super::mutation_error(
                                CREATE,
                                true,
                                Error::InvalidConfiguration {
                                    reason:
                                        "the storage reply did not identify the selected directory",
                                },
                            ));
                        }
                    }
                }
                Ok(Some(ResponseDiagnostic::new(reply.status, reply.body)))
            })
            .await;
        let original = workflow_write_result(CREATE, write, result);
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. }
                    | Error::AccessDenied { .. }
                    | Error::LicenseRequired { .. })
            );
        let mut report = DirectoryCreationReport {
            write,
            original,
            existed_before,
            directory_present: existed_before.filter(|exists| *exists),
            observation_error: None,
        };
        if let Some((generation, mount)) = selected.filter(|_| write.dispatched && !refused) {
            context.phase(OperationPhase::Verifying);
            let verified = context
                .wait(context.deadline, VERIFY, async {
                    self.require_configuration_generation(&generation).await?;
                    let found = self.directory_exists(&target, mount.as_ref()).await?;
                    self.require_configuration_generation(&generation).await?;
                    Ok(found)
                })
                .await;
            match verified {
                Ok(found) => report.directory_present = Some(found),
                Err(error) => report.observation_error = Some(error),
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    fn directory_request(&self, target: &DirectoryTarget<'_>) -> Result<(Url, Option<Value>)> {
        Ok(match target {
            DirectoryTarget::FileManager(path) => {
                if path.components.is_empty() {
                    return Err(Error::InvalidPath {
                        reason: "select a directory below the file-manager volume root",
                    });
                }
                (
                    resource_directory_url(self.resource_url("rest/f/api/resources", path)?),
                    None,
                )
            }
            DirectoryTarget::NativePicker(path) => {
                if path.style() != self.folder_path_style()? {
                    return Err(Error::InvalidPath {
                        reason: "path syntax differs from the connected engine",
                    });
                }
                (
                    self.connection.management_url("rest/system/adddir", &[])?,
                    Some(serde_json::json!({"path": path.to_protocol()?})),
                )
            }
            DirectoryTarget::LocalSync {
                endpoint,
                parent,
                name,
            } => {
                crate::local_sync::logical_subpath(parent)?;
                crate::local_sync::logical_subpath(name)?;
                if name.is_empty() || name.contains('/') {
                    return Err(Error::InvalidPath {
                        reason: "select one nonempty storage directory name",
                    });
                }
                endpoint.validate_target(self.folder_path_style()?)?;
                (
                    self.local_sync_url(&["mkdir"], &[])?,
                    Some(serde_json::json!({"side": endpoint, "parent": parent, "name": name})),
                )
            }
        })
    }

    async fn directory_exists(
        &self,
        target: &DirectoryTarget<'_>,
        mount: Option<&ResourcePath>,
    ) -> Result<bool> {
        match target {
            DirectoryTarget::FileManager(path) => self.resource_directory_exists(path).await,
            DirectoryTarget::NativePicker(path) => {
                let actual = self.local_file_manager_base(path).await?;
                if !mount.is_some_and(|selected| same_resource(selected, &actual)) {
                    return Err(Error::ConfigurationChanged);
                }
                let exists = self.resource_directory_exists(&actual).await?;
                if exists {
                    self.target_directories(path).await?;
                }
                Ok(exists)
            }
            DirectoryTarget::LocalSync {
                endpoint,
                parent,
                name,
            } => {
                let listing = self.browse_storage_endpoint(endpoint, parent).await?;
                if listing.path != *parent {
                    return Err(Error::InvalidConfiguration {
                        reason: "the storage backend returned a different directory listing",
                    });
                }
                let expected = storage_path(parent, name);
                let mut found = listing
                    .entries
                    .iter()
                    .filter(|entry| entry.path == expected);
                let first = found.next();
                if found.next().is_some() {
                    return Err(Error::InvalidConfiguration {
                        reason: "the storage backend returned duplicate directory entries",
                    });
                }
                match first {
                    Some(entry) if entry.directory => Ok(true),
                    Some(_) => Err(Error::ResourceAlreadyExists),
                    None => Ok(false),
                }
            }
        }
    }

    async fn resource_directory_exists(&self, path: &ResourcePath) -> Result<bool> {
        match self.resource_info(path).await {
            Ok(info) if info.is_dir && info.mode & (1 << 27) == 0 => Ok(true),
            Ok(_) => Err(Error::ResourceAlreadyExists),
            Err(Error::Http { response }) if response.status() == 404 => Ok(false),
            Err(error) => Err(error),
        }
    }
}

fn storage_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}
