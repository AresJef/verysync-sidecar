use crate::{audit_files::ArchiveWitness, audit_history, schedule, Stage};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};
use verysync_sidecar::{AuditHistorySettings, Client, ManagedInstance};

const PREVIOUS_SETTINGS: &str = "owned-audit-previous-settings";

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Step {
    Prepare,
    Record,
    Observe,
    Reset,
    Finish,
}

struct Proven {
    pages: Vec<Value>,
    files: Value,
}

pub(crate) struct AuditCase {
    engine: PathBuf,
    root: PathBuf,
    witness: Option<ArchiveWitness>,
    baseline: Option<Value>,
    proven: Option<Proven>,
}

impl AuditCase {
    pub(crate) fn new(engine: &Path, root: &Path) -> Self {
        Self {
            engine: engine.to_path_buf(),
            root: root.to_path_buf(),
            witness: None,
            baseline: None,
            proven: None,
        }
    }

    fn grant(&self) -> Stage<()> {
        schedule::check_authorization(&self.root.join(schedule::GRANT_REVOKED))
    }

    pub(crate) async fn apply(
        &mut self,
        step: Step,
        core: &ManagedInstance,
        run: &str,
    ) -> Stage<Value> {
        match step {
            Step::Prepare => self.prepare(core, run).await,
            Step::Record => self.record_changes(core.client()).await,
            Step::Observe => self.read_pages(core.client()).await,
            Step::Reset => self.reset(core.client()).await,
            Step::Finish => {
                self.cleanup(core.client()).await?;
                Ok(json!({"ok":true,"prior_settings_restored":true,"private_peer_stopped":true}))
            }
        }
    }

    async fn prepare(&mut self, core: &ManagedInstance, run: &str) -> Stage<Value> {
        self.grant()?;
        let previous_settings = self.root.join(PREVIOUS_SETTINGS);
        if load_prior_settings(&previous_settings)?.is_some()
            || self.root.join("audit-file-witness").exists()
        {
            return Err("audit-owned-case-already-used");
        }
        let client = core.client();
        if !client
            .folders()
            .await
            .map_err(|_| "audit-folder-ownership-unverified")?
            .is_empty()
        {
            return Err("audit-needs-an-exclusive-folder-free-start");
        }
        let prior = client
            .audit_history_settings()
            .await
            .map_err(|_| "audit-original-settings-unavailable")?;
        let baseline = audit_history::empty_view(client).await?;
        self.grant()?;
        save_prior_settings(&previous_settings, prior)?;
        if prior.enabled {
            self.grant()?;
            let inactive = AuditHistorySettings {
                enabled: false,
                ..prior
            };
            set_confirmed(client, inactive).await?;
        }
        let witness = ArchiveWitness::prepare(&self.engine, &self.root, core, run).await?;
        self.witness = Some(witness);
        self.grant()?;
        let selection = AuditHistorySettings {
            enabled: true,
            ..prior
        };
        set_confirmed(client, selection).await?;
        self.baseline = Some(baseline.clone());
        Ok(json!({"ok":true,"native_recording_enabled":true,
                 "owned_synthetic_peer_and_files_registered":true,
                 "retention_ceiling":selection.maximum_records,"baseline":baseline}))
    }

    async fn record_changes(&mut self, client: &Client) -> Stage<Value> {
        self.grant()?;
        if self.proven.is_some() || self.baseline.is_none() {
            return Err("audit-file-change-phase-unavailable");
        }
        let witness = self
            .witness
            .as_mut()
            .ok_or("audit-owned-file-witness-missing")?;
        let files = witness.archive_revisions(client).await?;
        witness.quiesce(client).await?;
        if witness.snapshot(client).await? != files {
            return Err("audit-file-evidence-changed-after-source-stop");
        }
        let first = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                match audit_history::owned_pages(
                    client,
                    witness.folder_id(),
                    witness.named_samples(),
                )
                .await
                {
                    Err(
                        "audit-native-more-than-one-page-unverified"
                        | "audit-native-owned-events-incomplete",
                    ) => tokio::time::sleep(Duration::from_millis(150)).await,
                    observed => return observed,
                }
            }
        })
        .await
        .map_err(|_| "audit-nonempty-pages-not-observed-after-real-transfer")??;
        let second =
            audit_history::owned_pages(client, witness.folder_id(), witness.named_samples())
                .await?;
        if first != second {
            return Err("audit-owned-native-pages-were-not-stable");
        }
        let observed = json!({"ok":true,"first_read":first,"second_read":second,
                           "file_census_before":files,"source_quiesced":true});
        self.proven = Some(Proven {
            pages: first,
            files,
        });
        Ok(observed)
    }

    async fn read_pages(&self, client: &Client) -> Stage<Value> {
        let witness = self
            .witness
            .as_ref()
            .ok_or("audit-owned-file-witness-missing")?;
        let pages =
            audit_history::owned_pages(client, witness.folder_id(), witness.named_samples())
                .await?;
        Ok(json!({"ok":true,"pages":pages}))
    }

    async fn reset(&self, client: &Client) -> Stage<Value> {
        self.grant()?;
        let proven = self
            .proven
            .as_ref()
            .ok_or("audit-reset-requires-proven-exclusive-records")?;
        let witness = self
            .witness
            .as_ref()
            .ok_or("audit-owned-file-witness-missing")?;
        let last = audit_history::owned_pages(client, witness.folder_id(), witness.named_samples())
            .await?;
        if last != proven.pages || witness.snapshot(client).await? != proven.files {
            return Err("audit-reset-scope-changed");
        }
        self.grant()?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.root.join("owned-audit-reset-submitted"))
            .and_then(|file| file.sync_all())
            .map_err(|_| "audit-reset-already-submitted-or-unrecordable")?;
        let ack = client.reset_audit_history().await.is_ok();
        let after = audit_history::empty_view(client).await;
        let files_after = witness.snapshot(client).await;
        let unchanged = files_after
            .as_ref()
            .is_ok_and(|files| files == &proven.files);
        Ok(json!({"ok":ack && after.is_ok() && unchanged,
                 "one_reset_submitted":true,"reset_acknowledged":ack,
                 "after_reset":after.ok(),"file_census_after":files_after.ok(),"files_preserved":unchanged}))
    }

    pub(crate) async fn stop_peer(&mut self) -> Stage<()> {
        match self.witness.as_mut() {
            Some(witness) => witness.stop_source().await,
            None => Ok(()),
        }
    }

    pub(crate) async fn cleanup(&mut self, client: &Client) -> Stage<()> {
        let peer_result = self.stop_peer().await;
        let previous_settings = self.root.join(PREVIOUS_SETTINGS);
        if let Some(prior) = load_prior_settings(&previous_settings)? {
            let actual = client
                .audit_history_settings()
                .await
                .map_err(|_| "audit-cleanup-read-failed")?;
            if actual != prior {
                set_confirmed(client, prior).await?;
            }
            fs::remove_file(previous_settings).map_err(|_| "audit-cleanup-marker-not-removed")?;
        }
        peer_result
    }
}

fn load_prior_settings(path: &Path) -> Stage<Option<AuditHistorySettings>> {
    match fs::read(path) {
        Ok(data) => serde_json::from_slice(&data)
            .map(Some)
            .map_err(|_| "audit-original-settings-marker-invalid"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("audit-original-settings-marker-unavailable"),
    }
}

fn save_prior_settings(path: &Path, prior: AuditHistorySettings) -> Stage<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "audit-original-settings-not-recorded")?;
    serde_json::to_writer(
        &mut file,
        &json!({"folderHistoryEnabled":prior.enabled,"folderHistoryMaxRecords":prior.maximum_records}),
    )
    .map_err(|_| "audit-original-settings-not-recorded")?;
    file.sync_all()
        .map_err(|_| "audit-original-settings-not-synced")
}

async fn set_confirmed(client: &Client, requested: AuditHistorySettings) -> Stage<()> {
    let written = client.set_audit_history_settings(requested).await;
    let actual = client
        .audit_history_settings()
        .await
        .map_err(|_| "audit-setting-readback-failed")?;
    if actual != requested {
        return Err("audit-native-recording-setting-not-retained");
    }
    if !written.is_ok_and(|reply| reply.requested_fields_match) {
        return Err("audit-native-configuration-write-unconfirmed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        load_prior_settings, save_prior_settings, AuditHistorySettings, PREVIOUS_SETTINGS,
    };
    use std::{env, fs, process, time::SystemTime};

    #[test]
    fn recovery_reads_the_original_settings_and_refuses_replacement_or_damage() {
        let root = env::temp_dir().join(format!(
            "r33-audit-original-settings-{}-{}",
            process::id(),
            SystemTime::UNIX_EPOCH.elapsed().unwrap().as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let marker = root.join(PREVIOUS_SETTINGS);
        assert_eq!(load_prior_settings(&marker).unwrap(), None);
        let prior = AuditHistorySettings {
            enabled: false,
            maximum_records: 117,
        };
        save_prior_settings(&marker, prior).unwrap();
        let replacement = AuditHistorySettings {
            enabled: true,
            maximum_records: 3,
        };
        assert!(save_prior_settings(&marker, replacement).is_err());
        assert_eq!(load_prior_settings(&marker).unwrap(), Some(prior));
        fs::write(&marker, b"{}").unwrap();
        assert!(load_prior_settings(&marker).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod native_control {
    use super::*;
    use crate::{device_alias, end, inspect, start};
    use std::env;

    #[tokio::test]
    #[ignore = "uses a fixed owned engine and two distinct private process lifetimes"]
    async fn recover_previous_audit_settings_without_writing_case_files() {
        let engine = PathBuf::from(env::var_os("R33_PINNED_ENGINE").unwrap());
        let root = PathBuf::from(env::var_os("R33_PRIVATE_CONTROL_DIR").unwrap());
        let phase = env::var("R33_RECOVERY_CONTROL_PHASE").unwrap();
        let mut core = start(engine.clone(), &root).await.unwrap();
        let result = audit_recovery(&engine, &root, &core, &phase).await;
        let exit = end(&mut core).await;
        println!(
            "R33_AUDIT_RECOVERY {}",
            json!({"normal_owned_exit":exit,"result":result})
        );
        assert!(exit);
        assert!(result.is_ok(), "{result:?}");
    }

    async fn audit_recovery(
        engine: &Path,
        root: &Path,
        core: &ManagedInstance,
        phase: &str,
    ) -> Stage<Value> {
        let run = "audit-recovery-private-identity";
        let observed = inspect(core, run).await?;
        if observed["account"] != "logged-out" || observed["pro_observations"] != json!([]) {
            return Err("signed-out-private-control-required");
        }
        let client = core.client();
        let original_marker = root.join(PREVIOUS_SETTINGS);
        let identity = root.join("audit-test-original-device");
        let readback = root.join("audit-test-retention-readback");
        let owned_case = root.join("audit-file-witness");
        let sample = owned_case.join("private-data.bin");
        let bytes = b"this isolated audit fixture stays byte-for-byte unchanged";
        let configured = client
            .audit_history_settings()
            .await
            .map_err(|_| "native-control-settings-unavailable")?;
        match phase {
            "seed" => {
                if configured.enabled {
                    return Err("signed-out-control-started-with-active-recording");
                }
                fs::create_dir(&owned_case).map_err(|_| "native-control-fixture-unavailable")?;
                fs::write(&sample, bytes).map_err(|_| "native-control-sample-unavailable")?;
                fs::write(identity, device_alias(core, run))
                    .map_err(|_| "native-control-identity-unavailable")?;
                save_prior_settings(&original_marker, configured)?;
                let modified = AuditHistorySettings {
                    enabled: false,
                    maximum_records: if configured.maximum_records == 73 {
                        99
                    } else {
                        73
                    },
                };
                let mutation = client
                    .set_audit_history_settings(modified)
                    .await
                    .map_err(|_| "native-control-setting-request-failed")?;
                let native = client
                    .audit_history_settings()
                    .await
                    .map_err(|_| "native-control-setting-readback-unavailable")?;
                println!(
                    "R33_AUDIT_SETTING_PROBE {}",
                    json!({
                        "initial":{"enabled":configured.enabled,"retention":configured.maximum_records},
                        "requested":{"enabled":modified.enabled,"retention":modified.maximum_records},
                        "returned":{"enabled":mutation.configuration.enabled,"retention":mutation.configuration.maximum_records},
                        "independent_read":{"enabled":native.enabled,"retention":native.maximum_records},
                        "fields_match":mutation.requested_fields_match,
                    })
                );
                if native.enabled
                    || native != mutation.configuration
                    || (native == modified) != mutation.requested_fields_match
                {
                    return Err("native-control-setting-effect-unclassified");
                }
                fs::write(&readback, native.maximum_records.to_string())
                    .map_err(|_| "native-control-retention-readback-unavailable")?;
                Ok(
                    json!({"device":observed["device"],"process":core.process_id(),
                          "saved_retention":configured.maximum_records,
                          "requested_retention":modified.maximum_records,
                          "observed_retention":native.maximum_records,
                          "signed_out_write_applied":native==modified}),
                )
            }
            "recover" => {
                let prior = load_prior_settings(&original_marker)?
                    .ok_or("native-control-original-settings-missing")?;
                if fs::read_to_string(identity).ok().as_deref()
                    != Some(device_alias(core, run).as_str())
                    || fs::read_to_string(&readback).ok().as_deref()
                        != Some(configured.maximum_records.to_string().as_str())
                {
                    return Err("native-control-persisted-state-not-confirmed");
                }
                let denial = fs::OpenOptions::new()
                    .write(true)
                    .open(&sample)
                    .err()
                    .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied);
                if !denial {
                    return Err("native-control-case-file-was-not-read-only");
                }
                AuditCase::new(engine, root).cleanup(client).await?;
                let final_state = client
                    .audit_history_settings()
                    .await
                    .map_err(|_| "native-control-after-settings-unavailable")?;
                if final_state != prior
                    || original_marker.exists()
                    || fs::read(sample).ok().as_deref() != Some(bytes.as_slice())
                {
                    return Err("native-control-original-settings-or-bytes-not-restored");
                }
                Ok(
                    json!({"device":observed["device"],"process":core.process_id(),
                          "case_write_denied":true,"original_settings_verified":true,
                          "a_restore_write_was_needed":configured!=prior,
                          "original_marker_removed":true,"sample_preserved":true,
                          "actual_retention_before_restore":configured.maximum_records,
                          "actual_retention_after_restore":final_state.maximum_records}),
                )
            }
            _ => Err("unknown-native-audit-control-phase"),
        }
    }
}
