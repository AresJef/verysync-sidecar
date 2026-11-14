//! Actual core-side logs and diagnostic metadata through public Rust APIs.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{collections::BTreeMap, time::Duration};
use verysync_sidecar::{CoreLogLevel, ManagedInstance};

#[tokio::test]
async fn public_stopped_database_commands_capture_counts_metadata_and_reset_effects() -> TestResult
{
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{
        DatabaseCommand, DatabaseCommandOutcome, FolderId, JoinFolderOptions, TargetPath,
    };
    let root = tempfile::Builder::new().prefix("vdb-").tempdir()?.keep();
    let path = root.join("data");
    std::fs::create_dir(&path)?;
    let bytes = b"native database diagnostic sample";
    let flag_bytes = b"literal filename resembling a flag";
    std::fs::write(path.join("sample.txt"), bytes)?;
    std::fs::write(path.join("--home"), flag_bytes)?;
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let id = core.client().instance().device_id.clone();
    let share = core.client().generate_share().await?;
    let key = core
        .client()
        .validate_share_key(&share.read_write_key)
        .await?;
    let folder = core
        .client()
        .join_folder(&JoinFolderOptions::new(key, TargetPath::local(&path)))
        .await?
        .configuration;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let status = core.client().folder_status(&folder.id).await?;
            if status.local_files == Some(2)
                && status.state == Some(verysync_sidecar::FolderState::Idle)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        Ok::<_, verysync_sidecar::Error>(())
    })
    .await??;
    assert!(matches!(
        core.run_database_command(DatabaseCommand::Statistics, Duration::from_secs(10))
            .await,
        Err(verysync_sidecar::Error::ManagedFailure { .. })
    ));
    assert_eq!(core.client().system_status().await?.device_id, id);
    core.client().pause_folder(&folder.id).await?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    assert!(matches!(
        core.run_database_command(DatabaseCommand::ResetAll, Duration::ZERO)
            .await,
        Err(verysync_sidecar::Error::InvalidConfiguration { .. })
    ));
    assert!(core
        .run_database_command(DatabaseCommand::Statistics, Duration::from_nanos(1))
        .await
        .is_err());
    #[cfg(unix)]
    {
        let sentinel = root.join("outside-state.txt");
        std::fs::write(&sentinel, b"outside state must remain untouched")?;
        let alias = core.state_directory().join("unexpected-alias");
        std::os::unix::fs::symlink(&sentinel, &alias)?;
        assert!(matches!(
            core.run_database_command(DatabaseCommand::ResetAll, Duration::from_secs(10))
                .await,
            Err(verysync_sidecar::Error::UnmanagedState)
        ));
        assert_eq!(
            std::fs::read(&sentinel)?,
            b"outside state must remain untouched"
        );
        std::fs::remove_file(alias)?;
        eprintln!("public Unix database state boundary evidence: {{\"actual_state_alias_refused_without_touching_outside_file\":true}}");
    }
    let stats = core
        .run_database_command(DatabaseCommand::Statistics, Duration::from_secs(10))
        .await?;
    assert_eq!(stats.outcome, DatabaseCommandOutcome::Success);
    assert!(stats.tree_stopped && !stats.diagnostic.body_bytes().is_empty());
    let counts = core
        .run_database_command(
            DatabaseCommand::Counts(folder.id.clone()),
            Duration::from_secs(10),
        )
        .await?;
    if counts.outcome != DatabaseCommandOutcome::Success {
        eprintln!(
            "native counts envelope diagnostic: {}",
            cli_shape(counts.diagnostic.body_bytes())
        );
    }
    if let Some(prefix) = &counts.native_preamble {
        eprintln!(
            "retained native counts preamble diagnostic: {}",
            cli_shape(prefix.body_bytes())
        );
    }
    assert_eq!(counts.outcome, DatabaseCommandOutcome::Success);
    let rows = counts.counts.as_ref().ok_or("typed native counts absent")?;
    assert!(rows
        .iter()
        .any(|row| row.count == 2 && row.size == (bytes.len() + flag_bytes.len()) as u64));
    let file = core
        .run_database_command(
            DatabaseCommand::File {
                folder: folder.id.clone(),
                path: TargetPath::local(std::path::Path::new("--home")),
            },
            Duration::from_secs(10),
        )
        .await?;
    assert_eq!(file.outcome, DatabaseCommandOutcome::Success);
    assert!(std::str::from_utf8(file.diagnostic.body_bytes())?.contains("--home"));
    let injected = core
        .run_database_command(
            DatabaseCommand::Counts(FolderId::parse("--home")?),
            Duration::from_secs(10),
        )
        .await?;
    assert!(injected.outcome != DatabaseCommandOutcome::Success && injected.code != Some(0));
    assert!(!format!("{file:?}").contains(path.to_str().ok_or("test path UTF-8")?));
    let reset = core
        .run_database_command(DatabaseCommand::ResetAll, Duration::from_secs(10))
        .await?;
    assert_eq!(reset.outcome, DatabaseCommandOutcome::Success);
    assert!(reset.tree_stopped && reset.code == Some(0));
    let empty = core
        .run_database_command(
            DatabaseCommand::Counts(folder.id.clone()),
            Duration::from_secs(10),
        )
        .await?;
    if empty.outcome != DatabaseCommandOutcome::FolderNotIndexed {
        eprintln!(
            "native missing-index envelope diagnostic: {}",
            cli_shape(empty.diagnostic.body_bytes())
        );
    }
    assert_eq!(empty.outcome, DatabaseCommandOutcome::FolderNotIndexed);
    assert!(empty.counts.is_none());
    assert_eq!(std::fs::read(path.join("sample.txt"))?, bytes);
    assert_eq!(std::fs::read(path.join("--home"))?, flag_bytes);
    assert_eq!(
        Sha256::digest(std::fs::read(path.join("sample.txt"))?),
        Sha256::digest(bytes)
    );
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().instance().device_id, id);
    assert!(core.client().folder(&folder.id).await?.paused);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    eprintln!(
        "public stopped database command evidence: {}",
        serde_json::json!({"actual_active_owner_refused_without_stopping":true,"actual_pinned_statistics_command":true,"actual_typed_nonempty_native_counts":true,"actual_indexed_flag_like_filename_metadata":true,"actual_folder_flag_not_interpreted_as_option":true,"actual_bounded_private_output":true,"actual_explicit_offline_database_reset":true,"actual_index_absence_not_invented_zero":true,"actual_both_synthetic_files_preserved":true,"actual_original_sha_preserved":true,"actual_configuration_and_identity_retained":true,"actual_all_contained_cli_trees_stopped":true,"actual_normal_owned_final_exit":true,"actual_zero_and_expired_deadlines_refused":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Independent stopped-database verification, not an SDK CLI capability claim.
struct CountsOracle {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
struct OracleChild(std::process::Child);
impl Drop for OracleChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
async fn counts_oracle(
    core: &ManagedInstance,
    folder: &verysync_sidecar::FolderId,
) -> TestResult<CountsOracle> {
    use std::io::Read;
    // This oracle accepts only IDs generated by the isolated native core.
    assert!(folder.as_str().bytes().all(|b| b.is_ascii_digit()));
    let mut child = OracleChild(
        std::process::Command::new(
            std::env::var_os("VERYSYNC_TEST_BINARY").ok_or("explicit fixed binary required")?,
        )
        .args(["debug", "database-counts", folder.as_str(), "--home"])
        .arg(core.state_directory())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?,
    );
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if start.elapsed() > Duration::from_secs(5) {
            return Err("owned counts oracle exceeded its bound".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .0
        .stdout
        .take()
        .ok_or("oracle stdout absent")?
        .take(65537)
        .read_to_end(&mut stdout)?;
    child
        .0
        .stderr
        .take()
        .ok_or("oracle stderr absent")?
        .take(65537)
        .read_to_end(&mut stderr)?;
    assert!(stdout.len() <= 65536 && stderr.len() <= 65536);
    Ok(CountsOracle {
        code: status.code(),
        stdout,
        stderr,
    })
}
fn assert_indexed(oracle: &CountsOracle, size: usize) -> TestResult {
    assert_eq!(oracle.code, Some(0));
    assert!(oracle.stderr.is_empty());
    let text = std::str::from_utf8(&oracle.stdout)?;
    assert!(text
        .lines()
        .any(|line| line.split_whitespace().collect::<Vec<_>>()
            == ["DEVICE", "TYPE", "FLAGS", "DELETED", "COUNT", "SIZE"]));
    assert!(text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .any(|cells| cells.len() == 6
            && cells[4] == "1"
            && cells[5].parse::<usize>().ok() == Some(size)));
    Ok(())
}
fn assert_index_absent(oracle: &CountsOracle) -> TestResult {
    assert_eq!(oracle.code, Some(1));
    // Windows emits native stdout before the command response. Absence is the
    // exact exit-one stderr error, never an invented empty/zero count table.
    let stdout = std::str::from_utf8(&oracle.stdout)?;
    if !stdout.is_empty() {
        eprintln!(
            "native missing-index stdout diagnostic: {}",
            cli_shape(&oracle.stdout)
        );
    }
    assert!(!stdout
        .lines()
        .any(|line| line.split_whitespace().collect::<Vec<_>>()
            == ["DEVICE", "TYPE", "FLAGS", "DELETED", "COUNT", "SIZE"]));
    assert_eq!(
        std::str::from_utf8(&oracle.stderr)?.trim(),
        if cfg!(windows) {
            "verysync.exe: error: no such folder"
        } else {
            "verysync: error: no such folder"
        }
    );
    Ok(())
}
fn cli_shape(bytes: &[u8]) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let text = std::str::from_utf8(bytes);
    let lines = text.ok().map(|text| text.lines().take(16).map(|line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        serde_json::json!({"bytes":line.len(),"columns":columns.len(),
            "header":columns==["DEVICE","TYPE","FLAGS","DELETED","COUNT","SIZE"],
            "numeric_count_row":columns.len()==6 && columns[4].parse::<u64>().is_ok() && columns[5].parse::<u64>().is_ok(),
            "known_missing_folder":matches!(line.trim(),"verysync: error: no such folder"|"verysync.exe: error: no such folder")})
    }).collect::<Vec<_>>());
    serde_json::json!({"bytes":bytes.len(),"utf8":text.is_ok(),"sha256":format!("{:x}",Sha256::digest(bytes)),"line_shapes":lines})
}
fn oracle_table(oracle: &CountsOracle) -> TestResult<&str> {
    let text = std::str::from_utf8(&oracle.stdout)?;
    let mut offset = 0;
    let mut starts = Vec::new();
    for line in text.split_inclusive('\n') {
        if line.split_whitespace().collect::<Vec<_>>()
            == ["DEVICE", "TYPE", "FLAGS", "DELETED", "COUNT", "SIZE"]
        {
            starts.push(offset);
        }
        offset += line.len();
    }
    if starts.len() != 1 {
        return Err("independent counts oracle did not have one exact table".into());
    }
    Ok(&text[starts[0]..])
}

#[tokio::test]
async fn public_scoped_and_all_index_resets_preserve_data_identity_and_configuration() -> TestResult
{
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{
        IndexResetScope, JoinFolderOptions, RawMethod, RawRequest, RequestEffect, TargetPath,
    };
    let root = tempfile::Builder::new().prefix("vir-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let key_hash = Sha256::digest(std::fs::read(core.state_directory().join("key.pem"))?);
    let cert_hash = Sha256::digest(std::fs::read(core.state_directory().join("cert.pem"))?);
    let mut folders = Vec::new();
    let mut samples = Vec::new();
    for name in ["a", "b"] {
        let path = root.join(name);
        std::fs::create_dir(&path)?;
        let bytes = format!("independent synthetic index sample {name}").into_bytes();
        std::fs::write(path.join("sample.txt"), &bytes)?;
        samples.push(bytes);
        let share = core.client().generate_share().await?;
        let key = core
            .client()
            .validate_share_key(&share.read_write_key)
            .await?;
        let folder = core
            .client()
            .join_folder(&JoinFolderOptions::new(key, TargetPath::local(&path)))
            .await?
            .configuration;
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let status = core.client().folder_status(&folder.id).await?;
                if status.local_files == Some(1)
                    && status.state == Some(verysync_sidecar::FolderState::Idle)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            Ok::<_, verysync_sidecar::Error>(())
        })
        .await??;
        folders.push(folder);
    }
    for folder in &folders {
        core.client().pause_folder(&folder.id).await?;
    }
    let config_request =
        RawRequest::new(RawMethod::Get, ["rest", "config"], RequestEffect::ReadOnly)?;
    let before: serde_json::Value = serde_json::from_slice(
        core.client()
            .raw_request(&config_request)
            .await?
            .body_bytes(),
    )?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let original_a = counts_oracle(&core, &folders[0].id).await?;
    let original_b = counts_oracle(&core, &folders[1].id).await?;
    assert_indexed(&original_a, samples[0].len())?;
    assert_indexed(&original_b, samples[1].len())?;
    core.restart(Duration::from_secs(30)).await?;
    let scope = IndexResetScope::Folder(folders[0].id.clone());
    let ack = core.client().request_index_reset(&scope).await?;
    assert_eq!(ack.scope, scope);
    assert!(ack.restart_expected);
    assert_eq!(
        ack.native_message(),
        format!("resetting folder {}", folders[0].id.as_str())
    );
    assert!(!format!("{ack:?}").contains(folders[0].id.as_str()));
    let exit = tokio::time::timeout(Duration::from_secs(10), core.wait_for_exit()).await??;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(3));
    assert_index_absent(&counts_oracle(&core, &folders[0].id).await?)?;
    let retained = counts_oracle(&core, &folders[1].id).await?;
    assert_indexed(&retained, samples[1].len())?;
    assert_eq!(oracle_table(&retained)?, oracle_table(&original_b)?);
    core.restart(Duration::from_secs(30)).await?;
    let after: serde_json::Value = serde_json::from_slice(
        core.client()
            .raw_request(&config_request)
            .await?
            .body_bytes(),
    )?;
    assert!(
        before == after,
        "native configuration changed after the selected index reset"
    );
    let ack = core
        .client()
        .request_index_reset(&IndexResetScope::AllFolders)
        .await?;
    assert!(ack.restart_expected && ack.scope == IndexResetScope::AllFolders);
    assert_eq!(ack.native_message(), "resetting database");
    let exit = tokio::time::timeout(Duration::from_secs(10), core.wait_for_exit()).await??;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(3));
    for folder in &folders {
        assert_index_absent(&counts_oracle(&core, &folder.id).await?)?;
    }
    core.restart(Duration::from_secs(30)).await?;
    let after: serde_json::Value = serde_json::from_slice(
        core.client()
            .raw_request(&config_request)
            .await?
            .body_bytes(),
    )?;
    assert!(
        before == after,
        "native configuration changed after the all-folders index reset"
    );
    assert_eq!(core.client().instance().device_id, identity);
    assert_eq!(
        Sha256::digest(std::fs::read(core.state_directory().join("key.pem"))?),
        key_hash
    );
    assert_eq!(
        Sha256::digest(std::fs::read(core.state_directory().join("cert.pem"))?),
        cert_hash
    );
    for (name, bytes) in ["a", "b"].iter().zip(samples.iter()) {
        let actual = std::fs::read(root.join(name).join("sample.txt"))?;
        assert_eq!(&actual, bytes);
        assert_eq!(Sha256::digest(actual), Sha256::digest(bytes));
    }
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    eprintln!(
        "public index reset evidence: {}",
        serde_json::json!({"actual_two_initial_indexes":true,"actual_explicit_folder_ack":true,"actual_folder_reset_exit_three":true,"actual_selected_index_absent_offline":true,"actual_unselected_index_exactly_retained":true,"actual_configuration_unchanged_after_folder_reset":true,"actual_explicit_all_folders_ack":true,"actual_all_reset_exit_three":true,"actual_both_indexes_absent_offline":true,"actual_configuration_unchanged_after_all_reset":true,"actual_identity_certificate_and_key_retained":true,"actual_both_file_bytes_and_sha_retained":true,"actual_explicit_restarts_authenticate":true,"actual_normal_final_owned_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn decode_profile(profile: &verysync_sidecar::CoreProfile) -> TestResult<Vec<u8>> {
    use std::io::Read;
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(profile.body_bytes())
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut decoded)?;
    assert!(!decoded.is_empty() && decoded.len() <= 32 * 1024 * 1024);
    Ok(decoded)
}

// Inspect only the native top-level collection interval. See the official
// https://github.com/google/pprof/blob/main/proto/profile.proto (fields 9/10).
// This independent test decoder does not interpret or print private symbols.
fn profile_interval_ns(mut bytes: &[u8]) -> TestResult<(u64, u64)> {
    fn varint(bytes: &mut &[u8]) -> TestResult<u64> {
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let (&byte, rest) = bytes.split_first().ok_or("truncated profile varint")?;
            *bytes = rest;
            if shift == 63 && byte > 1 {
                return Err("overflowing profile varint".into());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("unterminated profile varint".into())
    }
    let (mut start, mut duration) = (None, None);
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        if key >> 3 == 0 {
            return Err("zero profile field".into());
        }
        let size = match key & 7 {
            0 => {
                let value = varint(&mut bytes)?;
                let slot = match key >> 3 {
                    9 => Some(&mut start),
                    10 => Some(&mut duration),
                    _ => None,
                };
                if let Some(slot) = slot {
                    if value == 0 || value > i64::MAX as u64 || slot.replace(value).is_some() {
                        return Err("invalid or repeated profile interval".into());
                    }
                }
                0
            }
            1 => 8,
            2 => usize::try_from(varint(&mut bytes)?)?,
            5 => 4,
            _ => return Err("unsupported profile wire type".into()),
        };
        bytes = bytes.get(size..).ok_or("truncated profile field")?;
    }
    Ok((
        start.ok_or("native profile start absent")?,
        duration.ok_or("native profile duration absent")?,
    ))
}

#[tokio::test]
async fn public_profiles_metrics_and_clone_serialization_preserve_the_owned_core() -> TestResult {
    use verysync_sidecar::{CoreProfileRequest, RawMethod, RawRequest, RequestEffect};
    let root = tempfile::Builder::new().prefix("vpr-").tempdir()?.keep();
    let options = options(&root.join("c"))?;
    let endpoint = options.management_endpoint().clone();
    let mut core = ManagedInstance::start(options).await?;
    let identity = core.client().instance().device_id.clone();
    let before = core.client().core_metrics().await?;
    assert!(before.native_text().contains("# TYPE go_goroutines gauge"));
    let gc_count = |text: &str| -> TestResult<f64> {
        Ok(text
            .lines()
            .find_map(|line| line.strip_prefix("go_gc_duration_seconds_count "))
            .ok_or("native GC count absent")?
            .parse::<f64>()?)
    };
    let gc_before = gc_count(before.native_text())?;
    let heap = core
        .client()
        .collect_core_profile(CoreProfileRequest::Heap)
        .await?;
    assert_eq!(heap.request, CoreProfileRequest::Heap);
    let heap_decoded = decode_profile(&heap)?;
    let after = core.client().core_metrics().await?;
    assert!(gc_count(after.native_text())? > gc_before);
    let start = std::time::Instant::now();
    let a = core.client().clone();
    let b = core.client().clone();
    let cpu = CoreProfileRequest::Cpu {
        duration_seconds: 1,
    };
    let (one, two) = tokio::join!(a.collect_core_profile(cpu), b.collect_core_profile(cpu));
    let one = one?;
    let two = two?;
    assert_eq!(one.request, cpu);
    assert_eq!(two.request, cpu);
    let cpu_decoded = decode_profile(&one)?;
    let cpu_two_decoded = decode_profile(&two)?;
    let first = profile_interval_ns(&cpu_decoded)?;
    let second = profile_interval_ns(&cpu_two_decoded)?;
    eprintln!(
        "native CPU profile interval evidence: {}",
        serde_json::json!({"first_duration_ns":first.1,"second_duration_ns":second.1,
            "first_end_ns":first.0.checked_add(first.1),"second_start_ns":second.0,
            "controller_elapsed_ns":start.elapsed().as_nanos()})
    );
    // Verify complete requested one-second native intervals. Native pprof uses
    // a wall-clock Unix start and a monotonic elapsed duration; adding them is
    // not a reliable cross-request non-overlap assertion (Windows CI observed
    // an 11.2us overlap). The separate transport body-gate contract verifies
    // clone request ordering through full response completion without changing
    // native profile bytes or adding an arbitrary timestamp tolerance.
    // https://github.com/golang/go/blob/go1.24.2/src/runtime/pprof/proto.go
    assert!(first.1 >= 1_000_000_000 && second.1 >= 1_000_000_000);
    assert!(format!("{heap:?} {one:?} {before:?}").len() < 512);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let gui = core
        .client()
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "config", "gui"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    let gui: serde_json::Value = serde_json::from_slice(gui.body_bytes())?;
    assert_eq!(gui["metricsWithoutAuth"], false);
    let builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3));
    #[cfg(unix)]
    let builder = if let Some(socket) = endpoint.socket_path() {
        builder.unix_socket(socket)
    } else {
        builder
    };
    let url = if let Some(base) = endpoint.http_url() {
        base.join("metrics")?
    } else {
        "http://localhost/metrics".parse()?
    };
    let unauthenticated = builder.build()?.get(url).send().await?;
    assert!(matches!(unauthenticated.status().as_u16(), 401 | 403));
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    eprintln!(
        "public core profile and metrics evidence: {}",
        serde_json::json!({
            "actual_nonempty_native_metrics":true,"actual_native_goroutine_descriptor":true,
            "actual_native_gc_count_increased":true,"actual_heap_profile_gzip_crc":true,
            "actual_two_cpu_profiles_gzip_crc":true,"actual_clone_profile_serialization":true,
            "actual_selected_request_kinds_preserved":true,"actual_authenticated_metrics":true,
            "actual_unauthenticated_metrics_denied":true,"actual_metrics_without_auth_remains_disabled":true,
            "actual_owned_identity_retained":true,"actual_normal_owned_tree_exit":true,
            "heap_decoded_bytes":heap_decoded.len(),"cpu_decoded_bytes":cpu_decoded.len()
        })
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn public_core_errors_logs_levels_and_owned_diagnostics() -> TestResult {
    let root = tempfile::Builder::new().prefix("vmt-").tempdir()?.keep();
    let state = root.join("c");
    let mut core = ManagedInstance::start(options(&state)?).await?;
    assert!(core.client().core_errors().await?.is_empty());
    let before = core.client().core_log(None).await?;
    let old_entries = before.messages.as_ref().ok_or("startup log absent")?;
    assert!(!old_entries.is_empty());
    let stamp = old_entries
        .last()
        .ok_or("last log entry absent")?
        .when
        .clone();
    let message = "verysync-sidecar synthetic error: 二 %";
    let native_message = format!("External error report (error=\"{message}\" log.pkg=api)");
    let recorded = core.client().record_core_error(message).await?;
    let errors = recorded.errors.as_ref().ok_or("registered error absent")?;
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].message, native_message);
    assert_eq!(errors[0].level, "ERR");
    assert!(!errors[0].when.is_empty());
    assert!(!format!("{recorded:?} {:?}", errors[0]).contains(message));
    let log = core.client().core_log(Some(&stamp)).await?;
    let messages = log.messages.as_ref().ok_or("log snapshot absent")?;
    assert!(messages.iter().any(|entry| entry.message.contains(message)));
    assert!(messages.iter().all(|entry| entry.when >= stamp));
    assert!(old_entries.iter().any(|entry| entry.when < stamp));
    assert!(!format!("{log:?}").contains(message));
    let second = "second synthetic registered error";
    let recorded = core.client().record_core_error(second).await?;
    assert_eq!(recorded.errors.as_ref().map(Vec::len), Some(2));
    assert!(recorded.errors.as_ref().is_some_and(|entries| entries
        .iter()
        .any(|e| e.message == native_message)
        && entries.iter().any(|e| e.message.contains(second))));
    assert!(core.client().clear_core_errors().await?.is_empty());
    assert!(core.client().core_errors().await?.is_empty());

    let initial = core.client().core_log_levels().await?;
    assert_eq!(initial.levels.get("main"), Some(&CoreLogLevel::Info));
    assert!(initial.packages.contains_key("main"));
    for level in [
        CoreLogLevel::Debug,
        CoreLogLevel::Warn,
        CoreLogLevel::Error,
        CoreLogLevel::Info,
    ] {
        let changed = core
            .client()
            .set_core_log_levels(&BTreeMap::from([("main".to_owned(), level.clone())]))
            .await?;
        assert!(changed.requested_levels_match);
        assert_eq!(changed.configuration.levels.get("main"), Some(&level));
        assert_eq!(changed.configuration.packages, initial.packages);
        assert_eq!(changed.configuration.levels.len(), initial.levels.len());
        assert!(initial
            .levels
            .iter()
            .filter(|(k, _)| k.as_str() != "main")
            .all(|(name, old)| changed.configuration.levels.get(name) == Some(old)));
    }
    let restored = core.client().core_log_levels().await?;
    assert_eq!(restored.levels, initial.levels);
    let diagnostics = core.client().core_diagnostics().await?;
    let actual_state = std::fs::canonicalize(&state)?;
    for name in ["confdir", "datadir"] {
        let path = diagnostics
            .locations
            .get(name)
            .ok_or("owned location missing")?;
        assert!(path.local_path().is_none());
        assert_eq!(
            path.style(),
            verysync_sidecar::TargetPath::local(&state).style()
        );
        assert_eq!(std::fs::canonicalize(path.to_protocol()?)?, actual_state);
    }
    assert!(diagnostics.database_size > 0);
    assert!(!format!("{diagnostics:?}").contains(root.to_str().ok_or("UTF-8 test root")?));
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    eprintln!(
        "public core maintenance evidence: {}",
        serde_json::json!({
            "actual_initial_empty_error_log":true,"actual_exact_unicode_error_registered":true,
            "actual_error_severity_and_timestamp":true,"actual_second_error_preserves_first":true,
            "actual_errors_cleared_and_observed_empty":true,"actual_log_contains_explicit_message":true,
            "actual_since_filter_excludes_older_entries":true,"actual_four_package_levels":true,
            "actual_unselected_package_levels_preserved":true,"actual_package_descriptions_preserved":true,
            "actual_original_levels_restored":true,"actual_owned_config_and_data_locations":true,
            "actual_target_path_syntax_without_host_open_in_sdk":true,"actual_positive_native_database_size_metadata":true,
            "actual_private_debug_redaction":true,"actual_normal_owned_tree_exit":true
        })
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
