//! Explicit resource workload; external sampling observes only these owned PIDs.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/resource_faults.rs"]
mod resource_faults;
#[path = "common/resource_fixture.rs"]
mod resource_fixture;
use managed_fixture::{options, TestResult};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};
use verysync_sidecar::{ManagedInstance, ResourceTransferOptions};

async fn wait_for_sampler(path: &std::path::Path, nonce: &str) -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if std::fs::read_to_string(path).is_ok_and(|text| text == nonce) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

fn event(file: &mut File, value: serde_json::Value) -> TestResult {
    serde_json::to_writer(&mut *file, &value)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

#[tokio::test]
async fn explicit_native_resource_workload() -> TestResult {
    let scenario = std::env::var("VERYSYNC_RESOURCE_SCENARIO")?;
    let repeats: u32 = std::env::var("VERYSYNC_RESOURCE_REPEATS")?.parse()?;
    assert!((1..=32).contains(&repeats));
    let bytes = match scenario.as_str() {
        "idle" => 8192,
        "stream-small" => 8 * 1024 * 1024,
        "stream-large" => 128 * 1024 * 1024,
        "many-small" => 8192,
        _ => return Err("unknown explicit resource workload".into()),
    };
    let files = if scenario == "many-small" { 256 } else { 1 };
    let events =
        PathBuf::from(std::env::var_os("VERYSYNC_RESOURCE_EVENTS").ok_or("events path required")?);
    let nonce = std::env::var("VERYSYNC_RESOURCE_NONCE")?;
    assert!(events.is_absolute() && nonce.len() == 64);
    let ack = events.with_extension("ack");
    assert!(!ack.exists());
    let mut journal = File::options().write(true).create_new(true).open(&events)?;
    let root = tempfile::Builder::new().prefix("vrm-").tempdir()?.keep();
    let state = root.join("core");
    let mut core = ManagedInstance::start(options(&state)?).await?;
    let identity = core.client().instance().device_id.clone();
    let config = std::fs::read(state.join("setting.dat"))?;
    let volumes = core.client().resource_volumes().await?;
    let (profile, remote, _) = resource_fixture::owned_base(&core, &volumes)?;
    let mut expected = Vec::new();
    let mut pattern = Vec::new();
    for n in 0..files {
        let name = format!("resource-source-{n}.bin");
        let (p, hash) = resource_faults::write_pattern(&profile.join(&name), bytes)?;
        pattern = p;
        expected.push((name, hash));
    }
    let warm = profile.join("resource-warm.bin");
    let (_, warm_hash) = resource_faults::write_pattern(&warm, 8192)?;
    let limits = ResourceTransferOptions {
        max_bytes: bytes.max(8192),
        deadline: Duration::from_secs(30),
    };
    let warm_output = root.join("warm-output.bin");
    let receipt = core
        .client()
        .download_resource(
            &remote.clone().child("resource-warm.bin")?,
            &warm_output,
            None,
            &limits,
        )
        .await?;
    assert_eq!((receipt.bytes, receipt.sha256), (8192, warm_hash));
    std::fs::remove_file(warm_output)?;
    let executable = std::env::current_exe()?;
    let mut executable_file = File::open(&executable)?;
    let mut executable_hash = Sha256::new();
    std::io::copy(&mut executable_file, &mut executable_hash)?;
    let executable_hash: [u8; 32] = executable_hash.finalize().into();
    event(
        &mut journal,
        serde_json::json!({"kind":"ready","nonce":nonce,
        "scenario":scenario,"repeats":repeats,"bytes_each":bytes,"files":files,
        "controller_pid":std::process::id(),"engine_pid":core.process_id(),
        "controller_executable":executable,"controller_sha256":executable_hash,
        "engine_version":core.client().instance().version.version,
        "engine_sha256":std::env::var("VERYSYNC_TEST_BINARY_SHA256")?}),
    )?;
    wait_for_sampler(&ack, &nonce).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    event(
        &mut journal,
        serde_json::json!({"kind":"begin","nonce":nonce}),
    )?;
    wait_for_sampler(&events.with_extension("begin-ack"), &nonce).await?;
    let started = Instant::now();
    let output = root.join("measured-output.bin");
    tokio::time::timeout(Duration::from_secs(90), async {
        if scenario == "idle" {
            tokio::time::sleep(Duration::from_secs(2 * repeats as u64)).await;
        } else {
            for round in 0..repeats {
                for (index, (name, hash)) in expected.iter().enumerate() {
                    let receipt = core
                        .client()
                        .download_resource(&remote.clone().child(name)?, &output, None, &limits)
                        .await?;
                    assert_eq!((receipt.bytes, receipt.sha256), (bytes, *hash));
                    assert_eq!(std::fs::metadata(&output)?.len(), bytes);
                    if scenario == "many-small" {
                        assert_eq!(std::fs::read(&output)?, pattern[..bytes as usize]);
                    }
                    if round + 1 != repeats || index + 1 != expected.len() {
                        std::fs::remove_file(&output)?;
                    }
                }
            }
        }
        TestResult::Ok(())
    })
    .await??;
    let elapsed_ns = started.elapsed().as_nanos();
    event(
        &mut journal,
        serde_json::json!({"kind":"end","nonce":nonce,"elapsed_ns":elapsed_ns,
        "completed_calls":if scenario=="idle" {0} else {files * repeats},
        "transferred_bytes":if scenario=="idle" {0} else {bytes * files as u64 * repeats as u64}}),
    )?;
    wait_for_sampler(&events.with_extension("end-ack"), &nonce).await?;
    if scenario != "idle" {
        assert_eq!(
            resource_faults::verify_pattern(&output, &pattern, bytes)?,
            (bytes, expected.last().expect("source").1)
        );
    }
    for (name, hash) in &expected {
        assert_eq!(
            resource_faults::verify_pattern(&profile.join(name), &pattern, bytes)?,
            (bytes, *hash)
        );
    }
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(std::fs::read(state.join("setting.dat"))?, config);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    event(
        &mut journal,
        serde_json::json!({"kind":"complete","nonce":nonce,
        "all_actual_bytes_verified":true,"source_config_identity_unchanged":true,"normal_owned_tree_exit":true}),
    )?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
