//! Actual OS idle-sleep requests are scoped to the selected private native cores.
use super::managed_fixture::{options, TestResult};
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use verysync_sidecar::*;

struct SleepObservation {
    helpers: Vec<u32>,
    idle_assertion: bool,
    #[cfg(windows)]
    native_snapshot: String,
}

// The installed Apple SDK declares proc_pidpath(int, void *, uint32_t) and
// PROC_PIDPATHINFO_MAXSIZE as 4 * MAXPATHLEN. ps's comm may be just argv[0].
#[allow(unsafe_code)]
#[cfg(target_os = "macos")]
fn is_system_caffeinate(pid: u32) -> TestResult<bool> {
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, size: u32) -> i32;
    }
    let mut buffer = [0_u8; 4096];
    // SAFETY: The checked owned PID fits native int; this live writable buffer
    // has exactly the declared capacity and remains alive for the whole call.
    let length = unsafe {
        proc_pidpath(
            pid.try_into()?,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(3) || error.kind() == std::io::ErrorKind::NotFound {
            return Ok(false); // The helper can exit between ps and this read.
        }
        return Err(error.into());
    }
    let path = std::ffi::CStr::from_bytes_until_nul(&buffer)?;
    if path.to_bytes() != b"/usr/bin/caffeinate" {
        return Err("owned sleep helper kernel path is not system caffeinate".into());
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
async fn observe_sleep(root: u32, known_helpers: Vec<u32>) -> TestResult<SleepObservation> {
    tokio::task::spawn_blocking(move || {
        let ps = std::process::Command::new("/bin/ps")
            .args(["-A", "-o", "pid=,pgid=,comm="])
            .output()?;
        if !ps.status.success() || ps.stdout.len() > 4 * 1024 * 1024 {
            return Err("exact owned sleep-helper process observation failed".into());
        }
        let mut helpers = Vec::new();
        let mut root_seen = false;
        for line in String::from_utf8_lossy(&ps.stdout).lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }
            let pid = fields[0].parse::<u32>().ok();
            root_seen |= pid == Some(root);
            if fields[1].parse::<u32>().ok() == Some(root)
                && Path::new(fields[2]).file_name() == Some(std::ffi::OsStr::new("caffeinate"))
            {
                let pid = pid.ok_or("owned helper PID missing")?;
                if is_system_caffeinate(pid)? {
                    helpers.push(pid);
                }
            }
        }
        if !root_seen {
            return Err("selected owned core absent during sleep observation".into());
        }
        let pmset = std::process::Command::new("/usr/bin/pmset")
            .args(["-g", "assertions"])
            .output()?;
        if !pmset.status.success() || pmset.stdout.len() > 4 * 1024 * 1024 {
            return Err("owned system sleep-assertion observation failed".into());
        }
        let mut owned = known_helpers;
        owned.extend(helpers.iter().copied());
        owned.push(root);
        let idle_assertion = String::from_utf8_lossy(&pmset.stdout).lines().any(|line| {
            line.contains("PreventUserIdleSystemSleep")
                && owned
                    .iter()
                    .any(|pid| line.contains(&format!("pid {pid}(")))
        });
        // Other processes' names, assertion text and identifiers are discarded.
        Ok(SleepObservation {
            helpers,
            idle_assertion,
        })
    })
    .await?
}

#[cfg(windows)]
async fn observe_sleep(root: u32, _known_helpers: Vec<u32>) -> TestResult<SleepObservation> {
    let (idle_assertion, native_snapshot) = super::windows_sleep_observation::observe(root).await?;
    Ok(SleepObservation {
        helpers: Vec::new(),
        idle_assertion,
        native_snapshot,
    })
}

#[tokio::test]
async fn native_sleep_prevention_tracks_actual_owned_assertions_during_transfer() -> TestResult {
    #[cfg(windows)]
    let power_policy_before = super::windows_sleep_observation::powercfg("/query").await?;
    let root = tempfile::Builder::new()
        .prefix("vsawake-")
        .tempdir()?
        .keep();
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"caller bytes across native idle-sleep policy")?;
    let source = root.join("source");
    let received = root.join("received");
    std::fs::create_dir(&source)?;
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    for client in [a.client(), b.client()] {
        client
            .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(5))
            .await?;
    }
    let address = super::configuration_policy_listener(&b).await?;
    for (client, id, addresses) in [
        (a.client(), &bid, vec![format!("tcp://{address}")]),
        (b.client(), &aid, vec!["dynamic".into()]),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(id.clone()).settings(
                    DevicePatch::default()
                        .addresses(addresses)
                        .compression(DeviceCompression::Never)
                        .allowed_transports(vec![DeviceTransport::Tcp])
                        .advanced_configuration(
                            DeviceAdvancedPatch::default().num_connections(1),
                        )?,
                ),
            )
            .await?;
    }
    a.client()
        .update_bandwidth_configuration(
            &BandwidthPatch::default()
                .max_send_kib_per_second(1024)
                .limit_in_lan(true),
        )
        .await?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&received)).paused(true))
        .await?;
    a.client()
        .share_folder_with(&af.configuration.id, &bid)
        .await?;
    b.client()
        .share_folder_with(&bf.configuration.id, &aid)
        .await?;
    a.client().resume_folder(&af.configuration.id).await?;
    b.client().resume_folder(&bf.configuration.id).await?;
    let before_a = a.client().configuration().await?;
    let before_b = b.client().configuration().await?;
    let credentials_a: Vec<_> = ["key.pem", "cert.pem"]
        .iter()
        .map(|name| std::fs::read(a.state_directory().join(name)))
        .collect::<std::io::Result<_>>()?;
    let credentials_b: Vec<_> = ["key.pem", "cert.pem"]
        .iter()
        .map(|name| std::fs::read(b.state_directory().join(name)))
        .collect::<std::io::Result<_>>()?;
    let mut samples: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for (index, enabled) in [false, true, false].into_iter().enumerate() {
        for client in [a.client(), b.client()] {
            assert!(
                client
                    .update_general_options(
                        &GeneralOptionsPatch::default().disable_system_sleep_on_sync(enabled)
                    )
                    .await?
                    .requested_fields_match
            );
        }
        b.restart(Duration::from_secs(30)).await?;
        let address = super::configuration_policy_listener(&b).await?;
        a.client()
            .update_device(
                &bid,
                &DevicePatch::default().addresses(vec![format!("tcp://{address}")]),
            )
            .await?;
        a.restart(Duration::from_secs(30)).await?;
        super::name_policy_connection_pair(&a, &b, true).await?;
        assert_eq!(a.client().instance().device_id, aid);
        assert_eq!(b.client().instance().device_id, bid);
        assert_eq!(
            b.client()
                .general_options()
                .await?
                .disable_system_sleep_on_sync,
            enabled
        );
        let before = observe_sleep(b.process_id(), Vec::new()).await?;
        #[cfg(not(windows))]
        assert!(before.helpers.is_empty() && !before.idle_assertion);
        #[cfg(windows)]
        {
            // Older Windows can retain legacy power requests briefly after
            // they clear. Establish an actual idle baseline before new work;
            // never count a previous generation's image request as this phase.
            let _ = before;
            tokio::time::timeout(Duration::from_secs(150), async {
                loop {
                    if !observe_sleep(b.process_id(), Vec::new())
                        .await?
                        .idle_assertion
                    {
                        return TestResult::Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await??;
        }
        let name = format!("idle-sleep-二-{index}.bin");
        let bytes: Vec<u8> = (0..8 * 1024 * 1024)
            .map(|i| ((i * 73 + i / 251 + index * 41) % 251) as u8)
            .collect();
        std::fs::write(source.join(&name), &bytes)?;
        a.client().request_scan(&af.configuration.id).await?;
        let mut observed_active = false;
        let mut observed_assertion = false;
        let mut known_helpers = Vec::new();
        #[cfg(windows)]
        let mut last_native_snapshot = String::new();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let state = b.client().folder_status(&bf.configuration.id).await?.state;
                let observation = observe_sleep(b.process_id(), known_helpers.clone()).await?;
                #[cfg(windows)]
                {
                    last_native_snapshot = observation.native_snapshot.clone();
                }
                known_helpers.extend(observation.helpers.iter().copied());
                known_helpers.sort_unstable();
                known_helpers.dedup();
                if state == Some(FolderState::Syncing) {
                    observed_active = true;
                    observed_assertion |= (cfg!(windows) || !observation.helpers.is_empty())
                        && observation.idle_assertion;
                    if !enabled {
                        assert!(observation.helpers.is_empty() && !observation.idle_assertion);
                    }
                }
                if received.join(&name).is_file() && state == Some(FolderState::Idle) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            TestResult::Ok(())
        })
        .await??;
        assert!(
            observed_active,
            "a real incomplete native transfer must be observed"
        );
        #[cfg(not(windows))]
        assert_eq!(
            observed_assertion, enabled,
            "owned system idle-sleep assertion must follow policy"
        );
        #[cfg(windows)]
        assert_eq!(
            observed_assertion, enabled,
            "actual Windows request snapshot: {last_native_snapshot}"
        );
        let release_timeout = if cfg!(windows) { 150 } else { 10 };
        tokio::time::timeout(Duration::from_secs(release_timeout), async {
            loop {
                let after = observe_sleep(b.process_id(), known_helpers.clone()).await?;
                if after.helpers.is_empty() && !after.idle_assertion {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
        assert_eq!(std::fs::read(received.join(&name))?, bytes);
        samples.push((source.join(&name), bytes));
        println!(
            "native idle-sleep policy evidence: {}",
            serde_json::json!({
                "enabled":enabled,"actual_syncing_observed":true,
                "actual_system_idle_sleep_assertion_observed":observed_assertion,
                "actual_owned_system_caffeinate_observed":!known_helpers.is_empty(),
                "actual_owned_windows_private_image_system_request_observed":cfg!(windows) && observed_assertion,
                "windows_request_unique_pid_attribution_claimed":false,
                "actual_assertion_and_owned_helper_released_after_transfer":true,
                "actual_file_bytes_transferred":true,"actual_restart_preserved_policy_and_identities":true
            })
        );
    }
    for (path, bytes) in &samples {
        assert_eq!(&std::fs::read(path)?, bytes);
        assert_eq!(
            &std::fs::read(received.join(path.file_name().ok_or("sample basename absent")?))?,
            bytes
        );
    }
    assert_eq!(
        std::fs::read(sentinel)?,
        b"caller bytes across native idle-sleep policy"
    );
    for (core, before, identity) in [(&a, &before_a, &aid), (&b, &before_b, &bid)] {
        assert_eq!(&core.client().system_status().await?.device_id, identity);
        let after = core.client().configuration().await?;
        for section in ["gui", "folders", "defaults", "ldap"] {
            assert!(before.native_document()[section] == after.native_document()[section]);
        }
    }
    for (core, credentials) in [(&a, &credentials_a), (&b, &credentials_b)] {
        for (name, bytes) in ["key.pem", "cert.pem"].iter().zip(credentials) {
            assert!(
                std::fs::read(core.state_directory().join(name))? == *bytes,
                "owned native credentials changed"
            );
        }
    }
    for core in [&mut a, &mut b] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    #[cfg(windows)]
    assert_eq!(
        power_policy_before,
        super::windows_sleep_observation::powercfg("/query").await?,
        "the native option must not change the host power plan"
    );
    println!("native idle-sleep policy cleanup evidence: actual_three_transfers_and_source_receiver_bytes_retained=true actual_sentinel_and_identities_retained=true actual_both_normal_owned_tree_and_state_exit=true host_power_settings_changed=false host_suspend_attempted=false");
    Ok(())
}
