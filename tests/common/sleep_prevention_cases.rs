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
    #[cfg(windows)]
    requests_by_role: [bool; 2],
    #[cfg(windows)]
    native_read_elapsed_ms: u128,
}

#[cfg(windows)]
struct WindowsSleepTrace {
    phase: &'static str,
    selected: bool,
    root_pid: u32,
    started: std::time::Instant,
    reads: u64,
    maximum_read_ms: u128,
    states: Vec<String>,
    snapshot: String,
    requests_by_role: [bool; 2],
}

#[cfg(windows)]
impl WindowsSleepTrace {
    fn new(selected: bool, root_pid: u32) -> Self {
        Self {
            phase: "idle-baseline",
            selected,
            root_pid,
            started: std::time::Instant::now(),
            reads: 0,
            maximum_read_ms: 0,
            states: Vec::new(),
            snapshot: String::new(),
            requests_by_role: [false; 2],
        }
    }

    fn details(&self) -> serde_json::Value {
        serde_json::json!({
            "phase":self.phase,"selected":self.selected,"owned_root_pid":self.root_pid,
            "elapsed_ms":self.started.elapsed().as_millis(),"native_reads":self.reads,
            "maximum_native_read_ms":self.maximum_read_ms,"observed_states":self.states,
            "last_native_snapshot":self.snapshot,"sender_image_request":self.requests_by_role[0],
            "receiver_image_request":self.requests_by_role[1]
        })
    }

    fn phase(&mut self, phase: &'static str) {
        self.phase = phase;
        println!("native Windows sleep diagnostic: {}", self.details());
    }

    fn observe(&mut self, observation: &SleepObservation, state: Option<&FolderState>) {
        self.reads += 1;
        self.maximum_read_ms = self.maximum_read_ms.max(observation.native_read_elapsed_ms);
        self.snapshot.clone_from(&observation.native_snapshot);
        self.requests_by_role = observation.requests_by_role;
        if let Some(state) = state {
            let state = format!("{state:?}");
            if self.states.last() != Some(&state) && self.states.len() < 16 {
                self.states.push(state);
            }
        }
    }

    fn finish(
        &self,
        outcome: std::result::Result<TestResult, tokio::time::error::Elapsed>,
    ) -> TestResult {
        outcome.map_err(|_| format!("native Windows sleep deadline expired: {}", self.details()))?
    }
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
async fn observe_sleep(
    _sender: &ManagedInstance,
    receiver: &ManagedInstance,
    known_helpers: Vec<u32>,
) -> TestResult<SleepObservation> {
    let root = receiver.process_id();
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
async fn observe_sleep(
    sender: &ManagedInstance,
    receiver: &ManagedInstance,
    _known_helpers: Vec<u32>,
) -> TestResult<SleepObservation> {
    let started = std::time::Instant::now();
    let images = sleep_role_images(sender, receiver)?;
    let (requests_by_role, native_snapshot) =
        super::windows_sleep_observation::observe_distinct_images(&images).await?;
    Ok(SleepObservation {
        helpers: Vec::new(),
        idle_assertion: requests_by_role.into_iter().any(|active| active),
        native_snapshot,
        requests_by_role,
        native_read_elapsed_ms: started.elapsed().as_millis(),
    })
}

#[cfg(windows)]
fn sleep_role_images(
    sender: &ManagedInstance,
    receiver: &ManagedInstance,
) -> TestResult<[String; 2]> {
    let image = |core: &ManagedInstance| {
        super::windows_sleep_observation::owned_native_image(
            core.process_id(),
            core.selected_program().path(),
        )
    };
    Ok([image(sender)?, image(receiver)?])
}

#[cfg(windows)]
fn copy_sleep_role_program(root: &std::path::Path, state: &str) -> TestResult<ManagedOptions> {
    let base = options(&root.join(state))?;
    let original = std::fs::read(base.program().path())?;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&original);
    let expected = std::env::var("VERYSYNC_TEST_BINARY_SHA256")?;
    if format!("{digest:x}") != expected {
        return Err("fixed program digest differs before role-specific copy".into());
    }
    let program = root.join(state).with_extension("exe");
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&program)?
        .write_all(&original)?;
    Ok(ManagedOptions::new(
        LocalProgram::new(program)?.expected_sha256(digest.into()),
        base.state_directory(),
        base.management_endpoint().clone(),
    )?
    .startup_timeout(Duration::from_secs(25))?)
}

#[cfg(windows)]
async fn confirm_sleep_role_cleanup(program: &std::path::Path) -> TestResult {
    let program = program.to_owned();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("python")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("scripts")
                    .join("prepare-test-engine.py"),
            )
            .arg("check-cleanup")
            .env("VERYSYNC_TEST_BINARY", program)
            .output()
    })
    .await??;
    if !output.status.success() {
        return Err("exact role-specific executable cleanup did not pass".into());
    }
    Ok(())
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
    #[cfg(windows)]
    let (a_options, b_options) = (
        copy_sleep_role_program(&root, "a")?,
        copy_sleep_role_program(&root, "b")?,
    );
    #[cfg(not(windows))]
    let (a_options, b_options) = (options(&root.join("a"))?, options(&root.join("b"))?);
    let mut a = ManagedInstance::start(a_options.clone()).await?;
    let mut b = ManagedInstance::start(b_options.clone()).await?;
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
        #[cfg(windows)]
        let mut trace = WindowsSleepTrace::new(enabled, b.process_id());
        let before = observe_sleep(&a, &b, Vec::new()).await?;
        #[cfg(not(windows))]
        assert!(before.helpers.is_empty() && !before.idle_assertion);
        #[cfg(windows)]
        {
            // Older Windows can retain legacy power requests briefly after
            // they clear. Establish an actual idle baseline before new work;
            // never count a previous generation's image request as this phase.
            trace.observe(&before, None);
            trace.phase("idle-baseline");
            let outcome = tokio::time::timeout(Duration::from_secs(150), async {
                loop {
                    let observation = observe_sleep(&a, &b, Vec::new()).await?;
                    trace.observe(&observation, None);
                    if !observation.idle_assertion {
                        return TestResult::Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await;
            trace.finish(outcome)?;
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
        trace.phase("transfer-observation");
        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let state = b.client().folder_status(&bf.configuration.id).await?.state;
                let observation = observe_sleep(&a, &b, known_helpers.clone()).await?;
                #[cfg(windows)]
                {
                    trace.observe(&observation, state.as_ref());
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
        .await;
        #[cfg(windows)]
        trace.finish(outcome)?;
        #[cfg(not(windows))]
        outcome??;
        #[cfg(not(windows))]
        assert!(
            observed_active,
            "a real incomplete native transfer must be observed"
        );
        #[cfg(windows)]
        assert!(
            observed_active,
            "a real incomplete native transfer must be observed: {}",
            trace.details()
        );
        #[cfg(not(windows))]
        assert_eq!(
            observed_assertion, enabled,
            "owned system idle-sleep assertion must follow policy"
        );
        #[cfg(windows)]
        assert_eq!(
            observed_assertion,
            enabled,
            "actual Windows request snapshot: {}",
            trace.details()
        );
        let release_timeout = if cfg!(windows) { 150 } else { 10 };
        #[cfg(windows)]
        trace.phase("request-release");
        let outcome = tokio::time::timeout(Duration::from_secs(release_timeout), async {
            loop {
                let after = observe_sleep(&a, &b, known_helpers.clone()).await?;
                #[cfg(windows)]
                trace.observe(&after, None);
                if after.helpers.is_empty() && !after.idle_assertion {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        #[cfg(windows)]
        let retained_after_idle = if outcome.is_err()
            && enabled
            && super::windows_sleep_observation::known_retained_request_boundary(
                &a.program_info().version,
                std::env::consts::ARCH,
                &std::env::var("VERYSYNC_TEST_BINARY_SHA256")?,
            )
            && a.program_info().version == b.program_info().version
        {
            // R18-U05: retain the original failed automatic-release window.
            // Never waive an inner I/O/parser error, a false-policy request,
            // unknown program or missing transfer/identity/normal-exit evidence.
            let still = observe_sleep(&a, &b, known_helpers.clone()).await?;
            trace.observe(&still, None);
            assert!(
                still.idle_assertion,
                "retained request boundary not observed after original timeout"
            );
            let expected = u64::try_from(index + 1)?;
            for (core, folder) in [(&a, &af.configuration.id), (&b, &bf.configuration.id)] {
                let status = core.client().folder_status(folder).await?;
                assert_eq!(status.state, Some(FolderState::Idle));
                assert_eq!(status.local_files, Some(expected));
                assert_eq!(status.global_files, Some(expected));
                assert_eq!(status.local_bytes, Some(expected * 8 * 1024 * 1024));
                assert_eq!(status.global_bytes, Some(expected * 8 * 1024 * 1024));
                assert_eq!(status.need_bytes, Some(0));
            }
            assert_eq!(std::fs::read(source.join(&name))?, bytes);
            assert_eq!(std::fs::read(received.join(&name))?, bytes);
            let images = sleep_role_images(&a, &b)?;
            trace.phase("retained-after-original-150s-idle-window");
            for core in [&a, &b] {
                assert!(
                    core.client()
                        .update_general_options(
                            &GeneralOptionsPatch::default().disable_system_sleep_on_sync(false)
                        )
                        .await?
                        .requested_fields_match
                );
            }
            for core in [&mut a, &mut b] {
                let exit = core.shutdown(Duration::from_secs(10)).await?;
                assert!(
                    exit.tree_stopped
                        && exit.state_released
                        && !exit.forced
                        && exit.code == Some(0)
                );
            }
            // Resolve each private image while its owned PID is alive. After
            // both normal exits, inspect only those two recorded images.
            tokio::time::timeout(Duration::from_secs(150), async {
                loop {
                    let (requests_by_role, snapshot) =
                        super::windows_sleep_observation::observe_distinct_images(&images).await?;
                    trace.snapshot = snapshot;
                    trace.requests_by_role = requests_by_role;
                    if requests_by_role == [false; 2] {
                        return TestResult::Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await??;
            a = ManagedInstance::start(a_options.clone()).await?;
            b = ManagedInstance::start(b_options.clone()).await?;
            assert_eq!(a.client().instance().device_id, aid);
            assert_eq!(b.client().instance().device_id, bid);
            for core in [&a, &b] {
                assert!(
                    !core
                        .client()
                        .general_options()
                        .await?
                        .disable_system_sleep_on_sync
                );
            }
            // The final false phase below reconnects the fresh listener and
            // independently requires real transfer without a sleep request.
            true
        } else {
            trace.finish(outcome)?;
            false
        };
        #[cfg(not(windows))]
        let retained_after_idle = false;

        #[cfg(not(windows))]
        outcome??;
        #[cfg(windows)]
        trace.phase(if retained_after_idle {
            "verified-normal-stop-release-and-persisted-restart"
        } else {
            "verified-automatic-release"
        });
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
                "actual_assertion_and_owned_helper_released_after_transfer":!retained_after_idle,
                "native_request_retained_past_original_150s_idle_window":retained_after_idle,
                "actual_explicit_disable_normal_stop_cleared_request":retained_after_idle,
                "actual_persisted_restart_after_explicit_stop":retained_after_idle,
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
    #[cfg(windows)]
    {
        for options in [&a_options, &b_options] {
            confirm_sleep_role_cleanup(options.program().path()).await?;
        }
        println!("native_sleep_distinct_images_gone=true");
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
