//! Linux sleep locks are observed through logind and exact owned kernel images.
use super::managed_fixture::TestResult;
use std::collections::BTreeSet;

fn inhibitor_snapshot(bytes: &[u8], owned: &BTreeSet<u32>) -> TestResult<Vec<u32>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if value["type"] != "a(ssssuu)" {
        return Err("unexpected logind inhibitor signature".into());
    }
    let data = value["data"].as_array().ok_or("missing logind data")?;
    if data.len() != 1 {
        return Err("unexpected logind data fields".into());
    }
    let rows = data[0].as_array().ok_or("logind list is not an array")?;
    let mut pids = Vec::new();
    for row in rows {
        let row = row.as_array().ok_or("inhibitor row is not an array")?;
        if row.len() != 6 {
            return Err("inhibitor row length changed".into());
        }
        let what = row[0].as_str().ok_or("inhibitor what missing")?;
        let _who = row[1].as_str().ok_or("inhibitor who missing")?;
        let why = row[2].as_str().ok_or("inhibitor why missing")?;
        let mode = row[3].as_str().ok_or("inhibitor mode missing")?;
        let uid = u32::try_from(row[4].as_u64().ok_or("inhibitor uid missing")?)?;
        let pid = u32::try_from(row[5].as_u64().ok_or("inhibitor pid missing")?)?;
        if owned.contains(&pid) {
            if why != "VerysyncStayAwake"
                || mode != "block"
                || uid != 0
                || !what.split(':').any(|part| part == "sleep")
            {
                return Err("owned inhibitor differs from fixed native sleep backend".into());
            }
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

#[test]
fn inhibitor_snapshot_requires_actual_owned_native_sleep_lock() -> TestResult {
    let bytes=br#"{"type":"a(ssssuu)","data":[[["sleep","sleep","VerysyncStayAwake","block",0,17],["sleep","other","private unrelated reason","block",1000,99]]]}"#;
    assert_eq!(inhibitor_snapshot(bytes, &BTreeSet::from([17]))?, vec![17]);
    assert!(inhibitor_snapshot(bytes, &BTreeSet::from([18]))?.is_empty());
    assert!(inhibitor_snapshot(
        br#"{"type":"a(ssssuu)","data":[[]]}"#,
        &BTreeSet::from([17])
    )?
    .is_empty());
    Ok(())
}
#[test]
fn inhibitor_snapshot_refuses_missing_malformed_or_wrong_owned_lock() {
    for bytes in [
        br#"{}"#.as_slice(),
        br#"{"type":"a(ssssuu)","data":[]}"#,
        br#"{"type":"a(ssssuu)","data":[[["sleep","sleep","VerysyncStayAwake","block",0]]]}"#,
        br#"{"type":"a(ssssuu)","data":[[["idle","sleep","VerysyncStayAwake","block",0,17]]]}"#,
        br#"{"type":"a(ssssuu)","data":[[["sleep","sleep","VerysyncStayAwake","delay",0,17]]]}"#,
    ] {
        assert!(inhibitor_snapshot(bytes, &BTreeSet::from([17])).is_err());
    }
}

#[cfg(target_os = "linux")]
mod native {
    use super::super::managed_fixture::options;
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use verysync_sidecar::*;

    fn credential_bytes(core: &ManagedInstance) -> TestResult<Vec<Vec<u8>>> {
        ["key.pem", "cert.pem"]
            .iter()
            .map(|name| std::fs::read(core.state_directory().join(name)))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    struct SleepObservation {
        helpers: Vec<(u32, u64)>,
        idle_assertion: bool,
    }
    fn proc_identity(pid: u32) -> TestResult<Option<(u32, u64)>> {
        let text =
            match std::fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat")) {
                Ok(x) => x,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            };
        let (_, tail) = text
            .rsplit_once(") ")
            .ok_or("owned process stat malformed")?;
        let fields: Vec<_> = tail.split_whitespace().collect();
        Ok(Some((
            fields.get(2).ok_or("process group absent")?.parse()?,
            fields.get(19).ok_or("process birth absent")?.parse()?,
        )))
    }
    async fn observe_sleep(root: u32, known: Vec<(u32, u64)>) -> TestResult<SleepObservation> {
        tokio::task::spawn_blocking(move || {
            if !proc_identity(root)?.is_some_and(|(group, _)| group == root) {
                return Err("selected owned process group absent".into());
            }
            let expected = [
                std::fs::canonicalize("/usr/bin/systemd-inhibit")?,
                std::fs::canonicalize("/usr/bin/sleep")?,
            ];
            let mut helpers = Vec::new();
            for item in std::fs::read_dir("/proc")? {
                let item = item?;
                let Some(pid) = item
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<u32>().ok())
                else {
                    continue;
                };
                let Some((group, birth)) = proc_identity(pid)? else {
                    continue;
                };
                if group != root || pid == root {
                    continue;
                }
                let image = match std::fs::read_link(item.path().join("exe")) {
                    Ok(x) => x,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                };
                if expected.contains(&image) {
                    helpers.push((pid, birth));
                }
            }
            let mut owned = BTreeSet::from([root]);
            for (pid, birth) in helpers.iter().chain(known.iter()) {
                if let Some((group, current)) = proc_identity(*pid)? {
                    if current == *birth {
                        if group != root {
                            return Err("owned sleep helper changed process group".into());
                        }
                        owned.insert(*pid);
                    }
                }
            }
            let result = std::process::Command::new("/usr/bin/busctl")
                .args([
                    "--system",
                    "--json=short",
                    "--no-pager",
                    "--timeout=2s",
                    "call",
                    "org.freedesktop.login1",
                    "/org/freedesktop/login1",
                    "org.freedesktop.login1.Manager",
                    "ListInhibitors",
                ])
                .output()?;
            if !result.status.success() || result.stdout.len() > 4 * 1024 * 1024 {
                return Err("readonly logind inhibitor query failed".into());
            }
            let locks = inhibitor_snapshot(&result.stdout, &owned)?;
            Ok(SleepObservation {
                helpers,
                idle_assertion: !locks.is_empty(),
            })
        })
        .await?
    }
    async fn listener(core: &ManagedInstance) -> TestResult<std::net::SocketAddr> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                for status in core.client().listener_status().await?.into_values() {
                    for text in status.lan_addresses {
                        if let Some(address) = text
                            .strip_prefix("tcp://")
                            .and_then(|x| x.parse::<std::net::SocketAddr>().ok())
                            .filter(|a| {
                                a.ip() == std::net::Ipv4Addr::LOCALHOST
                                    && !matches!(a.port(), 0 | 18886)
                            })
                        {
                            return Ok::<_, Error>(address);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?
        .map_err(Into::into)
    }
    async fn connection_pair(
        a: &ManagedInstance,
        b: &ManagedInstance,
        connected: bool,
    ) -> TestResult {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let ab = a
                    .client()
                    .connections()
                    .await?
                    .connections
                    .get(&b.client().instance().device_id)
                    .is_some_and(|x| x.connected);
                let ba = b
                    .client()
                    .connections()
                    .await?
                    .connections
                    .get(&a.client().instance().device_id)
                    .is_some_and(|x| x.connected);
                if ab == connected && ba == connected {
                    return Ok::<(), Error>(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?
        .map_err(Into::into)
    }

    #[tokio::test]
    async fn privileged_native_linux_sleep_inhibitor_tracks_transfer_and_releases() -> TestResult {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        for name in [
            "VERYSYNC_TEST_ALLOW_HOST_CONFIGURATION",
            "VERYSYNC_TEST_ALLOW_SLEEP_INHIBITOR",
        ] {
            assert_eq!(
                std::env::var(name).as_deref(),
                Ok("github-actions-isolated-linux-vm")
            );
        }
        assert_eq!(
            super::super::effective_uid()?,
            0,
            "only the explicit disposable Linux VM may run this case"
        );
        let root = tempfile::Builder::new()
            .prefix("vsawake-")
            .tempdir()?
            .keep();
        let sentinel = root.join("caller-sentinel");
        std::fs::write(
            &sentinel,
            b"caller bytes across native Linux idle-sleep policy",
        )?;
        let source = root.join("source");
        let received = root.join("received");
        std::fs::create_dir(&source)?;
        let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
        let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
        let aid = a.client().instance().device_id.clone();
        let bid = b.client().instance().device_id.clone();
        for client in [a.client(), b.client()] {
            client
                .update_network_configuration(
                    &NetworkPatch::default().reconnection_interval_seconds(5),
                )
                .await?;
        }
        let address = listener(&b).await?;
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
        let credentials_a = credential_bytes(&a)?;
        let credentials_b = credential_bytes(&b)?;
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
            let address = listener(&b).await?;
            a.client()
                .update_device(
                    &bid,
                    &DevicePatch::default().addresses(vec![format!("tcp://{address}")]),
                )
                .await?;
            a.restart(Duration::from_secs(30)).await?;
            connection_pair(&a, &b, true).await?;
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
            assert!(before.helpers.is_empty() && !before.idle_assertion);
            let name = format!("idle-sleep-二-{index}.bin");
            let bytes: Vec<u8> = (0..8 * 1024 * 1024)
                .map(|i| ((i * 73 + i / 251 + index * 41) % 251) as u8)
                .collect();
            std::fs::write(source.join(&name), &bytes)?;
            a.client().request_scan(&af.configuration.id).await?;
            let mut observed_active = false;
            let mut observed_assertion = false;
            let mut known_helpers = Vec::new();
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let state = b.client().folder_status(&bf.configuration.id).await?.state;
                    let observation = observe_sleep(b.process_id(), known_helpers.clone()).await?;
                    known_helpers.extend(observation.helpers.iter().copied());
                    known_helpers.sort_unstable();
                    known_helpers.dedup();
                    if state == Some(FolderState::Syncing) {
                        observed_active = true;
                        observed_assertion |=
                            !observation.helpers.is_empty() && observation.idle_assertion;
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
            assert_eq!(
                observed_assertion, enabled,
                "owned system idle-sleep assertion must follow policy"
            );
            tokio::time::timeout(Duration::from_secs(10), async {
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
                "native Linux idle-sleep policy evidence: {}",
                serde_json::json!({
                    "enabled":enabled,"actual_syncing_observed":true,
                    "actual_system_idle_sleep_assertion_observed":observed_assertion,
                    "actual_owned_system_inhibit_helper_observed":!known_helpers.is_empty(),
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
            b"caller bytes across native Linux idle-sleep policy"
        );
        for (core, before, identity, credentials) in [
            (&a, &before_a, &aid, &credentials_a),
            (&b, &before_b, &bid, &credentials_b),
        ] {
            assert_eq!(&core.client().system_status().await?.device_id, identity);
            assert!(
                credential_bytes(core)? == *credentials,
                "owned native credentials changed"
            );
            let after = core.client().configuration().await?;
            for section in ["gui", "folders", "defaults", "ldap"] {
                assert!(before.native_document()[section] == after.native_document()[section]);
            }
        }
        for core in [&mut a, &mut b] {
            let exit = core.shutdown(Duration::from_secs(10)).await?;
            assert!(
                exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0)
            );
        }
        std::fs::remove_dir_all(root)?;
        println!("native Linux idle-sleep policy cleanup evidence: actual_three_transfers_and_source_receiver_bytes_retained=true actual_sentinel_and_identities_retained=true actual_both_normal_owned_tree_and_state_exit=true host_power_settings_changed=false host_suspend_attempted=false");
        Ok(())
    }
}
