//! Pending TLS dials to one selected device, distinct from admitted connections.
use super::managed_fixture::{options, TestResult};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use verysync_sidecar::*;

#[derive(Default)]
struct Counts {
    active: usize,
    peak: usize,
    hellos: usize,
    errors: usize,
    first: Option<Instant>,
}
struct Active(Arc<Mutex<Counts>>);
impl Drop for Active {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.active -= 1;
        }
    }
}

async fn hold_client_hello(mut stream: TcpStream, counts: Arc<Mutex<Counts>>) -> TestResult {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).await?;
    if header[0] != 22 || header[1] != 3 {
        return Err("owned dial did not begin with a TLS handshake record".into());
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if !(4..=65535).contains(&length) {
        return Err("owned TLS record length outside bounded fixture".into());
    }
    let mut record = vec![0_u8; length];
    stream.read_exact(&mut record).await?;
    if record[0] != 1 {
        return Err("owned dial did not send a TLS ClientHello".into());
    }
    {
        let mut state = counts.lock().map_err(|_| "dial counter poisoned")?;
        state.active += 1;
        state.hellos += 1;
        state.peak = state.peak.max(state.active);
        state.first.get_or_insert_with(Instant::now);
    }
    let _active = Active(counts);
    // No certificate or ServerHello is sent. No native peer authenticates here.
    let mut ignored = [0_u8; 512];
    while stream.read(&mut ignored).await? != 0 {}
    Ok(())
}

struct Canaries {
    addresses: Vec<String>,
    counts: Arc<Mutex<Counts>>,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}
impl Canaries {
    async fn start() -> TestResult<Self> {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let (stop, _) = watch::channel(false);
        let mut this = Self {
            addresses: Vec::new(),
            counts,
            stop,
            tasks: Vec::new(),
        };
        for _ in 0..3 {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            assert_ne!(address.port(), 18886);
            this.addresses.push(format!("tcp://{address}"));
            let counts = this.counts.clone();
            let mut stopped = this.stop.subscribe();
            this.tasks.push(tokio::spawn(async move {
                let mut children = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = stopped.changed() => break,
                        accepted = listener.accept() => match accepted {
                            Ok((stream,_)) => {
                                let counts=counts.clone();
                                children.spawn(async move {
                                    if hold_client_hello(stream,counts.clone()).await.is_err() {
                                        if let Ok(mut state)=counts.lock() { state.errors+=1; }
                                    }
                                });
                            }
                            Err(_) => { if let Ok(mut state)=counts.lock() { state.errors+=1; } break; }
                        },
                        _ = children.join_next(), if !children.is_empty() => {}
                    }
                }
                children.abort_all();
                while children.join_next().await.is_some() {}
            }));
        }
        Ok(this)
    }
    fn snapshot(&self) -> TestResult<(usize, usize, usize, usize, Option<Duration>)> {
        let state = self.counts.lock().map_err(|_| "dial counter poisoned")?;
        Ok((
            state.active,
            state.peak,
            state.hellos,
            state.errors,
            state.first.map(|t| t.elapsed()),
        ))
    }
    async fn close(mut self) -> TestResult {
        let _ = self.stop.send(true);
        for task in self.tasks.drain(..) {
            task.await?;
        }
        assert_eq!(self.snapshot()?.0, 0);
        Ok(())
    }
}
impl Drop for Canaries {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[tokio::test]
async fn native_dial_concurrency_limits_one_device_pending_targets_and_recovers_real_transfer(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsdial-").tempdir()?.keep();
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"concurrent dial caller data")?;
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    let protected = ["key.pem", "cert.pem"];
    let original_a = protected
        .iter()
        .map(|n| std::fs::read(a.state_directory().join(n)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let original_b = protected
        .iter()
        .map(|n| std::fs::read(b.state_directory().join(n)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    a.client()
        .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(5))
        .await?;
    a.client()
        .create_device(
            &CreateDeviceOptions::new(bid.clone()).settings(
                DevicePatch::default()
                    .paused(true)
                    .addresses(vec!["dynamic".into()])
                    .allowed_transports(vec![DeviceTransport::Tcp])
                    .advanced_configuration(DeviceAdvancedPatch::default().num_connections(1))?,
            ),
        )
        .await?;
    let before = a.client().configuration().await?;
    for limit in [1_u32, 2] {
        assert!(a.client().pause_device(&bid).await?.requested_fields_match);
        let canaries = Canaries::start().await?;
        assert!(
            a.client()
                .update_device(
                    &bid,
                    &DevicePatch::default()
                        .paused(true)
                        .addresses(canaries.addresses.clone())
                )
                .await?
                .requested_fields_match
        );
        assert!(
            a.client()
                .update_general_options(&GeneralOptionsPatch::default().max_dial_concurrent(limit))
                .await?
                .requested_fields_match
        );
        a.restart(Duration::from_secs(30)).await?;
        assert_eq!(
            a.client().general_options().await?.max_dial_concurrent,
            limit
        );
        assert_eq!(
            canaries.snapshot()?.2,
            0,
            "paused peer must not dial any controlled target"
        );
        assert!(a.client().resume_device(&bid).await?.requested_fields_match);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (active, peak, _, errors, _) = canaries.snapshot()?;
                assert_eq!(errors, 0);
                assert!(
                    peak <= limit as usize,
                    "native pending dial count exceeded selected limit"
                );
                if active == limit as usize {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        // The pinned native TLS helper has a ten-second deadline. Keep the
        // controlled one-second observation inside its first handshake window.
        assert!(canaries
            .snapshot()?
            .4
            .is_some_and(|age| age < Duration::from_secs(5)));
        let began = Instant::now();
        let mut samples = 0;
        while began.elapsed() < Duration::from_secs(1) {
            let (active, peak, hellos, errors, _) = canaries.snapshot()?;
            assert_eq!(active, limit as usize);
            assert_eq!(peak, limit as usize);
            assert_eq!(hellos, limit as usize);
            assert_eq!(errors, 0);
            assert!(!a
                .client()
                .connections()
                .await?
                .connections
                .get(&bid)
                .is_some_and(|p| p.connected));
            samples += 1;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(samples > 0);
        assert!(a.client().pause_device(&bid).await?.requested_fields_match);
        a.restart(Duration::from_secs(30)).await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while canaries.snapshot()?.0 != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            TestResult::Ok(())
        })
        .await??;
        canaries.close().await?;
        println!(
            "native dial concurrency evidence: {}",
            serde_json::json!({
                "selected":limit,"actual_pending_client_hellos":limit,"controlled_targets":3,
                "actual_first_handshake_window_observed":true,"observation_samples":samples,
                "actual_peer_not_authenticated_or_connected":true,
                "actual_paused_baseline_had_no_dials":true,
                "actual_owned_restart_closed_all_pending_attempts":true,
                "actual_normal_restart_retained_policy":true,"cross_device_global_bound_claimed":false
            })
        );
    }
    b.restart(Duration::from_secs(30)).await?;
    let address = super::configuration_policy_listener(&b).await?;
    b.client()
        .create_device(
            &CreateDeviceOptions::new(aid.clone()).settings(
                DevicePatch::default()
                    .addresses(vec!["dynamic".into()])
                    .allowed_transports(vec![DeviceTransport::Tcp]),
            ),
        )
        .await?;
    a.client()
        .update_device(
            &bid,
            &DevicePatch::default()
                .paused(false)
                .addresses(vec![format!("tcp://{address}")]),
        )
        .await?;
    super::name_policy_connection_pair(&a, &b, true).await?;
    let source = root.join("source");
    let received = root.join("received");
    std::fs::create_dir(&source)?;
    let bytes: Vec<u8> = (0..32768).map(|i| (i % 251) as u8).collect();
    let name = "dial-recovery-二 %.bin";
    std::fs::write(source.join(name), &bytes)?;
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
    a.client().request_scan(&af.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        while !std::fs::read(received.join(name)).is_ok_and(|x| x == bytes) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    let after = a.client().configuration().await?;
    for key in ["gui", "defaults", "ldap"] {
        assert!(before.native_document()[key] == after.native_document()[key]);
    }
    for (core, id, original) in [(&a, &aid, &original_a), (&b, &bid, &original_b)] {
        assert_eq!(&core.client().system_status().await?.device_id, id);
        for (file, bytes) in protected.iter().zip(original) {
            assert_eq!(&std::fs::read(core.state_directory().join(file))?, bytes);
        }
    }
    assert_eq!(std::fs::read(source.join(name))?, bytes);
    assert_eq!(std::fs::read(received.join(name))?, bytes);
    assert_eq!(std::fs::read(sentinel)?, b"concurrent dial caller data");
    for core in [&mut a, &mut b] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!("native dial concurrency cleanup evidence: actual_replaced_canaries_with_owned_real_peer=true actual_authenticated_connection_and_payload_transfer=true actual_source_receiver_sentinel_identity_keys_retained=true actual_unrelated_sections_retained=true actual_both_normal_owned_tree_and_state_exit=true no_performance_or_global_cross_device_cap_claim=true");
    Ok(())
}
