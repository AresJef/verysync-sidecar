//! Synthetic transport evidence, separate from real-engine acceptance.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, Error, ManagementEndpoint, VersionCompatibility, VersionPolicy,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const KEY: &str = "synthetic-transport-key";
const ID: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";

#[tokio::test]
async fn transport_partial_settings_and_relay_unknown_write_are_separate_receipts() -> TestResult {
    use verysync_sidecar::{RelayServerPatch, TransportPatch};
    let options = serde_json::json!({"trackerEnabled":false,"udpEnabled":false,"udpPort":12345,"natEnabled":false,"relaysEnabled":false,"tcpPunchEnabled":false,"stunServers":[],"customRelayAddresses":[],"natLeaseMinutes":60,"natRenewalMinutes":30,"natTimeoutSeconds":10,"futureSecret":KEY});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"options":options})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply {
            status: 500,
            body: KEY.as_bytes().to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let changed = client
        .update_transport_configuration(&TransportPatch::default().udp(true))
        .await?;
    assert!(!changed.requested_fields_match && !changed.configuration.udp_enabled);
    assert_eq!(changed.configuration.extra["futureSecret"], KEY);
    assert!(!format!("{changed:?}").contains(KEY));
    let error = client
        .update_relay_server_configuration(&RelayServerPatch::default().enabled(true))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?}").contains(KEY));
    for patch in [
        TransportPatch::default(),
        TransportPatch::default().udp_port(0),
        TransportPatch::default().stun_servers(vec!["bad\naddress".into()]),
    ] {
        assert!(matches!(
            client.update_transport_configuration(&patch).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let requests = server.finish().await?;
    let patches: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(patches.len(), 2);
    assert!(patches[0].starts_with("PATCH /prefix/rest/config/options "));
    assert!(patches[1].starts_with("PATCH /prefix/rest/config/relayserver "));
    for (request, expected) in [
        (patches[0], serde_json::json!({"udpEnabled":true})),
        (patches[1], serde_json::json!({"enabled":true})),
    ] {
        let body: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").ok_or("body missing")?.1)?;
        assert_eq!(body, expected);
    }
    Ok(())
}

#[tokio::test]
async fn relay_changed_readback_is_unknown_and_probe_never_follows_changed_identity() -> TestResult
{
    use verysync_sidecar::RelayServerPatch;
    let different = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"relayServer":null})),
        Reply::json(serde_json::json!({"myID":different})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client
            .update_relay_server_configuration(&RelayServerPatch::default().enabled(false))
            .await,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    assert!(matches!(
        client.probe_relay("relay://127.0.0.1:12345/").await,
        Err(Error::IdentityMismatch { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("PATCH ")).count(),
        1
    );
    assert!(!requests.iter().any(|r| r.contains("svc/test/relay")));
    Ok(())
}

#[tokio::test]
async fn explicit_relay_probe_preserves_unknown_result_and_redacts_sensitive_url() -> TestResult {
    use verysync_sidecar::RelayProbeResult;
    let address = format!("relay://127.0.0.1:12345/?token={KEY}&id=synthetic-id");
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"result":KEY,"error":KEY,"futureSecret":KEY})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    for invalid in [
        "https://example.invalid/",
        "relay://127.0.0.1:0/",
        "relay://user:password@127.0.0.1:12345/",
        "relay://127.0.0.1:12345/#fragment",
    ] {
        assert!(matches!(
            client.probe_relay(invalid).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let probe = client.probe_relay(&address).await?;
    assert_eq!(probe.result, RelayProbeResult::Unknown(KEY.into()));
    assert_eq!(probe.error.as_deref(), Some(KEY));
    assert_eq!(probe.extra["futureSecret"], KEY);
    assert!(!format!("{probe:?}").contains(KEY));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 4);
    let target = requests[3].lines().next().ok_or("probe target missing")?;
    assert!(target.starts_with("GET /prefix/rest/svc/test/relay?relay="));
    assert!(target.contains("relay%3A%2F%2F127.0.0.1%3A12345%2F%3Ftoken%3D"));
    Ok(())
}

#[tokio::test]
async fn network_patch_preserves_partial_body_and_distinguishes_stale_readback() -> TestResult {
    use verysync_sidecar::NetworkPatch;
    let config = serde_json::json!({"options":{
        "listenAddresses":["tcp://127.0.0.1:12345"], "globalAnnounceServers":[],
        "globalAnnounceEnabled":false, "localAnnounceEnabled":false,
        "localAnnouncePort":21027,"localAnnounceMCAddr":"[ff12::8384]:21027",
        "reconnectionIntervalS":5,"futureSecret":KEY
    }});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({})),
        Reply::json(config),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .update_network_configuration(&NetworkPatch::default().global_discovery(true))
        .await?;
    assert!(!result.requested_fields_match);
    assert!(!result.configuration.global_announce_enabled);
    assert_eq!(result.configuration.extra["futureSecret"], KEY);
    assert!(!format!("{result:?}").contains(KEY));
    let requests = server.finish().await?;
    let patches: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(patches.len(), 1);
    assert!(patches[0].starts_with("PATCH /prefix/rest/config/options "));
    let body: serde_json::Value =
        serde_json::from_str(patches[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body, serde_json::json!({"globalAnnounceEnabled":true}));
    Ok(())
}

#[tokio::test]
async fn network_patch_rechecks_identity_and_never_retries_unknown_outcomes() -> TestResult {
    use verysync_sidecar::NetworkPatch;
    let different = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    for failure in ["identity", "write", "readback"] {
        let mut replies = vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
            Reply::json(serde_json::json!({"myID":ID})),
            Reply::json(serde_json::json!({"myID":if failure=="identity" {different}else{ID}})),
        ];
        if failure != "identity" {
            replies.push(Reply {
                status: if failure == "write" { 500 } else { 200 },
                body: KEY.as_bytes().to_vec(),
                headers: String::new(),
                delay: Duration::ZERO,
            });
            if failure == "readback" {
                replies.push(Reply::json(serde_json::json!({"options":null})));
            }
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .update_network_configuration(&NetworkPatch::default().global_discovery(true))
            .await
            .unwrap_err();
        if failure == "identity" {
            assert!(matches!(error, Error::IdentityMismatch { .. }));
        } else {
            assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
        }
        assert!(!format!("{error:?}").contains(KEY));
        let requests = server.finish().await?;
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("PATCH ")).count(),
            usize::from(failure != "identity")
        );
    }
    Ok(())
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn https_without_tls_is_rejected_before_network_io() -> TestResult {
    let options = ConnectOptions::new(
        ManagementEndpoint::http("https://synthetic.invalid/")?,
        ApiKey::new(KEY)?,
    );
    assert!(matches!(
        Client::connect(options).await,
        Err(Error::UnsupportedTransport { .. })
    ));
    Ok(())
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    headers: String,
    delay: Duration,
}
impl Reply {
    fn json(value: serde_json::Value) -> Self {
        Self {
            status: 200,
            body: serde_json::to_vec(&value).unwrap(),
            headers: String::new(),
            delay: Duration::ZERO,
        }
    }
}

struct ScriptedServer {
    base: String,
    task: Option<JoinHandle<TestResult<Vec<String>>>>,
}
impl ScriptedServer {
    async fn start(replies: Vec<Reply>) -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let base = format!("http://{}/prefix", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
                let mut bytes = Vec::new();
                while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                    let mut buffer = [0; 1024];
                    let count =
                        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                            .await??;
                    if count == 0 || bytes.len() + count > 16 * 1024 {
                        return Err("invalid synthetic HTTP request".into());
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let header_end = bytes
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .ok_or("missing bounded header")?
                    + 4;
                let header = std::str::from_utf8(&bytes[..header_end])?;
                let length = header
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse::<usize>())
                    .transpose()?
                    .unwrap_or(0);
                if header_end + length > 16 * 1024 {
                    return Err("synthetic request body too large".into());
                }
                while bytes.len() < header_end + length {
                    let mut buffer = [0; 1024];
                    let count =
                        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                            .await??;
                    if count == 0 {
                        return Err("synthetic body ended early".into());
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                requests.push(String::from_utf8(bytes)?);
                tokio::time::sleep(reply.delay).await;
                let head = format!(
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
                    reply.status,
                    reply.body.len(),
                    reply.headers
                );
                // A deliberate timeout may close the client before this write.
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&reply.body).await;
            }
            Ok(requests)
        });
        Ok(Self {
            base,
            task: Some(task),
        })
    }
    fn options(&self) -> verysync_sidecar::Result<ConnectOptions> {
        Ok(ConnectOptions::new(
            ManagementEndpoint::http(&self.base)?,
            ApiKey::new(KEY)?,
        ))
    }
    async fn finish(mut self) -> TestResult<Vec<String>> {
        self.task
            .take()
            .ok_or("synthetic server already joined")?
            .await?
    }
}
impl Drop for ScriptedServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn version(value: &str) -> Reply {
    Reply::json(
        serde_json::json!({"version":value,"os":"synthetic-os","arch":"synthetic-arch","vendorExtension":{"preserved":true}}),
    )
}

#[tokio::test]
async fn device_ignore_put_preserves_full_unknown_configuration_and_other_records() -> TestResult {
    use verysync_sidecar::DeviceId;
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let other = serde_json::json!({"deviceID":"CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC","time":"2025-01-01T00:00:00Z","name":"private-name","address":"private-address","futureSecret":{"preserved":7}});
    let config = serde_json::json!({"version":54,"devices":[{"deviceID":ID,"futureDeviceField":{"keep":true}}],"remoteIgnoredDevices":[other.clone()],"gui":{"apiKey":KEY},"futureSetting":{"nested":[1,false,"private-value"]}});
    let mut readback = config.clone();
    readback["remoteIgnoredDevices"].as_array_mut().ok_or("missing ignore list")?.push(serde_json::json!({"deviceID":peer.as_str(),"time":"0001-01-01T00:00:00Z","name":"","address":""}));
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(config.clone()),
        Reply::json(serde_json::Value::Null),
        Reply::json(readback),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(client.ignore_device(&peer).await?.is_ignored);
    let requests = server.finish().await?;
    let puts: Vec<_> = requests.iter().filter(|v| v.starts_with("PUT ")).collect();
    assert_eq!(puts.len(), 1);
    assert!(puts[0].starts_with("PUT /prefix/rest/config HTTP/1.1\r\n"));
    let mut body: serde_json::Value =
        serde_json::from_str(puts[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body["remoteIgnoredDevices"][0], other);
    assert_eq!(
        body["remoteIgnoredDevices"][1],
        serde_json::json!({"deviceID":peer.as_str()})
    );
    body["remoteIgnoredDevices"] = config["remoteIgnoredDevices"].clone();
    assert_eq!(body, config);
    Ok(())
}

#[tokio::test]
async fn device_ignore_failed_readback_is_unknown_and_does_not_retry_full_put() -> TestResult {
    use verysync_sidecar::DeviceId;
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let config = serde_json::json!({"devices":[{"deviceID":ID}],"remoteIgnoredDevices":[],"gui":{"apiKey":KEY}});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(config),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({"devices":[],"remoteIgnoredDevices":"malformed"})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let error = client.ignore_device(&peer).await.unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|v| v.starts_with("PUT "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn pending_route_http_and_schema_errors_are_never_empty_snapshots() -> TestResult {
    for reply in [
        Reply {
            status: 404,
            body: b"missing route".to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
        Reply::json(serde_json::json!({"folder":{"offeredBy":"malformed"}})),
    ] {
        let server = ScriptedServer::start(vec![
            version("v2.33.2"),
            Reply::json(serde_json::json!({"myID":ID})),
            reply,
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        assert!(matches!(
            client.pending_folders(None).await,
            Err(Error::Http { .. }) | Err(Error::InvalidResponse { .. })
        ));
        assert_eq!(server.finish().await?.len(), 3);
    }
    Ok(())
}

#[tokio::test]
async fn candidate_pending_device_dismissal_is_exact_and_has_no_implicit_ignore() -> TestResult {
    use verysync_sidecar::DeviceId;
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let pending = serde_json::json!({peer.as_str():{"time":"2026-01-01T00:00:00Z","name":"private pending name","address":"private.invalid:1234","futureSecret":"private future value"}});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(pending),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(client.dismiss_pending_device(&peer).await?.record_absent);
    let requests = server.finish().await?;
    let writes: Vec<_> = requests.iter().filter(|v| !v.starts_with("GET ")).collect();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].starts_with(&format!(
        "DELETE /prefix/rest/cluster/pending/devices?device={} HTTP/1.1\r\n",
        peer.as_str()
    )));
    assert!(writes[0].ends_with("\r\n\r\n"));
    // Synthetic candidate wire evidence only; no nonempty native record claim.
    Ok(())
}

#[tokio::test]
async fn persistent_folder_ignore_preserves_other_entries_and_only_patches_that_field() -> TestResult
{
    use verysync_sidecar::{DeviceId, FolderId};
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let folder = FolderId::parse("remote ?/#%")?;
    let other = serde_json::json!({"id":"other","label":"keep","time":"2025-01-01T00:00:00Z","unknown":{"preserved":7}});
    let new =
        serde_json::json!({"id":folder.as_str(),"label":"offered","time":"2026-01-01T00:00:00Z"});
    let server=ScriptedServer::start(vec![
        version("v2.33.2"),Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({folder.as_str():{"offeredBy":{peer.as_str():{"time":"2026-01-01T00:00:00Z","label":"offered","receiveEncrypted":false,"remoteEncrypted":false}}}})),
        Reply::json(serde_json::json!({"devices":[{"deviceID":peer.as_str(),"ignoredFolders":[other.clone()]}]})),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({"devices":[{"deviceID":peer.as_str(),"ignoredFolders":[other.clone(),new.clone()]}]})),
        Reply::json(serde_json::json!({})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let result = client.ignore_folder_offer(&folder, &peer).await?;
    assert!(result.is_ignored && result.pending_offer_absent);
    let requests = server.finish().await?;
    let writes: Vec<_> = requests
        .iter()
        .filter(|v| v.starts_with("PATCH "))
        .collect();
    assert_eq!(writes.len(), 1);
    let body: serde_json::Value =
        serde_json::from_str(writes[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body, serde_json::json!({"ignoredFolders":[other,new]}));
    assert!(requests
        .iter()
        .filter(|v| v.contains("pending/folders?"))
        .all(|v| v.contains(&format!("device={}", peer.as_str()))));
    Ok(())
}

#[tokio::test]
async fn device_creation_preserves_unknown_defaults_and_rejects_cloned_duplicates() -> TestResult {
    use verysync_sidecar::{CreateDeviceOptions, DeviceId, DevicePatch};
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let configured = serde_json::json!({"deviceID":peer.as_str(),"name":"Chosen peer","addresses":["dynamic"],"compression":"metadata","paused":true,"vendorDefault":{"retained":7}});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"), Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"devices":[]})),
        Reply::json(serde_json::json!({"deviceID":"","name":"Default","addresses":["dynamic"],"compression":"metadata","paused":false,"vendorDefault":{"retained":7}})),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({"devices":[configured.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"devices":[configured]})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let options = CreateDeviceOptions::new(peer.clone())
        .settings(DevicePatch::default().name("Chosen peer").paused(true));
    assert!(client.create_device(&options).await?.requested_fields_match);
    assert!(matches!(
        client.clone().create_device(&options).await,
        Err(Error::DeviceAlreadyExists { .. })
    ));
    let requests = server.finish().await?;
    let posts: Vec<_> = requests.iter().filter(|v| v.starts_with("POST ")).collect();
    assert_eq!(posts.len(), 1);
    assert!(posts[0].starts_with("POST /prefix/rest/config/devices HTTP/1.1\r\n"));
    let body: serde_json::Value =
        serde_json::from_str(posts[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body["deviceID"], peer.as_str());
    assert_eq!(body["vendorDefault"]["retained"], 7);
    assert_eq!(body["addresses"], serde_json::json!(["dynamic"]));
    Ok(())
}

#[tokio::test]
async fn device_patch_reports_stale_values_and_rejects_wrong_target_before_write() -> TestResult {
    use verysync_sidecar::{DeviceId, DevicePatch};
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let configured = serde_json::json!({"deviceID":peer.as_str(),"name":"Old","addresses":["dynamic"],"compression":"metadata","paused":false});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"devices":[configured.clone()]})),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({"devices":[configured]})),
        Reply::json(serde_json::json!({"myID":peer.as_str()})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(
        !client
            .update_device(&peer, &DevicePatch::default().name("New"))
            .await?
            .requested_fields_match
    );
    assert!(matches!(
        client.remove_device(&peer).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert!(matches!(
        client.remove_device(&DeviceId::parse(ID)?).await,
        Err(Error::LocalDeviceProtected)
    ));
    let requests = server.finish().await?;
    let patches: Vec<_> = requests
        .iter()
        .filter(|v| v.starts_with("PATCH "))
        .collect();
    assert_eq!(patches.len(), 1);
    assert!(patches[0].starts_with(&format!(
        "PATCH /prefix/rest/config/devices/{} HTTP/1.1\r\n",
        peer.as_str()
    )));
    let body: serde_json::Value =
        serde_json::from_str(patches[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body, serde_json::json!({"name":"New"}));
    assert!(!requests.iter().any(|v| v.starts_with("DELETE ")));
    Ok(())
}

#[tokio::test]
async fn device_delete_readback_failure_is_unknown_without_retry_or_file_flags() -> TestResult {
    use verysync_sidecar::DeviceId;
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let configured = serde_json::json!({"deviceID":peer.as_str(),"name":"Peer","addresses":["dynamic"],"compression":"metadata","paused":false});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"devices":[configured]})),
        Reply::json(serde_json::Value::Null),
        Reply::json(
            serde_json::json!({"devices":[],"folders":[{"id":"sample","devices":"malformed"}]}),
        ),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(
        matches!(client.remove_device(&peer).await,Err(Error::MutationOutcomeUnknown { source,.. }) if matches!(*source,Error::InvalidResponse { .. }))
    );
    let requests = server.finish().await?;
    let deletes: Vec<_> = requests
        .iter()
        .filter(|v| v.starts_with("DELETE "))
        .collect();
    assert_eq!(deletes.len(), 1);
    assert!(deletes[0].starts_with(&format!(
        "DELETE /prefix/rest/config/devices/{} HTTP/1.1\r\n",
        peer.as_str()
    )));
    assert!(deletes[0].ends_with("\r\n\r\n"));
    assert!(!deletes[0].to_ascii_lowercase().contains("content-type:"));
    Ok(())
}

#[tokio::test]
async fn unverified_version_requires_explicit_policy_and_retains_unknown_metadata() -> TestResult {
    let server = ScriptedServer::start(vec![version("v99.0.0")]).await?;
    let error = Client::connect(server.options()?).await.unwrap_err();
    assert!(matches!(error, Error::IncompatibleVersion { actual } if actual == "v99.0.0"));
    assert_eq!(server.finish().await?.len(), 1);

    let server = ScriptedServer::start(vec![
        version("v99.0.0"),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(
        server
            .options()?
            .version_policy(VersionPolicy::AllowUnverified),
    )
    .await?;
    assert_eq!(
        client.instance().compatibility,
        VersionCompatibility::Unverified
    );
    assert_eq!(
        client.instance().version.extra["vendorExtension"]["preserved"],
        true
    );
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /prefix/rest/system/version HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("GET /prefix/rest/system/status HTTP/1.1\r\n"));
    assert!(requests.iter().all(|request| request
        .to_ascii_lowercase()
        .contains(&format!("x-api-key: {KEY}\r\n"))));
    Ok(())
}

#[tokio::test]
async fn reflected_credentials_are_redacted_in_version_errors_and_client_debug() -> TestResult {
    let reflected = format!("v99.0.0+{KEY}");
    let server = ScriptedServer::start(vec![version(&reflected)]).await?;
    let error = Client::connect(server.options()?).await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    server.finish().await?;

    let server = ScriptedServer::start(vec![
        version(&reflected),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(
        server
            .options()?
            .version_policy(VersionPolicy::AllowUnverified),
    )
    .await?;
    assert!(!format!("{client:?}").contains(KEY));
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn redirects_are_not_followed_and_response_diagnostics_are_not_logged() -> TestResult {
    let destination = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    destination.set_nonblocking(true)?;
    let redirect = Reply {
        status: 302,
        body: KEY.as_bytes().to_vec(),
        headers: format!(
            "Location: http://{}/owned-redirect-target\r\n",
            destination.local_addr()?
        ),
        delay: Duration::ZERO,
    };
    let server = ScriptedServer::start(vec![redirect]).await?;
    let error = Client::connect(server.options()?).await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    match error {
        Error::Http { response } => {
            assert_eq!(response.status(), 302);
            assert_eq!(response.body_bytes(), KEY.as_bytes());
        }
        other => return Err(format!("unexpected synthetic redirect result: {other}").into()),
    }
    assert_eq!(
        destination.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(server.finish().await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn malformed_metadata_or_identity_is_not_a_successful_connection() -> TestResult {
    for body in [
        serde_json::json!({}),
        serde_json::json!({"version":"","os":"linux","arch":"amd64"}),
    ] {
        let server = ScriptedServer::start(vec![Reply::json(body)]).await?;
        assert!(matches!(
            Client::connect(server.options()?).await,
            Err(Error::InvalidResponse {
                operation: "read version",
                ..
            })
        ));
        server.finish().await?;
    }
    let server = ScriptedServer::start(vec![
        version(verysync_sidecar::BASELINE_ENGINE_VERSION),
        Reply::json(serde_json::json!({"myID":"invalid-identity"})),
    ])
    .await?;
    assert!(matches!(
        Client::connect(server.options()?).await,
        Err(Error::InvalidResponse {
            operation: "read identity",
            ..
        })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn management_reads_enforce_response_size_and_deadlines() -> TestResult {
    let mut large = version(verysync_sidecar::BASELINE_ENGINE_VERSION);
    large.body = vec![b'x'; 1024];
    let server = ScriptedServer::start(vec![large]).await?;
    assert!(matches!(
        Client::connect(server.options()?.response_limit(64)?).await,
        Err(Error::ResponseTooLarge { limit: 64 })
    ));
    server.finish().await?;

    let mut delayed = version(verysync_sidecar::BASELINE_ENGINE_VERSION);
    delayed.delay = Duration::from_secs(2);
    let server = ScriptedServer::start(vec![delayed]).await?;
    assert!(matches!(
        Client::connect(server.options()?.request_timeout(Duration::from_secs(1))?).await,
        Err(Error::Timeout {
            operation: "read version"
        })
    ));
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn status_reads_are_fresh_preserve_unknowns_and_encode_folder_ids() -> TestResult {
    use verysync_sidecar::{FolderId, FolderState};
    let server=ScriptedServer::start(vec![
        version(verysync_sidecar::BASELINE_ENGINE_VERSION),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"synthetic-os","arch":"synthetic-arch","freshVendor":true})),
        Reply::json(serde_json::json!({"myID":ID,"vendorStatus":{"value":"sensitive-vendor-status"}})),
        Reply::json(serde_json::json!({"myID":ID,"uptime":7,"alloc":0,"cpuPercent":0,"goroutines":4})),
        Reply::json(serde_json::json!({"state":"future-hashing","localBytes":5,"vendorFolder":{"retained":true}})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let fresh_version = client.version().await?;
    assert_eq!(fresh_version.extra["freshVendor"], true);
    assert!(!client.instance().version.extra.contains_key("freshVendor"));
    let unknown = client.system_status().await?;
    assert_eq!(unknown.device_id.as_str(), ID);
    assert_eq!(unknown.uptime_seconds, None);
    assert_eq!(unknown.memory_allocated_bytes, None);
    assert_eq!(unknown.cpu_percent, None);
    assert_eq!(
        unknown.extra["vendorStatus"]["value"],
        "sensitive-vendor-status"
    );
    assert!(!format!("{unknown:?}").contains("sensitive-vendor-status"));
    let reported_zero = client.system_status().await?;
    assert_eq!(reported_zero.uptime_seconds, Some(7));
    assert_eq!(reported_zero.memory_allocated_bytes, Some(0));
    assert_eq!(reported_zero.cpu_percent, Some(0.0));
    let id = FolderId::parse("folder /?&中文")?;
    let status = client.folder_status(&id).await?;
    assert_eq!(
        status.state,
        Some(FolderState::Unknown("future-hashing".to_owned()))
    );
    assert_eq!(status.local_bytes, Some(5));
    assert_eq!(status.need_bytes, None);
    assert_eq!(status.extra["vendorFolder"]["retained"], true);
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 6);
    let path = requests[5].lines().next().ok_or("missing request line")?;
    assert!(path.starts_with("GET /prefix/rest/db/status?folder="));
    assert!(path.contains("folder+%2F%3F%26%E4%B8%AD%E6%96%87"));
    Ok(())
}

#[tokio::test]
async fn fresh_status_rejects_invalid_metrics_and_changed_identity() -> TestResult {
    let other = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        version(verysync_sidecar::BASELINE_ENGINE_VERSION),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID,"alloc":-1})),
        Reply::json(serde_json::json!({"myID":other,"uptime":9})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.system_status().await,
        Err(Error::InvalidResponse { .. })
    ));
    assert!(matches!(
        client.system_status().await,
        Err(Error::IdentityMismatch { .. })
    ));
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn create_folder_preserves_defaults_and_never_posts_over_an_existing_id() -> TestResult {
    use verysync_sidecar::{CreateFolderOptions, FolderId, PathStyle, TargetPath};
    let configured = serde_json::json!({"id":"test-folder","label":"New label","path":"/synthetic/folder","paused":true,"vendorDefault":{"retained":7},"secret":"sensitive-folder-secret"});
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[]})),
        Reply::json(serde_json::json!({"id":"","path":"","label":"Default","paused":false,"vendorDefault":{"retained":7},"secret":"sensitive-folder-secret"})),
        Reply { status:200,body:vec![],headers:String::new(),delay:Duration::ZERO },
        Reply::json(serde_json::json!({"folders":[configured.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[configured]})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let options = CreateFolderOptions::new(
        FolderId::parse("test-folder")?,
        TargetPath::remote(PathStyle::Unix, "/synthetic/folder")?,
    )
    .label("New label")
    .paused(true);
    let created = client.create_folder(&options).await?;
    assert_eq!(created.id, *options.id());
    assert_eq!(created.extra["vendorDefault"]["retained"], 7);
    assert!(!format!("{created:?}").contains("sensitive-folder-secret"));
    assert!(matches!(
        client.create_folder(&options).await,
        Err(Error::FolderAlreadyExists { .. })
    ));
    let requests = server.finish().await?;
    let posts: Vec<_> = requests
        .iter()
        .filter(|request| request.starts_with("POST "))
        .collect();
    assert_eq!(posts.len(), 1);
    let body: serde_json::Value =
        serde_json::from_str(posts[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body["label"], "New label");
    assert_eq!(body["paused"], true);
    assert_eq!(body["vendorDefault"]["retained"], 7);
    assert_eq!(body["secret"], "sensitive-folder-secret");
    Ok(())
}

#[tokio::test]
async fn modifying_request_failure_has_an_explicit_unknown_outcome_without_retry() -> TestResult {
    use verysync_sidecar::{CreateFolderOptions, FolderId, PathStyle, TargetPath};
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[]})),
        Reply::json(serde_json::json!({"vendorDefault":true})),
        Reply {
            status: 500,
            body: KEY.as_bytes().to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let options = CreateFolderOptions::new(
        FolderId::parse("uncertain-folder")?,
        TargetPath::remote(PathStyle::Unix, "/synthetic/uncertain")?,
    );
    let error = client.create_folder(&options).await.unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?}").contains(KEY));
    assert!(!error.to_string().contains(KEY));
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|request| request.starts_with("POST "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn folder_update_sends_only_requested_fields_and_reports_stale_readback() -> TestResult {
    use verysync_sidecar::{FolderId, FolderPatch};
    let id = FolderId::parse("folder 中文 /?#%")?;
    let before = serde_json::json!({"id":id.as_str(),"label":"Before","path":"/synthetic","paused":false,"unknown":{"keep":[1,2]},"secret":"synthetic-folder-key"});
    let mut after = before.clone();
    after["label"] = serde_json::json!("After");
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[before]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[after.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[after.clone()]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[after]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .update_folder(&id, &FolderPatch::default().label("After"))
        .await?;
    assert!(result.requested_fields_match);
    assert_eq!(
        result.configuration.extra["unknown"]["keep"],
        serde_json::json!([1, 2])
    );
    assert!(!format!("{result:?}").contains("synthetic-folder-key"));
    let pending = client.pause_folder(&id).await?;
    assert!(!pending.requested_fields_match);
    assert!(!pending.configuration.paused);
    assert!(matches!(
        client.resume_folder(&id).await,
        Err(Error::FolderNotFound { .. })
    ));
    assert!(matches!(
        client.update_folder(&id, &FolderPatch::default()).await,
        Err(Error::InvalidConfiguration { .. })
    ));
    for unsafe_segment in [".", ".."] {
        assert!(matches!(
            client.pause_folder(&FolderId::parse(unsafe_segment)?).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let requests = server.finish().await?;
    let patches: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(patches.len(), 2);
    let target = patches[0].lines().next().ok_or("missing request target")?;
    assert!(target.starts_with("PATCH /prefix/rest/config/folders/folder%20"));
    assert!(target.contains("%2F%3F%23%25"));
    let body = |r: &str| -> TestResult<serde_json::Value> {
        Ok(serde_json::from_str(
            r.split_once("\r\n\r\n").ok_or("missing body")?.1,
        )?)
    };
    assert_eq!(body(patches[0])?, serde_json::json!({"label":"After"}));
    assert_eq!(body(patches[1])?, serde_json::json!({"paused":true}));
    Ok(())
}

#[tokio::test]
async fn folder_remove_keep_files_checks_identity_existence_and_absence_readback() -> TestResult {
    use verysync_sidecar::FolderId;
    let id = FolderId::parse("remove 中文?#%")?;
    let other = serde_json::json!({"id":"other","label":"Retained","path":"/synthetic/other","paused":true});
    let target = serde_json::json!({"id":id.as_str(),"label":"Target","path":"/synthetic/target","paused":false,"unknown":{"keep":7}});
    let different = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[target,other.clone()]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[other.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[other]})),
        Reply::json(serde_json::json!({"myID":different})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let removed = client.remove_folder_keep_files(&id).await?;
    assert!(removed.configuration_absent);
    assert_eq!(removed.previous_configuration.id, id);
    assert_eq!(removed.previous_configuration.extra["unknown"]["keep"], 7);
    assert!(matches!(
        client.remove_folder_keep_files(&id).await,
        Err(Error::FolderNotFound { .. })
    ));
    assert!(matches!(
        client
            .remove_folder_keep_files(&FolderId::parse("other")?)
            .await,
        Err(Error::IdentityMismatch { .. })
    ));
    let requests = server.finish().await?;
    let deletes: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("DELETE "))
        .collect();
    assert_eq!(deletes.len(), 1);
    let line = deletes[0].lines().next().ok_or("missing target")?;
    assert!(line.starts_with("DELETE /prefix/rest/config/folders/remove%20"));
    assert!(line.contains("%3F%23%25"));
    assert!(!line.contains('?'));
    assert_eq!(
        deletes[0]
            .split_once("\r\n\r\n")
            .ok_or("missing body boundary")?
            .1,
        ""
    );
    Ok(())
}

#[tokio::test]
async fn unregister_acknowledgment_does_not_invent_absence_when_id_is_still_visible() -> TestResult
{
    let target = serde_json::json!({"id":"still-visible","label":"Concurrent writer","path":"/synthetic","paused":true});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[target.clone()]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[target]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .remove_folder_keep_files(&verysync_sidecar::FolderId::parse("still-visible")?)
        .await?;
    assert!(!result.configuration_absent);
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|r| r.starts_with("DELETE "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn error_contract_distinguishes_authentication_forbidden_and_body_failure() -> TestResult {
    for status in [401, 403] {
        let server = ScriptedServer::start(vec![Reply {
            status,
            body: KEY.as_bytes().to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        }])
        .await?;
        let error = Client::connect(server.options()?).await.unwrap_err();
        assert!(!format!("{error:?} {error}").contains(KEY));
        match (status, error) {
            (401, Error::Authentication { status: 401 }) => (),
            (403, Error::AccessDenied { response }) => {
                assert_eq!(response.status(), 403);
                assert_eq!(response.body_bytes(), KEY.as_bytes());
            }
            _ => return Err("access denial classification was incorrect".into()),
        }
        server.finish().await?;
    }
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"error":KEY})),
        Reply::json(
            serde_json::json!({"state":"error","error":"legitimate status detail","localFiles":0}),
        ),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let id = verysync_sidecar::FolderId::parse("synthetic-error-folder")?;
    let error = client.folder_status(&id).await.unwrap_err();
    assert!(matches!(error, Error::Api { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    let status = client.folder_status(&id).await?;
    assert_eq!(status.state, Some(verysync_sidecar::FolderState::Error));
    assert_eq!(status.extra["error"], "legitimate status detail");
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn body_deadline_and_post_write_readback_failure_are_not_success_or_retry() -> TestResult {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let base = format!("http://{}/", listener.local_addr()?);
    let task = tokio::spawn(async move {
        let (mut stream, _) =
            tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
        let mut request = [0; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut request)).await??;
        stream
            .write_all(b"HTTP/1.1 200 Test\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{")
            .await?;
        let mut tail = [0; 1];
        let closed =
            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tail)).await?? == 0;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(closed)
    });
    let options = ConnectOptions::new(ManagementEndpoint::http(&base)?, ApiKey::new(KEY)?)
        .request_timeout(Duration::from_secs(1))?;
    assert!(matches!(
        Client::connect(options).await,
        Err(Error::Timeout { .. })
    ));
    assert!(task.await??, "timed-out response connection must close");

    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[]})),
        Reply::json(serde_json::json!({"vendorDefault":true})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"unexpected":"instead of folders"})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let options = verysync_sidecar::CreateFolderOptions::new(
        verysync_sidecar::FolderId::parse("uncertain-readback")?,
        verysync_sidecar::TargetPath::remote(
            verysync_sidecar::PathStyle::Unix,
            "/synthetic/readback",
        )?,
    );
    assert!(
        matches!(client.create_folder(&options).await,Err(Error::MutationOutcomeUnknown { source,.. }) if matches!(*source,Error::InvalidResponse{..}))
    );
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|r| r.starts_with("POST "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn raw_request_preserves_error_binary_headers_and_selected_origin() -> TestResult {
    use verysync_sidecar::{RawMethod, RawRequest, RequestEffect};
    let destination = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    destination.set_nonblocking(true)?;
    let mut binary = vec![0, 255, 1];
    binary.extend_from_slice(KEY.as_bytes());
    let location = format!("http://{}/must-not-receive-key", destination.local_addr()?);
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply {
            status: 418,
            body: binary.clone(),
            headers: format!("X-Vendor: one\r\nX-Vendor: {KEY}\r\n"),
            delay: Duration::ZERO,
        },
        Reply {
            status: 302,
            body: Vec::new(),
            headers: format!("Location: {location}\r\n"),
            delay: Duration::ZERO,
        },
        Reply::json(serde_json::json!({"error":KEY})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let request = RawRequest::new(
        RawMethod::Get,
        ["rest", "https://synthetic.invalid", "../slash"],
        RequestEffect::ReadOnly,
    )?
    .query("name", "/ ?#%中文")
    .header("X-Business", "synthetic-business-value")?
    .body(b"explicit synthetic body".to_vec());
    let raw = client.raw_request(&request).await?;
    assert_eq!(raw.status(), 418);
    assert_eq!(raw.body_bytes(), binary);
    assert_eq!(
        raw.headers()
            .filter(|(name, _)| *name == "x-vendor")
            .count(),
        2
    );
    assert!(!format!("{raw:?}").contains(KEY));
    let redirect = client
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "redirect"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(redirect.status(), 302);
    assert!(redirect
        .headers()
        .any(|(name, value)| name == "location" && value == location.as_bytes()));
    assert_eq!(
        destination.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let body_error = client
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "unmodeled"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(body_error.status(), 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(body_error.body_bytes())?["error"],
        KEY
    );
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 5);
    let first = &requests[2];
    let target = first.lines().next().ok_or("missing raw target")?;
    assert!(target.starts_with("GET /prefix/rest/https:%2F%2Fsynthetic.invalid/..%2Fslash?name="));
    assert!(target.contains("%23%25%E4%B8%AD%E6%96%87"));
    assert!(first
        .to_ascii_lowercase()
        .contains(&format!("x-api-key: {KEY}\r\n")));
    assert!(first.ends_with("explicit synthetic body"));
    Ok(())
}

#[tokio::test]
async fn raw_state_changing_get_requires_fresh_identity_before_sending() -> TestResult {
    use verysync_sidecar::{RawMethod, RawRequest, RequestEffect};
    let different = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":different})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let request = RawRequest::new(
        RawMethod::Get,
        ["rest", "account", "logout"],
        RequestEffect::MayModify,
    )?;
    assert!(matches!(
        client.raw_request(&request).await,
        Err(Error::IdentityMismatch { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 3);
    assert!(!requests
        .iter()
        .any(|request| request.contains("account/logout")));
    Ok(())
}

#[tokio::test]
async fn capabilities_report_is_a_snapshot_without_optional_feature_probes() -> TestResult {
    use verysync_sidecar::{InstanceObservation, TargetValidation};
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"arm64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let report = client.capabilities();
    assert_eq!(report.target.engine_os, "linux");
    assert_eq!(report.target.engine_arch, "arm64");
    assert_eq!(
        report.target_validation,
        TargetValidation::OutsideNativeEvidence
    );
    assert_eq!(
        report.instance.authentication,
        InstanceObservation::ObservedAtHandshake
    );
    assert_eq!(
        report.instance.commercial_license,
        InstanceObservation::Unknown
    );
    assert_eq!(
        report.instance.operation_authorization,
        InstanceObservation::Unknown
    );
    assert!(!format!("{report:?}").contains(KEY));
    assert_eq!(
        server.finish().await?.len(),
        2,
        "report must not add management or license probes"
    );
    Ok(())
}
