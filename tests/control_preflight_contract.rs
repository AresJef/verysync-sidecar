//! Independently witness the methods, routes and scopes of operation preflights.
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
    task::JoinHandle,
};
use verysync_sidecar::{
    ApiKey, BuildVariant, Client, ConnectOptions, Error, FolderId, LocalApiClient,
    LocalApiConnectOptions, ManagementEndpoint, PinnedVersion, PreflightLicense,
    PreflightReadAccess, PreflightReads, ProgramArchitecture, ProgramOs, ProgramTarget,
    UpgradePreflightSource, UpgradeSourceEvidence, VersionCompatibility, VersionPolicy,
};

const DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const REPLACEMENT: &str = "BAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const KEY: &str = "preflight-fixture-key";

type Reply = (&'static str, u16, String);

fn response(path: &'static str, status: u16, json: serde_json::Value) -> Reply {
    (path, status, json.to_string())
}

fn version(path: &'static str, version: &str, os: &str, arch: &str) -> Reply {
    response(path, 200, json!({"version":version, "os":os, "arch":arch}))
}

fn identity(path: &'static str, id: &str) -> Reply {
    response(path, 200, json!({"myID":id}))
}

struct Witness {
    endpoint: ManagementEndpoint,
    task: JoinHandle<()>,
    stalled: Arc<Notify>,
}

impl Witness {
    async fn start(expected_key: bool, replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        assert_ne!(address.port(), 18886);
        let stalled = Arc::new(Notify::new());
        let signal = Arc::clone(&stalled);
        let task = tokio::spawn(async move {
            for (path, status, body) in replies {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .expect("expected exact read")
                        .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(
                        tokio::time::timeout(Duration::from_secs(5), stream.read_u8())
                            .await
                            .unwrap()
                            .unwrap(),
                    );
                    assert!(request.len() < 4096);
                }
                let request = std::str::from_utf8(&request).unwrap();
                let mut lines = request.lines();
                assert_eq!(lines.next().unwrap(), format!("GET {path} HTTP/1.1"));
                assert_eq!(
                    lines.any(|line| line.to_ascii_lowercase().starts_with("x-api-key:")),
                    expected_key
                );
                if status == 0 {
                    signal.notify_one();
                    let closed = tokio::time::timeout(Duration::from_secs(5), stream.read_u8())
                        .await
                        .expect("cancellation did not close the admitted read");
                    assert!(
                        matches!(closed, Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof || error.kind() == std::io::ErrorKind::ConnectionReset)
                    );
                    continue;
                }
                stream.write_all(format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ).as_bytes()).await.unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err(),
                "preflight sent a request beyond the exact read allowlist"
            );
        });
        Self {
            endpoint: ManagementEndpoint::http(&format!("http://{address}/")).unwrap(),
            task,
            stalled,
        }
    }

    async fn gui(&self) -> Client {
        Client::connect(
            ConnectOptions::new(self.endpoint.clone(), ApiKey::new(KEY).unwrap())
                .request_timeout(Duration::from_secs(5))
                .unwrap()
                .version_policy(VersionPolicy::AllowUnverified),
        )
        .await
        .unwrap()
    }

    async fn local(&self) -> LocalApiClient {
        LocalApiClient::connect(
            LocalApiConnectOptions::new(self.endpoint.clone())
                .unwrap()
                .request_timeout(Duration::from_secs(5))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn confirm(self) {
        self.task.await.expect("exact read-only witness");
    }
}

#[tokio::test]
async fn static_preflight_has_no_wire_effect_and_scopes_windows_arm64_archive_gap() {
    let native = Witness::start(
        true,
        vec![
            version("/rest/system/version", "v2.33.2", "windows", "arm64"),
            identity("/rest/system/status", DEVICE),
        ],
    )
    .await;
    let gui = native.gui().await;
    let static_gui = gui.preflight_gui_listener(PreflightReads::None).await;
    assert_eq!(static_gui.version, VersionCompatibility::ValidatedBaseline);
    assert!(static_gui.observation.is_none());
    assert_eq!(static_gui.device_id(), &gui.instance().device_id);
    let ordinary_debug = format!("{static_gui:?}");
    assert!(!ordinary_debug.contains(DEVICE));
    assert!(!ordinary_debug.contains(KEY));
    let provider = gui
        .preflight_upgrade(UpgradePreflightSource::ServerProvider, PreflightReads::None)
        .await
        .unwrap();
    assert!(matches!(
        provider.upgrade_source.unwrap(),
        UpgradeSourceEvidence::ServerProvider {
            recorded_windows_arm64_gap: true,
            observed_release: None
        }
    ));
    assert!(provider.observation.is_none());
    let pinned = PinnedVersion::new("v2.33.2").unwrap();
    let target = ProgramTarget::new(
        ProgramOs::Windows,
        ProgramArchitecture::Arm64,
        BuildVariant::Standard,
    );
    let fixed = gui
        .preflight_upgrade(
            UpgradePreflightSource::FixedArchive {
                version: &pinned,
                target,
            },
            PreflightReads::None,
        )
        .await
        .unwrap();
    assert!(matches!(
        fixed.upgrade_source.unwrap(),
        UpgradeSourceEvidence::FixedArchiveListed {
            matches_target_os_arch: true,
            ..
        }
    ));
    let url = gui
        .preflight_upgrade(UpgradePreflightSource::ExplicitUrl, PreflightReads::None)
        .await
        .unwrap();
    assert!(matches!(
        url.upgrade_source.unwrap(),
        UpgradeSourceEvidence::ExplicitUrlUninspected
    ));
    native.confirm().await;

    let unknown = Witness::start(
        true,
        vec![
            version("/rest/system/version", "v9.9.9", "windows", "arm64"),
            identity("/rest/system/status", DEVICE),
        ],
    )
    .await;
    let gui = unknown.gui().await;
    let report = gui
        .preflight_upgrade(UpgradePreflightSource::ServerProvider, PreflightReads::None)
        .await
        .unwrap();
    assert_eq!(report.version, VersionCompatibility::Unverified);
    assert!(matches!(
        report.upgrade_source.unwrap(),
        UpgradeSourceEvidence::ServerProvider {
            recorded_windows_arm64_gap: false,
            observed_release: None
        }
    ));
    unknown.confirm().await;
}

fn local_handshake() -> Vec<Reply> {
    vec![
        version("/rest/localapi/system/version", "v2.33.2", "linux", "amd64"),
        identity("/rest/localapi/system/status", DEVICE),
    ]
}

#[tokio::test]
async fn local_api_requires_explicit_probe_and_only_reads_selected_page() {
    let folder = FolderId::parse("one-folder").unwrap();
    let witness = Witness::start(false, local_handshake()).await;
    let local = witness.local().await;
    let unrequested = local
        .preflight_folder_need(&folder, PreflightReads::None)
        .await;
    assert!(unrequested.observation.is_none());
    witness.confirm().await;

    for (status, contents, permission, license) in [
        (
            200,
            json!({"code":3001,"error":"selected operation requires Local-API entitlement"}),
            PreflightReadAccess::LicenseDenied,
            PreflightLicense::ExplicitlyDenied {
                http_status: 200,
                native_code: 3001,
            },
        ),
        (
            403,
            json!({"code":3001,"error":"looks like native entitlement"}),
            PreflightReadAccess::Denied { http_status: 403 },
            PreflightLicense::Unobserved,
        ),
        (
            201,
            json!({"code":3001,"error":"similar but outside the verified envelope status"}),
            PreflightReadAccess::Inconclusive,
            PreflightLicense::Unobserved,
        ),
        (
            200,
            json!({"progress":[],"queued":[],"rest":[],"page":1,"perpage":1}),
            PreflightReadAccess::Observed,
            PreflightLicense::SelectedReadAccepted,
        ),
    ] {
        let mut script = local_handshake();
        script.extend(local_handshake());
        script.push(response(
            "/rest/localapi/folders/need/one-folder?page=1&perpage=1",
            status,
            contents,
        ));
        script.extend(local_handshake());
        let witness = Witness::start(false, script).await;
        let local = witness.local().await;
        let observed = local
            .preflight_folder_need(&folder, PreflightReads::SelectedOperation)
            .await
            .observation
            .unwrap();
        assert!(observed.identity_verified);
        assert_eq!(observed.permission, permission);
        assert_eq!(observed.license, license);
        if matches!(license, PreflightLicense::ExplicitlyDenied { .. }) {
            assert!(matches!(
                observed.issue.unwrap(),
                Error::LicenseRequired { code: 3001, .. }
            ));
        }
        witness.confirm().await;
    }
}

#[tokio::test]
async fn cancelling_a_pending_read_sends_no_next_request() {
    let mut script = local_handshake();
    script.push(("/rest/localapi/system/version", 0, String::new()));
    let witness = Witness::start(false, script).await;
    let local = witness.local().await;
    let task = tokio::spawn(async move {
        local
            .preflight_folder_need(
                &FolderId::parse("one-folder").unwrap(),
                PreflightReads::SelectedOperation,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), witness.stalled.notified())
        .await
        .expect("the first requested read must have reached its isolated listener");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    witness.confirm().await;
}

#[tokio::test]
async fn identity_change_cannot_be_used_to_attribute_a_permission_to_the_original_device() {
    let mut script = local_handshake();
    script.extend(local_handshake());
    script.push(response(
        "/rest/localapi/folders/need/one-folder?page=1&perpage=1",
        200,
        json!({"code":3001,"error":"requires entitlement"}),
    ));
    script.push(version(
        "/rest/localapi/system/version",
        "v2.33.2",
        "linux",
        "amd64",
    ));
    script.push(identity("/rest/localapi/system/status", REPLACEMENT));
    let witness = Witness::start(false, script).await;
    let local = witness.local().await;
    let report = local
        .preflight_folder_need(
            &FolderId::parse("one-folder").unwrap(),
            PreflightReads::SelectedOperation,
        )
        .await;
    let observation = report.observation.unwrap();
    assert!(!observation.identity_verified);
    assert_eq!(observation.permission, PreflightReadAccess::Inconclusive);
    assert_eq!(observation.license, PreflightLicense::Unobserved);
    assert!(matches!(
        observation.issue.unwrap(),
        Error::IdentityMismatch { .. }
    ));
    witness.confirm().await;
}

fn gui_handshake() -> Vec<Reply> {
    vec![
        version("/rest/system/version", "v2.33.2", "windows", "arm64"),
        identity("/rest/system/status", DEVICE),
    ]
}

#[tokio::test]
async fn gui_preflight_reports_a_refused_read_without_inferring_entitlement() {
    let mut script = gui_handshake();
    script.extend(gui_handshake());
    script.push(identity("/rest/system/status", DEVICE));
    script.push(response(
        "/rest/config/gui",
        403,
        json!({"code":3001,"error":"generic forbidden"}),
    ));
    script.extend(gui_handshake());
    let witness = Witness::start(true, script).await;
    let gui = witness.gui().await;
    let observed = gui
        .preflight_gui_listener(PreflightReads::SelectedOperation)
        .await
        .observation
        .unwrap();
    assert!(observed.identity_verified);
    assert_eq!(observed.license, PreflightLicense::Unobserved);
    assert_eq!(
        observed.permission,
        PreflightReadAccess::Denied { http_status: 403 }
    );
    assert!(matches!(observed.issue, Some(Error::AccessDenied { .. })));
    witness.confirm().await;

    let mut script = gui_handshake();
    script.push(response("/rest/system/version", 401, json!({})));
    let witness = Witness::start(true, script).await;
    let gui = witness.gui().await;
    let observed = gui
        .preflight_gui_listener(PreflightReads::SelectedOperation)
        .await
        .observation
        .unwrap();
    assert!(!observed.identity_verified);
    assert_eq!(observed.license, PreflightLicense::Unobserved);
    assert_eq!(
        observed.permission,
        PreflightReadAccess::AuthenticationRequired { http_status: 401 }
    );
    witness.confirm().await;
}

#[tokio::test]
async fn provider_read_does_not_trigger_upgrade_and_retains_observed_release_or_exact_refusal() {
    for reply in [
        response(
            "/rest/system/upgrade",
            200,
            json!({
                "running":"v2.33.2","latest":"v2.34.0","newer":true,"majorNewer":false
            }),
        ),
        (
            "/rest/system/upgrade",
            500,
            "couldn't find a release to download\n".to_owned(),
        ),
    ] {
        let accepted = reply.1 == 200;
        let mut script = gui_handshake();
        script.extend(gui_handshake());
        script.push(identity("/rest/system/status", DEVICE));
        script.push(reply);
        script.extend(gui_handshake());
        let witness = Witness::start(true, script).await;
        let gui = witness.gui().await;
        let report = gui
            .preflight_upgrade(
                UpgradePreflightSource::ServerProvider,
                PreflightReads::SelectedOperation,
            )
            .await
            .unwrap();
        let observed = report.observation.unwrap();
        assert!(observed.identity_verified);
        assert_eq!(observed.license, PreflightLicense::Unobserved);
        let UpgradeSourceEvidence::ServerProvider {
            recorded_windows_arm64_gap,
            observed_release,
        } = report.upgrade_source.unwrap()
        else {
            panic!("provider evidence absent")
        };
        assert!(recorded_windows_arm64_gap);
        if accepted {
            assert_eq!(observed_release.unwrap().latest, "v2.34.0");
            assert_eq!(observed.permission, PreflightReadAccess::Observed);
            assert!(observed.issue.is_none());
        } else {
            assert!(observed_release.is_none());
            assert_eq!(observed.permission, PreflightReadAccess::Inconclusive);
            assert!(matches!(
                observed.issue.unwrap(),
                Error::UpgradeReleaseUnavailable { .. }
            ));
        }
        witness.confirm().await;
    }
}
