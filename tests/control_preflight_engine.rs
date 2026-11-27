//! Actual read-only preflight on an isolated matching official core.
#![cfg(feature = "engine-tests")]

#[path = "common/managed_fixture.rs"]
mod managed_fixture;

use managed_fixture::{options, TestResult};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use verysync_sidecar::{
    BuildVariant, Client, CoreLogLevel, CreateFolderOptions, Error, FolderId, LocalApiClient,
    LocalApiConnectOptions, ManagedInstance, ManagedOptions, ManagementEndpoint, PinnedVersion,
    PreflightLicense, PreflightReadAccess, PreflightReads, ProgramArchitecture, ProgramOs,
    ProgramTarget, RawMethod, RawRequest, RequestEffect, TargetPath, UpgradePreflightSource,
    UpgradeSourceEvidence, BASELINE_ENGINE_VERSION,
};

const WAIT: Duration = Duration::from_secs(15);
const LOG_FILE: &str = ".verysync-sidecar-core.log";
const FOLDER: &str = "p5-selected-folder";
const DATA: &[u8] = b"owned preflight sample remains unchanged\n";
const LOCAL_STATUS: &str = "/rest/localapi/system/status";
const LOCAL_PROBE: [&str; 5] = [
    "/rest/localapi/system/version",
    LOCAL_STATUS,
    "/rest/localapi/folders/need/p5-selected-folder?page=1&perpage=1",
    "/rest/localapi/system/version",
    LOCAL_STATUS,
];

async fn marker(client: &Client, state: &Path, label: &str) -> TestResult<String> {
    let request = RawRequest::new(
        RawMethod::Get,
        ["rest", "system", "ping"],
        RequestEffect::ReadOnly,
    )?
    .query("p5_marker", label.to_owned());
    if client.raw_request(&request).await?.status() != 200 {
        return Err("native preflight marker did not return HTTP 200".into());
    }
    let expected = format!("http: GET \"/rest/system/ping?p5_marker={label}\": status ");
    let start = Instant::now();
    loop {
        let snapshot = log_snapshot(state)?;
        if snapshot
            .lines()
            .filter(|line| line.contains(&expected))
            .count()
            == 1
        {
            return Ok(expected);
        }
        if start.elapsed() > Duration::from_secs(3) {
            return Err("missing unique native preflight marker".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn log_snapshot(state: &Path) -> TestResult<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(state.join(LOG_FILE))?
        .take(65_537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        return Err("native preflight log exceeded its private observation bound".into());
    }
    String::from_utf8(bytes).map_err(|_| "native preflight log was not UTF-8".into())
}

fn assert_window(state: &Path, start: &str, end: &str, expected: &[&str]) -> TestResult {
    let snapshot = log_snapshot(state)?;
    if snapshot.matches(start).count() != 1 || snapshot.matches(end).count() != 1 {
        return Err("native preflight needs both unique markers in the final log".into());
    }
    let (_, tail) = snapshot.split_once(start).ok_or("start marker missing")?;
    let (between, _) = tail
        .split_once(end)
        .ok_or("end marker missing or reversed")?;
    let requests = between
        .lines()
        .filter_map(|line| line.split_once("http: "))
        .map(|(_, record)| -> TestResult<&str> {
            record
                .strip_prefix("GET \"")
                .and_then(|line| line.split_once("\": status "))
                .map(|(route, _)| {
                    // The fixed native Local-API status handler enriches its
                    // request URL for logging. The wire fixture checks the
                    // client's exact status route without those parameters.
                    if route.starts_with("/rest/localapi/system/status?") {
                        LOCAL_STATUS
                    } else {
                        route
                    }
                })
                .ok_or_else(|| {
                    "native preflight issued an unexpected method or malformed route".into()
                })
        })
        .collect::<TestResult<Vec<_>>>()?;
    if requests != expected {
        let observed: Vec<_> = requests
            .iter()
            .map(|route| safe_route_label(route))
            .collect();
        return Err(format!(
            "native preflight had an unexpected request sequence (expected {}, observed {observed:?})",
            expected.len()
        )
        .into());
    }
    Ok(())
}

fn safe_route_label(route: &str) -> (&'static str, Vec<(&'static str, bool)>) {
    let (path, query) = route.split_once('?').unwrap_or((route, ""));
    let path = match path {
        "/rest/localapi/system/version" => "local_version",
        "/rest/localapi/system/status" => "local_identity",
        "/rest/system/version" => "gui_version",
        "/rest/system/status" => "gui_identity",
        "/rest/config/gui" => "gui_configuration",
        "/rest/system/upgrade" => "provider",
        "/rest/localapi/folders/need/p5-selected-folder" => "selected_local_need",
        "/rest/db/need" => "native_db_need",
        _ => "unclassified",
    };
    let keys = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| match key {
            "page" => ("page", value == "1"),
            "perpage" => ("perpage", value == "1"),
            "folder" => ("folder", value == FOLDER),
            _ => ("unclassified_parameter", false),
        })
        .collect();
    (path, keys)
}

async fn check_package_consumer(endpoint: &ManagementEndpoint, device: &str) -> TestResult {
    let selected = std::env::var_os("VERYSYNC_TEST_PREFLIGHT_EXAMPLE")
        .ok_or("set VERYSYNC_TEST_PREFLIGHT_EXAMPLE to the independent consumer executable")?;
    let executable = PathBuf::from(selected);
    if !executable.is_absolute() || !executable.is_file() {
        return Err("the preflight consumer must be an explicit absolute executable".into());
    }
    let endpoint = endpoint
        .http_url()
        .ok_or("preflight consumer requires HTTP")?;
    let input = serde_json::to_vec(&json!({
        "endpoint":endpoint.as_str(), "expected_device_id":device, "folder_id":FOLDER
    }))?;
    let mut child = Command::new(executable)
        .args(["local-need", "--read"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let write = child
        .stdin
        .take()
        .ok_or("preflight consumer stdin missing")
        .and_then(|mut stream| {
            stream
                .write_all(&input)
                .map_err(|_| "preflight consumer input failed")
        });
    if let Err(error) = write {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    let deadline = Instant::now() + WAIT;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("preflight consumer timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let result = child.wait_with_output()?;
    if !result.status.success() || result.stdout.len() > 4096 || !result.stderr.is_empty() {
        return Err("preflight consumer did not produce bounded successful output".into());
    }
    let text = String::from_utf8(result.stdout)?;
    assert!(text.contains(
        "VerySync reported that this need page requires a Local-API entitlement (code 3001)."
    ));
    assert!(!text.contains(endpoint.as_str()) && !text.contains(device) && !text.contains(FOLDER));
    Ok(())
}

#[tokio::test]
async fn native_preflight_checks_only_its_selected_reads_and_preserves_state() -> TestResult {
    let root = tempfile::Builder::new().prefix("vss-p5-").tempdir()?;
    let state = root.path().join("state");
    let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = reserved.local_addr()?;
    assert_ne!(address.port(), 18886);
    drop(reserved);
    let endpoint = ManagementEndpoint::http(&format!("http://{address}/"))?;
    let mut core = ManagedInstance::start(
        ManagedOptions::new(options(&state)?.program().clone(), &state, endpoint.clone())?
            .local_api_enabled(true)?,
    )
    .await?;
    let sample = root.path().join("sample");
    let file = sample.join("keep.txt");
    let operation: TestResult<()> = async {
        let id = core.client().instance().device_id.clone();
        let pid = core.process_id();
        let local = LocalApiClient::connect(
            LocalApiConnectOptions::new(endpoint.clone())?.expected_device_id(id.clone()),
        )
        .await?;
        std::fs::create_dir(&sample)?;
        std::fs::write(&file, DATA)?;
        let folder = FolderId::parse(FOLDER)?;
        core.client()
            .create_folder(
                &CreateFolderOptions::new(folder.clone(), TargetPath::local(&sample)).paused(true),
            )
            .await?;
        let changed = core
            .client()
            .set_core_log_levels(&BTreeMap::from([("api".to_owned(), CoreLogLevel::Debug)]))
            .await?;
        assert!(changed.requested_levels_match);
        let gui = core.client();
        let native = &gui.instance().version;
        let os = match native.os.as_str() {
            "darwin" => ProgramOs::MacOs,
            "linux" => ProgramOs::Linux,
            "windows" => ProgramOs::Windows,
            _ => return Err("unsupported test runner engine OS".into()),
        };
        let arch = match native.arch.as_str() {
            "arm64" => ProgramArchitecture::Arm64,
            "amd64" => ProgramArchitecture::Amd64,
            _ => return Err("unsupported test runner engine architecture".into()),
        };
        let fixed = PinnedVersion::new(BASELINE_ENGINE_VERSION)?;
        let target = ProgramTarget::new(os, arch, BuildVariant::Standard);
        let source = UpgradePreflightSource::FixedArchive {
            version: &fixed,
            target,
        };
        let start = marker(gui, &state, "p5-static-start").await?;
        assert!(gui
            .preflight_gui_listener(PreflightReads::None)
            .await
            .observation
            .is_none());
        assert!(gui
            .preflight_upgrade(source, PreflightReads::None)
            .await?
            .observation
            .is_none());
        assert!(local
            .preflight_folder_need(&folder, PreflightReads::None)
            .await
            .observation
            .is_none());
        let end = marker(gui, &state, "p5-static-end").await?;
        assert_window(&state, &start, &end, &[])?;

        let start = marker(gui, &state, "p5-gui-start").await?;
        let observation = gui
            .preflight_gui_listener(PreflightReads::SelectedOperation)
            .await
            .observation
            .ok_or("missing GUI preflight observation")?;
        assert!(observation.identity_verified);
        assert_eq!(observation.permission, PreflightReadAccess::Observed);
        assert_eq!(observation.license, PreflightLicense::Unobserved);
        let end = marker(gui, &state, "p5-gui-end").await?;
        assert_window(
            &state,
            &start,
            &end,
            &[
                "/rest/system/version",
                "/rest/system/status",
                "/rest/system/status",
                "/rest/config/gui",
                "/rest/system/version",
                "/rest/system/status",
            ],
        )?;

        let start = marker(gui, &state, "p5-fixed-start").await?;
        let archive = gui
            .preflight_upgrade(source, PreflightReads::SelectedOperation)
            .await?;
        assert!(
            archive
                .observation
                .ok_or("missing archive preflight observation")?
                .identity_verified
        );
        assert!(matches!(
            archive.upgrade_source,
            Some(UpgradeSourceEvidence::FixedArchiveListed {
                matches_target_os_arch: true,
                ..
            })
        ));
        let end = marker(gui, &state, "p5-fixed-end").await?;
        assert_window(
            &state,
            &start,
            &end,
            &["/rest/system/version", "/rest/system/status"],
        )?;

        let start = marker(gui, &state, "p5-provider-start").await?;
        let provider = gui
            .preflight_upgrade(
                UpgradePreflightSource::ServerProvider,
                PreflightReads::SelectedOperation,
            )
            .await?
            .observation
            .ok_or("missing provider preflight observation")?;
        assert!(provider.identity_verified);
        assert_eq!(provider.permission, PreflightReadAccess::Inconclusive);
        assert!(
            matches!(provider.issue, Some(Error::Http { response }) if response.status() == 501)
        );
        let end = marker(gui, &state, "p5-provider-end").await?;
        assert_window(
            &state,
            &start,
            &end,
            &[
                "/rest/system/version",
                "/rest/system/status",
                "/rest/system/status",
                "/rest/system/upgrade",
                "/rest/system/version",
                "/rest/system/status",
            ],
        )?;

        let start = marker(gui, &state, "p5-local-start").await?;
        let need = local
            .preflight_folder_need(&folder, PreflightReads::SelectedOperation)
            .await
            .observation
            .ok_or("missing Local-API preflight observation")?;
        assert!(need.identity_verified);
        assert_eq!(need.permission, PreflightReadAccess::LicenseDenied);
        assert_eq!(
            need.license,
            PreflightLicense::ExplicitlyDenied {
                http_status: 200,
                native_code: 3001
            }
        );
        let Some(Error::LicenseRequired {
            code: 3001,
            response,
        }) = need.issue
        else {
            return Err("the selected need read did not retain its native refusal".into());
        };
        let refusal: serde_json::Value = serde_json::from_slice(response.body_bytes())?;
        assert!(refusal.as_object().is_some_and(|fields| {
            fields.len() == 2 && fields.contains_key("code") && fields.contains_key("error")
        }));
        let end = marker(gui, &state, "p5-local-end").await?;
        assert_window(&state, &start, &end, &LOCAL_PROBE)?;
        let start = marker(gui, &state, "p5-consumer-start").await?;
        check_package_consumer(&endpoint, id.as_str()).await?;
        let end = marker(gui, &state, "p5-consumer-end").await?;
        let consumer_reads = [&LOCAL_PROBE[..2], &LOCAL_PROBE[..]].concat();
        assert_window(&state, &start, &end, &consumer_reads)?;
        assert_eq!(core.process_id(), pid);
        assert_eq!(gui.system_status().await?.device_id, id);
        assert!(gui.folder(&folder).await?.paused);
        assert_eq!(std::fs::read(&file)?, DATA);
        Ok(())
    }
    .await;
    let exit = core.shutdown(WAIT).await;
    operation?;
    let exit = exit?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    assert_eq!(std::fs::read(&file)?, DATA);
    println!(
        "native operation preflight evidence {}",
        json!({
            "static_reads":0, "gui_reads":6, "fixed_source_reads":2, "disabled_provider_reads":6,
            "provider_status":501, "local_need_total_reads":5, "local_need_pages":1,
            "local_need_http_status":200, "local_need_native_code":3001, "writes":0,
            "local_need_denial_pagination_fields_absent":true,
            "external_example_local_need_reads":7, "external_example_local_need_pages":1,
            "external_example_english_entitlement_result":true,
        "same_process_and_device":true,
            "sample_preserved":true, "normal_owned_exit_and_state_release":true
        })
    );
    Ok(())
}
