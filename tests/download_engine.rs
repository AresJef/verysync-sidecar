//! Explicit official transfer followed by real isolated public managed operations.
use std::time::Duration;
use verysync_sidecar::{
    official_programs, BuildVariant, DownloadOptions, ManagedInstance, ManagedOptions,
    ManagementEndpoint, ProgramArchitecture, ProgramOs,
};

#[tokio::test]
async fn official_fixed_archive_prepares_and_runs_the_exact_native_program(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let os = match std::env::consts::OS {
        "macos" => ProgramOs::MacOs,
        "windows" => ProgramOs::Windows,
        "linux" => ProgramOs::Linux,
        _ => return Err("native acceptance host not selected".into()),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => ProgramArchitecture::Amd64,
        "aarch64" => ProgramArchitecture::Arm64,
        _ => return Err("native acceptance architecture not selected".into()),
    };
    let asset = official_programs()?
        .into_iter()
        .find(|a| {
            a.target().os() == os
                && a.target().architecture() == arch
                && a.target().variant() == BuildVariant::Standard
        })
        .ok_or("exact native asset missing")?;
    let root = tempfile::Builder::new()
        .prefix("vsd 中文 spaces-")
        .tempdir()?
        .keep();
    let destination = root.join("downloaded program");
    let prepared = DownloadOptions::new(asset.clone(), &destination)?
        .prepare()
        .await?;
    assert_eq!(prepared.asset().archive_sha256(), asset.archive_sha256());
    let actual_hex = prepared
        .executable_sha256()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(actual_hex, std::env::var("VERYSYNC_TEST_BINARY_SHA256")?);
    assert_eq!(std::fs::read_dir(&destination)?.count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(prepared.program().path())?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o700
        );
    }
    let state = root.join("private state");
    #[cfg(unix)]
    let endpoint = ManagementEndpoint::unix_socket(state.join("gui.sock"))?;
    #[cfg(windows)]
    let endpoint = {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?
    };
    let options = ManagedOptions::new(prepared.program().clone(), &state, endpoint)?
        .startup_timeout(Duration::from_secs(25))?;
    let mut instance = ManagedInstance::start(options).await?;
    assert_eq!(instance.program_info().sha256, prepared.executable_sha256());
    assert_eq!(instance.program_info().version, "v2.33.2");
    let _authenticated = instance.client().system_status().await?;
    let sample = root.join("retained sample");
    std::fs::write(&sample, b"synthetic retained bytes")?;
    let exit = instance.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    // A completed stop releases SDK-owned state handles before returning.
    // Windows rejects this immediate rename while the capture remains open.
    let capture = state.join(".verysync-sidecar-core.log");
    let renamed = state.join("after-exit-diagnostic.log");
    std::fs::rename(&capture, &renamed).inspect_err(|error| {
        eprintln!(
            "post-exit capture rename failed: kind={:?} native_code={:?}",
            error.kind(),
            error.raw_os_error()
        );
    })?;
    std::fs::rename(renamed, capture)?;
    assert_eq!(std::fs::read(sample)?, b"synthetic retained bytes");
    println!(
        "public Rust program preparation evidence: {}",
        serde_json::json!({"fixed_official_runtime_download":true,"complete_archive_sha_verified":true,"exact_inner_sha_matches_independent_fixture":true,"only_regular_executable_materialized":true,"private_executable_permissions":true,"spaces_and_unicode_native_paths":true,"actual_baseline_program_started":true,"actual_management_authenticated":true,"actual_normal_tree_exit":true,"diagnostic_handle_released_before_stop_returns":true,"synthetic_sample_retained":true})
    );
    std::fs::remove_dir_all(&root).inspect_err(|error| {
        // A stopped tree and successful diagnostic rename remain separate from
        // test-root deletion. Preserve a sharing failure without retry or waiver.
        eprintln!(
            "post-assertion download fixture cleanup: {}",
            serde_json::json!({"native_error":error.raw_os_error(),
                "program_remains":prepared.program().path().exists(),
                "destination_remains":destination.exists(),"state_remains":state.exists(),
                "capture_remains":state.join(".verysync-sidecar-core.log").exists(),
                "state_entry_count":std::fs::read_dir(&state).ok().map(|entries|entries.count())})
        );
    })?;
    Ok(())
}
