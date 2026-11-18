//! Original public SDK calls against a fixed core in a disposable old Linux guest.

#[path = "../tests/common/resource_fixture.rs"]
mod resource_fixture;

use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use verysync_sidecar::{
    CreateFolderOptions, FolderId, LocalProgram, ManagedInstance, ManagedOptions,
    ManagementEndpoint, ResourceTransferOptions, TargetPath,
};

type ProbeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const USER: u32 = 1000;
const PROGRAM: &str = "/bin/verysync";
const DATA: &str = "/vs-data";

fn require(condition: bool, reason: &'static str) -> ProbeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(reason.into())
    }
}

fn verify_guest_user() -> ProbeResult<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    for name in ["Uid:", "Gid:"] {
        let line = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or("guest process identity is missing")?;
        let actual: Vec<_> = line.split_whitespace().collect();
        require(
            actual == ["1000"; 4],
            "guest process did not have the fixed UID/GID",
        )?;
    }
    require(
        status.lines().any(|line| {
            line.strip_prefix("Groups:")
                .is_some_and(|groups| groups.trim().is_empty())
        }),
        "guest process retained supplementary groups",
    )?;
    let maps = fs::read_to_string("/proc/self/maps")?;
    require(
        maps.lines().any(|line| line.ends_with(" /lib64/libc.so.6")),
        "SDK process did not map the fixture libc",
    )?;
    println!("VS_MINIMUM_SDK_RUNTIME uid={USER} loaded_fixture_libc=true");
    Ok(())
}

fn selected_hash() -> ProbeResult<[u8; 32]> {
    let value = std::env::args()
        .nth(1)
        .ok_or("explicit fixed engine SHA-256 required")?;
    require(
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "expected 64 hex digits",
    )?;
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(digest)
}

fn owned_images(program: &Path) -> ProbeResult<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        if fs::read_link(entry.path().join("exe")).ok().as_deref() == Some(program) {
            pids.push(pid);
        }
    }
    Ok(pids)
}

async fn verify_guest(hash: [u8; 32]) -> ProbeResult<()> {
    let root = Path::new(DATA);
    let program = fs::canonicalize(PROGRAM)?;
    require(
        owned_images(&program)?.is_empty(),
        "unexpected program before startup",
    )?;
    let state = root.join("state");
    let endpoint = ManagementEndpoint::http("http://127.0.0.1:18435/")?;
    let options = ManagedOptions::new(
        LocalProgram::new(&program)?.expected_sha256(hash),
        state.clone(),
        endpoint,
    )?;
    println!("VS_MINIMUM_SDK_PHASE starting");
    let mut core = match ManagedInstance::start(options).await {
        Ok(core) => core,
        Err(error) => {
            let settings = state.join("setting.dat").is_file();
            let key_generated = state.join("key.pem").is_file();
            let configured = state.join(".verysync-sidecar-configured").is_file();
            let core_log_created = state.join(".verysync-sidecar-core.log").is_file();
            let exact_programs = owned_images(&program).map(|pids| pids.len()).ok();
            println!(
                "VS_MINIMUM_SDK_START_FAILURE {}",
                json!({"settings_created":settings,"key_generated":key_generated,
                    "configuration_completed":configured,"core_log_created":core_log_created,
                    "exact_programs_running":exact_programs})
            );
            return Err(error.into());
        }
    };
    require(
        core.program_info().version == "v2.33.2",
        "unexpected actual core version",
    )?;
    require(
        core.program_info().sha256 == hash,
        "unexpected actual core SHA-256",
    )?;
    let identity = core.client().system_status().await?.device_id;
    let first_pid = core.process_id();
    require(
        !owned_images(&program)?.is_empty(),
        "no actual fixed executable running",
    )?;
    println!("VS_MINIMUM_SDK_PHASE authenticated");

    let folder_dir = root.join("sync");
    fs::create_dir(&folder_dir)?;
    let folder = FolderId::parse("minimum-sdk-probe")?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(&folder_dir))
                .label("minimum"),
        )
        .await?;

    let (profile, base, _) =
        resource_fixture::owned_base(&core, &core.client().resource_volumes().await?)?;
    let target = base.child("minimum-sample.txt")?;
    let file = profile.join("minimum-sample.txt");
    fs::write(&file, b"synthetic seed\n")?;
    let content = "synthetic minimum Linux data\n";
    let edited = core.client().write_resource_text(&target, content).await?;
    require(
        !edited.is_dir
            && edited.size == content.len() as u64
            && fs::read(&file)? == content.as_bytes(),
        "native file write was not visible at the exact fixture path",
    )?;
    println!("VS_MINIMUM_SDK_PHASE native_write");

    core.restart(Duration::from_secs(20)).await?;
    require(
        core.process_id() != first_pid,
        "restart did not observe a new owner",
    )?;
    require(
        core.client().system_status().await?.device_id == identity,
        "identity changed",
    )?;
    require(
        core.client().folder(&folder).await?.label == "minimum",
        "folder registration was lost",
    )?;
    let (after_profile, after_base, _) =
        resource_fixture::owned_base(&core, &core.client().resource_volumes().await?)?;
    require(after_profile == profile, "restart resolved another profile")?;
    let output: PathBuf = root.join("download.txt");
    let download = core
        .client()
        .download_resource(
            &after_base.child("minimum-sample.txt")?,
            &output,
            None,
            &ResourceTransferOptions {
                max_bytes: 1024,
                deadline: Duration::from_secs(10),
            },
        )
        .await?;
    let expected: [u8; 32] = Sha256::digest(content.as_bytes()).into();
    require(
        download.bytes == content.len() as u64
            && download.sha256 == expected
            && fs::read(&output)? == content.as_bytes(),
        "download did not retain the expected bytes and digest",
    )?;
    println!("VS_MINIMUM_SDK_PHASE restart_and_download");

    let finish = core.shutdown(Duration::from_secs(15)).await?;
    require(
        finish.code == Some(0) && finish.tree_stopped && finish.state_released && !finish.forced,
        "normal owned-core shutdown was not observed",
    )?;
    require(
        owned_images(&program)?.is_empty(),
        "the fixed executable was still running",
    )?;
    require(
        fs::read(&file)? == content.as_bytes(),
        "shutdown changed the fixture data",
    )?;
    println!(
        "VS_MINIMUM_SDK_OK {}",
        json!({"version":"v2.33.2","authenticated":true,"created_folder":true,
            "native_file_write":true,"retained_identity_and_folder":true,
            "downloaded_bytes":download.bytes,"normal_exit":true,
            "state_released":true,"exact_images_after_exit":0})
    );
    Ok(())
}

fn main() -> ProbeResult<()> {
    require(
        cfg!(all(target_os = "linux", target_env = "gnu")),
        "this fixture requires a Linux GNU guest",
    )?;
    let hash = selected_hash()?;
    match std::env::args().nth(2).as_deref() {
        None => {
            let status = Command::new(std::env::current_exe()?)
                .arg(
                    std::env::args()
                        .nth(1)
                        .ok_or("explicit fixed engine SHA-256 required")?,
                )
                .arg("--guest-user")
                .uid(USER)
                .gid(USER)
                .status()?;
            require(
                status.success(),
                "unprivileged SDK fixture returned failure",
            )
        }
        Some("--guest-user") => {
            verify_guest_user()?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(verify_guest(hash))
        }
        Some(_) => Err("unknown fixture mode".into()),
    }
}
