//! Original public SDK calls against a fixed core in a disposable old Linux guest.

#[path = "../tests/common/resource_fixture.rs"]
mod resource_fixture;

use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
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

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn enter_guest_user() -> ProbeResult<()> {
    // The guest init is the only privileged caller. Drop all guest groups and
    // root credentials before creating the SDK runtime or starting the core.
    unsafe {
        let version = std::ffi::CStr::from_ptr(libc::gnu_get_libc_version());
        require(
            version.to_bytes() == b"2.17",
            "runtime glibc differed from the fixed 2.17 build baseline",
        )?;
        require(libc::geteuid() == 0, "guest init privileges were required")?;
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(USER) != 0
            || libc::setuid(USER) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        require(
            libc::geteuid() == USER && libc::getegid() == USER,
            "guest UID/GID differed",
        )?;
    }
    println!("VS_MINIMUM_SDK_RUNTIME glibc=2.17 uid={USER}");
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn enter_guest_user() -> ProbeResult<()> {
    let _ = USER;
    Err("this fixture requires a Linux GNU guest".into())
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
    let mut core = ManagedInstance::start(options).await?;
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
    let hash = selected_hash()?;
    enter_guest_user()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(verify_guest(hash))
}
