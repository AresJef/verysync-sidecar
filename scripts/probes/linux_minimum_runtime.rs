//! Original public SDK calls against a fixed core in a disposable old Linux guest.

#[path = "../tests/common/resource_fixture.rs"]
mod resource_fixture;

use fs2::FileExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use verysync_sidecar::{
    CreateFolderOptions, Error as SidecarError, FolderId, LocalProgram, ManagedInstance,
    ManagedOptions, ManagementEndpoint, ResourceTransferOptions, TargetPath,
};

type ProbeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const USER: u32 = 1000;
const PROGRAM: &str = "/bin/verysync";
const DATA: &str = "/vs-data";
const MANAGEMENT_PORT: u16 = 18_435;

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

fn listening_on_management_port(table: &str) -> Option<bool> {
    fs::read_to_string(table).ok().map(|sockets| {
        sockets.lines().skip(1).any(|line| {
            let mut columns = line.split_whitespace();
            let local = columns.nth(1);
            let state = columns.nth(1);
            state == Some("0A")
                && local
                    .and_then(|address| address.rsplit_once(':'))
                    .and_then(|(_, port)| u16::from_str_radix(port, 16).ok())
                    == Some(MANAGEMENT_PORT)
        })
    })
}

fn observe_management_builder() -> ProbeResult<()> {
    let debian_ca = Path::new("/etc/ssl/certs/ca-certificates.crt").is_file();
    let result = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("verysync-sidecar/", env!("CARGO_PKG_VERSION")))
        .build();
    let builder_ok = result.is_ok();
    let missing_platform_roots = result.is_err_and(|error| {
        let mut current = error.source();
        while let Some(cause) = current {
            if cause
                .to_string()
                .contains("No CA certificates were loaded from the system")
            {
                return error.is_builder();
            }
            current = cause.source();
        }
        false
    });
    println!(
        "VS_MINIMUM_CA_BUILDER debian_ca={debian_ca} builder_ok={builder_ok} missing_platform_roots={missing_platform_roots}"
    );
    require(
        (debian_ca && builder_ok) || (!debian_ca && missing_platform_roots),
        "unexpected result from the default management client builder",
    )
}

async fn read_native_health_code() -> Option<u16> {
    tokio::time::timeout(Duration::from_millis(750), async {
        let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, MANAGEMENT_PORT))
            .await
            .ok()?;
        stream
            .write_all(
                b"GET /rest/noauth/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .ok()?;
        let mut prefix = [0; 12];
        stream.read_exact(&mut prefix).await.ok()?;
        let scheme = &prefix[..9];
        if scheme == b"HTTP/1.1 " || scheme == b"HTTP/1.0 " {
            std::str::from_utf8(&prefix[9..]).ok()?.parse().ok()
        } else {
            None
        }
    })
    .await
    .ok()
    .flatten()
}

async fn startup_observation(state: &Path, program: &Path, elapsed: Duration) {
    let mut log = Vec::new();
    let read_log = fs::File::open(state.join(".verysync-sidecar-core.log"))
        .and_then(|file| file.take(65_536).read_to_end(&mut log))
        .ok();
    let log = String::from_utf8_lossy(&log).to_ascii_lowercase();
    let log_indicators: Vec<_> = [
        ("listener_start", "gui and api listening"),
        ("permission_denied", "permission denied"),
        ("missing_path", "no such file or directory"),
        ("address_in_use", "address already in use"),
        ("invalid_syscall", "function not implemented"),
        ("unsupported_kernel", "kernel too old"),
        ("go_panic", "panic:"),
        ("go_fatal", "fatal error:"),
        ("go_signal", "sigsegv"),
        ("db_error", "database error"),
    ]
    .into_iter()
    .filter_map(|(label, phrase)| log.contains(phrase).then_some(label))
    .collect();
    let pids = owned_images(program).ok();
    let ipv4_listening = listening_on_management_port("/proc/net/tcp");
    let health_code = if ipv4_listening == Some(true) {
        read_native_health_code().await
    } else {
        None
    };
    println!(
        "VS_MINIMUM_SDK_START_OBSERVATION {}",
        json!({"elapsed_ms":elapsed.as_millis(),
            "exact_programs_running":pids.as_ref().map(Vec::len),
            "configured":state.join(".verysync-sidecar-configured").is_file(),
            "ipv4_management_port_listening":ipv4_listening,
            "ipv6_management_port_listening":listening_on_management_port("/proc/net/tcp6"),
            "native_health_http_status":health_code,
            "private_core_log_bytes_read":read_log,"log_indicators":log_indicators})
    );
}

async fn observe_failed_start_cleanup(state: &Path, program: &Path) -> ProbeResult<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(state.join(".verysync-sidecar-lease"))?;
    loop {
        if owned_images(program)?.is_empty() {
            match FileExt::try_lock_exclusive(&lock) {
                Ok(()) => {
                    FileExt::unlock(&lock)?;
                    return Ok(true);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn verify_guest(hash: [u8; 32]) -> ProbeResult<()> {
    observe_management_builder()?;
    let root = Path::new(DATA);
    let program = fs::canonicalize(PROGRAM)?;
    require(
        owned_images(&program)?.is_empty(),
        "unexpected program before startup",
    )?;
    let state = root.join("state");
    let endpoint = ManagementEndpoint::http(&format!("http://127.0.0.1:{MANAGEMENT_PORT}/"))?;
    let options = ManagedOptions::new(
        LocalProgram::new(&program)?.expected_sha256(hash),
        state.clone(),
        endpoint,
    )?;
    println!("VS_MINIMUM_SDK_PHASE starting");
    let start_time = Instant::now();
    let observation_state = state.clone();
    let observation_program = program.clone();
    let observer = tokio::spawn(async move {
        for interval in [4, 6, 12] {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            startup_observation(
                &observation_state,
                &observation_program,
                start_time.elapsed(),
            )
            .await;
        }
    });
    let started = ManagedInstance::start(options).await;
    observer.abort();
    let _ = observer.await;
    let mut core = match started {
        Ok(core) => core,
        Err(error) => {
            let settings = state.join("setting.dat").is_file();
            let key_generated = state.join("key.pem").is_file();
            let configured = state.join(".verysync-sidecar-configured").is_file();
            let core_log_created = state.join(".verysync-sidecar-core.log").is_file();
            let exact_programs = owned_images(&program).map(|pids| pids.len()).ok();
            let native_io = match &error {
                SidecarError::LocalIo { operation, source } => Some(json!({
                    "operation": operation,
                    "kind": format!("{:?}", source.kind()),
                    "os_code": source.raw_os_error()
                })),
                _ => None,
            };
            startup_observation(&state, &program, start_time.elapsed()).await;
            println!(
                "VS_MINIMUM_SDK_START_FAILURE {}",
                json!({"settings_created":settings,"key_generated":key_generated,
                    "configuration_completed":configured,"core_log_created":core_log_created,
                    "exact_programs_running":exact_programs,"native_io":native_io})
            );
            let cleanup = observe_failed_start_cleanup(&state, &program).await;
            println!(
                "VS_MINIMUM_SDK_FAILURE_CLEANUP exact_exit_and_lease_release={}",
                cleanup.is_ok_and(|completed| completed)
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
