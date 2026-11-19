//! Diagnostic only. Runs on an owned Windows x64 CI sender and its diskless Linux peer.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};
use verysync_sidecar::{
    Client, ConfigurationSnapshot, CreateDeviceOptions, DeviceAdvancedPatch, DeviceCompression,
    DeviceId, DevicePatch, DeviceTransport, FolderId, FolderState, GeneralOptionsPatch,
    JoinFolderOptions, LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint,
    NetworkPatch, PeerConnectionType, ShareKey, TargetPath,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const HOST_IP: &str = "192.0.2.1";
const CONTROL: &str = "192.0.2.2:47527";
const LINUX_SHA: &str = "770324d3411bf6ff7d18109ba5fa1e5057056b5e93441f29185b50895f55693a";
const WINDOWS_SHA: &str = "b1455da891a0723404c8c025ca77dc5ee8bc73632979edf4542c45d57fc73ea7";
const LIMIT: usize = 128 * 1024 * 1024;
const FILE: &str = "fresh-owned-packet-sample.bin";
const SIZE: usize = 262_181;
const CASES: [(u8, i64); 6] = [(4, 16), (4, 32), (4, 0), (6, 16), (6, 32), (6, 0)];

#[derive(Deserialize, Serialize)]
struct Offer {
    family: u8,
    value: i64,
    sender: DeviceId,
    read_only_key: String,
}

#[derive(Deserialize, Serialize)]
struct Ready {
    peer: DeviceId,
    listener: SocketAddr,
}

#[derive(Deserialize)]
struct Header {
    source_port: u16,
    class_octet: u8,
    tcp_payload_bytes: usize,
    packets: usize,
}

#[derive(Deserialize, Serialize)]
struct Observation {
    family: u8,
    requested: i64,
    actual_sink_port: u16,
    actual_source: SocketAddr,
    sample_bytes: usize,
    sample_sha256: String,
    classes: BTreeSet<u8>,
    packet_count: usize,
    payload_tcp_bytes: usize,
    receiver_unrelated_settings_and_identity_retained: bool,
}

fn ensure(condition: bool, message: &'static str) -> Result {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn decode_sha(text: &str) -> Result<[u8; 32]> {
    let mut hash = [0; 32];
    for (i, item) in hash.iter_mut().enumerate() {
        *item = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?;
    }
    Ok(hash)
}

fn addresses(family: u8) -> Result<(IpAddr, IpAddr)> {
    let (host, guest) = match family {
        4 => (HOST_IP, "192.0.2.2"),
        6 => ("2001:db8:73f:43::1", "2001:db8:73f:43::2"),
        _ => return Err("expected a selected IPv4 or IPv6 case".into()),
    };
    Ok((host.parse()?, guest.parse()?))
}

fn put(stream: &mut TcpStream, bytes: &[u8]) -> Result {
    stream.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn get(stream: &mut TcpStream, limit: usize) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    ensure(
        length > 0 && length <= limit,
        "invalid owned transfer length",
    )?;
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn send<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result {
    put(stream, &serde_json::to_vec(value)?)
}

fn receive<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<T> {
    Ok(serde_json::from_slice(&get(stream, 16_384)?)?)
}

fn sample(case: (u8, i64)) -> Vec<u8> {
    let seed = u32::from(case.0) ^ case.1 as u32;
    (0..SIZE)
        .map(|i| ((i as u32).wrapping_mul(73) ^ (i as u32 >> 7) ^ seed) as u8)
        .collect()
}

fn managed(state: &Path, binary: &Path, sha: &str) -> Result<ManagedOptions> {
    let program = LocalProgram::new(binary.to_path_buf())?.expected_sha256(decode_sha(sha)?);
    if cfg!(windows) {
        let candidate = TcpListener::bind(("127.0.0.1", 0))?;
        let port = candidate.local_addr()?.port();
        ensure(port != 18886, "refuse the default management port")?;
        let endpoint = ManagementEndpoint::http(&format!("http://127.0.0.1:{port}/"))?;
        Ok(ManagedOptions::new(program, state, endpoint)?
            .startup_timeout(Duration::from_secs(25))?)
    } else {
        let endpoint = ManagementEndpoint::unix_socket(state.join("gui.sock"))?;
        Ok(ManagedOptions::new(program, state, endpoint)?
            .startup_timeout(Duration::from_secs(25))?)
    }
}

async fn closed(instance: &mut ManagedInstance) -> Result {
    let report = instance.shutdown(Duration::from_secs(10)).await?;
    ensure(
        report.tree_stopped
            && report.state_released
            && !report.forced
            && report.code == Some(0)
            && report.signal.is_none(),
        "owned SDK instance did not confirm a normal shutdown",
    )
}

async fn preconfigure(client: &Client, listener: Option<SocketAddr>) -> Result {
    let mut network = NetworkPatch::default()
        .global_discovery(false)
        .local_discovery(false)
        .reconnection_interval_seconds(5);
    if let Some(addr) = listener {
        network = network.listen_addresses(vec![format!("tcp://{addr}")]);
    }
    client.update_network_configuration(&network).await?;
    client
        .update_general_options(&GeneralOptionsPatch::default().disable_system_sleep_on_sync(false))
        .await?;
    Ok(())
}

fn retained(before: &ConfigurationSnapshot, after: &ConfigurationSnapshot) -> Result {
    for key in ["gui", "defaults", "ldap", "relayServer"] {
        ensure(
            before.native_document()[key] == after.native_document()[key],
            "unrelated configuration changed",
        )?;
    }
    Ok(())
}

fn credentials(instance: &ManagedInstance) -> Result<[Vec<u8>; 2]> {
    let path = instance.state_directory();
    Ok([
        fs::read(path.join("key.pem"))?,
        fs::read(path.join("cert.pem"))?,
    ])
}

async fn add_peer(client: &Client, peer: &DeviceId, address: String) -> Result {
    let options = CreateDeviceOptions::new(peer.clone()).settings(
        DevicePatch::default()
            .addresses(vec![address])
            .compression(DeviceCompression::Never)
            .allowed_transports(vec![DeviceTransport::Tcp])
            .advanced_configuration(DeviceAdvancedPatch::default().num_connections(1))?,
    );
    client.create_device(&options).await?;
    Ok(())
}

async fn connected(client: &Client, id: &DeviceId, kind: PeerConnectionType) -> Result<SocketAddr> {
    let snapshot = client.connections().await?;
    let peer = snapshot
        .connections
        .get(id)
        .ok_or("authenticated peer absent")?;
    ensure(
        peer.connected && peer.connection_type.as_ref() == Some(&kind),
        "peer did not establish the required direct TCP role",
    )?;
    Ok(peer
        .address
        .as_deref()
        .ok_or("actual peer address absent")?
        .parse()?)
}

struct Capture {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl Capture {
    fn start(family: u8, source: IpAddr, dest: SocketAddr) -> Result<Self> {
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-B",
                "/receive-headers.py",
                &family.to_string(),
                &source.to_string(),
                &dest.ip().to_string(),
                &dest.port().to_string(),
            ])
            .env("RUNNER_DISPOSABLE_RX", "true")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut capture = Self {
            stdin: child.stdin.take(),
            stdout: BufReader::new(child.stdout.take().ok_or("capture stdout unavailable")?),
            child,
        };
        ensure(
            capture.line()?.trim() == "RECEIVER_HEADERS_READY",
            "independent capture did not assert readiness",
        )?;
        Ok(capture)
    }

    fn line(&mut self) -> Result<String> {
        let mut line = String::new();
        (&mut self.stdout).take(49_153).read_line(&mut line)?;
        ensure(
            !line.is_empty() && line.len() <= 49_152,
            "missing or oversized capture reply",
        )?;
        Ok(line)
    }

    fn finish(mut self) -> Result<Vec<Header>> {
        self.stdin.take();
        let line = self.line()?;
        let receipt = line
            .strip_prefix("RECEIVER_HEADERS ")
            .ok_or("capture reply lacks its receipt")?;
        ensure(
            self.child.wait()?.success(),
            "capture did not exit normally",
        )?;
        Ok(serde_json::from_str(receipt)?)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.wait();
    }
}

async fn listener(client: &Client, address: SocketAddr) -> Result {
    let address = format!("tcp://{address}");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if client
                .listener_status()
                .await?
                .values()
                .any(|status| status.lan_addresses.contains(&address))
            {
                return Ok::<(), verysync_sidecar::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await??;
    Ok(())
}

async fn file_received(client: &Client, folder: &FolderId, path: &Path, bytes: &[u8]) -> Result {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if path.is_file()
                && fs::read(path)? == bytes
                && client.folder_status(folder).await?.state == Some(FolderState::Idle)
            {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await??;
    Ok(())
}

async fn inspect_guest(
    guest: &mut ManagedInstance,
    stream: &mut TcpStream,
    case: (u8, i64),
    target: &Path,
) -> Result<Observation> {
    let offer: Offer = receive(stream)?;
    println!("WIRE_GUEST_PHASE offer_received");
    ensure(
        (offer.family, offer.value) == case,
        "test cases are out of sequence",
    )?;
    let (source, dest) = addresses(case.0)?;
    let bind = SocketAddr::new(dest, 47529);
    let account = guest.client().instance().device_id.clone();
    let keys = credentials(guest)?;
    preconfigure(guest.client(), Some(bind)).await?;
    println!("WIRE_GUEST_PHASE configured_listener={bind}");
    guest.restart(Duration::from_secs(25)).await?;
    println!("WIRE_GUEST_PHASE exact_core_restarted");
    let client = guest.client();
    let before = client.configuration().await?;
    listener(client, bind).await.map_err(|error| {
        format!("fixed guest listener {bind} did not become observable: {error}")
    })?;
    println!("WIRE_GUEST_PHASE actual_listener={bind}");
    add_peer(client, &offer.sender, "dynamic".to_string()).await?;
    let key = ShareKey::new(offer.read_only_key)?;
    let authorized = client.validate_share_key(&key).await?;
    let folder = client
        .join_folder(&JoinFolderOptions::new(authorized, TargetPath::local(target)).paused(true))
        .await?
        .configuration
        .id;
    client.share_folder_with(&folder, &offer.sender).await?;
    client.resume_folder(&folder).await?;
    println!("WIRE_GUEST_PHASE folder_shared_and_resumed");
    let capture = Capture::start(case.0, source, bind)?;
    println!("WIRE_GUEST_PHASE independent_observer_ready");
    send(
        stream,
        &Ready {
            peer: account.clone(),
            listener: bind,
        },
    )?;

    let bytes = sample(case);
    let file = target.join(FILE);
    file_received(client, &folder, &file, &bytes).await?;
    println!("WIRE_GUEST_PHASE exact_bytes_and_idle");
    let peer = connected(client, &offer.sender, PeerConnectionType::TcpServer).await?;
    ensure(
        peer.ip() == source && peer.port() > 0,
        "authenticated sender does not match the isolated address",
    )?;
    let headers = capture.finish()?;
    let headers: Vec<_> = headers
        .iter()
        .filter(|h| h.source_port == peer.port())
        .collect();
    let packet_count = headers.iter().map(|h| h.packets).sum();
    let payload_tcp_bytes = headers.iter().map(|h| h.tcp_payload_bytes).sum();
    ensure(
        packet_count > 0 && payload_tcp_bytes >= SIZE,
        "authenticated flow lacks real TCP data headers",
    )?;
    let classes = headers.iter().map(|h| h.class_octet & 0xfc).collect();
    retained(&before, &client.configuration().await?)?;
    ensure(
        client.system_status().await?.device_id == account && credentials(guest)? == keys,
        "receiver identity or credentials changed",
    )?;
    let observed = Observation {
        family: case.0,
        requested: case.1,
        actual_sink_port: bind.port(),
        actual_source: peer,
        sample_bytes: bytes.len(),
        sample_sha256: digest(&fs::read(file)?),
        classes,
        packet_count,
        payload_tcp_bytes,
        receiver_unrelated_settings_and_identity_retained: true,
    };
    send(stream, &observed)?;
    ensure(
        receive::<bool>(stream)?,
        "sender did not confirm its own connection and file",
    )?;
    Ok(observed)
}

async fn inspect_sender(
    sender: &mut ManagedInstance,
    stream: &mut TcpStream,
    case: (u8, i64),
    source: &Path,
) -> Result<Observation> {
    let (addr, dest) = addresses(case.0)?;
    let bytes = sample(case);
    let file = source.join(FILE);
    fs::write(&file, &bytes)?;
    preconfigure(sender.client(), None).await?;
    let before = sender.client().configuration().await?;
    let identity = sender.client().instance().device_id.clone();
    let cert = credentials(sender)?;
    let patched = sender
        .client()
        .update_general_options(&GeneralOptionsPatch::default().traffic_class(case.1))
        .await?;
    ensure(
        patched.requested_fields_match,
        "sender traffic-class patch did not match",
    )?;
    sender.restart(Duration::from_secs(30)).await?;
    let client = sender.client();
    ensure(
        client.general_options().await?.traffic_class == Some(case.1),
        "restart lost the selected traffic class",
    )?;
    let keys = client.generate_share().await?;
    let write_key = client.validate_share_key(&keys.read_write_key).await?;
    let folder = client
        .join_folder(&JoinFolderOptions::new(write_key, TargetPath::local(source)).paused(true))
        .await?
        .configuration
        .id;
    send(
        stream,
        &Offer {
            family: case.0,
            value: case.1,
            sender: identity.clone(),
            read_only_key: keys.read_only_key.expose_secret().to_owned(),
        },
    )?;
    let guest: Ready = receive(stream)?;
    ensure(
        guest.listener == SocketAddr::new(dest, 47529) && guest.peer != identity,
        "guest did not announce the expected explicit test address and unique identity",
    )?;
    add_peer(client, &guest.peer, format!("tcp://{}", guest.listener)).await?;
    client.share_folder_with(&folder, &guest.peer).await?;
    client.resume_folder(&folder).await?;
    let observed: Observation = receive(stream)?;
    ensure(
        (observed.family, observed.requested) == case
            && observed.actual_sink_port == guest.listener.port()
            && observed.actual_source.ip() == addr
            && observed.sample_bytes == SIZE
            && observed.sample_sha256 == digest(&bytes)
            && observed.packet_count > 0
            && observed.payload_tcp_bytes >= SIZE
            && observed.receiver_unrelated_settings_and_identity_retained,
        "mismatched independent data or packet evidence",
    )?;
    ensure(
        connected(client, &guest.peer, PeerConnectionType::TcpClient).await? == guest.listener,
        "sender's authenticated route differs from that of the independent receiver",
    )?;
    ensure(
        fs::read(file)? == bytes
            && credentials(sender)? == cert
            && client.system_status().await?.device_id == identity,
        "sender data or identity changed",
    )?;
    retained(&before, &client.configuration().await?)?;
    Ok(observed)
}

fn configure_stream(stream: &TcpStream) -> Result {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(75)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    Ok(())
}

async fn guest() -> Result {
    ensure(
        cfg!(target_os = "linux")
            && std::env::var("OWNED_DISKLESS_HYPERV").as_deref() == Ok("true"),
        "expected the isolated Linux guest",
    )?;
    let loopback = TcpListener::bind(CONTROL)?;
    println!("WIRE_GUEST_CONTROL_READY");
    let (mut stream, host) = loopback.accept()?;
    ensure(
        host.ip() == HOST_IP.parse::<IpAddr>()?,
        "unexpected control source",
    )?;
    configure_stream(&stream)?;
    let root = tempfile::Builder::new().prefix("rx-").tempdir_in("/run")?;
    let binary = root.path().join("linux-core");
    let bytes = get(&mut stream, LIMIT)?;
    ensure(
        digest(&bytes) == LINUX_SHA,
        "guest executable did not match the fixed official SHA-256",
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&binary)?;
    file.write_all(&bytes)?;
    drop(file);
    drop(bytes);
    let mode = Command::new("/bin/chmod")
        .arg("700")
        .arg(&binary)
        .status()?;
    ensure(
        mode.success(),
        "guest could not prepare its owned executable",
    )?;
    println!("WIRE_GUEST_ENGINE_EXACT sha256={LINUX_SHA}");
    send(&mut stream, &true)?;
    for case in CASES {
        let folder = root.path().join(format!("{}-{}", case.0, case.1));
        fs::create_dir(&folder)?;
        let target = folder.join("data");
        fs::create_dir(&target)?;
        println!(
            "WIRE_GUEST_PHASE start_native_engine family={} value={}",
            case.0, case.1
        );
        let mut node =
            ManagedInstance::start(managed(&folder.join("state"), &binary, LINUX_SHA)?).await?;
        println!("WIRE_GUEST_PHASE native_engine_authenticated");
        let seen = inspect_guest(&mut node, &mut stream, case, &target).await;
        let stop = closed(&mut node).await;
        seen?;
        stop?;
        println!("WIRE_GUEST_NORMAL family={} value={}", case.0, case.1);
        send(&mut stream, &true)?;
    }
    root.close()?;
    println!("WIRE_GUEST_OWNED_STATE_REMOVED");
    Ok(())
}

fn approved_default_octet(approved: bool, requested: i64, classes: &BTreeSet<u8>) -> bool {
    approved && matches!(requested, 16 | 32) && classes.len() == 1 && classes.contains(&0)
}

#[test]
fn amd64_packet_boundary_accepts_only_scoped_nonzero_requests_with_only_zero_observed() {
    let zero = BTreeSet::from([0]);
    let wrong = BTreeSet::from([4]);
    let mixed = BTreeSet::from([0, 4]);
    let variants = [
        (true, 16, &zero),
        (true, 32, &zero),
        (false, 16, &zero),
        (true, 0, &zero),
        (true, 8, &zero),
        (true, 16, &wrong),
        (true, 32, &mixed),
    ];
    assert_eq!(
        variants.map(|(approved, requested, observed)| approved_default_octet(
            approved, requested, observed
        )),
        [true, true, false, false, false, false, false],
    );
}

async fn sender(guest_core: &Path, approved_amd64_boundary: bool) -> Result {
    ensure(
        cfg!(all(windows, target_arch = "x86_64"))
            && std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true"),
        "expected the explicitly authorized native AMD64 Windows CI runner",
    )?;
    ensure(
        !approved_amd64_boundary || std::env::var("RUNNER_ARCH").as_deref() == Ok("X64"),
        "the approved v2.33.2 packet boundary requires a native Windows AMD64 runner",
    )?;
    let windows =
        std::env::var_os("VERYSYNC_TEST_BINARY").ok_or("explicit owned sender program required")?;
    let windows = Path::new(&windows);
    ensure(
        std::env::var("VERYSYNC_TEST_BINARY_SHA256").as_deref() == Ok(WINDOWS_SHA),
        "Windows executable SHA-256 differs from the pinned official program",
    )?;
    let bytes = fs::read(guest_core)?;
    ensure(
        digest(&bytes) == LINUX_SHA,
        "guest source executable did not match its fixed SHA-256",
    )?;
    let dest: SocketAddr = CONTROL.parse()?;
    let source = SocketAddr::new(HOST_IP.parse()?, 0);
    let deadline = Instant::now() + Duration::from_secs(55);
    let mut stream = loop {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind(source)?;
        match tokio::time::timeout(Duration::from_secs(2), socket.connect(dest)).await {
            Ok(Ok(stream)) => break stream.into_std()?,
            Ok(Err(err)) if Instant::now() >= deadline => {
                return Err(format!("owned control connect from {source} to {dest}: {err}").into());
            }
            Err(_) if Instant::now() >= deadline => {
                return Err("owned source-bound control connection timed out".into());
            }
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    };
    stream.set_nonblocking(false)?;
    configure_stream(&stream)?;
    ensure(
        stream.local_addr()?.ip() == source.ip(),
        "control is not on the owned Hyper-V link",
    )?;
    println!(
        "WIRE_CONTROL_CONNECTED source={} target={dest}",
        stream.local_addr()?
    );
    put(&mut stream, &bytes)?;
    println!("WIRE_GUEST_UPLOAD_COMPLETE bytes={}", bytes.len());
    drop(bytes);
    ensure(
        receive::<bool>(&mut stream)?,
        "guest did not verify its exact conventional Linux executable",
    )?;
    let home = std::env::var_os("RUNNER_TEMP").ok_or("isolated Windows directory required")?;
    let root = tempfile::Builder::new()
        .prefix("vs-wire-")
        .tempdir_in(home)?;
    let caller = root.path().join("caller");
    fs::write(&caller, b"preserve caller bytes")?;
    let mut matched = true;
    let mut accepted = true;
    let mut approved_defaults = 0;
    for case in CASES {
        println!("WIRE_CASE_START family={} value={}", case.0, case.1);
        let folder = root.path().join(format!("{}-{}", case.0, case.1));
        fs::create_dir(&folder)?;
        let data = folder.join("data");
        fs::create_dir(&data)?;
        let mut node =
            ManagedInstance::start(managed(&folder.join("state"), windows, WINDOWS_SHA)?).await?;
        let observed = inspect_sender(&mut node, &mut stream, case, &data).await;
        let stop = closed(&mut node).await;
        let observed = observed?;
        stop?;
        send(&mut stream, &true)?;
        ensure(
            receive::<bool>(&mut stream)?,
            "receiver normal stop missing",
        )?;
        let case_match = observed.classes.contains(&(case.1 as u8))
            && (case.1 != 0 || observed.classes.len() == 1);
        let known_default =
            approved_default_octet(approved_amd64_boundary, case.1, &observed.classes);
        matched &= case_match;
        accepted &= case_match || known_default;
        approved_defaults += usize::from(known_default);
        println!(
            "WIRE_CASE_RESULT {}",
            serde_json::json!({
                "sample": observed, "expected_wire_value_seen": case_match,
                "approved_amd64_default_octet": known_default,
                "windows_native_identity_and_configuration_retained": true,
                "both_normal_owned_exits": true,
            })
        );
    }
    ensure(
        fs::read(&caller)? == b"preserve caller bytes",
        "caller data changed",
    )?;
    root.close()?;
    println!("WIRE_WINDOWS_OWNED_STATE_REMOVED wire_gate={matched}");
    println!(
        "WIRE_WINDOWS_PACKET_CONTRACT strict_wire_match={matched} effective_match={accepted} approved_defaults={approved_defaults}"
    );
    ensure(accepted, "one or more real Windows packet classes differed")
}

#[cfg(all(windows, target_arch = "aarch64"))]
mod paired_wire_arm64;

#[tokio::main]
async fn main() -> Result {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        #[cfg(all(windows, target_arch = "aarch64"))]
        [mode, relay, dll, adapter] if mode == "arm64-owned-wire" => {
            paired_wire_arm64::exercise(Path::new(relay), Path::new(dll), adapter).await
        }
        [mode] if mode == "guest" => guest().await,
        [mode, file] if mode == "send" => sender(Path::new(file), false).await,
        [mode, file, boundary] if mode == "send" && boundary == "approved-windows-amd64-v2.33.2-default" => {
            sender(Path::new(file), true).await
        }
        _ => Err("usage: paired_wire guest | send PINNED_LINUX_BINARY [approved-windows-amd64-v2.33.2-default]".into()),
    }
}
