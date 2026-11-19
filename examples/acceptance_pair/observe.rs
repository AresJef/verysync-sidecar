use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, DeviceId, ManagementEndpoint, PathStyle, PeerConnection,
    PeerConnectionType, ResourcePath, ResourceTransferOptions, ResourceVolumeId, TargetPath,
    BASELINE_ENGINE_VERSION,
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    sender: Node,
    receiver: Node,
    transport: Transport,
    expected_bytes: u64,
    expected_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    receipt: PathBuf,
    management: Management,
    volume: String,
    resource: String,
    path_style: TargetStyle,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Management {
    Loopback { port: u16 },
    UnixSocket { path: PathBuf },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TargetStyle {
    Unix,
    Windows,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Transport {
    Tcp,
    Quic,
    Relay,
}

#[derive(Deserialize)]
struct Receipt {
    schema: u32,
    api_key: String,
    device_id: String,
    program_version: String,
    program_sha256: String,
}

#[derive(Serialize)]
pub struct PairEvidence {
    pub sender: NodeEvidence,
    pub receiver: NodeEvidence,
    pub bytes: u64,
    pub file_sha256: String,
}

#[derive(Serialize)]
pub struct NodeEvidence {
    pub device_id: String,
    pub program_version: String,
    pub ready_program_sha256: String,
    pub peer_connection_type: &'static str,
    pub peer_address: String,
    pub peer_in_bytes: Option<u64>,
    pub peer_out_bytes: Option<u64>,
}

fn read_small(path: &Path, private: bool) -> Result<Vec<u8>> {
    const LIMIT: u64 = 16 * 1024;
    if !path.is_absolute() || !std::fs::symlink_metadata(path)?.is_file() {
        return Err("use an absolute path to a regular input file".into());
    }
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("the opened input must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err("each node receipt must be private to its owner".into());
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err("the input exceeds 16 KiB".into());
    }
    Ok(bytes)
}

fn hex_digest(hash: &[u8]) -> Result<String> {
    let mut encoded = String::with_capacity(hash.len() * 2);
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn read_receipt(path: &Path) -> Result<Receipt> {
    let data = read_small(path, true)?;
    let receipt: Receipt =
        serde_json::from_slice(&data).map_err(|_| "invalid private node receipt")?;
    if receipt.schema != 1
        || receipt.program_version != BASELINE_ENGINE_VERSION
        || !is_digest(&receipt.program_sha256)
    {
        return Err("node receipt must bind the fixed VerySync program".into());
    }
    Ok(receipt)
}

impl Node {
    fn endpoint(&self) -> Result<ManagementEndpoint> {
        match &self.management {
            Management::Loopback { port: 0 | 18886 } => {
                Err("use a dedicated loopback port other than 18886".into())
            }
            Management::Loopback { port } => Ok(ManagementEndpoint::http(&format!(
                "http://127.0.0.1:{port}/"
            ))?),
            Management::UnixSocket { path } => Ok(ManagementEndpoint::unix_socket(path)?),
        }
    }

    fn resource(&self) -> Result<ResourcePath> {
        let style = match self.path_style {
            TargetStyle::Unix => PathStyle::Unix,
            TargetStyle::Windows => PathStyle::Windows,
        };
        Ok(ResourcePath::relative(
            ResourceVolumeId::parse(&self.volume)?,
            &TargetPath::remote(style, &self.resource)?,
        )?)
    }
}

fn peer(
    receipt: Receipt,
    connection: &PeerConnection,
    transport: &Transport,
) -> Result<NodeEvidence> {
    let kind = match (transport, &connection.connection_type) {
        (Transport::Tcp, Some(PeerConnectionType::TcpClient)) => "tcp-client",
        (Transport::Tcp, Some(PeerConnectionType::TcpServer)) => "tcp-server",
        (Transport::Quic, Some(PeerConnectionType::QuicClient)) => "quic-client",
        (Transport::Quic, Some(PeerConnectionType::QuicServer)) => "quic-server",
        (Transport::Relay, Some(PeerConnectionType::RelayClient)) => "relay-client",
        (Transport::Relay, Some(PeerConnectionType::RelayServer)) => "relay-server",
        _ => return Err("a peer did not report the expected transport".into()),
    };
    let address = connection
        .address
        .as_ref()
        .filter(|a| !a.is_empty())
        .ok_or("a peer did not report its connection address")?;
    if !connection.connected {
        return Err("a peer is disconnected".into());
    }
    Ok(NodeEvidence {
        device_id: receipt.device_id,
        program_version: receipt.program_version,
        ready_program_sha256: receipt.program_sha256,
        peer_connection_type: kind,
        peer_address: address.clone(),
        peer_in_bytes: connection.in_bytes_total,
        peer_out_bytes: connection.out_bytes_total,
    })
}

async fn fetch(
    client: &Client,
    resource: &ResourcePath,
    destination: &Path,
    input: &Input,
) -> Result<()> {
    let options = ResourceTransferOptions {
        max_bytes: input.expected_bytes,
        deadline: Duration::from_secs(30),
    };
    let got = client
        .download_resource(resource, destination, None, &options)
        .await?;
    let saved = tokio::fs::read(destination).await?;
    if got.bytes != input.expected_bytes
        || saved.len() as u64 != input.expected_bytes
        || Sha256::digest(&saved)[..] != got.sha256
        || hex_digest(&got.sha256)? != input.expected_sha256
    {
        return Err("a retrieved synthetic file differs from its declared size or digest".into());
    }
    Ok(())
}

pub async fn run(path: &Path) -> Result<PairEvidence> {
    let input: Input = serde_json::from_slice(&read_small(path, false)?)
        .map_err(|_| "invalid acceptance pair plan")?;
    if !(1..=16 * 1024 * 1024).contains(&input.expected_bytes) || !is_digest(&input.expected_sha256)
    {
        return Err(
            "specify the synthetic file size (1 byte to 16 MiB) and lowercase SHA-256".into(),
        );
    }
    let sender = read_receipt(&input.sender.receipt)?;
    let receiver = read_receipt(&input.receiver.receipt)?;
    let sender_id = DeviceId::parse(&sender.device_id)?;
    let receiver_id = DeviceId::parse(&receiver.device_id)?;
    let sender_endpoint = input.sender.endpoint()?;
    let receiver_endpoint = input.receiver.endpoint()?;
    let sender_resource = input.sender.resource()?;
    let receiver_resource = input.receiver.resource()?;
    if sender_id == receiver_id || sender_endpoint == receiver_endpoint {
        return Err("the nodes must have distinct identities and management endpoints".into());
    }
    let (a, b) = tokio::try_join!(
        Client::connect(
            ConnectOptions::new(sender_endpoint, ApiKey::new(&sender.api_key)?)
                .expected_device_id(sender_id.clone())
        ),
        Client::connect(
            ConnectOptions::new(receiver_endpoint, ApiKey::new(&receiver.api_key)?)
                .expected_device_id(receiver_id.clone())
        ),
    )?;
    let (asnap, bsnap) = tokio::try_join!(a.connections(), b.connections())?;
    let a_peer = peer(
        sender,
        asnap
            .connections
            .get(&receiver_id)
            .ok_or("sender does not report the paired device")?,
        &input.transport,
    )?;
    let b_peer = peer(
        receiver,
        bsnap
            .connections
            .get(&sender_id)
            .ok_or("receiver does not report the paired device")?,
        &input.transport,
    )?;

    let output = tempfile::tempdir()?;
    let a_destination = output.path().join("sender-sample");
    let b_destination = output.path().join("receiver-sample");
    // Let both operations finish before removing their private output directory.
    let (saved_a, saved_b) = tokio::join!(
        fetch(&a, &sender_resource, &a_destination, &input),
        fetch(&b, &receiver_resource, &b_destination, &input),
    );
    saved_a?;
    saved_b?;
    output.close()?;
    Ok(PairEvidence {
        sender: a_peer,
        receiver: b_peer,
        bytes: input.expected_bytes,
        file_sha256: input.expected_sha256,
    })
}
