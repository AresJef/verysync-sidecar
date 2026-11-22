//! Finite, explicitly started node for caller-controlled acceptance networks.
use serde_json::json;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::TcpListener;
use std::path::{Component, PathBuf};
use std::time::Duration;
use verysync_sidecar::{LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn digest(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("SHA-256 must contain exactly 64 ASCII hexadecimal characters".into());
    }
    let mut value = [0; 32];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16)?;
    }
    Ok(value)
}

fn private_receipt(path: &std::path::Path, value: &serde_json::Value) -> Result {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // On Windows the SDK-created parent has a protected, inheritable DACL
    // granting access only to the current user and SYSTEM.
    let mut output = options.open(path)?;
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    Ok(())
}

async fn serve(instance: &ManagedInstance, root: &std::path::Path, ttl: Duration) -> Result {
    let configuration = instance.client().configuration().await?;
    let document = configuration.native_document();
    let key = document
        .pointer("/gui/apiKey")
        .and_then(serde_json::Value::as_str)
        .filter(|key| !key.is_empty())
        .ok_or("The test node has no management credential to include in its private receipt.")?;
    let endpoint = instance
        .client()
        .endpoint()
        .http_url()
        .ok_or("This test node needs its dedicated loopback HTTP endpoint.")?;
    let receipt = root.join("state").join("acceptance-connection.json");
    let identity = instance.client().system_status().await?.device_id;
    let program = instance.program_info();
    let mut program_sha256 = String::with_capacity(2 * program.sha256.len());
    for byte in &program.sha256 {
        write!(&mut program_sha256, "{byte:02x}")?;
    }
    private_receipt(
        &receipt,
        &json!({
            "schema":1, "endpoint":endpoint.as_str(), "api_key":key,
            "device_id":identity.as_str(), "ttl_seconds":ttl.as_secs(),
            "program_version":program.version, "program_sha256":program_sha256
        }),
    )?;
    writeln!(
        io::stdout(),
        "{}",
        json!({"event":"ready", "process_id":instance.process_id(),
        "device_id":identity.as_str(), "endpoint":endpoint.as_str(),
        "program_version":program.version, "program_sha256":program_sha256,
        "receipt":receipt, "ttl_seconds":ttl.as_secs()})
    )?;
    io::stdout().flush()?;
    eprintln!("The test node is ready. Its private receipt contains the connection credential. The node stops at the requested deadline or when it receives a stop command.");

    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    // A blocked standard-input reader must not prevent Tokio runtime shutdown
    // when TTL expires. This ordinary thread owns no core or credentials.
    std::thread::Builder::new()
        .name("acceptance-stop-input".into())
        .spawn(move || {
            let mut input = io::stdin().lock();
            loop {
                let mut line = Vec::new();
                // Oversized commands cause a normal shutdown; input is bounded.
                let read = input.by_ref().take(65).read_until(b'\n', &mut line);
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line.len() > 64 || line == b"stop\n" || line == b"stop\r\n" => break,
                    Ok(_) => continue,
                }
            }
            let _ = sender.blocking_send(());
        })?;
    tokio::select! {
        _ = tokio::time::sleep(ttl) => {},
        _ = receiver.recv() => {},
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result {
    let mut args = std::env::args_os().skip(1);
    let program = PathBuf::from(
        args.next()
            .ok_or("usage: acceptance_node PROGRAM SHA256 NEW_ROOT TTL_SECONDS")?,
    );
    let hash = args
        .next()
        .ok_or("Supply the expected SHA-256 of the isolated test program.")?;
    let hash = digest(hash.to_str().ok_or("SHA-256 must be ASCII")?)?;
    let root = PathBuf::from(
        args.next()
            .ok_or("Supply an absolute path to a new directory for the test node.")?,
    );
    let ttl: u64 = args
        .next()
        .ok_or("Supply how many seconds the test node should wait before shutting down.")?
        .to_str()
        .ok_or("TTL must be ASCII")?
        .parse()?;
    if args.next().is_some() || !(1..=7200).contains(&ttl) {
        return Err("Supply exactly four arguments and a lifetime from 1 to 7200 seconds.".into());
    }
    if !root.is_absolute() || root.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("Use a new absolute test directory without parent path components.".into());
    }
    let program = LocalProgram::new(program)?.expected_sha256(hash);
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = builder;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    // Never reuse, empty, delete or adopt an existing application directory.
    builder.create(&root)?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    if port == 18886 {
        return Err("The selected port is reserved for the user instance. The test program was not started.".into());
    }
    let endpoint = ManagementEndpoint::http(&format!("http://127.0.0.1:{port}"))?;
    let options = ManagedOptions::new(program, root.join("state"), endpoint)?;
    // The SDK authenticates the selected fresh identity after binding; a port
    // race is a startup failure, never permission to adopt another instance.
    drop(listener);
    let mut instance = ManagedInstance::start(options).await?;
    let served = serve(&instance, &root, Duration::from_secs(ttl)).await;
    // Always request normal shutdown, including receipt/stdout/input failures.
    let exit = instance.shutdown(Duration::from_secs(30)).await?;
    if exit.code != Some(0)
        || exit.signal.is_some()
        || exit.forced
        || !exit.tree_stopped
        || !exit.state_released
    {
        return Err("The test node could not confirm a normal shutdown. Check the owned test processes before cleaning its directory.".into());
    }
    println!(
        "{}",
        json!({"event":"stopped", "code":exit.code,
        "forced":exit.forced, "tree_stopped":exit.tree_stopped,
        "state_released":exit.state_released})
    );
    eprintln!("The owned test node shut down normally. Its private state was kept.");
    served
}
