//! Explicit owned startup or read-only private-state reconnection; no discovery.
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use verysync_sidecar::{
    LocalProgram, ManagedInstance, ManagedLifetime, ManagedOptions, ManagementEndpoint,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or("usage: manage_owned <owned|persistent|connect|shutdown> PROGRAM STATE <http|socket> ADDRESS")?;
    let mode = mode.to_str().ok_or("mode must be UTF-8")?;
    let program_path = PathBuf::from(
        args.next()
            .ok_or("explicit absolute program path required")?,
    );
    let state = PathBuf::from(args.next().ok_or("explicit private state path required")?);
    let transport = args
        .next()
        .ok_or("explicit http or socket transport required")?;
    let address = args.next().ok_or("explicit management address required")?;
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    let endpoint = match transport.to_str() {
        Some("http") => {
            ManagementEndpoint::http(address.to_str().ok_or("HTTP URL must be UTF-8")?)?
        }
        Some("socket") => ManagementEndpoint::unix_socket(PathBuf::from(address))?,
        _ => return Err("transport must be http or socket".into()),
    };
    let mut program = LocalProgram::new(program_path)?;
    if let Ok(hex) = std::env::var("VERYSYNC_EXAMPLE_PROGRAM_SHA256") {
        if hex.len() != 64 {
            return Err("expected program digest must be 64 hexadecimal characters".into());
        }
        let mut digest = [0; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
        }
        program = program.expected_sha256(digest);
    }
    let options = ManagedOptions::new(program, state, endpoint)?;
    match mode {
        "owned" | "persistent" => {
            let lifetime = if mode == "persistent" {
                ManagedLifetime::Persistent
            } else {
                ManagedLifetime::CallerOwned
            };
            let mut instance = ManagedInstance::start(options.lifetime(lifetime)).await?;
            let status = instance.client().system_status().await?;
            let pid = instance.process_id();
            let exit = if mode == "owned" {
                Some(instance.shutdown(Duration::from_secs(15)).await?)
            } else {
                None
            };
            println!(
                "{}",
                json!({"mode":mode,"device_id":status.device_id.as_str(),"process_id":pid,"management_ready":true,
                "actual_tree_exit":exit.as_ref().map(|e|e.tree_stopped),"forced":exit.as_ref().map(|e|e.forced)})
            );
            // Persistent deliberately survives this owner/caller exit. The
            // default owned path already observed its normal tree exit above.
            drop(instance);
        }
        "connect" | "shutdown" => {
            let client = options.connect_existing().await?;
            let identity = client.system_status().await?.device_id;
            if mode == "shutdown" {
                client.request_shutdown().await?;
            }
            println!(
                "{}",
                json!({"mode":mode,"device_id":identity.as_str(),"management_ready":true,
                "shutdown_acknowledged":mode=="shutdown"})
            );
            // A shutdown acknowledgement is not an observed OS process exit.
        }
        _ => return Err("mode must be owned, persistent, connect or shutdown".into()),
    }
    Ok(())
}
