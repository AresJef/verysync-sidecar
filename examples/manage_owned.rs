//! Explicit owned startup or read-only private-state reconnection; no discovery.
#[path = "common/owned_shutdown.rs"]
mod owned_shutdown;

use owned_shutdown::shutdown_once_observing_exit;
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use verysync_sidecar::{
    LocalProgram, ManagedExitObservationOutcome, ManagedInstance, ManagedLifetime, ManagedOptions,
    ManagementEndpoint,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const USAGE: &str = "Usage: manage_owned <owned|persistent|connect|shutdown|observe-shutdown> PROGRAM STATE <http|socket> ADDRESS";
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or(USAGE)?;
    if mode == "--help" && args.next().is_none() {
        println!("{USAGE}");
        return Ok(());
    }
    let mode = mode.to_str().ok_or("mode must be UTF-8")?;
    let program_path = PathBuf::from(
        args.next()
            .ok_or("Supply the absolute path of the verified VerySync program.")?,
    );
    let state = PathBuf::from(
        args.next()
            .ok_or("Supply the private state directory for this instance.")?,
    );
    let transport = args
        .next()
        .ok_or("Choose http or socket for the management connection.")?;
    let address = args
        .next()
        .ok_or("Supply the address for this management connection.")?;
    if args.next().is_some() {
        return Err(
            "Supply one mode, program path, state directory, connection type and address.".into(),
        );
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
            return Err("The expected program SHA-256 must have 64 hexadecimal characters.".into());
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
            match exit {
                Some(result) if result.tree_stopped && !result.forced && result.code == Some(0) =>
                    eprintln!("The owned VerySync instance started and shut down normally. Its state was kept."),
                Some(result) if result.tree_stopped =>
                    eprintln!("The owned VerySync processes exited without a normal shutdown. Check the saved state before starting again."),
                Some(_) =>
                    eprintln!("VerySync started. This run could not confirm that all owned processes stopped."),
                None =>
                    eprintln!("The managed VerySync instance started in persistent mode. Use the same private state to reconnect or request shutdown."),
            }
            // Persistent deliberately survives this owner/caller exit. The
            // default owned path already observed its normal tree exit above.
            drop(instance);
        }
        "observe-shutdown" => {
            // With an unresolved exit, keep the core under its explicit
            // persistent lifetime when this short-lived example returns.
            let mut instance =
                ManagedInstance::start(options.lifetime(ManagedLifetime::Persistent)).await?;
            let report = shutdown_once_observing_exit(
                &mut instance,
                Duration::from_secs(5),
                Duration::from_secs(15),
            )
            .await;
            if let Err(error) = &report.original {
                eprintln!("The shutdown call did not confirm exit. {error}");
            }
            match report.later {
                Some(Ok(observation)) => {
                    match observation.outcome {
                        ManagedExitObservationOutcome::Exited(exit)
                            if exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0) =>
                        {
                            println!("Later observation confirmed that the original VerySync process exited normally.");
                            return Ok(());
                        }
                        ManagedExitObservationOutcome::TimedOut =>
                            eprintln!("The observation ended before exit was confirmed. Check whether the original instance is still running."),
                        _ => eprintln!("The original instance did not produce a confirmed normal exit. Check its exit report and saved state."),
                    }
                }
                Some(Err(error)) => eprintln!("Could not observe the original process. {error}"),
                None => {}
            }
            if let Err(error) = report.original {
                return Err(error.into());
            }
            println!("The original VerySync process exited. Check its exit report before changing its files.");
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
            if mode == "shutdown" {
                eprintln!("VerySync accepted the shutdown request. Check that the selected process has stopped before changing its files.");
            } else {
                eprintln!(
                    "Connected to the running VerySync instance using its private state record."
                );
            }
            // Keep the JSON acknowledgement distinct from observed process exit.
        }
        _ => {
            return Err(
                "mode must be owned, persistent, connect, shutdown or observe-shutdown".into(),
            )
        }
    }
    Ok(())
}
