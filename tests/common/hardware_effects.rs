//! Observe native hardware data and native backend refusal independently.
use super::managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{Error, ManagedInstance, TargetPath};
#[tokio::test]
async fn actual_native_hardware_data_and_backend_refusals_preserve_owned_state() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vshardware-")
        .tempdir()?
        .keep();
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = owner.client().instance().device_id.clone();
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"hardware reads retain bytes")?;
    let cpu = owner.client().native_cpu_hardware().await?;
    assert!(cpu.total_cores > 0 && cpu.total_threads > 0);
    assert!(!cpu
        .processors
        .as_ref()
        .ok_or("native packages unreported")?
        .is_empty());
    let blocks = owner.client().native_block_hardware().await?;
    assert!(blocks.total_size_bytes > 0);
    let disks = blocks.disks.as_ref().ok_or("native disks unreported")?;
    assert!(!disks.is_empty());
    for disk in disks.iter().flatten() {
        for partition in disk.partitions.iter().flatten().flatten() {
            if let Some(path) = partition.mount_point()? {
                assert_eq!(path.style(), TargetPath::local(&root).style());
                assert!(path.local_path().is_none());
            }
        }
    }
    let darwin = owner.client().instance().version.os == "darwin";
    let memory_positive = match owner.client().native_memory_hardware().await {
        Ok(value) => {
            assert!(
                !darwin,
                "fixed Darwin backend unexpectedly changed; review native evidence"
            );
            let _ = value.total_usable_bytes;
            true
        }
        Err(Error::Api { response, .. }) => {
            assert_eq!(response.status(), 200);
            false
        }
        Err(error) => return Err(error.into()),
    };
    let network_positive = match owner.client().native_network_hardware().await {
        Ok(value) => {
            assert!(
                !darwin,
                "fixed Darwin backend unexpectedly changed; review native evidence"
            );
            let _ = value.nics;
            true
        }
        Err(Error::Api { response, .. }) => {
            assert_eq!(response.status(), 200);
            false
        }
        Err(error) => return Err(error.into()),
    };
    assert_eq!(owner.client().system_status().await?.device_id, id);
    assert!(owner.client().folders().await?.is_empty());
    assert_eq!(std::fs::read(sentinel)?, b"hardware reads retain bytes");
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_hardware_effects=8 cpu_positive=true block_positive=true memory_positive={memory_positive} network_positive={network_positive} native_refusals_are_not_support=true no_configuration_or_controller_io=true");
    Ok(())
}
