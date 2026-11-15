//! Observe native hardware data and native backend refusal independently.
use super::managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{Error, ManagedInstance, TargetPath};

fn trace_hardware<T>(component: &'static str, result: &verysync_sidecar::Result<T>) {
    let (kind, status, length, category, native_tool) = match result {
        Ok(_) => ("data", None, None, None, None),
        Err(Error::Api { response, .. }) => {
            let value: serde_json::Value =
                serde_json::from_slice(response.body_bytes()).unwrap_or_default();
            let text = value["error"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let category = if text.contains("unable to populate sysctl map") {
                "sysctl_map_population"
            } else if text.contains("ioreg unmarshal resulted in") {
                "ioreg_node_shape"
            } else if text.contains("diskutil list plist unmarshal failed") {
                "diskutil_list_schema"
            } else if text.contains("diskutil list failed") {
                "diskutil_list"
            } else if text.contains("ioreg query for") {
                "ioreg_query"
            } else if text.contains("enabletools=false") {
                "external_tools_disabled"
            } else if text.contains("not implemented") || text.contains("unsupported") {
                "not_implemented"
            } else if text.contains("permission denied") || text.contains("operation not permitted")
            {
                "permission"
            } else if text.contains("resource temporarily unavailable") {
                "resource_unavailable"
            } else if text.contains("no such file") || text.contains("not found") {
                "missing_prerequisite"
            } else if text.contains("exit status") {
                "native_tool_exit"
            } else {
                "unclassified"
            };
            let tool = ["sysctl", "diskutil", "ioreg", "system_profiler"]
                .into_iter()
                .find(|name| text.contains(name));
            (
                "native_error",
                Some(response.status()),
                Some(response.body_bytes().len()),
                Some(category),
                tool,
            )
        }
        Err(_) => ("other_error", None, None, None, None),
    };
    // Only fixed labels and numeric metadata; never native error text, hardware
    // attributes, paths, serial numbers or a private inventory fingerprint.
    println!(
        "native hardware observation: {}",
        serde_json::json!({"component":component,"kind":kind,"http_status":status,"body_bytes":length,"category":category,"native_tool":native_tool})
    );
}

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
    let cpu = owner.client().native_cpu_hardware().await;
    trace_hardware("cpu", &cpu);
    let blocks = owner.client().native_block_hardware().await;
    trace_hardware("block", &blocks);
    let memory = owner.client().native_memory_hardware().await;
    trace_hardware("memory", &memory);
    let network = owner.client().native_network_hardware().await;
    trace_hardware("network", &network);
    if let Ok(value) = &blocks {
        println!(
            "native hardware block shape: {}",
            serde_json::json!({"total_is_zero":value.total_size_bytes==0,"disks_reported":value.disks.is_some(),"disks_empty":value.disks.as_ref().map(Vec::is_empty),"non_null_disk_present":value.disks.as_ref().map(|values|values.iter().any(Option::is_some))})
        );
    }
    // Complete each independent read once before propagating any failure. Keep
    // the original CPU/block data requirements and all cleanup assertions.
    let cpu = cpu?;
    assert!(cpu.total_cores > 0 && cpu.total_threads > 0);
    assert!(!cpu
        .processors
        .as_ref()
        .ok_or("native packages unreported")?
        .is_empty());
    let blocks = blocks?;
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
    let memory_positive = match memory {
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
    let network_positive = match network {
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
