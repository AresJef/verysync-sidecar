//! Observe native hardware data and native backend refusal independently.
use super::managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{Error, ManagedInstance, ResponseDiagnostic, TargetPath};

#[path = "linux32_memory_prerequisite.rs"]
mod linux32_memory_prerequisite;

fn native_error_message(response: &ResponseDiagnostic) -> TestResult<String> {
    assert_eq!(response.status(), 200);
    let value: serde_json::Value = serde_json::from_slice(response.body_bytes())?;
    Ok(value["error"]
        .as_str()
        .filter(|text| !text.is_empty())
        .ok_or("native hardware refusal has no error message")?
        .to_owned())
}

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
            let category = if text == "could not determine total usable bytes of memory" {
                "ghw_total_usable_unavailable"
            } else if text.contains("unable to populate sysctl map") {
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

#[cfg(all(target_os = "linux", target_arch = "s390x"))]
fn observed_s390x_cpu_parser_limitation() -> bool {
    use std::io::Read;
    let read_bounded = |path: &std::path::Path, limit: u64| {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
            .ok()
            .filter(|_| bytes.len() as u64 <= limit)
            .map(|_| bytes)
    };
    let cpuinfo = read_bounded(std::path::Path::new("/proc/cpuinfo"), 1_048_576);
    let text = cpuinfo
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok());
    let exact_processor_key = text.map(|text| {
        text.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(key, _)| key.trim() == "processor")
        })
    });
    let s390_processor_record = text.map(|text| {
        text.lines().any(|line| {
            line.split_once(':').is_some_and(|(key, value)| {
                key.trim().strip_prefix("processor ").is_some_and(|id| {
                    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
                }) && value.contains("version")
            })
        })
    });
    let binary = std::env::var_os("VERYSYNC_TEST_BINARY")
        .and_then(|path| read_bounded(std::path::Path::new(&path), 67_108_864));
    let ghw_013 = binary.as_ref().map(|bytes| {
        let record = b"\ndep\tgithub.com/jaypipes/ghw\tv0.13.0\t";
        bytes.windows(record.len()).any(|window| window == record)
    });
    println!(
        "native s390x CPU prerequisites: {}",
        serde_json::json!({
            "explicit_s390x_emulation_profile":std::env::var("VERYSYNC_TEST_EMULATION_PROFILE").ok().as_deref()==Some("linux-s390x-standard"),
            "guest_cpuinfo_bounded_utf8":text.is_some(),"exact_processor_key_present":exact_processor_key,
            "s390_processor_record_present":s390_processor_record,"fixed_core_ghw_013_build_record":ghw_013,
            "positive_cpu_claim_requires_positive_data":true,"hardware_attributes_omitted":true
        })
    );
    std::env::var("VERYSYNC_TEST_EMULATION_PROFILE")
        .ok()
        .as_deref()
        == Some("linux-s390x-standard")
        && text.is_some()
        && exact_processor_key == Some(false)
        && s390_processor_record == Some(true)
        && ghw_013 == Some(true)
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
    // Complete each independent read once before propagating any failure.
    // Native empty/refused inventory is separate from positive hardware data.
    let cpu = cpu?;
    #[cfg(all(target_os = "linux", target_arch = "s390x"))]
    let cpu_native_empty = cpu.total_cores == 0
        && cpu.total_threads == 0
        && cpu.processors.as_ref().is_some_and(Vec::is_empty)
        && observed_s390x_cpu_parser_limitation();
    #[cfg(not(all(target_os = "linux", target_arch = "s390x")))]
    let cpu_native_empty = false;
    if !cpu_native_empty {
        assert!(cpu.total_cores > 0 && cpu.total_threads > 0);
        assert!(!cpu
            .processors
            .as_ref()
            .ok_or("native packages unreported")?
            .is_empty());
    }
    let cpu_positive = !cpu_native_empty;
    let darwin = owner.client().instance().version.os == "darwin";
    let (block_positive, block_native_empty, block_native_refusal) = match blocks {
        Ok(blocks)
            if darwin
                && blocks.total_size_bytes == 0
                && blocks.disks.as_ref().is_some_and(Vec::is_empty) =>
        {
            (false, true, false)
        }
        Ok(blocks) => {
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
            (true, false, false)
        }
        Err(Error::Api { response, .. }) if darwin => {
            let message = native_error_message(&response)?;
            // Exact upstream ghw v0.13.0 rejection observed on the hosted Mac.
            // Unknown errors and a supposedly successful one-node result fail.
            let nodes = message
                .split_once("ioreg unmarshal resulted in ")
                .and_then(|(_, tail)| tail.strip_suffix(" I/O device tree nodes (expected 1)"))
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or("unverified native block refusal; preserve the failure")?;
            assert_ne!(nodes, 1);
            (false, false, true)
        }
        Err(error) => return Err(error.into()),
    };
    let (memory_positive, memory_native_refusal) = match memory {
        Ok(value) => {
            assert!(
                !darwin,
                "fixed Darwin backend unexpectedly changed; review native evidence"
            );
            let _ = value.total_usable_bytes;
            (true, false)
        }
        Err(Error::Api { response, .. }) if darwin => {
            assert!(native_error_message(&response)?.contains("not implemented"));
            (false, true)
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "32"))]
        Err(Error::Api { response, .. }) => {
            use std::io::Read;
            assert!(matches!(
                owner.client().instance().version.arch.as_str(),
                "386" | "arm"
            ));
            assert!(
                native_error_message(&response)?
                    == "Could not determine total usable bytes of memory",
                "unverified native total-usable-memory refusal"
            );
            // Explicit test-only prerequisite observation, never an SDK fallback
            // or an attempt to correct the target's native hardware data.
            let mut meminfo = String::new();
            std::fs::File::open(std::path::Path::new("/proc/meminfo"))?
                .take(65537)
                .read_to_string(&mut meminfo)?;
            assert!(
                meminfo.len() <= 65536,
                "unverified memory prerequisite size"
            );
            assert!(
                linux32_memory_prerequisite::unusable_wrapped_total(&meminfo)?,
                "the exact native refusal has no matching verified int32 prerequisite"
            );
            (false, true)
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
        Err(Error::Api { response, .. }) if darwin => {
            assert!(native_error_message(&response)?.contains("not implemented"));
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
    println!("native_hardware_observations=4 cpu_positive={cpu_positive} cpu_native_empty={cpu_native_empty} block_positive={block_positive} block_native_empty={block_native_empty} block_native_refusal={block_native_refusal} memory_positive={memory_positive} memory_native_refusal={memory_native_refusal} network_positive={network_positive} native_refusals_are_not_support=true identity_and_folder_state_retained=true sentinel_retained=true normal_tree_exit=true no_sdk_hardware_fallback=true");
    Ok(())
}
