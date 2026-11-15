//! Native hardware schema, target path, refusal and privacy boundaries.
use super::*;
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn cpu() -> serde_json::Value {
    serde_json::json!({"total_cores":1,"total_threads":2,"processors":[{"id":4,"total_cores":1,"total_threads":2,"vendor":KEY,"model":KEY,"capabilities":[KEY],"cores":[null,{"id":8,"total_threads":2,"logical_processors":[1,3]}]}],"future":KEY})
}
fn memory() -> serde_json::Value {
    serde_json::json!({"total_physical_bytes":-1,"total_usable_bytes":1024,"supported_page_sizes":[4096],"modules":[null,{"label":KEY,"location":KEY,"serial_number":KEY,"size_bytes":-1,"vendor":KEY}]})
}
fn blocks() -> serde_json::Value {
    serde_json::json!({"total_size_bytes":1024,"disks":[{"name":KEY,"size_bytes":1024,"physical_block_size_bytes":512,"drive_type":"future-drive","removable":false,"storage_controller":"future-controller","bus_path":KEY,"vendor":KEY,"model":KEY,"serial_number":KEY,"wwn":KEY,"wwnNoExtension":KEY,"partitions":[null,{"name":KEY,"label":KEY,"mount_point":"/private/target","size_bytes":1024,"type":"future-partition","read_only":false,"uuid":KEY,"filesystem_label":KEY}]}]})
}
fn network() -> serde_json::Value {
    serde_json::json!({"nics":[null,{"name":KEY,"mac_address":KEY,"is_virtual":true,"capabilities":[null,{"name":KEY,"is_enabled":true,"can_enable":false}],"speed":"native label","duplex":"future-duplex"}]})
}

#[tokio::test]
async fn hardware_reads_preserve_nulls_negative_unknowns_native_categories_and_private_data(
) -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(cpu()),
        identity(),
        Reply::json(memory()),
        identity(),
        Reply::json(blocks()),
        identity(),
        Reply::json(network()),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let cpu = client.native_cpu_hardware().await?;
    assert_eq!(cpu.total_threads, 2);
    let package = cpu.processors.as_ref().unwrap()[0].as_ref().unwrap();
    assert!(package.cores.as_ref().unwrap()[0].is_none());
    assert_eq!(package.cores.as_ref().unwrap()[1].as_ref().unwrap().id, 8);
    let memory = client.native_memory_hardware().await?;
    assert_eq!(memory.total_physical_bytes, -1);
    assert!(memory.modules.as_ref().unwrap()[0].is_none());
    let blocks = client.native_block_hardware().await?;
    let disk = blocks.disks.as_ref().unwrap()[0].as_ref().unwrap();
    assert_eq!(disk.drive_type, "future-drive");
    let partition = disk.partitions.as_ref().unwrap()[1].as_ref().unwrap();
    let mount = partition.mount_point()?.unwrap();
    assert_eq!(mount.to_protocol()?, "/private/target");
    assert!(mount.local_path().is_none());
    let network = client.native_network_hardware().await?;
    assert!(network.nics.as_ref().unwrap()[0].is_none());
    for debug in [
        format!("{cpu:?}"),
        format!("{package:?}"),
        format!("{memory:?}"),
        format!("{blocks:?}"),
        format!("{disk:?}"),
        format!("{partition:?}"),
        format!("{network:?}"),
    ] {
        assert!(!debug.contains(KEY));
    }
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 10);
    for (index, name) in [
        (3, "cpu"),
        (5, "memory"),
        (7, "blockstorage"),
        (9, "network"),
    ] {
        assert!(requests[index].starts_with(&format!("GET /prefix/rest/hardware/{name} ")));
    }
    Ok(())
}

#[tokio::test]
async fn hardware_native_errors_and_missing_schemas_are_not_empty_successes() -> TestResult {
    for body in [
        serde_json::json!({"error":KEY}),
        serde_json::json!({}),
        serde_json::json!({"error":false}),
    ] {
        for kind in 0..4 {
            let server = ScriptedServer::start(vec![
                version(),
                identity(),
                identity(),
                Reply::json(body.clone()),
            ])
            .await?;
            let client = Client::connect(server.options()?).await?;
            let error = match kind {
                0 => client.native_cpu_hardware().await.unwrap_err(),
                1 => client.native_memory_hardware().await.unwrap_err(),
                2 => client.native_block_hardware().await.unwrap_err(),
                _ => client.native_network_hardware().await.unwrap_err(),
            };
            if body.get("error").is_some_and(|v| v.is_string()) {
                assert!(matches!(error, Error::Api { .. }));
            } else {
                assert!(matches!(error, Error::InvalidResponse { .. }));
            }
            assert!(!format!("{error:?}").contains(KEY));
            assert_eq!(server.finish().await?.len(), 4);
        }
    }
    Ok(())
}

#[tokio::test]
async fn hardware_null_inventory_is_unknown_and_changed_identity_stops_the_read() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"nics":null})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(client.native_network_hardware().await?.nics.is_none());
    assert_eq!(server.finish().await?.len(), 4);
    let other = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        Reply::json(serde_json::json!({"myID":other})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.native_cpu_hardware().await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}
