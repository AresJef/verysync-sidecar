//! Native hardware reads with explicit error-envelope and schema checks.
use super::Client;
use crate::{
    Error, NativeBlockHardware, NativeCpuHardware, NativeMemoryHardware, NativeNetworkHardware,
    ResponseDiagnostic, Result,
};
use serde::de::DeserializeOwned;

impl Client {
    /// Read native CPU packages/cores without changing scheduling or measuring performance.
    /// Native null records and private unknown fields are retained.
    pub async fn native_cpu_hardware(&self) -> Result<NativeCpuHardware> {
        self.read_native_hardware(
            "rest/hardware/cpu",
            &["total_cores", "total_threads", "processors"],
        )
        .await
    }
    /// Read native memory inventory. A native unsupported/permission error is an
    /// error, including HTTP 200 error envelopes; it is never an empty success.
    pub async fn native_memory_hardware(&self) -> Result<NativeMemoryHardware> {
        self.read_native_hardware(
            "rest/hardware/memory",
            &[
                "total_physical_bytes",
                "total_usable_bytes",
                "supported_page_sizes",
                "modules",
            ],
        )
        .await
    }
    /// Read native disk/partition inventory, not filesystem free space or unique
    /// physical capacity. Mount text uses the connected target's path rules.
    pub async fn native_block_hardware(&self) -> Result<NativeBlockHardware> {
        let mut result: NativeBlockHardware = self
            .read_native_hardware("rest/hardware/blockstorage", &["total_size_bytes", "disks"])
            .await?;
        let style = self.folder_path_style()?;
        for disk in result.disks.iter_mut().flatten().flatten() {
            for partition in disk.partitions.iter_mut().flatten().flatten() {
                partition.path_style = Some(style);
            }
        }
        Ok(result)
    }
    /// Read native NIC inventory/capabilities. This changes no network setting,
    /// contacts no peer, and does not interpret link labels as measured throughput.
    pub async fn native_network_hardware(&self) -> Result<NativeNetworkHardware> {
        self.read_native_hardware("rest/hardware/network", &["nics"])
            .await
    }
    async fn read_native_hardware<T: DeserializeOwned>(
        &self,
        route: &str,
        required: &[&str],
    ) -> Result<T> {
        let operation = "read native hardware inventory";
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection.management_url(route, &[])?,
                None,
                false,
            )
            .await?;
        let invalid = || Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, bytes.clone()),
        };
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let object = value.as_object().ok_or_else(invalid)?;
        if let Some(error) = object.get("error") {
            let error = error.as_str().ok_or_else(invalid)?;
            if !error.is_empty() {
                return Err(Error::Api {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                });
            }
        }
        if required.iter().any(|name| !object.contains_key(*name)) {
            return Err(invalid());
        }
        serde_json::from_value(value).map_err(|_| invalid())
    }
}
