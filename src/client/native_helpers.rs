//! Explicit native helpers, without local UI or automatic link handling.
use super::{mutation_error, Client};
use crate::{
    DeviceId, Error, NativeUsageReport, PendingNativeLink, ResponseDiagnostic, Result,
    TargetIpLocation,
};
use serde::Deserialize;
use std::{collections::BTreeMap, net::IpAddr};

impl Client {
    /// Normalize/validate a device ID using the target's native service. This
    /// accepts native forms such as lowercase or ungrouped text, unlike the
    /// local layout-only `DeviceId::parse`. It neither adds a device nor verifies
    /// possession of a remote certificate. Native rejection remains an error.
    pub async fn normalize_device_id(&self, value: &str) -> Result<DeviceId> {
        if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
            return Err(Error::InvalidIdentity {
                reason: "native device ID input must be nonempty, bounded and free of controls",
            });
        }
        #[derive(Deserialize)]
        struct Reply {
            id: DeviceId,
        }
        self.system_status().await?;
        let reply: Reply = self
            .connection
            .get_json_with_query(
                "normalize native device ID",
                "rest/svc/deviceid",
                &[("id", value)],
            )
            .await?;
        Ok(reply.id)
    }

    /// Explicitly generate one native decimal random number. No cryptographic
    /// strength, uniqueness or suitability for credentials is promised. Use
    /// `ApiKey::generate` for a secure management key instead. This GET is
    /// treated as a mutation because native random state can advance; it is
    /// never retried, including after a malformed acknowledgement.
    pub async fn native_random_number(&self) -> Result<u64> {
        #[derive(Deserialize)]
        struct Reply {
            random: String,
        }
        let operation = "generate native random number";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection
                    .management_url("rest/svc/random/number", &[])?,
                None,
                true,
            )
            .await?;
        let invalid = || {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                },
            )
        };
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if reply.random.is_empty() || !reply.random.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        reply.random.parse().map_err(|_| invalid())
    }

    /// Request target-side lookup for one explicit IP. This can use native
    /// network/data services; it is not a controller-side lookup. The echoed IP
    /// must match. Empty native location strings are preserved as valid data.
    pub async fn lookup_target_ip(&self, ip: IpAddr) -> Result<TargetIpLocation> {
        #[derive(Deserialize)]
        struct Reply {
            ip: IpAddr,
            pro: String,
            city: String,
            addr: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }
        let operation = "look up target IP location";
        self.system_status().await?;
        let value = ip.to_string();
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection
                    .management_url("rest/svc/ip/lookup", &[("ip", &value)])?,
                None,
                false,
            )
            .await?;
        let invalid = || Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, bytes.clone()),
        };
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if reply.ip != ip {
            return Err(invalid());
        }
        Ok(TargetIpLocation {
            ip,
            province: reply.pro,
            city: reply.city,
            description: reply.addr,
            extra: reply.extra,
        })
    }

    /// Explicitly collect the native report snapshot. The SDK neither enables
    /// usage reporting nor uploads this response. Collection can affect native
    /// diagnostic state, so it serializes with mutations and is never retried.
    /// Counters and benchmark-like fields remain native observations only.
    pub async fn collect_native_usage_report(&self) -> Result<NativeUsageReport> {
        let operation = "collect native usage report";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection.management_url("rest/svc/report", &[])?,
                None,
                true,
            )
            .await?;
        let invalid = || {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                },
            )
        };
        let report: NativeUsageReport = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if report.version.is_empty() || report.platform.is_empty() {
            return Err(invalid());
        }
        Ok(report)
    }

    /// Explicitly retrieve one native GUI-link snapshot. The fixed engine can
    /// return an empty link immediately. No returned text is opened, followed,
    /// parsed as a sharing key or automatically registered. Treat it as private,
    /// untrusted data. The call conservatively uses mutation semantics because
    /// native link delivery may consume state; uncertain results are not retried.
    pub async fn pending_native_link(&self) -> Result<PendingNativeLink> {
        #[derive(Deserialize)]
        struct Reply {
            link: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }
        let operation = "retrieve native pending link";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection.management_url("rest/svc/link/await", &[])?,
                None,
                true,
            )
            .await?;
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            )
        })?;
        Ok(PendingNativeLink {
            link: if reply.link.is_empty() {
                None
            } else {
                Some(reply.link)
            },
            extra: reply.extra,
        })
    }
}
