//! Explicit core-side maintenance without installing a controller logger.
use super::{mutation_error, Client};
use crate::{
    CoreDiagnostics, CoreErrorLog, CoreLogLevel, CoreLogLevelUpdate, CoreLogLevels,
    CoreLogSnapshot, CoreLogText, CoreMetricsSnapshot, CoreProfile, CoreProfileRequest, Error,
    ResponseDiagnostic, Result, TargetPath,
};
use crate::{IndexResetAcknowledgement, IndexResetScope};
use std::collections::BTreeMap;

fn validate_log_since(since: Option<&str>) -> Result<()> {
    if since.is_some_and(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control)) {
        return Err(invalid(
            "native log timestamp must be nonempty, bounded and control-free",
        ));
    }
    Ok(())
}

impl Client {
    /// Explicitly request a native synchronization-index reset for one configured
    /// folder or all folders. The native program can exit for restart; this does
    /// not stop/restart an owned instance on the caller's behalf.
    ///
    /// This is an acknowledgement, not proof of index removal or data retention.
    /// Coordinate peers and keep an independent state backup. Future rescans or
    /// synchronization can change files. The SDK does not delete controller
    /// paths, pause peers, retry or roll back this native operation.
    pub async fn request_index_reset(
        &self,
        scope: &IndexResetScope,
    ) -> Result<IndexResetAcknowledgement> {
        #[derive(serde::Deserialize)]
        struct Ack {
            ok: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }
        let operation = "request native synchronization index reset";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let (query, expected) = match scope {
            IndexResetScope::Folder(id) => {
                self.folder(id).await?;
                (
                    vec![("folder", id.as_str())],
                    format!("resetting folder {}", id.as_str()),
                )
            }
            IndexResetScope::AllFolders => (Vec::new(), "resetting database".to_owned()),
        };
        let url = self
            .connection
            .management_url("rest/system/reset", &query)?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::POST, url, None, true)
            .await?;
        let ack: Ack = serde_json::from_slice(&bytes).map_err(|_| {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                },
            )
        })?;
        if ack.ok != expected {
            return Err(mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            ));
        }
        Ok(IndexResetAcknowledgement {
            scope: scope.clone(),
            restart_expected: true,
            native_message: ack.ok,
            extra: ack.extra,
        })
    }
    /// Collect one explicitly requested native profile. This GET is treated as
    /// a mutation: heap collection invokes native GC and CPU collection changes
    /// native profiler state. No automatic retry, storage, global controller
    /// profiling or program restart occurs. Native gzip bytes remain unchanged.
    ///
    /// The connection's configured deadline/response bound still applies. A CPU
    /// duration must be 1..=30 whole seconds; choose a longer request deadline
    /// explicitly when needed. Cancellation or a transport failure can leave
    /// profiling active on the target until its native duration ends; dropping
    /// this future does not prove native cancellation.
    ///
    /// ```rust,no_run
    /// # async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
    /// use verysync_sidecar::CoreProfileRequest;
    /// let profile = client.collect_core_profile(CoreProfileRequest::Cpu {
    ///     duration_seconds: 1,
    /// }).await?;
    /// // Explicit access can reveal private native profiling data.
    /// assert!(!profile.body_bytes().is_empty());
    /// # Ok(()) }
    /// ```
    pub async fn collect_core_profile(&self, request: CoreProfileRequest) -> Result<CoreProfile> {
        let (operation, endpoint, duration) = match request {
            CoreProfileRequest::Heap => {
                ("collect native heap profile", "rest/debug/heapprof", None)
            }
            CoreProfileRequest::Cpu { duration_seconds } => {
                if !(1..=30).contains(&duration_seconds) {
                    return Err(invalid("CPU profile duration must be 1..=30 whole seconds"));
                }
                (
                    "collect native CPU profile",
                    "rest/debug/cpuprof",
                    Some(format!("{duration_seconds}s")),
                )
            }
        };
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let query = duration
            .as_ref()
            .map(|d| vec![("duration", d.as_str())])
            .unwrap_or_default();
        let url = self.connection.management_url(endpoint, &query)?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::GET, url, None, true)
            .await?;
        // A gzip member has at least a fixed header and CRC/size trailer. Do not
        // turn an empty body or an HTTP-success JSON/HTML error into a profile.
        if bytes.len() < 18 || !bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
            return Err(mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            ));
        }
        Ok(CoreProfile { request, bytes })
    }

    /// Explicitly collect the native support archive once.
    ///
    /// The fixed handler collects target configuration/logs/metrics and native
    /// heap, CPU and goroutine profiles. Its CPU collection runs for four seconds
    /// when available. This GET serializes with mutations because native GC and
    /// profiler state can change. It does not change the GUI debugging setting,
    /// install a controller profiler, save a file, unpack data or retry.
    ///
    /// The connection's response bound and deadline apply without extension.
    /// Cancellation or a failed response can leave native collection running;
    /// it does not prove target cancellation. Native entries can be unavailable,
    /// and native redaction is not a guarantee that the ZIP is safe to publish.
    /// ZIP signature validation is not CRC or archive-content validation.
    ///
    /// ```rust,no_run
    /// # async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
    /// let bundle = client.collect_core_support_bundle().await?;
    /// // Inspect or store privately only when explicitly selected by your caller.
    /// assert!(!bundle.body_bytes().is_empty());
    /// # Ok(()) }
    /// ```
    pub async fn collect_core_support_bundle(&self) -> Result<crate::CoreSupportBundle> {
        let operation = "collect native support bundle";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/debug/support", &[])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::GET, url, None, true)
            .await?;
        if bytes.len() < 52 || !bytes.starts_with(b"PK\x03\x04") {
            return Err(mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            ));
        }
        Ok(crate::CoreSupportBundle { bytes })
    }

    /// Read one bounded native metrics exposition from `metrics` under the
    /// selected management base path. The API key is attached normally. This
    /// does not enable unauthenticated metrics, open another listener, parse
    /// rates, convert units or configure the caller's metrics exporter.
    pub async fn core_metrics(&self) -> Result<CoreMetricsSnapshot> {
        self.system_status().await?;
        let operation = "read native core metrics";
        let url = self.connection.management_url("metrics", &[])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::GET, url, None, false)
            .await?;
        let text = String::from_utf8(bytes).map_err(|error| Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, error.into_bytes()),
        })?;
        if !text.starts_with("# HELP ") || !text.lines().any(|line| line.starts_with("# TYPE ")) {
            return Err(Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(status, text.into_bytes()),
            });
        }
        Ok(CoreMetricsSnapshot { text })
    }

    /// Read the actual core error log. Native null is retained; malformed or
    /// missing error containers are errors, not successful empty logs.
    pub async fn core_errors(&self) -> Result<CoreErrorLog> {
        self.system_status().await?;
        self.connection
            .get_json("read core error log", "rest/system/error")
            .await
    }
    /// Register one explicit nonempty UTF-8 message of at most 8 KiB in the
    /// target core's error log, then return actual readback. The native core
    /// wraps external reports in its own message format; the SDK preserves it.
    /// No write is retried.
    /// This does not write to the caller's global logger or stderr.
    pub async fn record_core_error(&self, message: &str) -> Result<CoreErrorLog> {
        if message.is_empty() || message.len() > 8192 || message.contains('\0') {
            return Err(invalid(
                "core error message must be nonempty, NUL-free and at most 8 KiB",
            ));
        }
        let operation = "record explicit core error";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/system/error", &[])?;
        let request = self
            .connection
            .http
            .post(url)
            .header("X-API-Key", self.connection.key.header())
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(message.to_owned());
        self.maintenance_empty_ack(operation, request).await?;
        self.core_errors()
            .await
            .map_err(|e| mutation_error(operation, true, e))
    }
    /// Clear the target's current error log once, then observe its actual log.
    /// Concurrent native errors can appear again; inspect the returned snapshot.
    /// No retry, backup or restoration of removed log entries is implicit.
    pub async fn clear_core_errors(&self) -> Result<CoreErrorLog> {
        let operation = "clear core error log";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self
            .connection
            .management_url("rest/system/error/clear", &[])?;
        let request = self
            .connection
            .http
            .post(url)
            .header("X-API-Key", self.connection.key.header());
        self.maintenance_empty_ack(operation, request).await?;
        self.core_errors()
            .await
            .map_err(|e| mutation_error(operation, true, e))
    }
    /// Read a bounded native log snapshot, optionally using an exact native
    /// timestamp from an earlier entry. No timezone conversion, retry, polling,
    /// deduplication or controller logging is performed.
    pub async fn core_log(&self, since: Option<&str>) -> Result<CoreLogSnapshot> {
        validate_log_since(since)?;
        self.system_status().await?;
        let query = since.map(|s| vec![("since", s)]).unwrap_or_default();
        self.connection
            .get_json_with_query("read core log", "rest/system/log", &query)
            .await
    }
    /// Read the native plain-text log once, optionally preserving an exact
    /// native timestamp's offset and precision. Text and line endings remain
    /// unchanged; an empty filtered snapshot is valid. Identity checks,
    /// response bounds and deadlines apply. Invalid UTF-8 retains bounded
    /// diagnostics as an error; no lossy replacement or automatic retry occurs.
    /// The SDK does not drain logs, parse lines or install a controller logger.
    pub async fn core_log_text(&self, since: Option<&str>) -> Result<CoreLogText> {
        validate_log_since(since)?;
        self.system_status().await?;
        let operation = "read native text log";
        let query = since.map(|s| vec![("since", s)]).unwrap_or_default();
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection
                    .management_url("rest/system/log.txt", &query)?,
                None,
                false,
            )
            .await?;
        let text = String::from_utf8(bytes).map_err(|error| Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, error.into_bytes()),
        })?;
        Ok(CoreLogText { text })
    }
    /// Read active core-side package levels. This neither installs a logger nor
    /// changes the calling application's logging configuration.
    pub async fn core_log_levels(&self) -> Result<CoreLogLevels> {
        self.system_status().await?;
        self.connection
            .get_json("read core log levels", "rest/system/loglevels")
            .await
    }
    /// Set 1..=128 exact existing packages to verified native levels, preserving
    /// unselected packages. Readback reports actual runtime settings; persistence
    /// after program restart is a separate condition. Changes are never retried.
    ///
    /// ```rust,no_run
    /// # async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
    /// use std::collections::BTreeMap;
    /// use verysync_sidecar::CoreLogLevel;
    /// let result = client.set_core_log_levels(&BTreeMap::from([
    ///     ("main".to_owned(), CoreLogLevel::Info),
    /// ])).await?;
    /// assert!(result.requested_levels_match);
    /// # Ok(()) }
    /// ```
    pub async fn set_core_log_levels(
        &self,
        levels: &BTreeMap<String, CoreLogLevel>,
    ) -> Result<CoreLogLevelUpdate> {
        let body = core_log_level_body(levels)?;
        let operation = "set core log levels";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let before: CoreLogLevels = self
            .connection
            .get_json(operation, "rest/system/loglevels")
            .await?;
        if levels.keys().any(|name| !before.levels.contains_key(name)) {
            return Err(invalid(
                "a requested package is absent from active native log levels",
            ));
        }
        let url = self
            .connection
            .management_url("rest/system/loglevels", &[])?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::POST,
                url,
                Some(&serde_json::json!(body)),
                true,
            )
            .await?;
        if !bytes.is_empty() {
            return Err(mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            ));
        }
        let configuration = self
            .core_log_levels()
            .await
            .map_err(|e| mutation_error(operation, true, e))?;
        let requested_levels_match = levels
            .iter()
            .all(|(name, level)| configuration.levels.get(name) == Some(level));
        Ok(CoreLogLevelUpdate {
            configuration,
            requested_levels_match,
        })
    }
    /// Read native database-size metadata and explicit target-syntax locations.
    /// This opens no controller path and does not infer filesystem permissions.
    pub async fn core_diagnostics(&self) -> Result<CoreDiagnostics> {
        #[derive(serde::Deserialize)]
        struct Wire {
            #[serde(rename = "databaseSize")]
            size: u64,
            locations: BTreeMap<String, String>,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }
        self.system_status().await?;
        let operation = "read core diagnostics";
        let url = self
            .connection
            .management_url("rest/system/diagnostics", &[])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::GET, url, None, false)
            .await?;
        let invalid = || Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, bytes.clone()),
        };
        let wire: Wire = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let style = self.folder_path_style()?;
        let locations = wire
            .locations
            .into_iter()
            .map(|(name, value)| {
                TargetPath::remote(style, value)
                    .map(|path| (name, path))
                    .map_err(|_| invalid())
            })
            .collect::<Result<_>>()?;
        Ok(CoreDiagnostics {
            database_size: wire.size,
            locations,
            extra: wire.extra,
        })
    }
    async fn maintenance_empty_ack(
        &self,
        operation: &'static str,
        request: reqwest::RequestBuilder,
    ) -> Result<()> {
        let (status, bytes) = self
            .connection
            .request_prepared(operation, request, true)
            .await?;
        verify_empty_maintenance_reply(operation, status, &bytes)
    }
}
fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfiguration { reason }
}

pub(super) fn core_log_level_body(
    levels: &BTreeMap<String, CoreLogLevel>,
) -> Result<BTreeMap<&str, &str>> {
    if !(1..=128).contains(&levels.len())
        || levels.iter().any(|(name, level)| {
            name.is_empty()
                || name.len() > 128
                || name.chars().any(char::is_control)
                || level.wire().is_none()
        })
    {
        return Err(invalid(
            "core log update requires bounded existing package names and verified levels",
        ));
    }
    let body: BTreeMap<&str, &str> = levels
        .iter()
        .map(|(name, level)| {
            level
                .wire()
                .map(|value| (name.as_str(), value))
                .ok_or_else(|| invalid("unmodeled core log level cannot be submitted"))
        })
        .collect::<Result<_>>()?;
    Ok(body)
}

pub(super) fn verify_empty_maintenance_reply(
    operation: &'static str,
    status: u16,
    bytes: &[u8],
) -> Result<()> {
    if !bytes.is_empty() {
        return Err(mutation_error(
            operation,
            true,
            Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(status, bytes.to_vec()),
            },
        ));
    }
    Ok(())
}
