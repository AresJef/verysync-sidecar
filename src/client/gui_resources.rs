//! Selected native GUI resources, without implementing or evaluating the GUI.
use super::Client;
use crate::{Error, NativeGuiMetadata, NativeQrCode, ResponseDiagnostic, Result};

impl Client {
    /// Read the native language preferences for one explicit Accept-Language
    /// header. This is request-header negotiation, not changing the engine or
    /// a browser's selected language. Native order, casing and empty entries
    /// remain intact; no host locale or browser storage is inspected.
    pub async fn native_preferred_languages(&self, accept_language: &str) -> Result<Vec<String>> {
        let invalid = || Error::InvalidConfiguration {
            reason: "language header must be bounded and free of controls",
        };
        if accept_language.len() > 8192 || accept_language.chars().any(char::is_control) {
            return Err(invalid());
        }
        let header =
            reqwest::header::HeaderValue::from_str(accept_language).map_err(|_| invalid())?;
        let operation = "read native language preferences";
        self.system_status().await?;
        let outgoing = self
            .connection
            .http
            .get(self.connection.management_url("rest/svc/lang", &[])?)
            .header("X-API-Key", self.connection.key.header())
            .header("Accept-Language", header);
        let r = self
            .connection
            .request_prepared_response(operation, outgoing, false)
            .await?;
        serde_json::from_slice(r.body_bytes()).map_err(|_| Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(r.status(), r.body_bytes().to_vec()),
        })
    }

    /// Read the fixed `var metadata = <JSON>;` resource without executing code.
    /// Unexpected wrappers, schema or identity are errors. The same authenticated
    /// connection, prefix, response bound and deadline apply to this root resource.
    pub async fn native_gui_metadata(&self) -> Result<NativeGuiMetadata> {
        let operation = "read native GUI metadata";
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection.management_url("meta.js", &[])?,
                None,
                false,
            )
            .await?;
        let invalid = || Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, bytes.clone()),
        };
        let json = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.trim().strip_prefix("var metadata = "))
            .and_then(|s| s.strip_suffix(';'))
            .ok_or_else(invalid)?;
        let metadata: NativeGuiMetadata = serde_json::from_str(json).map_err(|_| invalid())?;
        if metadata.device_id != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: metadata.device_id,
            });
        }
        if metadata.device_id.as_str().split('-').next() != Some(metadata.short_device_id.as_str())
        {
            return Err(invalid());
        }
        Ok(metadata)
    }

    /// Explicitly ask the native program to encode text as a PNG QR code.
    /// The resource is `qr/` with a real trailing slash; text is query-encoded
    /// exactly once. Text over 4096 bytes is refused before I/O; the native QR
    /// capacity can be lower and native rejection is retained. Nothing is saved,
    /// decoded, opened or registered on the caller's behalf.
    pub async fn native_qr_code(&self, text: &str) -> Result<NativeQrCode> {
        if text.len() > 4096 {
            return Err(Error::InvalidConfiguration {
                reason: "native QR text exceeds the bounded request size",
            });
        }
        let operation = "read native QR code";
        self.system_status().await?;
        let outgoing = self
            .connection
            .http
            .get(self.connection.management_url("qr/", &[("text", text)])?)
            .header("X-API-Key", self.connection.key.header());
        let r = self
            .connection
            .request_prepared_response(operation, outgoing, false)
            .await?;
        let invalid = || Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(r.status(), r.body_bytes().to_vec()),
        };
        let media = r
            .headers()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
            .and_then(|s| s.split(';').next());
        let b = r.body_bytes();
        if media
            .map(str::trim)
            .is_none_or(|s| !s.eq_ignore_ascii_case("image/png"))
            || b.len() < 33
            || !b.starts_with(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR")
        {
            return Err(invalid());
        }
        let width = u32::from_be_bytes(b[16..20].try_into().map_err(|_| invalid())?);
        let height = u32::from_be_bytes(b[20..24].try_into().map_err(|_| invalid())?);
        if width == 0 || height == 0 {
            return Err(invalid());
        }
        Ok(NativeQrCode {
            bytes: b.to_vec(),
            width,
            height,
        })
    }
}
