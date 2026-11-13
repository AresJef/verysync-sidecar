//! Remote file-manager reads, separate from native controller filesystem I/O.
use super::Client;
use crate::{
    Error, ResourceChecksum, ResourceInfo, ResourcePath, ResourceVolume, ResponseDiagnostic, Result,
};
impl Client {
    /// Fetch the engine's thumbnail for an explicit resource with inline=true.
    /// The response must be nonempty image content within the configured byte
    /// limit. It can populate the engine's own cache; the SDK opens no local
    /// image and makes no promise about a fixed thumbnail size or encoding.
    pub async fn resource_thumbnail(&self, path: &ResourcePath) -> Result<crate::ResourcePreview> {
        self.system_status().await?;
        let operation = "read resource thumbnail";
        let mut url = self.resource_url("rest/f/api/preview/thumb", path)?;
        url.query_pairs_mut().append_pair("inline", "true");
        let request = self
            .connection
            .http
            .get(url)
            .header("X-API-Key", self.connection.key.header());
        let response = self
            .connection
            .request_prepared_response(operation, request, false)
            .await?;
        let media_type = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
            .filter(|value| value.to_ascii_lowercase().starts_with("image/"))
            .map(str::to_owned);
        let Some(media_type) = media_type else {
            return Err(Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(response.status, response.body),
            });
        };
        if response.body.is_empty() {
            return Err(Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(response.status, response.body),
            });
        }
        Ok(crate::ResourcePreview {
            media_type,
            bytes: response.body,
        })
    }
    /// Read actual file-manager mounts. An unknown/denied response is an error,
    /// never a successful empty list. This reads no local controller directory.
    pub async fn resource_volumes(&self) -> Result<Vec<ResourceVolume>> {
        self.system_status().await?;
        self.connection
            .get_json("read file-manager volumes", "rest/f/api/volumes")
            .await
    }
    /// Read one resource or directory tree page within the management response
    /// byte limit. File responses can contain inline text; responses above that
    /// bound return ResponseTooLarge. Nothing is opened on the controller.
    pub async fn resource_info(&self, path: &ResourcePath) -> Result<ResourceInfo> {
        self.read_resource_metadata(path, None)
            .await
            .map(|(value, _, _)| value)
    }
    /// Ask the engine to hash the actual remote file. A missing/malformed digest
    /// is an error, not a zero/empty digest or evidence that a transfer completed.
    pub async fn resource_checksum(
        &self,
        path: &ResourcePath,
        algorithm: ResourceChecksum,
    ) -> Result<String> {
        let (value, status, body) = self.read_resource_metadata(path, Some(algorithm)).await?;
        value
            .checksums
            .get(algorithm.name())
            .filter(|s| s.len() == algorithm.hex_len() && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .cloned()
            .ok_or(Error::InvalidResponse {
                operation: "read resource checksum",
                response: ResponseDiagnostic::new(status, body),
            })
    }
    async fn read_resource_metadata(
        &self,
        path: &ResourcePath,
        algorithm: Option<ResourceChecksum>,
    ) -> Result<(ResourceInfo, u16, Vec<u8>)> {
        self.system_status().await?;
        let operation = "read resource metadata";
        let mut url = self.resource_url("rest/f/api/resources", path)?;
        if let Some(algorithm) = algorithm {
            url.query_pairs_mut()
                .append_pair("checksum", algorithm.name());
        }
        let (status, body) = self
            .connection
            .request_bytes(operation, reqwest::Method::GET, url, None, false)
            .await?;
        let value = serde_json::from_slice(&body).map_err(|_| Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, body.clone()),
        })?;
        Ok((value, status, body))
    }
    pub(super) fn resource_url(&self, route: &str, path: &ResourcePath) -> Result<url::Url> {
        if path.style != self.folder_path_style()? {
            return Err(Error::InvalidPath {
                reason: "resource path syntax differs from the connected target",
            });
        }
        let mut url = self.connection.management_url(route, &[])?;
        // URL path setters discard literal ASCII tabs/newlines during parsing.
        // Serialize each logical component first, retaining C0 filenames and
        // encoding literal '%' exactly once. This constructs a URL path only;
        // native filesystem paths are never assembled here.
        const SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
            .remove(b'-')
            .remove(b'_')
            .remove(b'.')
            .remove(b'~');
        let mut encoded = url.path().trim_end_matches('/').to_owned();
        for component in
            std::iter::once(path.volume.as_str()).chain(path.components.iter().map(String::as_str))
        {
            encoded.push('/');
            encoded.extend(percent_encoding::utf8_percent_encode(component, SEGMENT));
        }
        if path.components.is_empty() {
            encoded.push('/');
        }
        url.set_path(&encoded);
        Ok(url)
    }
}
