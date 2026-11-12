//! Explicit raw requests bound to an authenticated management connection.

use crate::{Error, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::fmt;

/// HTTP methods available through the selected management connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawMethod {
    /// HTTP GET. Some upstream GET routes still modify state.
    Get,
    /// HTTP HEAD.
    Head,
    /// HTTP OPTIONS.
    Options,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}
impl RawMethod {
    pub(crate) fn http(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::Head => reqwest::Method::HEAD,
            Self::Options => reqwest::Method::OPTIONS,
            Self::Post => reqwest::Method::POST,
            Self::Put => reqwest::Method::PUT,
            Self::Patch => reqwest::Method::PATCH,
            Self::Delete => reqwest::Method::DELETE,
        }
    }
}

/// The caller's explicit declaration of an unmodeled operation's effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestEffect {
    /// The caller has established that this specific operation only reads data.
    ReadOnly,
    /// The operation can modify state, including state-changing GET routes.
    MayModify,
}

/// A buffered request with structured relative path components and query values.
///
/// Components are encoded individually under the connection's selected base
/// path. They never supply a scheme, authority or independent URL. Debug omits
/// path/query/header/body values because those may contain credentials.
#[derive(Clone)]
pub struct RawRequest {
    pub(crate) method: RawMethod,
    pub(crate) components: Vec<String>,
    pub(crate) query: Vec<(String, String)>,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) effect: RequestEffect,
}
impl RawRequest {
    /// Choose a method, explicit path components and known request effects.
    ///
    /// Empty, control-containing and literal dot components are rejected. An
    /// empty component collection addresses the configured base path itself.
    /// Slashes and percent signs inside a component are encoded as data.
    pub fn new<S: Into<String>>(
        method: RawMethod,
        components: impl IntoIterator<Item = S>,
        effect: RequestEffect,
    ) -> Result<Self> {
        let components: Vec<String> = components.into_iter().map(Into::into).collect();
        if components.iter().any(|part| {
            part.is_empty()
                || matches!(part.as_str(), "." | "..")
                || part.chars().any(char::is_control)
        }) {
            return Err(Error::InvalidConfiguration {
                reason: "raw path components must be nonempty, non-dot and free of controls",
            });
        }
        Ok(Self {
            method,
            components,
            query: Vec::new(),
            headers: HeaderMap::new(),
            body: None,
            effect,
        })
    }
    /// Append one query parameter, encoding its name and value exactly once.
    pub fn query(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query.push((name.into(), value.into()));
        self
    }
    /// Set an ordinary request header without overriding transport/authentication.
    ///
    /// Host, connection authentication and hop-by-hop/framing headers are
    /// protected. Header parsing rejects controls without echoing their values.
    pub fn header(mut self, name: &str, value: &str) -> Result<Self> {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| Error::InvalidConfiguration {
                reason: "invalid raw request header name",
            })?;
        if matches!(
            name.as_str(),
            "host"
                | "authorization"
                | "proxy-authorization"
                | "x-api-key"
                | "connection"
                | "proxy-connection"
                | "content-length"
                | "transfer-encoding"
                | "upgrade"
                | "keep-alive"
                | "te"
                | "trailer"
        ) {
            return Err(Error::InvalidConfiguration {
                reason: "raw requests cannot override connection authentication, host or framing",
            });
        }
        let mut value = HeaderValue::from_str(value).map_err(|_| Error::InvalidConfiguration {
            reason: "invalid raw request header value",
        })?;
        value.set_sensitive(true);
        self.headers.insert(name, value);
        Ok(self)
    }
    /// Supply an explicit buffered body. No file is opened or streamed implicitly.
    pub fn body(mut self, bytes: Vec<u8>) -> Self {
        self.body = Some(bytes);
        self
    }
    /// Encode a JSON value and select its JSON content type.
    pub fn json_body(self, value: &serde_json::Value) -> Result<Self> {
        let bytes = serde_json::to_vec(value).map_err(|_| Error::InvalidConfiguration {
            reason: "raw JSON body cannot be encoded",
        })?;
        Ok(self.header("Content-Type", "application/json")?.body(bytes))
    }
}
impl fmt::Debug for RawRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawRequest")
            .field("method", &self.method)
            .field("effect", &self.effect)
            .field("component_count", &self.components.len())
            .field("query_count", &self.query.len())
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

/// A bounded raw HTTP response, without a typed business-success interpretation.
///
/// HTTP status, duplicate headers and exact body bytes remain available even
/// for upstream errors. Header/body values may contain secrets; Debug omits them.
#[derive(Clone)]
pub struct RawResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, Vec<u8>)>,
    pub(crate) body: Vec<u8>,
}
impl RawResponse {
    /// The actual upstream HTTP status, including non-success statuses.
    pub fn status(&self) -> u16 {
        self.status
    }
    /// Explicitly inspect exact bounded body bytes; no JSON envelope is inferred.
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }
    /// Inspect headers with duplicate values and original value bytes preserved.
    pub fn headers(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
    }
}
impl fmt::Debug for RawResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}
