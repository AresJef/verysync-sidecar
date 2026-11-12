//! Explicit management credentials and device identity values.

use std::fmt;

use reqwest::header::HeaderValue;

use crate::{Error, Result};

/// A management API key whose debug representation is always redacted.
///
/// Cloning a key shares its header storage. The library does not install a
/// global credential provider or look up credentials in ambient configuration.
#[derive(Clone)]
pub struct ApiKey(HeaderValue);

impl ApiKey {
    /// Validate a nonempty ASCII key without control characters.
    ///
    /// Invalid values are not included in errors. The key is sent only as a
    /// sensitive `X-API-Key` header on the explicit management connection.
    pub fn new(value: &str) -> Result<Self> {
        if value.is_empty() || !value.is_ascii() || value.bytes().any(|b| b.is_ascii_control()) {
            return Err(Error::InvalidCredential {
                reason: "API key must be nonempty ASCII without control characters",
            });
        }
        let mut header = HeaderValue::from_str(value).map_err(|_| Error::InvalidCredential {
            reason: "API key is not a valid HTTP header value",
        })?;
        header.set_sensitive(true);
        Ok(Self(header))
    }

    pub(crate) fn header(&self) -> HeaderValue {
        self.0.clone()
    }

    pub(crate) fn redact(&self, text: &str) -> String {
        match self.0.to_str() {
            Ok(key) => text.replace(key, "[REDACTED]"),
            Err(_) => "[REDACTED]".to_owned(),
        }
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKey([REDACTED])")
    }
}

/// A device identity in the engine's uppercase, hyphenated character layout.
///
/// Parsing checks the eight groups of seven Base32 characters. It does not
/// claim to verify the underlying device certificate or its cryptographic key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DeviceId(String);

impl DeviceId {
    /// Parse the canonical character layout without changing the supplied ID.
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() != 63
            || value.split('-').count() != 8
            || value.split('-').any(|part| {
                part.len() != 7
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
            })
        {
            return Err(Error::InvalidIdentity {
                reason: "device ID must have eight groups of seven uppercase Base32 characters",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Borrow the unchanged canonical string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::str::FromStr for DeviceId {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}
