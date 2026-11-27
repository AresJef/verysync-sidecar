//! Typed control identity reads and the recovery-only management facade.

use std::{fmt, time::SystemTime};

use super::{Client, ConnectOptions, EngineVersion};
use crate::control_operation::version_fingerprint;
use crate::{
    managed::ManagedControlGeneration, ControlOperationReceipt, DeviceId, Error, GuiListenerConfig,
    ManagementEndpoint, Result,
};

/// Device identity and engine metadata observed on one selected management connection.
///
/// Identity is reported by the authenticated engine. Its reads are separate requests.
/// They cannot establish an atomic snapshot or identify a borrowed process generation.
#[derive(Clone)]
pub struct ControlIdentityObservation {
    device_id: DeviceId,
    engine_version: EngineVersion,
    observed_at: SystemTime,
    generation: Option<ManagedControlGeneration>,
}

impl ControlIdentityObservation {
    /// Borrow the device identity returned by the selected endpoint.
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Inspect engine metadata explicitly. Build labels and additional fields are upstream data.
    pub fn engine_version(&self) -> &EngineVersion {
        &self.engine_version
    }

    /// Return the caller's wall-clock time when the identity checks finished.
    pub fn observed_at(&self) -> SystemTime {
        self.observed_at
    }

    /// Borrow the observed generation of a locally owned instance, if available.
    ///
    /// A borrowed management connection cannot distinguish a replacement process
    /// using the same logical device identity, so its generation is absent.
    pub fn process_generation(&self) -> Option<&ManagedControlGeneration> {
        self.generation.as_ref()
    }

    pub(crate) fn with_generation(mut self, generation: ManagedControlGeneration) -> Self {
        self.generation = Some(generation);
        self
    }
}

impl fmt::Debug for ControlIdentityObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlIdentityObservation")
            .field("observed_at", &self.observed_at)
            .field("owned_generation_observed", &self.generation.is_some())
            .finish_non_exhaustive()
    }
}

impl Client {
    pub(super) fn require_prepared_control_target(
        &self,
        endpoint: &ManagementEndpoint,
        receipt: &ControlOperationReceipt,
    ) -> Result<()> {
        if endpoint != self.endpoint() {
            return Err(Error::InvalidConfiguration {
                reason: "the prepared operation belongs to a different management address",
            });
        }
        if receipt.target_device_id() != &self.instance().device_id {
            return Err(Error::IdentityMismatch {
                expected: receipt.target_device_id().clone(),
                actual: self.instance().device_id.clone(),
            });
        }
        if receipt.version_fingerprint() != &version_fingerprint(&self.instance().version.version) {
            return Err(Error::InvalidConfiguration {
                reason: "the prepared operation belongs to a different engine version",
            });
        }
        Ok(())
    }

    /// Check the selected endpoint's version and device identity again.
    ///
    /// The version must match this connection's handshake. The check uses named
    /// reads and does not establish ownership of an engine process. Reconnect
    /// explicitly to check a different endpoint or admit a different version.
    pub async fn observe_control_identity(&self) -> Result<ControlIdentityObservation> {
        let version = self.version().await?;
        if version.version != self.instance().version.version {
            return Err(self.control_version_mismatch(&version));
        }
        let status = self.system_status().await?;
        Ok(ControlIdentityObservation {
            device_id: status.device_id,
            engine_version: version,
            observed_at: SystemTime::now(),
            generation: None,
        })
    }

    fn control_version_mismatch(&self, version: &EngineVersion) -> Error {
        Error::IncompatibleVersion {
            actual: self
                .connection
                .transport
                .version_diagnostic(&self.connection.key.redact(&version.version)),
        }
    }
}

/// Recovery callers only receive these selected read methods. The authenticated
/// connection, generic request builder and all write capabilities stay private.
pub(super) struct ReadOnlyControl(Client);

impl ReadOnlyControl {
    pub(super) async fn connect(
        options: ConnectOptions,
        expected_device: &DeviceId,
        expected_version: &[u8; 32],
    ) -> Result<Self> {
        if options
            .expected_device_id
            .as_ref()
            .is_some_and(|identity| identity != expected_device)
        {
            return Err(Error::InvalidConfiguration {
                reason: "the supplied expected device ID differs from the operation target",
            });
        }

        let client = Client::connect(options.expected_device_id(expected_device.clone()))
            .await
            .map_err(recovery_read_error)?;
        let version = &client.instance().version;
        if version_fingerprint(&version.version) != *expected_version {
            return Err(client.control_version_mismatch(version));
        }
        Ok(Self(client))
    }

    pub(super) async fn gui_listener(
        &self,
    ) -> Result<(ControlIdentityObservation, GuiListenerConfig)> {
        let current = self.0.gui_listener().await.map_err(recovery_read_error)?;
        let identity = self
            .0
            .observe_control_identity()
            .await
            .map_err(recovery_read_error)?;
        Ok((identity, current))
    }

    pub(super) async fn device_registration(
        &self,
        peer: &DeviceId,
    ) -> Result<(
        ControlIdentityObservation,
        super::device_control::DeviceRegistrationState,
    )> {
        self.0.system_status().await.map_err(recovery_read_error)?;
        let registration = self
            .0
            .device_registration_state(peer)
            .await
            .map_err(recovery_read_error)?;
        let identity = self
            .0
            .observe_control_identity()
            .await
            .map_err(recovery_read_error)?;
        Ok((identity, registration))
    }
}

fn recovery_read_error(error: Error) -> Error {
    #[cfg(feature = "tls")]
    if let Error::Transport { source, .. } = &error {
        if certificate_rejection(source) {
            return Error::TlsCertificateRejected {
                source: Box::new(error),
            };
        }
    }
    error
}

#[cfg(feature = "tls")]
fn certificate_rejection(mut cause: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if matches!(
            cause.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(_))
        ) {
            return true;
        }
        // Tokio-rustls wraps protocol errors inside io::Error. Inspect the
        // typed inner error rather than inferring trust failure from its kind.
        if let Some(inner) = cause
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            cause = inner;
        } else if let Some(source) = cause.source() {
            cause = source;
        } else {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiKey, ManagementEndpoint};

    const DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
    const OTHER: &str = "BAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";

    #[tokio::test]
    async fn recovery_rejects_conflicting_explicit_device_before_connecting() -> Result<()> {
        let options = ConnectOptions::new(
            ManagementEndpoint::http("http://127.0.0.1:1/")?,
            ApiKey::new("synthetic-private-authority")?,
        )
        .expected_device_id(DeviceId::parse(OTHER)?);
        let version = version_fingerprint(crate::BASELINE_ENGINE_VERSION);
        let failure = ReadOnlyControl::connect(options, &DeviceId::parse(DEVICE)?, &version)
            .await
            .err()
            .expect("conflicting caller identity must be refused");
        assert!(matches!(
            failure,
            Error::InvalidConfiguration {
                reason: "the supplied expected device ID differs from the operation target"
            }
        ));
        assert!(!format!("{failure:?}").contains("synthetic-private-authority"));
        Ok(())
    }

    #[cfg(feature = "tls")]
    #[test]
    fn certificate_rejection_uses_a_typed_cause() {
        let genuinely_rejected = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        assert!(certificate_rejection(&genuinely_rejected));

        let broken_protocol =
            std::io::Error::new(std::io::ErrorKind::InvalidData, "synthetic handshake error");
        assert!(!certificate_rejection(&broken_protocol));
        assert!(!certificate_rejection(&std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused
        )));
    }
}
