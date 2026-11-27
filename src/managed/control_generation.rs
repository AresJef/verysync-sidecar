//! Generation observations and explicitly guarded owned lifecycle actions.

use std::{fmt, time::Duration};

use super::{state::Generation, ManagedExit, ManagedInstance};
use crate::{client::ControlIdentityObservation, DeviceId, Error, Result};

/// Opaque marker for one startup of a managed instance.
///
/// Retain it across an explicit restart to detect a generation change. The
/// marker provides a comparison value. The owning instance still controls
/// whether an operation can be admitted.
#[derive(Clone, Eq, PartialEq)]
pub struct ManagedControlGeneration {
    device: DeviceId,
    generation: Generation,
}

impl fmt::Debug for ManagedControlGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedControlGeneration")
            .finish_non_exhaustive()
    }
}

/// How a saved generation marker compares with the selected owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ManagedGenerationStatus {
    /// The marker matches and the owner has not retired control admission.
    Current,
    /// The same logical device has a different owned startup generation.
    Replaced,
    /// The owner belongs to a different logical device.
    DifferentDevice,
    /// Control admission is retired while final exit evidence is pending.
    Retired,
    /// The owner recorded exit for the selected generation. Its exit report
    /// describes whether process containment and private state were released.
    Exited,
}

impl ManagedControlGeneration {
    fn classify(
        &self,
        device: &DeviceId,
        generation: Generation,
        retired: bool,
        observed_exit: bool,
    ) -> ManagedGenerationStatus {
        use ManagedGenerationStatus::{Current, DifferentDevice, Exited, Replaced, Retired};

        if self.device != *device {
            DifferentDevice
        } else if self.generation != generation {
            Replaced
        } else if observed_exit {
            Exited
        } else if retired {
            Retired
        } else {
            Current
        }
    }
}

impl ManagedInstance {
    /// Capture the generation recorded by this owning handle at startup.
    pub fn control_generation(&self) -> ManagedControlGeneration {
        ManagedControlGeneration {
            device: self.client().instance().device_id.clone(),
            generation: self.generation,
        }
    }

    /// Compare a saved generation with this owner's recorded state.
    ///
    /// This check does not send a request. Current means this owner has not
    /// observed retirement. An engine can exit after the check.
    pub fn check_control_generation(
        &self,
        expected: &ManagedControlGeneration,
    ) -> ManagedGenerationStatus {
        expected.classify(
            &self.client().instance().device_id,
            self.generation,
            self.shutdown_admission.is_retired(),
            self.exit_snapshot().is_some(),
        )
    }

    /// Require a same-generation owner that still admits control operations.
    ///
    /// No request is sent. Recheck through a generation-guarded entry point
    /// when an observation precedes a lifecycle action.
    pub fn require_control_generation(&self, expected: &ManagedControlGeneration) -> Result<()> {
        let reason = match self.check_control_generation(expected) {
            ManagedGenerationStatus::Current => return Ok(()),
            ManagedGenerationStatus::Replaced => {
                "the owned VerySync generation has changed. Check the current instance before requesting control"
            }
            ManagedGenerationStatus::DifferentDevice => {
                "the owned VerySync device differs from the saved generation. Check which instance you selected"
            }
            ManagedGenerationStatus::Retired => {
                "the owned VerySync generation is retiring. Wait for its exit report before requesting control"
            }
            ManagedGenerationStatus::Exited => {
                "the owned VerySync generation has an exit report. Inspect the report before requesting control"
            }
        };
        Err(Error::ManagedFailure { reason })
    }

    /// Observe the owned device and engine version while the owner still admits control.
    ///
    /// The generation check brackets the management reads. The owner may exit
    /// after this observation. Borrowed readers expose only the logical identity.
    pub async fn observe_owned_control_identity(&self) -> Result<ControlIdentityObservation> {
        let generation = self.control_generation();
        self.require_control_generation(&generation)?;
        let identity = self.client().observe_control_identity().await?;
        self.require_control_generation(&generation)?;
        Ok(identity.with_generation(generation))
    }

    /// Request normal shutdown for the saved generation and wait for its exit.
    ///
    /// A replaced or retired owner is refused before a shutdown request can be
    /// admitted. This operation uses the same owning shutdown path and deadline
    /// as [`ManagedInstance::shutdown`].
    pub async fn shutdown_control_generation(
        &mut self,
        expected: &ManagedControlGeneration,
        timeout: Duration,
    ) -> Result<ManagedExit> {
        self.require_control_generation(expected)?;
        self.shutdown(timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
    const OTHER: &str = "BAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";

    #[test]
    fn generation_comparison_separates_identity_replacement_and_retirement() -> Result<()> {
        let original = ManagedControlGeneration {
            device: DeviceId::parse(DEVICE)?,
            generation: [1; 32],
        };
        assert_eq!(
            original.classify(&DeviceId::parse(DEVICE)?, [1; 32], false, false),
            ManagedGenerationStatus::Current
        );
        assert_eq!(
            original.classify(&DeviceId::parse(DEVICE)?, [2; 32], false, false),
            ManagedGenerationStatus::Replaced
        );
        assert_eq!(
            original.classify(&DeviceId::parse(OTHER)?, [2; 32], false, false),
            ManagedGenerationStatus::DifferentDevice
        );
        assert_eq!(
            original.classify(&DeviceId::parse(DEVICE)?, [1; 32], true, false),
            ManagedGenerationStatus::Retired
        );
        assert_eq!(
            original.classify(&DeviceId::parse(DEVICE)?, [1; 32], true, true),
            ManagedGenerationStatus::Exited
        );
        assert!(!format!("{original:?}").contains(DEVICE));
        Ok(())
    }
}
