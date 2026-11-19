//! Native minimum-free-space settings with explicit decimal units.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Units used by the native configuration; decimal byte units are not KiB/MiB.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskSpaceUnit {
    /// Percentage of the target volume.
    #[serde(rename = "%")]
    Percent,
    /// Decimal kilobytes.
    #[serde(rename = "kB")]
    Kilobytes,
    /// Decimal megabytes.
    #[serde(rename = "MB")]
    Megabytes,
    /// Decimal gigabytes.
    #[serde(rename = "GB")]
    Gigabytes,
    /// Decimal terabytes.
    #[serde(rename = "TB")]
    Terabytes,
    /// Unrecognized readback; typed writes reject it.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for DiskSpaceUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Percent => "DiskSpaceUnit::Percent",
            Self::Kilobytes => "DiskSpaceUnit::Kilobytes",
            Self::Megabytes => "DiskSpaceUnit::Megabytes",
            Self::Gigabytes => "DiskSpaceUnit::Gigabytes",
            Self::Terabytes => "DiskSpaceUnit::Terabytes",
            Self::Unknown(_) => "DiskSpaceUnit::Unknown([REDACTED])",
        })
    }
}

/// Minimum free space on a target volume. Zero requests the native disabled policy.
/// This value neither measures the controller disk nor reserves storage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiskFreeRequirement {
    #[serde(serialize_with = "serialize_value")]
    value: f64,
    unit: DiskSpaceUnit,
}

fn serialize_value<S: serde::Serializer>(
    value: &f64,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    // Go emits integral float64 settings as JSON integers. Preserve that wire
    // shape so exact configuration reconciliation does not invent a mismatch.
    if *value >= 0.0 && *value <= 9_007_199_254_740_992.0 && value.fract() == 0.0 {
        serializer.serialize_u64(*value as u64)
    } else {
        serializer.serialize_f64(*value)
    }
}
impl DiskFreeRequirement {
    /// Construct a finite nonnegative threshold; percentages cannot exceed 100.
    pub fn new(value: f64, unit: DiskSpaceUnit) -> Result<Self> {
        let requirement = Self { value, unit };
        requirement.validate()?;
        Ok(requirement)
    }
    /// Actual native numeric value, without converting decimal units.
    pub fn value(&self) -> f64 {
        self.value
    }
    /// Actual native unit, retaining unknown future values.
    pub fn unit(&self) -> &DiskSpaceUnit {
        &self.unit
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.value.is_finite()
            || self.value < 0.0
            || (self.unit == DiskSpaceUnit::Percent && self.value > 100.0)
            || matches!(self.unit, DiskSpaceUnit::Unknown(_))
        {
            return Err(Error::InvalidConfiguration {
                reason: "disk free requirement must use a known unit and a valid finite threshold",
            });
        }
        Ok(())
    }
}
