//! Asynchronous management of the official VerySync program.
//!
//! This crate is under development. The current foundation identifies the fixed
//! engine baseline; management operations are added only with their tests and
//! documentation. Adding this dependency or compiling it does not download or
//! start VerySync, install services, or configure global logging or signals.
//!
//! All public interfaces are unstable during alpha.

/// The fixed upstream version selected for initial compatibility acceptance.
///
/// This identifies a test baseline, not an automatic download or a claim that
/// every feature and platform has passed acceptance.
pub const BASELINE_ENGINE_VERSION: &str = "v2.33.2";
