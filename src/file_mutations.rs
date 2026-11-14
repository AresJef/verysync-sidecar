//! Explicit collision and deletion intent for native resource mutations.
use crate::{ResourceInfo, ResourcePath};

/// Native collision policy. Parent/metadata preflights are observations, not
/// transactions against external filesystem or management writers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceConflictPolicy {
    /// Refuse an already observed destination before sending a mutation.
    RejectExisting,
    /// Overwrite colliding files; merge directory trees while retaining
    /// destination-only children. This does not replace an entire directory.
    OverwriteAndMerge,
    /// Preserve the requested existing target and let the kernel choose a new
    /// name. Require one unambiguous new parent entry after acknowledgement.
    KeepBoth,
}
/// Explicit deletion scope; neither choice may address a volume root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceDeleteScope {
    /// Require a file snapshot; refuse a currently observed directory.
    File,
    /// Require a directory snapshot and explicitly permit recursive data removal.
    RecursiveDirectory,
}
/// Fresh destination metadata after a known native acknowledgement. This is
/// not a transaction or a recursive content-hash verification receipt.
#[derive(Debug)]
pub struct ResourceMutation {
    /// Actual observed destination, including an unambiguous generated name.
    pub destination: ResourcePath,
    /// Actual metadata after the change; remote names/content remain untrusted.
    pub metadata: ResourceInfo,
    /// Whether the observed destination differs from the requested destination.
    pub generated_name: bool,
}
/// The exact resource was observed absent after its deletion acknowledgement.
/// Other writers can recreate it later; deletion is not a synchronization detach.
#[derive(Debug)]
pub struct ResourceRemoval {
    /// Snapshot read before the destructive request; no local backup is created.
    pub previous: ResourceInfo,
}
