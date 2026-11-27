//! Audited native boundaries; caller-global state is never changed.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(super) use unix::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(super) use windows::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::managed) struct FileIdentity {
    volume: u64,
    file: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::managed) struct FileStamp {
    pub(in crate::managed) identity: FileIdentity,
    pub(in crate::managed) bytes: u64,
    pub(in crate::managed) links: u64,
    modified: [i64; 2],
    changed: [i64; 2],
}
