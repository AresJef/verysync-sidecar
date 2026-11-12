//! Audited native boundaries; caller-global state is never changed.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(super) use unix::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(super) use windows::*;
