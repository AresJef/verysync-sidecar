//! Explicit normal stop followed by authenticated startup of the same state.

use std::time::Duration;

use super::{shutdown, ManagedInstance};
use crate::{Error, Result};

impl ManagedInstance {
    /// Normally stop, then start the same program/state and authenticate again.
    ///
    /// One total deadline covers shutdown and new readiness. The configured
    /// startup deadline still applies to the new start. Success replaces this
    /// owner's Client, program information and exit observation with those of
    /// the authenticated new generation; persisted identity, credentials,
    /// folders and unrelated configuration are reused.
    ///
    /// A failed stop never starts a second owner or escalates to force. If the
    /// old generation stopped but the new start fails, this object retains the
    /// old exit observation and options so the caller can explicitly retry.
    /// A cancelled/failed new startup requests its own exact cleanup and retains
    /// partial state; cleanup can still be completing when an immediate retry
    /// reports the state busy. No automatic retry or rollback occurs. Borrowed
    /// Client clones retain their previous connection snapshot.
    pub async fn restart(&mut self, timeout: Duration) -> Result<()> {
        let deadline = shutdown::deadline(timeout)?;
        tokio::time::timeout_at(deadline, async {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(restart_timeout());
            }
            self.shutdown(remaining).await?;
            if tokio::time::Instant::now() >= deadline {
                return Err(restart_timeout());
            }
            let next = Self::start(self.options.clone()).await?;
            *self = next;
            Ok(())
        })
        .await
        .map_err(|_| restart_timeout())?
    }
}

fn restart_timeout() -> Error {
    Error::Timeout {
        operation: "restart owned program",
    }
}
