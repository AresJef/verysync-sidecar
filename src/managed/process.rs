//! Exact-child ownership. All blocking work runs on the private owner thread.

#[cfg(windows)]
use super::native::Child;
use std::fs::File;
use std::io;
#[cfg(unix)]
use std::process::Child;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use super::native;

pub(in crate::managed) struct ProcessIo {
    pub(in crate::managed) stdin_pipe: bool,
    pub(in crate::managed) stdout: Option<File>,
    pub(in crate::managed) stderr: Option<File>,
}

pub(super) struct OwnedProcess {
    child: Child,
    guard: native::ProcessGuard,
}

impl OwnedProcess {
    pub(super) fn spawn(
        command: Command,
        helper: bool,
        lifetime: super::ManagedLifetime,
        io: ProcessIo,
    ) -> io::Result<Self> {
        let (child, guard) = native::spawn(command, helper, lifetime, io)?;
        Ok(Self { child, guard })
    }

    pub(super) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }
    pub(super) fn id(&self) -> u32 {
        self.child.id()
    }
    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
    pub(super) fn tree_stopped(&self) -> io::Result<bool> {
        self.guard.tree_stopped()
    }

    pub(super) fn finish(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.guard.tree_stopped()? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned process tree did not finish",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    pub(super) fn abort(&mut self) -> io::Result<()> {
        self.guard.stop(&mut self.child)?;
        let _status = self.child.wait()?;
        self.finish()
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        // This guard is owned by a dedicated thread, never an async executor
        // thread. It retains the exact child and native containment until reaped.
        let _ = self.abort();
    }
}
