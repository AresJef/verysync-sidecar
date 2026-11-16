//! Independent one-shot launcher lifetime. No owned-core cleanup policy changes.

#[cfg(windows)]
use super::native::Child;
use super::{native, process::ProcessIo, ManagedLifetime};
#[cfg(unix)]
use std::process::Child;
use std::{
    io,
    process::{Command, ExitStatus},
};

/// A one-shot UI launcher has a different lifetime from an owned serving core.
/// Release is explicit and possible only after its exact root exits zero.
pub(super) struct LauncherProcess {
    child: Child,
    guard: native::ProcessGuard,
    released: bool,
}
impl LauncherProcess {
    pub(super) fn spawn(command: Command, io: ProcessIo) -> io::Result<Self> {
        // No controlling PTY or Windows kill-on-close Job: a successful command
        // may have handed its URL to a desktop process that must remain alive.
        let (child, guard) = native::spawn(command, false, ManagedLifetime::Persistent, io)?;
        Ok(Self {
            child,
            guard,
            released: false,
        })
    }
    pub(super) fn id(&self) -> u32 {
        self.child.id()
    }
    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
    pub(super) fn release_after_success(mut self) -> io::Result<ExitStatus> {
        let status = self
            .child
            .try_wait()?
            .filter(ExitStatus::success)
            .ok_or_else(|| {
                io::Error::other("only a successfully exited launcher root may be released")
            })?;
        self.released = true;
        Ok(status)
    }
}
impl Drop for LauncherProcess {
    fn drop(&mut self) {
        if !self.released {
            // Root cancellation is exact-child scoped. A root that already
            // dispatched a desktop request cannot promise a graphical rollback.
            let _ = self.guard.stop(&mut self.child);
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{native, process::ProcessIo};
    use super::*;
    use std::{
        path::{Path, PathBuf},
        process::Command,
        time::{Duration, Instant},
    };
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
    const FIXTURE: &str = "managed::launcher::tests::fixture_process";
    const MODE: &str = "VERYSYNC_LAUNCHER_FIXTURE_MODE";
    const ROOT: &str = "VERYSYNC_LAUNCHER_FIXTURE_ROOT";

    fn command(root: &Path, mode: &str) -> TestResult<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", FIXTURE, "--test-threads=1"])
            .env(MODE, mode)
            .env(ROOT, root)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
        }
        Ok(command)
    }
    fn until(mut condition: impl FnMut() -> TestResult<bool>) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !condition()? {
            if Instant::now() >= deadline {
                return Err("owned launcher fixture deadline exceeded".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
    #[test]
    fn fixture_process() -> TestResult {
        let Some(mode) = std::env::var_os(MODE) else {
            return Ok(());
        };
        let root = PathBuf::from(std::env::var_os(ROOT).ok_or("owned fixture root required")?);
        if mode == "root" {
            let child = command(&root, "descendant")?.spawn()?;
            // Publish the complete PID before the observer can see its journal.
            // A ready child can otherwise race the parent's create-then-write.
            let journal = root.join("descendant-pid");
            let partial = journal.with_extension("pending");
            std::fs::write(&partial, child.id().to_string())?;
            std::fs::rename(partial, journal)?;
            until(|| Ok(root.join("descendant-ready").try_exists()?))?;
            until(|| Ok(root.join("exit-root").try_exists()?))?;
            drop(child); // The intended browser-style descendant outlives its root.
            if root.join("fail-root").try_exists()? {
                return Err("synthetic launcher failure after dispatch".into());
            }
        } else if mode == "descendant" {
            std::fs::write(root.join("descendant-ready"), b"ready")?;
            let deadline = Instant::now() + Duration::from_secs(20);
            while root.is_dir() && !root.join("stop-descendant").try_exists()? {
                if Instant::now() >= deadline {
                    return Err("bounded descendant fixture expired".into());
                }
                if root.join("after-release").try_exists()? {
                    std::fs::write(root.join("alive-after-release"), b"still executing")?;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        } else {
            return Err("unknown owned launcher fixture mode".into());
        }
        Ok(())
    }
    fn io() -> ProcessIo {
        ProcessIo {
            stdin_pipe: false,
            stdout: None,
            stderr: None,
        }
    }
    fn descendant(root: &Path, group: u32) -> TestResult<native::TestChildObservation> {
        until(|| {
            Ok(root.join("descendant-ready").try_exists()?
                && root.join("descendant-pid").try_exists()?)
        })?;
        let pid = std::fs::read_to_string(root.join("descendant-pid"))?.parse()?;
        Ok(native::observe_test_descendant(group, pid)?)
    }
    #[test]
    fn successful_launcher_release_keeps_the_exact_owned_descendant_running_after_drop(
    ) -> TestResult {
        let root = tempfile::Builder::new()
            .prefix("vs-launcher-release-")
            .tempdir()?;
        let mut launcher = LauncherProcess::spawn(command(root.path(), "root")?, io())?;
        let observation = descendant(root.path(), launcher.id())?;
        std::fs::write(root.path().join("exit-root"), b"exit")?;
        until(|| Ok(launcher.try_wait()?.is_some()))?;
        let status = launcher.release_after_success()?;
        assert!(status.success());
        std::fs::write(root.path().join("after-release"), b"observe")?;
        until(|| Ok(root.path().join("alive-after-release").try_exists()?))?;
        assert!(!observation.stopped()?);
        std::fs::write(root.path().join("stop-descendant"), b"stop")?;
        until(|| Ok(observation.stopped()?))?;
        Ok(())
    }
    #[test]
    fn an_unfinished_launcher_cannot_release_ownership_and_its_owned_tree_is_stopped() -> TestResult
    {
        let root = tempfile::Builder::new()
            .prefix("vs-launcher-refusal-")
            .tempdir()?;
        let launcher = LauncherProcess::spawn(command(root.path(), "root")?, io())?;
        let observation = descendant(root.path(), launcher.id())?;
        assert!(launcher.release_after_success().is_err());
        until(|| Ok(observation.stopped()?))?;
        Ok(())
    }
    #[test]
    fn a_nonzero_launcher_exit_never_becomes_a_successful_release() -> TestResult {
        let root = tempfile::Builder::new()
            .prefix("vs-launcher-failure-")
            .tempdir()?;
        let mut launcher = LauncherProcess::spawn(command(root.path(), "root")?, io())?;
        let observation = descendant(root.path(), launcher.id())?;
        std::fs::write(root.path().join("fail-root"), b"fail")?;
        std::fs::write(root.path().join("exit-root"), b"exit")?;
        until(|| Ok(launcher.try_wait()?.is_some()))?;
        assert!(launcher.release_after_success().is_err());
        // Explicit fixture cleanup; native graphical rollback is not promised.
        std::fs::write(root.path().join("stop-descendant"), b"stop")?;
        until(|| Ok(observation.stopped()?))?;
        Ok(())
    }
}
