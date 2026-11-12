//! Test-only suspension of one retained, newly created managed root PID.
#![allow(unsafe_code)]

#[cfg(unix)]
pub struct PausedRoot(u32);
#[cfg(unix)]
impl PausedRoot {
    pub fn new(pid: u32) -> std::io::Result<Self> {
        // SAFETY: The test retains the managed owner of this exact live root;
        // no process-name search or unrelated process is signalled.
        if unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let paused = Self(pid);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !paused.is_paused()? {
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "owned root did not suspend",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(paused)
    }
    pub fn is_paused(&self) -> std::io::Result<bool> {
        let output = std::process::Command::new("ps")
            .args(["-o", "state=", "-p", &self.0.to_string()])
            .output()?;
        Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).contains('T'))
    }
}
#[cfg(unix)]
impl Drop for PausedRoot {
    fn drop(&mut self) {
        // SAFETY: Tests resume before stopping/reaping their retained exact root,
        // so its PID cannot be recycled. This never signals a global group.
        unsafe {
            libc::kill(self.0 as libc::pid_t, libc::SIGCONT);
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, OpenThread, ResumeThread, SuspendThread,
        PROCESS_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    pub struct PausedRoot {
        process: OwnedHandle,
        threads: Vec<OwnedHandle>,
    }
    impl PausedRoot {
        pub fn new(pid: u32) -> io::Result<Self> {
            // SAFETY: PID comes only from the newly started retained test owner.
            let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: OpenProcess returned one independently owned valid handle.
            let mut paused = Self {
                process: unsafe { OwnedHandle::from_raw_handle(raw) },
                threads: Vec::new(),
            };
            let mut seen = std::collections::HashSet::new();
            for _ in 0..10 {
                let before = seen.len();
                // SAFETY: Snapshot API has no pointer arguments.
                let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
                if raw == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }
                let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
                let mut entry = THREADENTRY32 {
                    dwSize: size_of::<THREADENTRY32>() as u32,
                    ..THREADENTRY32::default()
                };
                // SAFETY: Live snapshot and correctly sized writable entry.
                let mut present = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
                while present != 0 {
                    if entry.th32OwnerProcessID == pid && !seen.contains(&entry.th32ThreadID) {
                        // SAFETY: Only suspend rights for a thread of the retained
                        // exact test root. Each successful increment is undone once.
                        let raw =
                            unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                        if !raw.is_null() {
                            let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
                            if unsafe { SuspendThread(thread.as_raw_handle()) } == u32::MAX {
                                return Err(io::Error::last_os_error());
                            }
                            seen.insert(entry.th32ThreadID);
                            paused.threads.push(thread);
                        } else if io::Error::last_os_error().raw_os_error() != Some(87) {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    // SAFETY: Same live snapshot and correctly initialized output.
                    present = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
                }
                if io::Error::last_os_error().raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                    return Err(io::Error::last_os_error());
                }
                if !seen.is_empty() && seen.len() == before {
                    return Ok(paused);
                }
            }
            Err(io::Error::other("owned root thread set did not stabilize"))
        }
        pub fn is_paused(&self) -> io::Result<bool> {
            let mut code = 0;
            // SAFETY: Retained process handle and writable native output.
            if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(code == 259 && !self.threads.is_empty())
        }
    }
    impl Drop for PausedRoot {
        fn drop(&mut self) {
            for thread in &self.threads {
                // SAFETY: Each handle is retained from one successful SuspendThread;
                // exactly one decrement restores the previous suspension count.
                unsafe {
                    ResumeThread(thread.as_raw_handle());
                }
            }
        }
    }
}
#[cfg(windows)]
pub use windows::PausedRoot;
