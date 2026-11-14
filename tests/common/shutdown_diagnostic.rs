//! Bounded observations of identities captured from one owned macOS group.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)] // Native read-only test boundary, matching managed native helpers.
mod macos {
    use serde_json::{json, Value};

    struct Member {
        pid: i32,
        started: (u64, u64),
        root: bool,
    }
    pub struct Snapshot {
        members: Vec<Member>,
        complete: bool,
    }

    fn info(pid: i32) -> Result<libc::proc_bsdinfo, (i32, i32)> {
        // SAFETY: A zeroed plain C output struct with the native exact size and
        // flavor. This only reads process metadata; it sends no signal.
        let mut value: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&value) as i32;
        // SAFETY: Initialized output storage and exact size/flavor; errno is
        // thread-local and this call only reads the supplied identity's metadata.
        let bytes = unsafe {
            *libc::__error() = 0;
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut value as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if bytes == size {
            Ok(value)
        } else {
            Err((
                bytes,
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            ))
        }
    }

    impl Snapshot {
        pub fn capture(root: u32) -> Self {
            let mut result = Self {
                members: Vec::new(),
                complete: false,
            };
            let Ok(root) = i32::try_from(root) else {
                return result;
            };
            let Ok(owner) = info(root) else { return result };
            if owner.pbi_pgid != root as u32 {
                return result;
            }
            let mut pids = [0_i32; 16];
            let capacity = std::mem::size_of_val(&pids) as i32;
            // SAFETY: Query only the retained root's verified private group,
            // into this initialized bounded buffer. No all-process scan occurs.
            let bytes =
                unsafe { libc::proc_listpids(2, root as u32, pids.as_mut_ptr().cast(), capacity) };
            if bytes <= 0 || bytes >= capacity || bytes as usize % std::mem::size_of::<i32>() != 0 {
                return result;
            }
            result.complete = true;
            for pid in pids
                .into_iter()
                .take(bytes as usize / std::mem::size_of::<i32>())
                .filter(|pid| *pid > 0)
            {
                if let Ok(member) = info(pid) {
                    if member.pbi_pgid == root as u32 {
                        if pid == root
                            && (member.pbi_start_tvsec, member.pbi_start_tvusec)
                                != (owner.pbi_start_tvsec, owner.pbi_start_tvusec)
                        {
                            result.members.clear();
                            result.complete = false;
                            return result;
                        }
                        result.members.push(Member {
                            pid,
                            started: (member.pbi_start_tvsec, member.pbi_start_tvusec),
                            root: pid == root,
                        });
                    } else {
                        result.complete = false;
                    }
                } else {
                    result.complete = false;
                }
            }
            result.complete &= result.members.iter().any(|member| member.root);
            result
        }

        pub fn observe(&self) -> Value {
            let members: Vec<_> = self.members.iter().map(|member| match info(member.pid) {
                Ok(current) => {
                    let same_identity = (current.pbi_start_tvsec, current.pbi_start_tvusec) == member.started;
                    if same_identity {
                        json!({"root":member.root,"same_identity":true,"native_status":current.pbi_status,"zombie":current.pbi_status==libc::SZOMB})
                    } else {
                        json!({"root":member.root,"same_identity":false,"identity_changed":true})
                    }
                }
                Err((bytes, errno)) => json!({"root":member.root,"same_identity":false,"absent":errno==libc::ESRCH,"native_bytes":bytes,"native_errno":errno}),
            }).collect();
            json!({"scope":"macos_exact_pre_shutdown_member_identities","complete_before_shutdown":self.complete,"captured_members":members.len(),"members":members,"signals_sent":false})
        }
    }

    #[test]
    fn snapshot_checks_birth_identity_and_observes_only_its_retained_child() -> std::io::Result<()>
    {
        use std::{
            os::unix::process::CommandExt,
            process::{Child, Command, Stdio},
        };
        struct Retained(Child);
        impl Drop for Retained {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Retained(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let mut snapshot = Snapshot::capture(child.0.id());
        assert!(snapshot.complete);
        assert_eq!(snapshot.members.len(), 1);
        let live = snapshot.observe();
        assert_eq!(live["members"][0]["same_identity"], true);
        assert_eq!(live["members"][0]["zombie"], false);
        snapshot.members[0].started.1 += 1;
        assert_eq!(snapshot.observe()["members"][0]["identity_changed"], true);
        snapshot.members[0].started.1 -= 1;
        child.0.kill()?;
        child.0.wait()?;
        assert_eq!(snapshot.observe()["members"][0]["same_identity"], false);
        Ok(())
    }
}
#[cfg(target_os = "macos")]
pub use macos::Snapshot;

#[cfg(not(target_os = "macos"))]
pub struct Snapshot;
#[cfg(not(target_os = "macos"))]
impl Snapshot {
    pub fn capture(_: u32) -> Self {
        Self
    }
    pub fn observe(&self) -> serde_json::Value {
        serde_json::json!({"scope":"macos_exact_pre_shutdown_member_identities","available":false})
    }
}
