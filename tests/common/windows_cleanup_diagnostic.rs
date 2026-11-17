//! Failure-only observations of the exact synthetic fixture; never process control.
#![allow(unsafe_code)] // Audited native test boundary, matching windows_fixture.
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    os::windows::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::FILETIME,
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};

#[repr(C)]
#[derive(Clone, Copy)]
struct UniqueProcess {
    pid: u32,
    started: FILETIME,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessInfo {
    process: UniqueProcess,
    application: [u16; 256],
    service: [u16; 64],
    application_type: i32,
    status: u32,
    session: u32,
    restartable: i32,
}

// C ABI checked against the pinned windows-sys 0.61.2 metadata and Microsoft:
// https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist
// No shutdown/restart entry point is declared or called.
#[link(name = "Rstrtmgr")]
extern "system" {
    fn RmStartSession(session: *mut u32, flags: u32, key: *mut u16) -> u32;
    fn RmEndSession(session: u32) -> u32;
    fn RmRegisterResources(
        session: u32,
        file_count: u32,
        files: *const *const u16,
        process_count: u32,
        processes: *const UniqueProcess,
        service_count: u32,
        services: *const *const u16,
    ) -> u32;
    fn RmGetList(
        session: u32,
        needed: *mut u32,
        count: *mut u32,
        applications: *mut ProcessInfo,
        reboot_reasons: *mut u32,
    ) -> u32;
}

struct Session(u32);
impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: This session was created here and is never shared.
        unsafe { RmEndSession(self.0) };
    }
}

fn holders(files: &[PathBuf]) -> Value {
    if files.is_empty() {
        return json!({"queried":false,"reason":"no remaining file with a denied delete-access probe"});
    }
    let (mut handle, mut key) = (0, [0_u16; 33]);
    // SAFETY: Writable handle and CCH_RM_SESSION_KEY + 1 code units.
    let status = unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) };
    if status != 0 {
        return json!({"queried":false,"start_status":status});
    }
    let session = Session(handle);
    let wide: Vec<Vec<u16>> = files
        .iter()
        .map(|p| p.as_os_str().encode_wide().chain(Some(0)).collect())
        .collect();
    let pointers: Vec<_> = wide.iter().map(|p| p.as_ptr()).collect();
    // SAFETY: At most 64 live, NUL-terminated owned-file paths; no process or
    // service is registered. Registration and listing do not stop any process.
    let status = unsafe {
        RmRegisterResources(
            session.0,
            pointers.len() as u32,
            pointers.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return json!({"queried":false,"register_status":status});
    }
    // SAFETY: The C structure contains only integers and integer arrays.
    let mut applications: [ProcessInfo; 64] = unsafe { std::mem::zeroed() };
    let (mut needed, mut count, mut reboot) = (0, applications.len() as u32, 0);
    // SAFETY: All output pointers and the bounded, initialized array are live.
    let status = unsafe {
        RmGetList(
            session.0,
            &mut needed,
            &mut count,
            applications.as_mut_ptr(),
            &mut reboot,
        )
    };
    if status != 0 || count as usize > applications.len() {
        return json!({"queried":false,"list_status":status,"needed":needed});
    }
    let processes: Vec<_> = applications[..count as usize]
        .iter()
        .map(|p| {
            json!({"pid":p.process.pid,"started_filetime_low":p.process.started.dwLowDateTime,
                "started_filetime_high":p.process.started.dwHighDateTime,
                "same_test_process":p.process.pid==std::process::id(),"application_type":p.application_type})
        })
        .collect();
    json!({"queried":true,"processes":processes,"empty_list_is_not_proof_of_no_holder":true})
}

pub(super) fn delete_admission(path: &Path) -> std::io::Result<()> {
    // DELETE access with every share flag probes sharing without deleting,
    // renaming, following a reparse point, or reading any file contents.
    OpenOptions::new()
        .access_mode(0x0001_0000)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map(drop)
}

pub(super) fn snapshot(root: &Path) -> Value {
    let mut pending = vec![(root.to_owned(), 0)];
    let (mut entries, mut blocked_files) = (Vec::new(), Vec::new());
    while let Some((path, depth)) = pending.pop() {
        if entries.len() >= 64 {
            pending.push((path, depth));
            break;
        }
        let metadata = match path.symlink_metadata() {
            Ok(value) => value,
            Err(error) => {
                entries.push(json!({"metadata_os_error":error.raw_os_error()}));
                continue;
            }
        };
        let reparse = metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let probe_error = delete_admission(&path).err().and_then(|e| e.raw_os_error());
        entries.push(
            json!({"relative":path.strip_prefix(root).ok().map(|p|p.to_string_lossy()),
            "directory":metadata.is_dir(),"reparse":reparse,"delete_access_os_error":probe_error}),
        );
        if metadata.is_file() && !reparse && probe_error.is_some() {
            blocked_files.push(path.clone());
        }
        if metadata.is_dir() && !reparse && depth < 8 && entries.len() < 64 {
            match fs::read_dir(&path) {
                Ok(children) => {
                    for child in children.take(64 - entries.len()) {
                        match child {
                            Ok(child) => pending.push((child.path(), depth + 1)),
                            Err(error) => {
                                entries.push(json!({"enumeration_os_error":error.raw_os_error()}))
                            }
                        }
                    }
                }
                Err(error) => entries.push(json!({"enumeration_os_error":error.raw_os_error()})),
            }
        }
    }
    json!({"scope":"remaining entries of this exact synthetic fixture only",
        "entries":entries,"inventory_may_be_incomplete":true,"maximum_entries":64,
        "maximum_depth":8,"resource_holders":holders(&blocked_files),
        "file_contents_read":false,"delete_retry":false,"process_control":false})
}
