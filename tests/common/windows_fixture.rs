//! Windows-only process-tree ownership for the integration-test fixture.
//!
//! A child starts suspended, joins a private noninheritable job, then resumes.
//! This closes the race where the engine creates descendants before assignment.
#![allow(unsafe_code)]

use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::process::Child;
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{LocalFree, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetSecurityDescriptorControl, IsValidSid, ACCESS_ALLOWED_ACE, ACL,
    DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

pub(super) struct Job(OwnedHandle);

struct LocalAllocation(*mut core::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: Only successful Windows LocalAlloc-based API results enter
        // this unique owner; every borrowed ACL/SID is used before this drop.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn sid(value: &str) -> io::Result<LocalAllocation> {
    let value: Vec<_> = value.encode_utf16().chain(Some(0)).collect();
    let mut result = ptr::null_mut();
    // SAFETY: NUL-terminated input and writable output. This API allocates an
    // independent SID, released with LocalFree by the returned owner.
    if unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut result) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalAllocation(result))
}

pub(super) fn private_acl(path: &Path, require_protected: bool, owner: &str) -> io::Result<bool> {
    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: NUL-terminated native path; output pointers are valid. Only the
    // DACL is requested. Its lifetime is bounded by the returned descriptor.
    let result = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _descriptor = LocalAllocation(descriptor);
    if descriptor.is_null() || acl.is_null() {
        return Ok(false);
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: A successful API result owns a valid descriptor for this call.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if require_protected && control & SE_DACL_PROTECTED == 0 {
        return Ok(false);
    }
    // SAFETY: The DACL is a valid OS-returned ACL within the live descriptor.
    if unsafe { (*acl).AceCount } != 2 {
        return Ok(false);
    }
    let owner = sid(owner)?;
    let system = sid("S-1-5-18")?;
    let mut seen_owner = false;
    let mut seen_system = false;
    for index in 0..2 {
        let mut raw = ptr::null_mut();
        // SAFETY: Index is within the checked AceCount; output pointer is valid.
        if unsafe { GetAce(acl, index, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce returns a valid, DWORD-aligned ACE in the descriptor.
        // Check its type/size before reading the allowed-ACE payload.
        let header = unsafe { &*raw.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Ok(false);
        }
        // SAFETY: Checked ACCESS_ALLOWED_ACE type/size above. The SID starts at
        // SidStart and continues within the valid variable-length OS ACE.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Mask != 0x001f_01ff {
            return Ok(false);
        } // FILE_ALL_ACCESS
        let principal = ptr::from_ref(&ace.SidStart).cast_mut().cast();
        // SAFETY: The OS ACE contains the SID; validate before EqualSid, whose
        // other arguments come from successful ConvertStringSidToSidW calls.
        if unsafe { IsValidSid(principal) } == 0 {
            return Ok(false);
        }
        if unsafe { EqualSid(principal, owner.0) } != 0 {
            seen_owner = true;
        } else if unsafe { EqualSid(principal, system.0) } != 0 {
            seen_system = true;
        } else {
            return Ok(false);
        }
    }
    Ok(seen_owner && seen_system)
}

impl Job {
    pub(super) fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Self)
    }

    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: Null security attributes/name create a fresh unnamed,
        // noninheritable handle. Check it before transferring unique ownership.
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateJobObjectW returned a newly owned valid handle.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: The handle lives through the call; the pointer and byte count
        // describe the initialized structure required by this information class.
        let result = unsafe {
            SetInformationJobObject(
                job.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    pub(super) fn assign_and_resume(&self, child: &Child) -> io::Result<()> {
        // SAFETY: Both handles remain live. The caller created this child with
        // CREATE_SUSPENDED and retains its kill/wait guard on every error path.
        if unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), child.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        resume_initial_thread(child.id())
    }

    fn active_processes(&self) -> io::Result<u32> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: Correct writable initialized structure, size, information
        // class and live job handle. The optional return-length pointer is null.
        let result = unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                ptr::from_mut(&mut info).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info.ActiveProcesses)
    }

    pub(super) fn wait_empty(&self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        while self.active_processes()? != 0 {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "private Windows fixture job still has live processes",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    pub(super) fn terminate_and_wait(&self) -> io::Result<()> {
        if self.active_processes()? != 0 {
            // SAFETY: This is the private job, containing only the suspended-
            // then-assigned fixture and its descendants; no global PID lookup.
            if unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.wait_empty(Duration::from_secs(5))
    }
}

fn resume_initial_thread(pid: u32) -> io::Result<()> {
    // SAFETY: Toolhelp snapshot flags require no pointer arguments.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The successful snapshot handle has exactly one owner here.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    // SAFETY: A live snapshot and correctly sized writable entry.
    let mut present = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
    while present != 0 {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: Request only resume rights on this exact suspended child's
            // thread. The child cannot exit or create threads before resuming.
            let raw = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: OpenThread returned a newly owned valid handle.
            let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
            // SAFETY: Live thread handle with THREAD_SUSPEND_RESUME rights.
            let previous = unsafe { ResumeThread(thread.as_raw_handle()) };
            if previous == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            if previous != 1 {
                return Err(io::Error::other(
                    "unexpected fixture initial-thread suspend count",
                ));
            }
            return Ok(());
        }
        // SAFETY: Same valid snapshot and initialized writable entry.
        present = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
        return Err(error);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "fixture initial thread not found",
    ))
}
