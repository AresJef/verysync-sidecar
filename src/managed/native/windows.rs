//! Windows private resources; all unsafe operations stay at this native boundary.
#![allow(unsafe_code)]

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetSecurityDescriptorControl, GetTokenInformation, IsValidSid, TokenUser,
    ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
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
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

pub(in crate::managed) struct ProcessGuard(OwnedHandle);

pub(in crate::managed) fn spawn(
    mut command: Command,
    _helper: bool,
) -> io::Result<(Child, ProcessGuard)> {
    // SAFETY: Null attributes/name create an unnamed noninheritable private Job.
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful API returned one newly owned handle.
    let guard = ProcessGuard(unsafe { OwnedHandle::from_raw_handle(raw) });
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: Live Job and correctly typed initialized native structure/length.
    if unsafe {
        SetInformationJobObject(
            guard.0.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            ptr::from_ref(&limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    command.creation_flags(0x0800_0004); // CREATE_NO_WINDOW | CREATE_SUSPENDED.
    let mut child = command.spawn()?;
    // SAFETY: The exact child is suspended and both handles remain live. It
    // cannot create any descendants before joining the private Job.
    if unsafe { AssignProcessToJobObject(guard.0.as_raw_handle(), child.as_raw_handle()) } == 0 {
        let error = io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    if let Err(error) = resume_initial_thread(child.id()) {
        let _ = guard.stop(&mut child);
        let _ = child.wait();
        return Err(error);
    }
    Ok((child, guard))
}

impl ProcessGuard {
    pub(in crate::managed) fn stop(&self, _child: &mut Child) -> io::Result<()> {
        if !self.tree_stopped()? {
            // SAFETY: Only the private contained tree is terminated.
            if unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub(in crate::managed) fn tree_stopped(&self) -> io::Result<bool> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: Correct native class, writable structure, byte length and live Job.
        if unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                ptr::from_mut(&mut info).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(info.ActiveProcesses == 0)
    }
}

fn resume_initial_thread(pid: u32) -> io::Result<()> {
    // SAFETY: Snapshot API takes no pointers; its returned handle is uniquely owned.
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
        if entry.th32OwnerProcessID == pid {
            // SAFETY: The exact retained child remains suspended; its PID cannot
            // be reused and this is its initial thread, not another process's.
            let raw = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
            if unsafe { ResumeThread(thread.as_raw_handle()) } != 1 {
                return Err(io::Error::other("unexpected initial suspend count"));
            }
            return Ok(());
        }
        // SAFETY: Same live snapshot and writable initialized entry.
        present = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
    }
    Err(io::Error::other("initial owned thread was not found"))
}

struct LocalAllocation(*mut core::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: Only successful LocalAlloc-based API results enter this owner.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn owner_sid() -> io::Result<String> {
    let mut token = ptr::null_mut();
    // SAFETY: Current-process pseudo handle and a valid writable output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful OpenProcessToken returns one owned valid handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut length = 0;
    // SAFETY: The first query deliberately supplies no buffer to obtain its size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut length,
        );
    }
    if length == 0 || length > 65536 {
        return Err(io::Error::other("invalid token information size"));
    }
    let mut storage = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    // SAFETY: Aligned writable storage covers the requested size; token is live.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful TokenUser result contains a valid SID within the buffer.
    let sid = unsafe { (*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text = ptr::null_mut();
    // SAFETY: Valid SID and writable output; successful allocation is uniquely owned.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(text.cast());
    let mut units = Vec::new();
    for index in 0..512 {
        // SAFETY: A successful Windows SID conversion produces a NUL-terminated
        // SID string; valid SID strings are much shorter than the bound.
        let unit = unsafe { *text.add(index) };
        if unit == 0 {
            return String::from_utf16(&units)
                .map_err(|_| io::Error::other("invalid SID encoding"));
        }
        units.push(unit);
    }
    Err(io::Error::other("SID string exceeds limit"))
}

fn sid(text: &str) -> io::Result<LocalAllocation> {
    let wide: Vec<_> = text.encode_utf16().chain(Some(0)).collect();
    let mut result = ptr::null_mut();
    // SAFETY: NUL-terminated input and writable output, freed through LocalFree.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut result) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalAllocation(result))
}

fn private_acl(path: &Path, protected: bool) -> io::Result<()> {
    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: Native NUL-terminated path and correctly typed writable outputs.
    let error = unsafe {
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
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let _allocation = LocalAllocation(descriptor);
    if descriptor.is_null() || acl.is_null() {
        return Err(io::Error::other("state DACL is missing"));
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: Successful API returns a live descriptor and DACL.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Valid OS-returned ACL inside the owned descriptor.
    if (protected && control & SE_DACL_PROTECTED == 0) || unsafe { (*acl).AceCount } != 2 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state DACL is not exclusively private",
        ));
    }
    let owner = sid(&owner_sid()?)?;
    let system = sid("S-1-5-18")?;
    let mut seen = [false; 2];
    for index in 0..2 {
        let mut raw = ptr::null_mut();
        // SAFETY: Index is within the checked ACL count, with writable output.
        if unsafe { GetAce(acl, index, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: The OS returned an aligned ACE. Check its header before payload.
        let header = unsafe { &*raw.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err(io::Error::other("unexpected state ACE"));
        }
        // SAFETY: Checked allowed-ACE type and size in a valid OS descriptor.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let principal = ptr::from_ref(&ace.SidStart).cast_mut().cast();
        // SAFETY: ACE SID validated before comparison to independently owned SIDs.
        if ace.Mask != 0x001f_01ff || unsafe { IsValidSid(principal) } == 0 {
            return Err(io::Error::other("invalid state ACE"));
        }
        if unsafe { EqualSid(principal, owner.0) } != 0 {
            seen[0] = true;
        } else if unsafe { EqualSid(principal, system.0) } != 0 {
            seen[1] = true;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected state principal",
            ));
        }
    }
    if !seen.into_iter().all(|value| value) {
        return Err(io::Error::other("state DACL principals differ"));
    }
    Ok(())
}

pub(in crate::managed) fn private_directory(path: &Path, metadata: &Metadata) -> io::Result<()> {
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("state reparse points are forbidden"));
    }
    private_acl(path, true)
}

pub(in crate::managed) fn create_directory(path: &Path) -> io::Result<()> {
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{})", owner_sid()?);
    let sddl: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: NUL-terminated SDDL, revision 1 and writable output.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: Live descriptor and native path. Privacy applies atomically when
    // creating the directory, before any identity or credential file exists.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options
}

pub(in crate::managed) fn open_private(path: &Path, read_only: bool) -> io::Result<File> {
    let mut options = options();
    options.read(true);
    if !read_only {
        options.write(true).create(true);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(
            "control file must be regular and not a reparse point",
        ));
    }
    private_acl(path, false)?;
    Ok(file)
}

pub(in crate::managed) fn create_private(path: &Path) -> io::Result<File> {
    options().read(true).write(true).create_new(true).open(path)
}

pub(in crate::managed) fn protect_generated(path: &Path) -> io::Result<()> {
    open_private(path, true).map(drop)
}

pub(in crate::managed) fn open_owned_lock(path: &Path) -> io::Result<File> {
    open_private(path, false)
}
