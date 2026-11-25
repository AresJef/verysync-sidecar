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

use std::process::Command;
mod launch;
pub(in crate::managed) use launch::Child;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetSecurityDescriptorControl, GetTokenInformation, IsValidSid, TokenUser,
    ACCESS_ALLOWED_ACE, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
    NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    READ_CONTROL,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, ResumeThread};

pub(in crate::managed) struct ProcessGuard(OwnedHandle);

// Observe the held descendant process, not a duplicated Job handle. Keeping a
// Job open in a test would conceal an erroneous kill-on-last-close policy.
#[cfg(test)]
pub(in crate::managed) struct TestChildObservation(OwnedHandle);
#[cfg(test)]
pub(in crate::managed) fn observe_test_descendant(
    _group: u32,
    pid: u32,
) -> io::Result<TestChildObservation> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};
    // SAFETY: Read-only synchronization access to a task-owned descendant PID.
    // The returned noninheritable handle retains its identity across root exit.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful OpenProcess returns one uniquely owned live handle.
    Ok(TestChildObservation(unsafe {
        OwnedHandle::from_raw_handle(handle)
    }))
}
#[cfg(test)]
impl TestChildObservation {
    pub(in crate::managed) fn stopped(&self) -> io::Result<bool> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        // SAFETY: Zero-time read-only observation on the retained process handle.
        match unsafe { WaitForSingleObject(self.0.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

pub(in crate::managed) fn spawn(
    mut command: Command,
    helper: bool,
    lifetime: crate::managed::ManagedLifetime,
    io: crate::managed::process::ProcessIo,
) -> io::Result<(Child, ProcessGuard)> {
    let guard = private_job(helper || lifetime == crate::managed::ManagedLifetime::CallerOwned)?;
    if !helper {
        // The SDK owns monitoring/restart for this fixed baseline. Select the
        // direct core so suspended creation and private Job ownership apply to
        // that core, without another upstream monitoring generation.
        command.env("VSMONITORED", "yes");
    }
    let (mut child, thread) = launch::create(&command, io, &guard.0)?;
    // SAFETY: The exact initial thread returned by CreateProcess remains owned
    // and suspended, after the process joined its private Job.
    if unsafe { ResumeThread(thread.as_raw_handle()) } != 1 {
        let error = io::Error::other("unexpected initial suspend count");
        let _ = guard.stop(&mut child);
        let _ = child.wait();
        return Err(error);
    }
    Ok((child, guard))
}

fn private_job(caller_owned: bool) -> io::Result<ProcessGuard> {
    // SAFETY: Null attributes/name create an unnamed noninheritable private Job.
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful API returned one newly owned handle.
    let guard = ProcessGuard(unsafe { OwnedHandle::from_raw_handle(raw) });
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    if caller_owned {
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }
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
    Ok(guard)
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

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";

fn allowed_principals(caller: &str) -> impl Iterator<Item = &str> {
    std::iter::once(caller).chain((caller != SYSTEM).then_some(SYSTEM))
}

fn private_acl(file: &File, directory: bool) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: A live opened file handle and correctly typed writable outputs.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
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
    if descriptor.is_null() || owner.is_null() || acl.is_null() {
        return Err(io::Error::other("state owner or DACL is missing"));
    }
    let caller = owner_sid()?;
    let principals = allowed_principals(&caller)
        .map(sid)
        .collect::<io::Result<Vec<_>>>()?;
    let administrators = sid(ADMINISTRATORS)?;
    // Elevated native files can have the built-in Administrators default owner.
    // This group is already inside the machine administrator trust boundary.
    // It receives no DACL grant here.
    // SAFETY: All SIDs are live in checked native allocations.
    let trusted_owner = unsafe {
        IsValidSid(owner) != 0
            && (EqualSid(owner, administrators.0) != 0
                || principals.iter().any(|known| EqualSid(owner, known.0) != 0))
    };
    if !trusted_owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the state has a different owner. Use a new private directory or ask an administrator to review ownership before migrating",
        ));
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: Successful API returns a live descriptor and DACL.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Valid OS-returned ACL inside the owned descriptor.
    if (directory && control & SE_DACL_PROTECTED == 0)
        || usize::from(unsafe { (*acl).AceCount }) != principals.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state DACL is not exclusively private",
        ));
    }
    let mut seen = vec![false; principals.len()];
    for index in 0..principals.len() {
        let mut raw = ptr::null_mut();
        // SAFETY: Index is within the checked ACL count, with writable output.
        if unsafe { GetAce(acl, index as u32, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: The OS returned an aligned ACE. Check its header before payload.
        let header = unsafe { &*raw.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        let flags = u32::from(header.AceFlags);
        let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        if header.AceType != 0
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            || flags & (INHERIT_ONLY_ACE | NO_PROPAGATE_INHERIT_ACE) != 0
            || (directory && flags & inheritance != inheritance)
        {
            return Err(io::Error::other("unexpected state ACE"));
        }
        // SAFETY: Checked allowed-ACE type and size in a valid OS descriptor.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let principal = ptr::from_ref(&ace.SidStart).cast_mut().cast();
        // SAFETY: ACE SID validated before comparison to independently owned SIDs.
        if ace.Mask != FILE_ALL_ACCESS || unsafe { IsValidSid(principal) } == 0 {
            return Err(io::Error::other("invalid state ACE"));
        }
        let Some(matched) = principals
            .iter()
            .position(|known| unsafe { EqualSid(principal, known.0) } != 0)
        else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected state principal",
            ));
        };
        if seen[matched] {
            return Err(io::Error::other("duplicate state principal"));
        }
        seen[matched] = true;
    }
    Ok(())
}

pub(in crate::managed) fn private_directory(path: &Path, _metadata: &Metadata) -> io::Result<()> {
    retain_private_directory(path).map(drop)
}

pub(in crate::managed) fn retain_private_directory(path: &Path) -> io::Result<File> {
    let file = options()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(
            "state directory must not be a reparse point",
        ));
    }
    private_acl(&file, true)?;
    Ok(file)
}

pub(in crate::managed) fn create_directory(path: &Path) -> io::Result<()> {
    let caller = owner_sid()?;
    let mut sddl = format!("O:{caller}D:P");
    for principal in allowed_principals(&caller) {
        use std::fmt::Write;
        write!(sddl, "(A;OICI;FA;;;{principal})").expect("writing to a String cannot fail");
    }
    create_directory_with_sddl(path, &sddl)?;
    retain_private_directory(path).map(drop)
}

fn create_directory_with_sddl(path: &Path, sddl: &str) -> io::Result<()> {
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
    validate_control_file(file)
}

fn validate_control_file(file: File) -> io::Result<File> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(
            "control file must be regular and not a reparse point",
        ));
    }
    private_acl(&file, false)?;
    Ok(file)
}

pub(in crate::managed) fn create_private(path: &Path) -> io::Result<File> {
    let file = options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    validate_control_file(file)
}

pub(in crate::managed) fn protect_generated(path: &Path) -> io::Result<()> {
    open_private(path, true).map(drop)
}

pub(in crate::managed) fn open_owned_lock(path: &Path) -> io::Result<File> {
    // This is an observation of an existing upstream resource, not admission
    // that may create the library's own private control files.
    let file = options().read(true).write(true).open(path)?;
    validate_control_file(file)
}

pub(in crate::managed) fn open_snapshot_input(path: &Path) -> io::Result<File> {
    open_private(path, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_private_directories_and_controls_reopen_for_the_actual_caller() -> io::Result<()> {
        let caller = owner_sid()?;
        if std::env::var_os("VSS_WINDOWS_REQUIRE_SYSTEM").is_some() {
            assert_eq!(caller, SYSTEM);
        }
        let fixture = tempfile::tempdir()?;
        let path = fixture.path().join("state");
        create_directory(&path)?;
        drop(retain_private_directory(&path)?);
        let control = path.join("private-test-control");
        let content = b"synthetic file";
        std::io::Write::write_all(&mut create_private(&control)?, content)?;
        let mut reopened = open_private(&control, true)?;
        let mut observed = Vec::new();
        std::io::Read::read_to_end(&mut reopened, &mut observed)?;
        assert_eq!(observed, content);
        let leased_state = fixture.path().join("leased-state");
        use crate::managed::state::StateLease;
        let acquire = || StateLease::acquire(&leased_state).map_err(io::Error::other);
        drop(acquire()?);
        drop(acquire()?);
        let extra = fixture.path().join("extra-grant");
        let grants: String = allowed_principals(&caller)
            .map(|sid| format!("(A;OICI;FA;;;{sid})"))
            .collect();
        create_directory_with_sddl(&extra, &format!("O:{caller}D:P{grants}(A;OICI;FR;;;WD)"))?;
        assert_eq!(
            retain_private_directory(&extra).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        println!(
            "Windows native ACL evidence: caller_is_system={}, expected_principals={}, private state, lease and controls reopened, extra ACL rejected",
            caller == SYSTEM,
            allowed_principals(&caller).count()
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires a disposable Windows service-owned ACL fixture"]
    fn windows_rejects_the_foreign_owner_before_mutating_directory_or_file() -> io::Result<()> {
        let root = std::env::var_os("VSS_WINDOWS_FOREIGN_FIXTURE")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| io::Error::other("an isolated foreign-owner fixture is required"))?;
        let directory = root.join("foreign-state");
        let error = retain_private_directory(&directory).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("the state has a different owner"));
        let file = root.join("foreign-control.bin");
        let error = open_private(&file, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("the state has a different owner"));
        assert_eq!(std::fs::read(file)?, b"synthetic foreign control");
        assert_eq!(
            std::fs::read(directory.join("sample.bin"))?,
            b"synthetic foreign state"
        );
        println!("Windows owner evidence: opened foreign-owned state and control were refused before writing; both canaries are unchanged.");
        Ok(())
    }

    #[test]
    fn windows_job_contains_child_before_the_first_resume() -> io::Result<()> {
        use windows_sys::Win32::Foundation::{FILETIME, WAIT_OBJECT_0};
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        use windows_sys::Win32::System::Threading::{GetProcessTimes, WaitForSingleObject};

        let guard = private_job(true)?;
        let mut command = Command::new(std::env::current_exe()?);
        command.arg("--list").env_clear().envs(std::env::vars_os());
        let io = crate::managed::process::ProcessIo {
            stdin_pipe: false,
            stdout: None,
            stderr: None,
        };
        let (mut child, thread) = launch::create(&command, io, &guard.0)?;
        let job = guard.0.as_raw_handle();
        let mut child_member = 0;
        let mut host_member = 0;
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: The private Job, child, initial thread and host handles are
        // live, and each native query has separate writable output.
        let measured = unsafe {
            IsProcessInJob(child.as_raw_handle(), job, &mut child_member) != 0
                && IsProcessInJob(GetCurrentProcess(), job, &mut host_member) != 0
                && GetProcessTimes(
                    child.as_raw_handle(),
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                ) != 0
        };
        let born = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        let pid = child.id();
        assert!(child.try_wait()?.is_none());
        drop(guard);
        // SAFETY: Wait only on the exact still-unresumed process with a bound.
        let closed = unsafe { WaitForSingleObject(child.as_raw_handle(), 10_000) } == WAIT_OBJECT_0;
        if !closed {
            child.kill()?;
            child.wait()?;
        }
        drop(thread);
        assert!(measured && born != 0 && child_member != 0 && host_member == 0 && closed);
        println!("Windows native Job evidence: exact_pid={pid}, creation_filetime={born}, child_member_before_resume=true, unrelated_host_member=false, reaped_on_last_job_handle_close=true");
        Ok(())
    }
}
