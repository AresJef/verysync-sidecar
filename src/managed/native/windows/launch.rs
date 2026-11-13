//! Exact Windows process creation with an explicit inherited-handle list.
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::os::windows::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::ptr;

use windows_sys::Win32::Foundation::{
    DuplicateHandle, SetHandleInformation, DUPLICATE_SAME_ACCESS, HANDLE, HANDLE_FLAG_INHERIT,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

pub(in crate::managed) struct Child {
    process: OwnedHandle,
    pid: u32,
    status: Option<ExitStatus>,
    pub(in crate::managed) stdin: Option<File>,
}
impl AsRawHandle for Child {
    fn as_raw_handle(&self) -> RawHandle {
        self.process.as_raw_handle()
    }
}
impl Child {
    pub(in crate::managed) fn id(&self) -> u32 {
        self.pid
    }
    pub(in crate::managed) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        // SAFETY: Read-only wait on this uniquely retained exact process handle.
        match unsafe { WaitForSingleObject(self.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => self.exit_status().map(Some),
            _ => Err(io::Error::last_os_error()),
        }
    }
    pub(in crate::managed) fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        // SAFETY: This blocking native call runs only on the private owner thread.
        if unsafe { WaitForSingleObject(self.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        self.exit_status()
    }
    fn exit_status(&mut self) -> io::Result<ExitStatus> {
        let mut code = 0;
        // SAFETY: Live retained process and initialized writable output. Its
        // signaled state was checked first, so exit code 259 is not misclassified.
        if unsafe { GetExitCodeProcess(self.as_raw_handle(), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = ExitStatus::from_raw(code);
        self.status = Some(status);
        Ok(status)
    }
    pub(in crate::managed) fn kill(&mut self) -> io::Result<()> {
        // SAFETY: Only this retained exact child is terminated on creation errors.
        if unsafe { TerminateProcess(self.as_raw_handle(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native process value contains NUL",
        ));
    }
    value.push(0);
    Ok(value)
}

// Quote each native argument using the Windows backslash-before-quote rules.
// There is no shell, raw command-line interpolation or lossy UTF-8 conversion.
fn argument(output: &mut Vec<u16>, value: &OsStr) -> io::Result<()> {
    let value = wide(value)?;
    output.push(b'"' as u16);
    let mut slashes = 0;
    for &unit in &value[..value.len() - 1] {
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        let count = if unit == b'"' as u16 {
            slashes * 2 + 1
        } else {
            slashes
        };
        output.extend(std::iter::repeat_n(b'\\' as u16, count));
        output.push(unit);
        slashes = 0;
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    output.push(b'"' as u16);
    Ok(())
}

fn inheritable(file: &File) -> io::Result<OwnedHandle> {
    let mut handle = ptr::null_mut();
    // SAFETY: Duplicate only our private selected file; the original's flags
    // are never changed. No caller standard handle or global state is mutated.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            file.as_raw_handle(),
            GetCurrentProcess(),
            &mut handle,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: A successful call returned one newly owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn null(input: bool) -> io::Result<OwnedHandle> {
    inheritable(
        &OpenOptions::new()
            .read(input)
            .write(!input)
            .open(r"\\.\NUL")?,
    )
}
fn stdin(pipe: bool) -> io::Result<(OwnedHandle, Option<File>)> {
    if !pipe {
        return Ok((null(true)?, None));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: Initialized security attributes and distinct writable outputs.
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful CreatePipe returned two uniquely owned handles.
    let read = unsafe { OwnedHandle::from_raw_handle(read) };
    let write = unsafe { File::from_raw_handle(write) };
    // SAFETY: Change only this newly allocated private parent writer's flag.
    if unsafe { SetHandleInformation(write.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((read, Some(write)))
}

struct Attributes(Vec<usize>);
impl Attributes {
    fn new(handles: &[HANDLE]) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: The documented sizing call writes only the required length.
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 1024 * 1024 {
            return Err(io::Error::other("invalid native attribute allocation size"));
        }
        let mut memory = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: Initialized pointer-aligned allocation has at least bytes bytes.
        if unsafe {
            InitializeProcThreadAttributeList(memory.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut result = Self(memory);
        // SAFETY: Live initialized list, exactly three live inheritable handles;
        // the handle slice remains alive until CreateProcess returns below.
        if unsafe {
            UpdateProcThreadAttribute(
                result.0.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: This owner is constructed only after successful initialization.
        unsafe {
            DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast());
        }
    }
}

pub(super) fn create(
    command: &Command,
    io: crate::managed::process::ProcessIo,
) -> io::Result<(Child, OwnedHandle)> {
    let program = wide(command.get_program())?;
    let mut line = Vec::new();
    argument(&mut line, command.get_program())?;
    for value in command.get_args() {
        line.push(b' ' as u16);
        argument(&mut line, value)?;
    }
    line.push(0);
    let directory = command
        .get_current_dir()
        .map(|p| wide(p.as_os_str()))
        .transpose()?;
    let mut environment = Vec::new();
    // The internal builder env_clear/vars_os snapshot is complete; Command's
    // Windows environment map already provides native case-insensitive ordering.
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            let key = wide(key)?;
            let value = wide(value)?;
            environment.extend_from_slice(&key[..key.len() - 1]);
            environment.push(b'=' as u16);
            environment.extend(value);
        }
    }
    if environment.is_empty() {
        environment.push(0);
    }
    environment.push(0);
    let (input, writer) = stdin(io.stdin_pipe)?;
    let output = io
        .stdout
        .as_ref()
        .map_or_else(|| null(false), inheritable)?;
    let error = io
        .stderr
        .as_ref()
        .map_or_else(|| null(false), inheritable)?;
    let handles = [
        input.as_raw_handle(),
        output.as_raw_handle(),
        error.as_raw_handle(),
    ];
    let mut attributes = Attributes::new(&handles)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.0.as_mut_ptr().cast();
    let mut created = PROCESS_INFORMATION::default();
    // SAFETY: All native strings are NUL terminated, line is writable, the
    // environment is double-NUL terminated, and structures/selected handles and
    // attribute storage stay live. The exact child starts suspended, without a
    // new console, inheriting only the explicitly listed private stdio handles.
    if unsafe {
        CreateProcessW(
            program.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            directory.as_ref().map_or(ptr::null(), |d| d.as_ptr()),
            &startup.StartupInfo,
            &mut created,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful creation returned two uniquely owned exact handles.
    let process = unsafe { OwnedHandle::from_raw_handle(created.hProcess) };
    let thread = unsafe { OwnedHandle::from_raw_handle(created.hThread) };
    Ok((
        Child {
            process,
            pid: created.dwProcessId,
            status: None,
            stdin: writer,
        },
        thread,
    ))
}
