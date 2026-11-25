//! Read the Darwin ACL on the same descriptor used for the private object.

use std::ffi::{c_int, c_void};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::ptr::{self, NonNull};

const TYPE_EXTENDED: c_int = 0x100;
const FIRST_ENTRY: c_int = 0;
const NEXT_ENTRY: c_int = -1;
const ALLOW: c_int = 1;
const DENY: c_int = 2;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
    fn acl_valid(acl: *mut c_void) -> c_int;
    fn acl_get_entry(acl: *mut c_void, selector: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
    fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
    fn acl_free(value: *mut c_void) -> c_int;
    fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> c_int;
}

struct AclAllocation(NonNull<c_void>);

impl Drop for AclAllocation {
    fn drop(&mut self) {
        // SAFETY: This allocation was returned by Darwin's ACL library.
        unsafe { acl_free(self.0.as_ptr()) };
    }
}

fn privacy_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Cannot confirm private access. Choose a private directory that grants access only to your account.",
    )
}

pub(super) fn check(file: &File, owner: libc::uid_t) -> io::Result<()> {
    // SAFETY: The file owns an open descriptor. Darwin returns either a new ACL
    // allocation or null, and never changes the underlying object.
    let Some(raw) = NonNull::new(unsafe { acl_get_fd_np(file.as_raw_fd(), TYPE_EXTENDED) }) else {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            // A present descriptor with no extended ACL is reported as ENOENT.
            Ok(())
        } else {
            Err(privacy_error())
        };
    };
    let acl = AclAllocation(raw);
    // SAFETY: The opaque ACL allocation remains valid for this check.
    if unsafe { acl_valid(acl.0.as_ptr()) } != 0 {
        return Err(privacy_error());
    }
    let mut selector = FIRST_ENTRY;
    loop {
        let mut entry = ptr::null_mut();
        // SAFETY: The selector is first or next in the validated ACL, and
        // entry points to writable pointer storage for its borrowed entry.
        if unsafe { acl_get_entry(acl.0.as_ptr(), selector, &mut entry) } != 0 {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                // Darwin uses EINVAL once the validated list is exhausted.
                Ok(())
            } else {
                Err(privacy_error())
            };
        }
        let mut tag = 0;
        // SAFETY: The entry was obtained from the live ACL. Tag is writable.
        if entry.is_null() || unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
            return Err(privacy_error());
        }
        match tag {
            DENY => {}
            ALLOW => {
                // Include inherited and inherit-only entries. A grant can
                // affect descendants even when it does not apply to this object.
                let mut owner_uuid = [0_u8; 16];
                // SAFETY: Darwin uuid_t is a 16-byte writable array.
                if unsafe { mbr_uid_to_uuid(owner, owner_uuid.as_mut_ptr()) } != 0 {
                    return Err(privacy_error());
                }
                // SAFETY: The entry remains valid within this ACL and its
                // allocated qualifier is a Darwin uuid_t.
                let Some(qualifier) = NonNull::new(unsafe { acl_get_qualifier(entry) }) else {
                    return Err(privacy_error());
                };
                let qualifier = AclAllocation(qualifier);
                // SAFETY: The live allocated qualifier contains 16 bytes.
                if unsafe { *qualifier.0.as_ptr().cast::<[u8; 16]>() } != owner_uuid {
                    return Err(privacy_error());
                }
            }
            _ => return Err(privacy_error()),
        }
        selector = NEXT_ENTRY;
    }
}
