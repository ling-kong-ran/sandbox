use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, REVOKE_ACCESS,
    SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_FORM,
    TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_TYPE, TRUSTEE_W,
};
use windows::Win32::Security::{ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, PSID};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    OPEN_EXISTING,
};
use windows::core::{PCWSTR, PWSTR};

use crate::SandboxError;

const INHERIT_CHILDREN: u32 = 0x3;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

struct LocalAllocation(*mut core::ffi::c_void);

struct FileHandle(HANDLE);

impl Drop for FileHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

pub fn grant_tree(root: &Path, sid: &str, access: u32) -> Result<(), SandboxError> {
    let entries = checked_tree(root, true)?;
    for (path, directory) in entries {
        apply_acl(
            &path,
            sid,
            Some(access),
            if directory { INHERIT_CHILDREN } else { 0 },
        )?;
    }
    Ok(())
}

pub fn revoke_tree(root: &Path, sid: &str) -> Result<(), SandboxError> {
    if !root.exists() {
        return Ok(());
    }
    let mut entries = checked_tree(root, false)?;
    entries.reverse();
    for (path, _) in entries {
        apply_acl(&path, sid, None, 0)?;
    }
    Ok(())
}

fn checked_tree(root: &Path, reject_aliases: bool) -> Result<Vec<(PathBuf, bool)>, SandboxError> {
    let mut entries = Vec::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|error| {
            SandboxError::CapabilityUnavailable(format!(
                "cannot inspect mount before ACL lease: {error}"
            ))
        })?;
        let metadata = entry.metadata().map_err(|error| {
            SandboxError::CapabilityUnavailable(format!(
                "cannot inspect mount object before ACL lease: {error}"
            ))
        })?;
        use std::os::windows::fs::MetadataExt;
        if reject_aliases && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(SandboxError::CapabilityUnavailable(format!(
                "mount contains a reparse point: {}",
                entry.path().display()
            )));
        }
        if reject_aliases && metadata.is_file() && has_multiple_links(entry.path())? {
            return Err(SandboxError::CapabilityUnavailable(format!(
                "mount contains a hard-linked file: {}",
                entry.path().display()
            )));
        }
        entries.push((entry.path().to_path_buf(), metadata.is_dir()));
    }
    Ok(entries)
}

fn has_multiple_links(path: &Path) -> Result<bool, SandboxError> {
    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| {
        SandboxError::CapabilityUnavailable(format!(
            "cannot open mount object for link validation: {error}"
        ))
    })?;
    let handle = FileHandle(handle);
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle.0, &mut information) }.map_err(|error| {
        SandboxError::CapabilityUnavailable(format!("cannot validate mount hard links: {error}"))
    })?;
    Ok(information.nNumberOfLinks > 1)
}

fn apply_acl(
    path: &Path,
    sid: &str,
    access: Option<u32>,
    inheritance: u32,
) -> Result<(), SandboxError> {
    unsafe { apply_acl_inner(path, sid, access, inheritance) }
}

unsafe fn apply_acl_inner(
    path: &Path,
    sid: &str,
    access: Option<u32>,
    inheritance: u32,
) -> Result<(), SandboxError> {
    let sid_wide: Vec<u16> = sid.encode_utf16().chain(Some(0)).collect();
    let mut sid_pointer = PSID::default();
    unsafe { ConvertStringSidToSidW(PCWSTR(sid_wide.as_ptr()), &mut sid_pointer) }.map_err(
        |error| SandboxError::Internal(format!("cannot decode AppContainer SID: {error}")),
    )?;
    let _sid_guard = LocalAllocation(sid_pointer.0);

    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
    let mut old_acl: *mut ACL = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old_acl),
            None,
            &mut descriptor,
        )
    };
    if status.0 != 0 {
        return Err(SandboxError::CapabilityUnavailable(format!(
            "cannot read mount ACL for {}: {status:?}",
            path.display()
        )));
    }
    let _descriptor_guard = LocalAllocation(descriptor.0);

    let trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_FORM(TRUSTEE_IS_SID.0),
        TrusteeType: TRUSTEE_TYPE(TRUSTEE_IS_UNKNOWN.0),
        ptstrName: PWSTR(sid_pointer.0.cast()),
        ..Default::default()
    };

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access.unwrap_or_default(),
        grfAccessMode: if access.is_some() {
            if old_acl.is_null() {
                GRANT_ACCESS
            } else {
                SET_ACCESS
            }
        } else {
            REVOKE_ACCESS
        },
        grfInheritance: ACE_FLAGS(inheritance),
        Trustee: trustee,
    };

    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let status = unsafe {
        SetEntriesInAclW(
            Some(std::slice::from_ref(&entry)),
            (!old_acl.is_null()).then_some(old_acl as *const ACL),
            &mut new_acl,
        )
    };
    if status.0 != 0 {
        return Err(SandboxError::CapabilityUnavailable(format!(
            "cannot construct mount ACL for {}: {status:?}",
            path.display()
        )));
    }
    let _acl_guard = LocalAllocation(new_acl.cast());
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_acl as *const ACL),
            None,
        )
    };
    if status.0 != 0 {
        return Err(SandboxError::CapabilityUnavailable(format!(
            "cannot update mount ACL for {}: {status:?}",
            path.display()
        )));
    }
    Ok(())
}
