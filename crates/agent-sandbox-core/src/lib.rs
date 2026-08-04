mod native;
mod policy;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_backend;
#[cfg(windows)]
mod windows_acl;

pub use native::{AuthorizationSpec, NativeBackend, NativeProcess, PreparedSandbox, ProfileSpec};
pub use policy::{SandboxError, ValidatedExecution, ValidatedMount, ValidatedPolicy};

#[cfg(target_os = "linux")]
pub fn run_linux_init(
    read_paths: &[std::path::PathBuf],
    write_paths: &[std::path::PathBuf],
    deny_network: bool,
    program: &std::ffi::OsStr,
    args: &[std::ffi::OsString],
) -> Result<(), SandboxError> {
    unix_backend::run_init(read_paths, write_paths, deny_network, program, args)
}
