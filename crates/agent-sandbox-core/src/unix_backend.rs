#[cfg(target_os = "linux")]
#[path = "linux_backend.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "macos_backend.rs"]
mod platform;

#[cfg(target_os = "linux")]
pub(crate) use platform::run_init;

pub(crate) use platform::{
    PreparedUnixSandbox, ProcessControl, cleanup, prepare, probe, report, spawn,
};
