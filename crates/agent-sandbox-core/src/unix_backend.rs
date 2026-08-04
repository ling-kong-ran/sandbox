use std::collections::BTreeSet;
#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use agent_sandbox_protocol::{
    CapabilityReport, CommandSpec, EnforcementStatus, FeatureState, MountAccess, NetworkMode,
    ResourceLimits,
};
use sha2::{Digest, Sha256};

use crate::{NativeProcess, SandboxError, ValidatedExecution, ValidatedPolicy};

#[derive(Debug)]
pub(crate) struct PreparedUnixSandbox {
    pub(crate) temp_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessControl {
    process_group: i32,
}

impl ProcessControl {
    pub(crate) fn terminate(&self) {
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
    }
}

pub(crate) fn probe() -> Result<(), SandboxError> {
    #[cfg(target_os = "linux")]
    probe_linux()?;
    #[cfg(target_os = "macos")]
    probe_macos()?;
    Ok(())
}

pub(crate) fn report() -> CapabilityReport {
    let mut features = std::collections::BTreeMap::new();
    features.insert("filesystemReadBoundary".into(), FeatureState::Enforced);
    features.insert("filesystemWriteBoundary".into(), FeatureState::Enforced);
    features.insert("networkDeny".into(), FeatureState::Enforced);
    features.insert("processTree".into(), FeatureState::Enforced);
    features.insert("memoryLimit".into(), FeatureState::Enforced);
    features.insert("cpuLimit".into(), FeatureState::Enforced);
    features.insert("processLimit".into(), FeatureState::Limited);
    features.insert("filesystemRpc".into(), FeatureState::Unavailable);
    CapabilityReport {
        platform: std::env::consts::OS.into(),
        backend: if cfg!(target_os = "linux") {
            "linux-landlock-seccomp"
        } else {
            "macos-seatbelt"
        }
        .into(),
        status: EnforcementStatus::Limited,
        features,
        reasons: vec![
            "per-user process count cannot be isolated without a privileged PID namespace".into(),
        ],
    }
}

pub(crate) async fn prepare(
    sandbox_id: &str,
    policy: &ValidatedPolicy,
) -> Result<PreparedUnixSandbox, SandboxError> {
    let suffix: String = sandbox_id
        .chars()
        .filter(|value| value.is_ascii_alphanumeric())
        .take(48)
        .collect();
    let temp_dir = std::env::temp_dir().join(format!("agent-sandbox-{suffix}"));
    if temp_dir.exists() {
        tokio::fs::remove_dir_all(&temp_dir)
            .await
            .map_err(|error| {
                SandboxError::BackendUnavailable(format!(
                    "cannot reset sandbox temp directory: {error}"
                ))
            })?;
    }
    tokio::fs::create_dir(&temp_dir).await.map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot create sandbox temp directory: {error}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|error| {
                SandboxError::BackendUnavailable(format!(
                    "cannot protect sandbox temp directory: {error}"
                ))
            })?;
    }
    let _ = policy;
    Ok(PreparedUnixSandbox { temp_dir })
}

pub(crate) async fn cleanup(platform: &PreparedUnixSandbox) -> Result<(), SandboxError> {
    match tokio::fs::remove_dir_all(&platform.temp_dir).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SandboxError::BackendUnavailable(format!(
            "cannot remove sandbox temp directory: {error}"
        ))),
    }
}

pub(crate) async fn spawn(
    policy: &ValidatedPolicy,
    platform: &PreparedUnixSandbox,
    execution: &ValidatedExecution,
    stdin_pipe: bool,
) -> Result<NativeProcess, SandboxError> {
    let workdir = native_workdir(policy, &execution.workdir)?;
    let (program, args) = command_line(&execution.command)?;
    let read_paths = runtime_read_paths(policy, execution, &program);
    let write_paths: Vec<PathBuf> = policy
        .mounts
        .values()
        .filter(|mount| mount.access == MountAccess::ReadWrite)
        .map(|mount| mount.source.clone())
        .chain(std::iter::once(platform.temp_dir.clone()))
        .collect();
    let deny_network = policy.original.network.mode == NetworkMode::Deny;
    let limits = execution.limits.clone();

    let mut command = Command::new(&program);
    command
        .args(args)
        .current_dir(&workdir)
        .env_clear()
        .envs(&execution.environment)
        .env("TMPDIR", &platform.temp_dir)
        .stdin(if stdin_pipe {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            apply_resource_limits(&limits)?;
            #[cfg(target_os = "linux")]
            apply_linux_sandbox(&read_paths, &write_paths, deny_network)?;
            #[cfg(target_os = "macos")]
            apply_macos_sandbox(&read_paths, &write_paths, deny_network)?;
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(|error| {
        SandboxError::Process(format!("failed to launch sandbox process: {error}"))
    })?;
    let pid =
        i32::try_from(child.id()).map_err(|_| SandboxError::Process("invalid child PID".into()))?;
    let stdin = child.stdin.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_fd(stream.into_raw_fd()))
    });
    let stdout = child.stdout.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_fd(stream.into_raw_fd()))
    });
    let stderr = child.stderr.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_fd(stream.into_raw_fd()))
    });
    let child = Arc::new(Mutex::new(Some(child)));
    let wait_child = Arc::clone(&child);
    let wait = tokio::task::spawn_blocking(move || {
        let mut guard = wait_child
            .lock()
            .map_err(|_| SandboxError::Process("process wait lock was poisoned".into()))?;
        let status = guard
            .as_mut()
            .ok_or_else(|| SandboxError::Process("process handle is unavailable".into()))?
            .wait()
            .map_err(|error| SandboxError::Process(format!("failed while waiting: {error}")))?;
        *guard = None;
        Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
    });
    Ok(NativeProcess {
        stdin,
        stdout,
        stderr,
        wait,
        control: ProcessControl { process_group: pid },
    })
}

fn native_workdir(policy: &ValidatedPolicy, logical: &str) -> Result<PathBuf, SandboxError> {
    let rest = logical
        .strip_prefix("mount://")
        .ok_or_else(|| SandboxError::InvalidPolicy("invalid logical cwd".into()))?;
    let (name, relative) = rest.split_once('/').unwrap_or((rest, ""));
    let mount = policy
        .mounts
        .get(name)
        .ok_or_else(|| SandboxError::InvalidPolicy("logical cwd mount is unavailable".into()))?;
    Ok(if relative.is_empty() {
        mount.source.clone()
    } else {
        mount.source.join(relative)
    })
}

fn command_line(command: &CommandSpec) -> Result<(PathBuf, Vec<String>), SandboxError> {
    match command {
        CommandSpec::Exec { program, args } => Ok((PathBuf::from(program), args.clone())),
        CommandSpec::Shell { shell, script } if shell == "default" => {
            Ok((PathBuf::from("/bin/sh"), vec!["-c".into(), script.clone()]))
        }
        CommandSpec::Shell { shell, .. } => Err(SandboxError::InvalidPolicy(format!(
            "unsupported native shell: {shell}"
        ))),
    }
}

fn runtime_read_paths(
    policy: &ValidatedPolicy,
    execution: &ValidatedExecution,
    program: &Path,
) -> Vec<PathBuf> {
    let mut paths: BTreeSet<PathBuf> = policy
        .mounts
        .values()
        .map(|mount| mount.source.clone())
        .collect();
    for path in [
        "/bin",
        "/usr/bin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
    ] {
        let path = PathBuf::from(path);
        if path.exists() {
            paths.insert(path.canonicalize().unwrap_or(path));
        }
    }
    for path in ["/etc/ld.so.cache", "/dev/null", "/dev/urandom"] {
        let path = PathBuf::from(path);
        if path.exists() {
            paths.insert(path.canonicalize().unwrap_or(path));
        }
    }
    if let Some(parent) = program.parent() {
        paths.insert(parent.to_path_buf());
    }
    if let Some(path) = execution.environment.get("PATH") {
        paths.extend(std::env::split_paths(path).filter_map(|entry| entry.canonicalize().ok()));
    }
    paths.into_iter().collect()
}

fn apply_resource_limits(limits: &ResourceLimits) -> std::io::Result<()> {
    let cpu_seconds = limits.cpu_time_ms.saturating_add(999) / 1000;
    let cpu = libc::rlimit {
        rlim_cur: cpu_seconds as libc::rlim_t,
        rlim_max: cpu_seconds as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &cpu) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let memory = libc::rlimit {
        rlim_cur: limits.memory_bytes as libc::rlim_t,
        rlim_max: limits.memory_bytes as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &memory) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn probe_linux() -> Result<(), SandboxError> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr,
    };
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V4))
        .and_then(|ruleset| ruleset.handle_access(AccessNet::from_all(ABI::V4)))
        .and_then(|ruleset| ruleset.create())
        .map_err(|error| {
            SandboxError::BackendUnavailable(format!("Linux Landlock ABI V4 is required: {error}"))
        })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_linux_sandbox(
    read_paths: &[PathBuf],
    write_paths: &[PathBuf],
    deny_network: bool,
) -> std::io::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr,
    };
    let abi = ABI::V4;
    let handled_fs = AccessFs::from_all(abi);
    let mut builder = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled_fs)
        .map_err(std::io::Error::other)?;
    if deny_network {
        builder = builder
            .handle_access(AccessNet::from_all(abi))
            .map_err(std::io::Error::other)?;
    }
    let mut ruleset = builder.create().map_err(std::io::Error::other)?;
    let read_access = (AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute) & handled_fs;
    let write_access = (read_access
        | AccessFs::WriteFile
        | AccessFs::MakeChar
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeBlock
        | AccessFs::MakeSym
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::Refer
        | AccessFs::Truncate)
        & handled_fs;
    for path in read_paths {
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(path).map_err(std::io::Error::other)?,
                read_access,
            ))
            .map_err(std::io::Error::other)?;
    }
    for path in write_paths {
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(path).map_err(std::io::Error::other)?,
                write_access,
            ))
            .map_err(std::io::Error::other)?;
    }
    ruleset.restrict_self().map_err(std::io::Error::other)?;
    if deny_network {
        install_network_seccomp()?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_network_seccomp() -> std::io::Result<()> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };
    let mut rules = Vec::new();
    for domain in [libc::AF_INET, libc::AF_INET6, libc::AF_PACKET] {
        rules.push(
            SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain as u64)
                    .map_err(std::io::Error::other)?,
            ])
            .map_err(std::io::Error::other)?,
        );
    }
    let filter: BpfProgram = SeccompFilter::new(
        [(libc::SYS_socket, rules)].into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH
            .try_into()
            .map_err(std::io::Error::other)?,
    )
    .map_err(std::io::Error::other)?
    .try_into()
    .map_err(std::io::Error::other)?;
    seccompiler::apply_filter(&filter).map_err(std::io::Error::other)
}

#[cfg(target_os = "macos")]
fn probe_macos() -> Result<(), SandboxError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_macos_sandbox(
    read_paths: &[PathBuf],
    write_paths: &[PathBuf],
    deny_network: bool,
) -> std::io::Result<()> {
    let mut profile = String::from(
        "(version 1)\n(deny default)\n(allow process*)\n(allow signal (target self))\n(allow file-read-metadata)\n",
    );
    for path in read_paths {
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            seatbelt_escape(path)?
        ));
    }
    for path in write_paths {
        profile.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))\n",
            seatbelt_escape(path)?
        ));
    }
    if !deny_network {
        profile.push_str("(allow network*)\n");
    }
    let profile = CString::new(profile).map_err(std::io::Error::other)?;
    let mut error_buffer = std::ptr::null_mut();
    let status = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error_buffer) };
    if status != 0 {
        let message = if error_buffer.is_null() {
            "sandbox_init failed".into()
        } else {
            let message = unsafe { CStr::from_ptr(error_buffer) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandbox_free_error(error_buffer) };
            message
        };
        return Err(std::io::Error::other(message));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn seatbelt_escape(path: &Path) -> std::io::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| std::io::Error::other("Seatbelt path is not UTF-8"))?;
    if value.chars().any(char::is_control) {
        return Err(std::io::Error::other(
            "Seatbelt path contains control characters",
        ));
    }
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> i32;
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

trait ExitStatusSignal {
    fn signal(&self) -> Option<i32>;
}

impl ExitStatusSignal for std::process::ExitStatus {
    fn signal(&self) -> Option<i32> {
        use std::os::unix::process::ExitStatusExt;
        ExitStatusExt::signal(self)
    }
}
