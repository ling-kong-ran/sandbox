use std::collections::{BTreeSet, HashMap};
use std::ffi::{CStr, CString};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_sandbox_protocol::{
    CapabilityReport, CommandSpec, EnforcementStatus, FeatureState, MountAccess, NetworkMode,
    ResourceLimits, ShellChoice,
};

use crate::{NativeProcess, SandboxError, ValidatedExecution, ValidatedPolicy};

#[derive(Debug)]
pub(crate) struct PreparedUnixSandbox {
    pub(crate) temp_dir: PathBuf,
}

#[derive(Debug)]
struct WatchState {
    process_group: i32,
    tracked: Mutex<BTreeSet<i32>>,
    done: AtomicBool,
}

impl WatchState {
    fn terminate(&self) {
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        if let Ok(tracked) = self.tracked.lock() {
            for pid in tracked.iter().copied() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessControl {
    state: Arc<WatchState>,
}

impl ProcessControl {
    pub(crate) fn terminate(&self) {
        self.state.terminate();
    }
}

pub(crate) fn probe() -> Result<(), SandboxError> {
    Ok(())
}

pub(crate) fn report() -> CapabilityReport {
    let mut features = std::collections::BTreeMap::new();
    for name in [
        "filesystemReadBoundary",
        "filesystemWriteBoundary",
        "networkDeny",
        "processTree",
        "memoryLimit",
        "cpuLimit",
        "processLimit",
    ] {
        features.insert(name.into(), FeatureState::Enforced);
    }
    features.insert("filesystemRpc".into(), FeatureState::Unavailable);
    CapabilityReport {
        platform: "macos".into(),
        backend: "macos-seatbelt-libproc-watchdog".into(),
        status: EnforcementStatus::Enforced,
        features,
        reasons: vec![
            "Seatbelt restrictions inherit across the complete descendant tree".into(),
            "libproc watchdog enforcement terminates the tracked tree on aggregate resource limits"
                .into(),
        ],
    }
}

pub(crate) async fn prepare(
    sandbox_id: &str,
    _policy: &ValidatedPolicy,
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
                SandboxError::BackendUnavailable(format!("cannot reset sandbox temp: {error}"))
            })?;
    }
    tokio::fs::create_dir(&temp_dir).await.map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot create sandbox temp: {error}"))
    })?;
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| {
            SandboxError::BackendUnavailable(format!("cannot protect sandbox temp: {error}"))
        })?;
    Ok(PreparedUnixSandbox { temp_dir })
}

pub(crate) async fn cleanup(platform: &PreparedUnixSandbox) -> Result<(), SandboxError> {
    match tokio::fs::remove_dir_all(&platform.temp_dir).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SandboxError::BackendUnavailable(format!(
            "cannot remove sandbox temp: {error}"
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
            apply_cpu_limit(&limits)
                .map_err(|error| std::io::Error::other(format!("CPU limit: {error}")))?;
            apply_seatbelt(&read_paths, &write_paths, deny_network)
                .map_err(|error| std::io::Error::other(format!("Seatbelt: {error}")))
        });
    }

    let mut child = command.spawn().map_err(|error| {
        SandboxError::Process(format!("failed to launch macOS sandbox process: {error}"))
    })?;
    let pid =
        i32::try_from(child.id()).map_err(|_| SandboxError::Process("invalid child PID".into()))?;
    let state = Arc::new(WatchState {
        process_group: pid,
        tracked: Mutex::new(BTreeSet::from([pid])),
        done: AtomicBool::new(false),
    });
    start_watchdog(Arc::clone(&state), execution.limits.clone());

    let stdin = child.stdin.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_fd(stream.into_raw_fd()))
    });
    let stdout = child.stdout.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_fd(stream.into_raw_fd()))
    });
    let stderr = child.stderr.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_fd(stream.into_raw_fd()))
    });
    let wait_state = Arc::clone(&state);
    let wait = tokio::task::spawn_blocking(move || {
        let result = child
            .wait()
            .map(|status| status.code().unwrap_or(1))
            .map_err(|error| SandboxError::Process(format!("macOS sandbox wait failed: {error}")));
        wait_state.done.store(true, Ordering::Release);
        wait_state.terminate();
        result
    });
    Ok(NativeProcess {
        stdin,
        stdout,
        stderr,
        wait,
        control: ProcessControl { state },
    })
}

fn start_watchdog(state: Arc<WatchState>, limits: ResourceLimits) {
    std::thread::spawn(move || {
        while !state.done.load(Ordering::Acquire) {
            let snapshots = process_snapshots();
            let mut tracked = match state.tracked.lock() {
                Ok(tracked) => tracked,
                Err(_) => {
                    state.terminate();
                    return;
                }
            };
            let mut changed = true;
            while changed {
                changed = false;
                for snapshot in snapshots.values() {
                    if tracked.contains(&snapshot.ppid) && tracked.insert(snapshot.pid) {
                        changed = true;
                    }
                }
            }
            let mut count = 0_u32;
            let mut resident = 0_u64;
            let mut cpu_nanos = 0_u64;
            tracked.retain(|pid| {
                if let Some(snapshot) = snapshots.get(pid) {
                    count = count.saturating_add(1);
                    resident = resident.saturating_add(snapshot.resident_size);
                    cpu_nanos = cpu_nanos
                        .saturating_add(snapshot.user_time)
                        .saturating_add(snapshot.system_time);
                    true
                } else {
                    false
                }
            });
            let exceeded = count > limits.processes
                || resident > limits.memory_bytes
                || cpu_nanos > limits.cpu_time_ms.saturating_mul(1_000_000);
            drop(tracked);
            if exceeded {
                state.terminate();
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

#[derive(Debug, Clone, Copy)]
struct ProcessSnapshot {
    pid: i32,
    ppid: i32,
    resident_size: u64,
    user_time: u64,
    system_time: u64,
}

fn process_snapshots() -> HashMap<i32, ProcessSnapshot> {
    let capacity = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if capacity <= 0 {
        return HashMap::new();
    }
    let mut pids = vec![0_i32; capacity as usize + 64];
    let bytes = i32::try_from(pids.len() * std::mem::size_of::<i32>()).unwrap_or(i32::MAX);
    let count = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    if count <= 0 {
        return HashMap::new();
    }
    pids.truncate(count as usize);
    pids.into_iter()
        .filter_map(process_snapshot)
        .map(|value| (value.pid, value))
        .collect()
}

fn process_snapshot(pid: i32) -> Option<ProcessSnapshot> {
    let mut bsd = ProcBsdInfo::default();
    let bsd_size = i32::try_from(std::mem::size_of::<ProcBsdInfo>()).ok()?;
    if unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            (&mut bsd as *mut ProcBsdInfo).cast(),
            bsd_size,
        )
    } != bsd_size
    {
        return None;
    }
    let mut task = ProcTaskInfo::default();
    let task_size = i32::try_from(std::mem::size_of::<ProcTaskInfo>()).ok()?;
    if unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTASKINFO,
            0,
            (&mut task as *mut ProcTaskInfo).cast(),
            task_size,
        )
    } != task_size
    {
        return None;
    }
    Some(ProcessSnapshot {
        pid,
        ppid: bsd.pbi_ppid as i32,
        resident_size: task.pti_resident_size,
        user_time: task.pti_total_user,
        system_time: task.pti_total_system,
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
        .ok_or_else(|| SandboxError::InvalidPolicy("logical cwd mount unavailable".into()))?;
    Ok(mount.source.join(relative))
}

fn command_line(command: &CommandSpec) -> Result<(PathBuf, Vec<String>), SandboxError> {
    match command {
        CommandSpec::Exec { program, args } => Ok((PathBuf::from(program), args.clone())),
        CommandSpec::Shell {
            shell: ShellChoice::Default,
            script,
        } => Ok((PathBuf::from("/bin/sh"), vec!["-c".into(), script.clone()])),
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
        "/usr/lib",
        "/System/Library",
        "/Library/Apple",
    ] {
        let path = PathBuf::from(path);
        if path.exists() {
            paths.insert(path.canonicalize().unwrap_or(path));
        }
    }
    for path in ["/dev/null", "/dev/urandom"] {
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

fn apply_cpu_limit(limits: &ResourceLimits) -> std::io::Result<()> {
    let seconds = limits.cpu_time_ms.saturating_add(999) / 1000;
    let value = libc::rlimit {
        rlim_cur: seconds as libc::rlim_t,
        rlim_max: seconds as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &value) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn apply_seatbelt(
    read_paths: &[PathBuf],
    write_paths: &[PathBuf],
    deny_network: bool,
) -> std::io::Result<()> {
    let mut profile = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec*)\n\
         (allow process-fork)\n\
         (allow process-info* (target self))\n\
         (allow process-info* (target same-sandbox))\n\
         (allow signal (target self))\n\
         (allow signal (target same-sandbox))\n\
         (allow sysctl-read)\n\
         (allow mach-lookup)\n\
         (deny mach-lookup (global-name \"com.apple.SecurityServer\"))\n\
         (deny mach-lookup (global-name \"com.apple.securityd\"))\n\
         (deny mach-lookup (global-name \"com.apple.security.keychaind\"))\n\
         (deny mach-lookup (global-name \"com.apple.secd\"))\n\
         (deny mach-lookup (global-name \"com.apple.security.agent\"))\n\
         (allow mach-per-user-lookup)\n\
         (allow mach-task-name)\n\
         (deny mach-priv*)\n\
         (allow ipc-posix-shm-read-data)\n\
         (allow ipc-posix-shm-write-data)\n\
         (allow ipc-posix-shm-write-create)\n\
         (allow system-fsctl)\n\
         (allow system-info)\n\
         (allow file-read-metadata)\n\
         (allow file-read* (literal \"/\"))\n",
    );
    for path in read_paths {
        let path = seatbelt_escape(path)?;
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{path}\"))\n\
             (allow file-map-executable (subpath \"{path}\"))\n"
        ));
    }
    for path in write_paths {
        profile.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))\n",
            seatbelt_escape(path)?
        ));
    }
    if !deny_network {
        profile.push_str("(allow network*)\n(allow system-socket)\n");
    }
    let profile = CString::new(profile).map_err(std::io::Error::other)?;
    let mut error = std::ptr::null_mut();
    let status = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::other(sandbox_error(error)))
    }
}

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

fn sandbox_error(error: *mut libc::c_char) -> String {
    if error.is_null() {
        return "sandbox_init failed".into();
    }
    let message = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    unsafe { sandbox_free_error(error) };
    message
}

const PROC_PIDTBSDINFO: i32 = 3;
const PROC_PIDTASKINFO: i32 = 4;

#[repr(C)]
#[derive(Default)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [u8; 16],
    pbi_name: [u8; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[repr(C)]
#[derive(Default)]
struct ProcTaskInfo {
    pti_virtual_size: u64,
    pti_resident_size: u64,
    pti_total_user: u64,
    pti_total_system: u64,
    pti_threads_user: u64,
    pti_threads_system: u64,
    pti_policy: i32,
    pti_faults: i32,
    pti_pageins: i32,
    pti_cow_faults: i32,
    pti_messages_sent: i32,
    pti_messages_received: i32,
    pti_syscalls_mach: i32,
    pti_syscalls_unix: i32,
    pti_csw: i32,
    pti_threadnum: i32,
    pti_numrunning: i32,
    pti_priority: i32,
}

unsafe extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> i32;
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
    fn proc_listallpids(buffer: *mut libc::c_void, buffersize: i32) -> i32;
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: i32,
    ) -> i32;
}
