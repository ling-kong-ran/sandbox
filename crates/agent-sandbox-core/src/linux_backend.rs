use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use agent_sandbox_protocol::{
    CapabilityReport, CommandSpec, EnforcementStatus, FeatureState, MountAccess, NetworkMode,
    ResourceLimits, ShellChoice,
};

use crate::{NativeProcess, SandboxError, ValidatedExecution, ValidatedPolicy};

static CGROUP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static CGROUP_ROOT: OnceLock<Result<PathBuf, String>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct PreparedUnixSandbox {
    pub(crate) temp_dir: PathBuf,
    bwrap: PathBuf,
    cgroup_root: PathBuf,
}

#[derive(Debug)]
struct Cgroup {
    path: PathBuf,
    done: AtomicBool,
}

impl Cgroup {
    fn kill(&self) {
        let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        self.kill();
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessControl {
    cgroup: Arc<Cgroup>,
}

impl ProcessControl {
    pub(crate) fn terminate(&self) {
        self.cgroup.kill();
    }
}

pub(crate) fn probe() -> Result<(), SandboxError> {
    let bwrap = bwrap_path()?;
    probe_bwrap(&bwrap)?;
    let root = cgroup_root()?;
    probe_cgroup(&root)?;
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
        platform: "linux".into(),
        backend: "linux-bwrap-landlock-cgroup2".into(),
        status: EnforcementStatus::Enforced,
        features,
        reasons: vec![
            "bubblewrap supplies user, PID, mount, and network namespaces".into(),
            "Landlock preserves the policy read/write mount boundary inside the namespace".into(),
            "delegated cgroup v2 supplies tree memory, process, CPU, and kill controls".into(),
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
    Ok(PreparedUnixSandbox {
        temp_dir,
        bwrap: bwrap_path()?,
        cgroup_root: cgroup_root()?,
    })
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
    let landlock_write_paths: Vec<PathBuf> = write_paths
        .iter()
        .cloned()
        .chain([
            PathBuf::from("/proc/self/uid_map"),
            PathBuf::from("/proc/self/gid_map"),
            PathBuf::from("/proc/self/setgroups"),
        ])
        .collect();
    let deny_network = policy.original.network.mode == NetworkMode::Deny;
    let cgroup = create_cgroup(&platform.cgroup_root, &execution.limits)?;
    let (sync_read, sync_write) = sync_pipe()?;

    let mut command = Command::new(&platform.bwrap);
    command
        .args([
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
        ])
        .arg("--sync-fd")
        .arg(sync_read.to_string())
        .args(["--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"])
        .arg("--bind")
        .arg(&platform.temp_dir)
        .arg(&platform.temp_dir);
    if deny_network {
        command.arg("--unshare-net");
    }
    for path in &write_paths {
        if path != &platform.temp_dir {
            command.arg("--bind").arg(path).arg(path);
        }
    }
    command
        .arg("--chdir")
        .arg(&workdir)
        .arg("--")
        .arg(&program)
        .args(args)
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

    let limits = execution.limits.clone();
    unsafe {
        command.pre_exec(move || {
            apply_resource_limits(&limits)
                .map_err(|error| std::io::Error::other(format!("resource limits: {error}")))?;
            apply_landlock(&read_paths, &landlock_write_paths)
                .map_err(|error| std::io::Error::other(format!("Landlock: {error}")))?;
            if deny_network {
                install_network_seccomp()
                    .map_err(|error| std::io::Error::other(format!("seccomp: {error}")))?;
            }
            Ok(())
        });
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            close_fd(sync_read);
            close_fd(sync_write);
            return Err(SandboxError::Process(format!(
                "failed to launch bubblewrap: {error}"
            )));
        }
    };
    close_fd(sync_read);
    if let Err(error) = std::fs::write(cgroup.path.join("cgroup.procs"), child.id().to_string()) {
        let _ = child.kill();
        close_fd(sync_write);
        return Err(SandboxError::Process(format!(
            "cannot attach bubblewrap to cgroup: {error}"
        )));
    }
    close_fd(sync_write);
    start_cpu_watchdog(Arc::clone(&cgroup), execution.limits.cpu_time_ms);

    let stdin = child.stdin.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_fd(stream.into_raw_fd()))
    });
    let stdout = child.stdout.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_fd(stream.into_raw_fd()))
    });
    let stderr = child.stderr.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_fd(stream.into_raw_fd()))
    });
    let wait_cgroup = Arc::clone(&cgroup);
    let wait = tokio::task::spawn_blocking(move || {
        let result = child
            .wait()
            .map(|status| status.code().unwrap_or(1))
            .map_err(|error| SandboxError::Process(format!("bubblewrap wait failed: {error}")));
        wait_cgroup.done.store(true, Ordering::Release);
        wait_cgroup.kill();
        result
    });
    Ok(NativeProcess {
        stdin,
        stdout,
        stderr,
        wait,
        control: ProcessControl { cgroup },
    })
}

fn bwrap_path() -> Result<PathBuf, SandboxError> {
    if let Some(path) = std::env::var_os("AGENT_SANDBOX_BWRAP") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|directory| directory.join("bwrap"))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            SandboxError::BackendUnavailable(
                "bubblewrap is unavailable; install or stage the bwrap sandbox helper".into(),
            )
        })
}

fn probe_bwrap(bwrap: &Path) -> Result<(), SandboxError> {
    let status = Command::new(bwrap)
        .args([
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--",
            "/bin/true",
        ])
        .status()
        .map_err(|error| SandboxError::BackendUnavailable(format!("bubblewrap probe: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(SandboxError::BackendUnavailable(format!(
            "bubblewrap cannot create required namespaces (exit {status})"
        )))
    }
}

fn cgroup_root() -> Result<PathBuf, SandboxError> {
    match CGROUP_ROOT.get_or_init(|| initialize_cgroup_root().map_err(|error| error.to_string())) {
        Ok(root) => Ok(root.clone()),
        Err(error) => Err(SandboxError::BackendUnavailable(error.clone())),
    }
}

fn initialize_cgroup_root() -> Result<PathBuf, SandboxError> {
    let (root, discovered) = match std::env::var_os("AGENT_SANDBOX_CGROUP_ROOT") {
        Some(path) if !path.is_empty() => (PathBuf::from(path), false),
        _ => (current_cgroup_path()?, true),
    };
    if discovered {
        prepare_delegated_root(&root)?;
    }
    if root.is_dir() && root.join("cgroup.controllers").is_file() {
        Ok(root)
    } else {
        Err(SandboxError::BackendUnavailable(format!(
            "delegated cgroup v2 root is unavailable at {}; configure AGENT_SANDBOX_CGROUP_ROOT",
            root.display()
        )))
    }
}

fn current_cgroup_path() -> Result<PathBuf, SandboxError> {
    let value = std::fs::read_to_string("/proc/self/cgroup").map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot inspect current cgroup: {error}"))
    })?;
    let relative = value
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            SandboxError::BackendUnavailable(
                "cannot discover the current unified cgroup v2 path".into(),
            )
        })?;
    Ok(Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')))
}

fn prepare_delegated_root(root: &Path) -> Result<(), SandboxError> {
    let manager = root.join("agent-sandboxd");
    std::fs::create_dir_all(&manager).map_err(|error| {
        SandboxError::BackendUnavailable(format!(
            "cannot create daemon cgroup in delegated scope: {error}"
        ))
    })?;
    std::fs::write(manager.join("cgroup.procs"), std::process::id().to_string()).map_err(
        |error| {
            SandboxError::BackendUnavailable(format!(
                "cannot move daemon into delegated manager cgroup: {error}"
            ))
        },
    )?;
    std::fs::write(root.join("cgroup.subtree_control"), "+cpu +memory +pids").map_err(|error| {
        SandboxError::BackendUnavailable(format!(
            "cannot enable delegated cgroup controllers: {error}"
        ))
    })?;
    Ok(())
}

fn probe_cgroup(root: &Path) -> Result<(), SandboxError> {
    let path = root.join(format!("probe-{}", std::process::id()));
    std::fs::create_dir(&path).map_err(|error| {
        SandboxError::BackendUnavailable(format!("cgroup v2 delegation is not writable: {error}"))
    })?;
    let result = [
        ("memory.max", "67108864"),
        ("pids.max", "4"),
        ("cpu.max", "10000 100000"),
    ]
    .into_iter()
    .try_for_each(|(name, value)| std::fs::write(path.join(name), value));
    let _ = std::fs::remove_dir(&path);
    result.map_err(|error| {
        SandboxError::BackendUnavailable(format!(
            "cgroup v2 controllers are not delegated: {error}"
        ))
    })
}

fn create_cgroup(root: &Path, limits: &ResourceLimits) -> Result<Arc<Cgroup>, SandboxError> {
    let sequence = CGROUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = root.join(format!("exec-{}-{sequence}", std::process::id()));
    std::fs::create_dir(&path).map_err(|error| {
        SandboxError::Process(format!("cannot create execution cgroup: {error}"))
    })?;
    let cgroup = Arc::new(Cgroup {
        path,
        done: AtomicBool::new(false),
    });
    let period = 100_000_u64;
    let quota = limits
        .cpu_time_ms
        .saturating_mul(period)
        .checked_div(limits.wall_time_ms.max(1))
        .unwrap_or(period)
        .clamp(1_000, period);
    for (name, value) in [
        ("memory.max", limits.memory_bytes.to_string()),
        ("pids.max", limits.processes.to_string()),
        ("cpu.max", format!("{quota} {period}")),
    ] {
        std::fs::write(cgroup.path.join(name), value).map_err(|error| {
            SandboxError::Process(format!("cannot configure cgroup {name}: {error}"))
        })?;
    }
    Ok(cgroup)
}

fn start_cpu_watchdog(cgroup: Arc<Cgroup>, cpu_time_ms: u64) {
    std::thread::spawn(move || {
        while !cgroup.done.load(Ordering::Acquire) {
            if cpu_usage_usec(&cgroup.path)
                .is_some_and(|usage| usage >= cpu_time_ms.saturating_mul(1_000))
            {
                cgroup.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

fn cpu_usage_usec(path: &Path) -> Option<u64> {
    let value = std::fs::read_to_string(path.join("cpu.stat")).ok()?;
    value.lines().find_map(|line| {
        let (name, value) = line.split_once(' ')?;
        (name == "usage_usec").then(|| value.parse().ok()).flatten()
    })
}

fn sync_pipe() -> Result<(RawFd, RawFd), SandboxError> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(SandboxError::Process(format!(
            "cannot create bubblewrap synchronization pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((fds[0], fds[1]))
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
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
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/etc/ssl",
        "/etc/pki",
        "/etc/ca-certificates",
    ] {
        let path = PathBuf::from(path);
        if path.exists() {
            paths.insert(path.canonicalize().unwrap_or(path));
        }
    }
    for path in [
        "/etc/ld.so.cache",
        "/dev/null",
        "/dev/urandom",
        "/proc/sys/kernel/overflowuid",
        "/proc/sys/kernel/overflowgid",
    ] {
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
    Ok(())
}

fn apply_landlock(read_paths: &[PathBuf], write_paths: &[PathBuf]) -> std::io::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };
    let abi = ABI::V4;
    let handled = AccessFs::from_all(abi);
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(std::io::Error::other)?
        .create()
        .map_err(std::io::Error::other)?;
    let read_dir = (AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute) & handled;
    let read_file = (AccessFs::ReadFile | AccessFs::Execute) & handled;
    let write = (read_dir
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
        & handled;
    for path in read_paths {
        let access = if path.is_dir() { read_dir } else { read_file };
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(path).map_err(std::io::Error::other)?,
                access,
            ))
            .map_err(std::io::Error::other)?;
    }
    for path in write_paths {
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(path).map_err(std::io::Error::other)?,
                write,
            ))
            .map_err(std::io::Error::other)?;
    }
    ruleset
        .restrict_self()
        .map(|_| ())
        .map_err(std::io::Error::other)
}

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
        [(libc::SYS_socket, rules)]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
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
