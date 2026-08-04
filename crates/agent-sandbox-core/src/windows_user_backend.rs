use std::collections::BTreeSet;
use std::net::TcpListener;
use std::os::windows::io::{FromRawHandle, IntoRawHandle};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use agent_sandbox_protocol::{
    CapabilityReport, CommandSpec, EnforcementStatus, FeatureState, FilesystemLeaseMode,
    MountAccess, NetworkMode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

use super::{AuthorizationSpec, NativeProcess, PreparedSandbox};
use crate::{SandboxError, ValidatedExecution, ValidatedPolicy, windows_acl};

const HELPER_NAME: &str = "srt-win.exe";
const LEASE_VERSION: u8 = 1;
const AUTHORIZATION_VERSION: u8 = 1;

#[derive(Debug)]
pub struct PreparedWindowsSandbox {
    pub profile_name: String,
    helper: PathBuf,
    sid: String,
    lease: Option<PathBuf>,
    mounts: Vec<PathBuf>,
    persistent: bool,
}

#[derive(Debug)]
struct ProcessHandle(HANDLE);

unsafe impl Send for ProcessHandle {}
unsafe impl Sync for ProcessHandle {}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessControl {
    process: Arc<ProcessHandle>,
}

impl ProcessControl {
    pub fn terminate(&self) {
        unsafe {
            let _ = TerminateProcess(self.process.0, 1);
        }
    }
}

#[derive(Debug, Deserialize)]
struct HelperStatus {
    user: HelperUserEnvelope,
}

#[derive(Debug, Deserialize)]
struct HelperUserEnvelope {
    cred_present: bool,
    marker_version: Option<u32>,
    marker_user_sid: Option<String>,
    user: HelperUser,
}

#[derive(Debug, Deserialize)]
struct HelperUser {
    exists: bool,
    in_builtin_users: bool,
    in_sandbox_group: bool,
    hidden_from_logon: bool,
}

#[derive(Debug, Deserialize)]
struct EgressProbe {
    egress_probe: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeaseRecord {
    version: u8,
    sid: String,
    mounts: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistentMount {
    source: PathBuf,
    access: MountAccess,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistentAuthorization {
    version: u8,
    sid: String,
    policy_fingerprint: String,
    mounts: Vec<PersistentMount>,
    #[serde(default)]
    granted: Vec<PathBuf>,
}

pub fn probe() -> Result<(), SandboxError> {
    let helper = helper_path()?;
    let status = helper_status(&helper)?;
    validate_status(&status)?;
    verify_wfp(&helper)?;
    Ok(())
}

pub fn report() -> CapabilityReport {
    let mut features = std::collections::BTreeMap::new();
    features.insert("filesystemReadBoundary".into(), FeatureState::Limited);
    for name in [
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
        platform: "windows".into(),
        backend: "windows-user-wfp-job".into(),
        status: EnforcementStatus::Limited,
        features,
        reasons: vec![
            "BUILTIN\\Users read grants outside explicit mounts remain visible to the dedicated sandbox account"
                .into(),
            "filesystem grants use a dedicated local user SID and additive NTFS ACL leases".into(),
            "network denial uses a persistent WFP egress fence keyed to the sandbox user SID"
                .into(),
            "process-tree and resource limits use a non-breakaway Job Object".into(),
        ],
    }
}

pub async fn recover_journals() -> Result<(), SandboxError> {
    let directory = state_directory()?.join("leases");
    let mut entries = match tokio::fs::read_dir(&directory).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(SandboxError::BackendUnavailable(format!(
                "cannot inspect Windows ACL leases: {error}"
            )));
        }
    };
    while let Some(entry) = entries.next_entry().await.map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot enumerate Windows ACL leases: {error}"))
    })? {
        if !entry
            .file_type()
            .await
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        let bytes = tokio::fs::read(entry.path()).await.map_err(|error| {
            SandboxError::BackendUnavailable(format!("cannot read Windows ACL lease: {error}"))
        })?;
        let record: LeaseRecord = serde_json::from_slice(&bytes).map_err(|error| {
            SandboxError::BackendUnavailable(format!("invalid Windows ACL lease: {error}"))
        })?;
        validate_lease(&record)?;
        for mount in record.mounts.iter().rev() {
            revoke_root(mount.clone(), record.sid.clone()).await?;
        }
        tokio::fs::remove_file(entry.path())
            .await
            .map_err(|error| {
                SandboxError::BackendUnavailable(format!("cannot clear Windows ACL lease: {error}"))
            })?;
    }
    Ok(())
}

pub async fn prepare(
    sandbox_id: &str,
    policy: &ValidatedPolicy,
    authorization: &AuthorizationSpec,
) -> Result<PreparedWindowsSandbox, SandboxError> {
    if policy.original.network.mode != NetworkMode::Deny {
        return Err(SandboxError::CapabilityUnavailable(
            "the Windows dedicated-user backend currently supports deny-only networking".into(),
        ));
    }
    let helper = helper_path()?;
    let status = helper_status(&helper)?;
    validate_status(&status)?;
    verify_wfp(&helper)?;
    let sid = status.user.marker_user_sid.ok_or_else(|| {
        SandboxError::BackendUnavailable("sandbox helper did not report its user SID".into())
    })?;
    let persistent = policy.original.filesystem.lease.mode == FilesystemLeaseMode::Persistent;
    if persistent {
        prepare_persistent_authorization(policy, authorization, &sid).await?;
        return Ok(PreparedWindowsSandbox {
            profile_name: "srt-sandbox".into(),
            helper,
            sid,
            lease: None,
            mounts: Vec::new(),
            persistent: true,
        });
    }

    let suffix: String = sandbox_id
        .chars()
        .filter(|value| value.is_ascii_alphanumeric())
        .take(48)
        .collect();
    let directory = state_directory()?.join("leases");
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(|error| {
            SandboxError::BackendUnavailable(format!(
                "cannot create Windows lease directory: {error}"
            ))
        })?;
    let lease = directory.join(format!("{suffix}.json"));
    let mut record = LeaseRecord {
        version: LEASE_VERSION,
        sid: sid.clone(),
        mounts: Vec::new(),
    };
    tokio::fs::write(
        &lease,
        serde_json::to_vec(&record).map_err(|error| SandboxError::Internal(error.to_string()))?,
    )
    .await
    .map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot persist Windows ACL lease: {error}"))
    })?;

    let mut granted = Vec::new();
    for mount in policy.mounts.values() {
        if mount.access == MountAccess::ReadOnly {
            continue;
        }
        match grant_existing_tree(mount.source.clone(), sid.clone(), mount.access).await {
            Ok(paths) => {
                granted.extend(paths);
                record.mounts = granted.clone();
                tokio::fs::write(
                    &lease,
                    serde_json::to_vec(&record)
                        .map_err(|error| SandboxError::Internal(error.to_string()))?,
                )
                .await
                .map_err(|error| {
                    SandboxError::BackendUnavailable(format!(
                        "cannot update Windows ACL lease: {error}"
                    ))
                })?;
            }
            Err(error) => {
                for path in granted.into_iter().rev() {
                    let _ = revoke_root(path, sid.clone()).await;
                }
                let _ = tokio::fs::remove_file(&lease).await;
                return Err(error);
            }
        }
    }
    Ok(PreparedWindowsSandbox {
        profile_name: "srt-sandbox".into(),
        helper,
        sid,
        lease: Some(lease),
        mounts: granted,
        persistent: false,
    })
}

pub async fn cleanup(platform: &PreparedWindowsSandbox) -> Result<(), SandboxError> {
    if platform.persistent {
        return Ok(());
    }
    let mut failures = Vec::new();
    for mount in platform.mounts.iter().rev() {
        if let Err(error) = revoke_root(mount.clone(), platform.sid.clone()).await {
            failures.push(error.to_string());
        }
    }
    if failures.is_empty() {
        if let Some(lease) = &platform.lease {
            tokio::fs::remove_file(lease).await.map_err(|error| {
                SandboxError::BackendUnavailable(format!(
                    "cannot remove Windows ACL lease: {error}"
                ))
            })?;
        }
        Ok(())
    } else {
        Err(SandboxError::BackendUnavailable(format!(
            "cannot fully revoke Windows ACL lease: {}",
            failures.join("; ")
        )))
    }
}

pub async fn spawn(
    sandbox: &PreparedSandbox,
    execution: &ValidatedExecution,
    stdin_pipe: bool,
) -> Result<NativeProcess, SandboxError> {
    if stdin_pipe {
        return Err(SandboxError::CapabilityUnavailable(
            "interactive stdin is not supported by the Windows dedicated-user helper".into(),
        ));
    }
    let workdir = native_workdir(&sandbox.policy, &execution.workdir)?;
    let (program, args) = command_line(&execution.command)?;
    let mut command = Command::new(&sandbox.platform.helper);
    command
        .arg("exec")
        .arg("--quiet")
        .arg("--memory-bytes")
        .arg(execution.limits.memory_bytes.to_string())
        .arg("--cpu-time-ms")
        .arg(execution.limits.cpu_time_ms.to_string())
        .arg("--processes")
        .arg(execution.limits.processes.to_string());
    for (name, value) in &execution.environment {
        command.arg("--env").arg(format!("{name}={value}"));
    }
    command
        .arg("--")
        .arg(&program)
        .args(args)
        .current_dir(workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|error| {
        SandboxError::Process(format!("failed to launch Windows sandbox helper: {error}"))
    })?;
    let pid = child.id();
    let process = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }.map_err(|error| {
        let _ = child.kill();
        SandboxError::Process(format!(
            "cannot open Windows sandbox helper process: {error}"
        ))
    })?;
    let process = Arc::new(ProcessHandle(process));
    let stdout = child.stdout.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_handle(stream.into_raw_handle()))
    });
    let stderr = child.stderr.take().map(|stream| unsafe {
        tokio::fs::File::from_std(std::fs::File::from_raw_handle(stream.into_raw_handle()))
    });
    let wait = tokio::task::spawn_blocking(move || {
        child
            .wait()
            .map(|status| status.code().unwrap_or(1))
            .map_err(|error| SandboxError::Process(format!("Windows sandbox wait failed: {error}")))
    });
    Ok(NativeProcess {
        stdin: None,
        stdout,
        stderr,
        wait,
        control: ProcessControl { process },
    })
}

pub async fn revoke_persistent_authorization(
    authorization: &AuthorizationSpec,
) -> Result<(), SandboxError> {
    let directory = state_directory()?.join("authorizations");
    let path = directory.join(format!("{}.json", authorization_hash(authorization)));
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(SandboxError::BackendUnavailable(format!(
                "cannot read persistent authorization: {error}"
            )));
        }
    };
    let record: PersistentAuthorization = serde_json::from_slice(&bytes).map_err(|error| {
        SandboxError::BackendUnavailable(format!("invalid persistent authorization: {error}"))
    })?;
    validate_authorization(&record)?;
    tokio::fs::remove_file(&path).await.map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot retire authorization record: {error}"))
    })?;
    let referenced = referenced_mounts(&directory).await?;
    for mount in record.granted.iter().rev() {
        if !referenced.contains(mount) {
            revoke_root(mount.clone(), record.sid.clone()).await?;
        }
    }
    Ok(())
}

async fn prepare_persistent_authorization(
    policy: &ValidatedPolicy,
    authorization: &AuthorizationSpec,
    sid: &str,
) -> Result<(), SandboxError> {
    let mounts: Vec<_> = policy
        .mounts
        .values()
        .map(|mount| PersistentMount {
            source: mount.source.clone(),
            access: mount.access,
        })
        .collect();
    let policy_fingerprint = mount_fingerprint(&mounts);
    let directory = state_directory()?.join("authorizations");
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(|error| {
            SandboxError::BackendUnavailable(format!(
                "cannot create authorization directory: {error}"
            ))
        })?;
    let path = directory.join(format!("{}.json", authorization_hash(authorization)));
    if let Ok(bytes) = tokio::fs::read(&path).await {
        let record: PersistentAuthorization = serde_json::from_slice(&bytes).map_err(|error| {
            SandboxError::BackendUnavailable(format!("invalid persistent authorization: {error}"))
        })?;
        validate_authorization(&record)?;
        if record.sid != sid
            || record.policy_fingerprint != policy_fingerprint
            || record.mounts != mounts
        {
            return Err(SandboxError::InvalidPolicy(
                "persistent authorization does not match the requested policy".into(),
            ));
        }
        return Ok(());
    }
    for mount in mounts
        .iter()
        .filter(|mount| mount.access == MountAccess::ReadWrite)
    {
        let mut entries = tokio::fs::read_dir(&mount.source).await.map_err(|error| {
            SandboxError::CapabilityUnavailable(format!(
                "cannot inspect managed workspace before enrollment: {error}"
            ))
        })?;
        if entries
            .next_entry()
            .await
            .map_err(|error| {
                SandboxError::CapabilityUnavailable(format!(
                    "cannot inspect managed workspace before enrollment: {error}"
                ))
            })?
            .is_some()
        {
            return Err(SandboxError::InvalidPolicy(
                "persistent workspace enrollment requires an empty managed directory".into(),
            ));
        }
    }
    let mut record = PersistentAuthorization {
        version: AUTHORIZATION_VERSION,
        sid: sid.into(),
        policy_fingerprint,
        mounts,
        granted: Vec::new(),
    };
    tokio::fs::write(
        &path,
        serde_json::to_vec(&record).map_err(|error| SandboxError::Internal(error.to_string()))?,
    )
    .await
    .map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot journal authorization: {error}"))
    })?;
    let mut granted = Vec::new();
    for mount in &record.mounts {
        if mount.access == MountAccess::ReadOnly {
            continue;
        }
        match grant_root(mount.source.clone(), sid.into(), mount.access).await {
            Ok(true) => granted.push(mount.source.clone()),
            Ok(false) => {}
            Err(error) => {
                for source in granted.into_iter().rev() {
                    let _ = revoke_root(source, sid.into()).await;
                }
                let _ = tokio::fs::remove_file(&path).await;
                return Err(error);
            }
        }
    }
    record.granted = granted;
    tokio::fs::write(
        &path,
        serde_json::to_vec(&record).map_err(|error| SandboxError::Internal(error.to_string()))?,
    )
    .await
    .map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot activate authorization: {error}"))
    })?;
    Ok(())
}

async fn referenced_mounts(directory: &Path) -> Result<BTreeSet<PathBuf>, SandboxError> {
    let mut result = BTreeSet::new();
    let mut entries = match tokio::fs::read_dir(directory).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(result),
        Err(error) => {
            return Err(SandboxError::BackendUnavailable(format!(
                "cannot inspect authorization references: {error}"
            )));
        }
    };
    while let Some(entry) = entries.next_entry().await.map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot enumerate authorizations: {error}"))
    })? {
        let Ok(bytes) = tokio::fs::read(entry.path()).await else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<PersistentAuthorization>(&bytes) else {
            continue;
        };
        result.extend(record.granted);
    }
    Ok(result)
}

fn helper_path() -> Result<PathBuf, SandboxError> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("AGENT_SANDBOX_WINDOWS_HELPER") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(executable) = std::env::current_exe()
        && let Some(parent) = executable.parent()
    {
        candidates.push(parent.join(HELPER_NAME));
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(root) = manifest.parent().and_then(Path::parent) {
        candidates.push(root.join("target").join("release").join(HELPER_NAME));
        candidates.push(root.join("target").join("debug").join(HELPER_NAME));
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            SandboxError::BackendUnavailable(
                "Windows sandbox helper is unavailable; install or stage srt-win.exe".into(),
            )
        })
}

fn helper_status(helper: &Path) -> Result<HelperStatus, SandboxError> {
    let output = Command::new(helper)
        .arg("status")
        .output()
        .map_err(|error| {
            SandboxError::BackendUnavailable(format!(
                "cannot inspect Windows sandbox setup: {error}"
            ))
        })?;
    if !output.status.success() {
        return Err(SandboxError::BackendUnavailable(format!(
            "Windows sandbox setup check failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        SandboxError::BackendUnavailable(format!("invalid Windows sandbox status: {error}"))
    })
}

fn validate_status(status: &HelperStatus) -> Result<(), SandboxError> {
    let user = &status.user;
    if !user.cred_present
        || user.marker_version != Some(1)
        || user
            .marker_user_sid
            .as_deref()
            .is_none_or(|sid| !sid.starts_with("S-1-5-21-"))
        || !user.user.exists
        || !user.user.in_builtin_users
        || !user.user.in_sandbox_group
        || !user.user.hidden_from_logon
    {
        return Err(SandboxError::BackendUnavailable(
            "Windows sandbox is not provisioned; run `srt-win.exe install` once with UAC approval"
                .into(),
        ));
    }
    Ok(())
}

fn verify_wfp(helper: &Path) -> Result<(), SandboxError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot create WFP readiness probe: {error}"))
    })?;
    let target = listener.local_addr().map_err(|error| {
        SandboxError::BackendUnavailable(format!("cannot inspect WFP readiness probe: {error}"))
    })?;
    let output = Command::new(helper)
        .args(["wfp", "verify", "--target"])
        .arg(target.to_string())
        .output()
        .map_err(|error| {
            SandboxError::BackendUnavailable(format!("cannot verify Windows WFP fence: {error}"))
        })?;
    drop(listener);
    let probe: EgressProbe = serde_json::from_slice(&output.stdout).map_err(|error| {
        SandboxError::BackendUnavailable(format!(
            "invalid Windows WFP verification result: {error}; {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    })?;
    if output.status.success() && probe.egress_probe == "blocked" {
        Ok(())
    } else {
        Err(SandboxError::BackendUnavailable(format!(
            "Windows WFP egress fence is inactive: {}",
            probe.egress_probe
        )))
    }
}

fn native_workdir(policy: &ValidatedPolicy, logical: &str) -> Result<PathBuf, SandboxError> {
    for mount in policy.mounts.values() {
        if logical == mount.destination || logical.starts_with(&format!("{}/", mount.destination)) {
            let relative = logical
                .strip_prefix(&mount.destination)
                .unwrap_or_default()
                .trim_start_matches('/');
            return Ok(mount.source.join(relative));
        }
    }
    Err(SandboxError::InvalidPolicy(
        "logical cwd is outside mounted paths".into(),
    ))
}

fn command_line(command: &CommandSpec) -> Result<(PathBuf, Vec<String>), SandboxError> {
    match command {
        CommandSpec::Exec { program, args } => Ok((PathBuf::from(program), args.clone())),
        CommandSpec::Shell { .. } => Err(SandboxError::CapabilityUnavailable(
            "Windows shell execution requires a host-declared executable".into(),
        )),
    }
}

fn state_directory() -> Result<PathBuf, SandboxError> {
    std::env::var_os("AGENT_SANDBOX_STATE_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .map(|path| path.join("agent-sandbox"))
        })
        .ok_or_else(|| {
            SandboxError::BackendUnavailable("sandbox state directory is unavailable".into())
        })
}

fn authorization_hash(authorization: &AuthorizationSpec) -> String {
    let mut digest = Sha256::new();
    digest.update(authorization.tenant_id.as_bytes());
    digest.update([0]);
    digest.update(authorization.authorization_id.as_bytes());
    hex::encode(digest.finalize())
}

fn mount_fingerprint(mounts: &[PersistentMount]) -> String {
    let mut digest = Sha256::new();
    for mount in mounts {
        digest.update(mount.source.to_string_lossy().as_bytes());
        digest.update([0]);
        digest.update(match mount.access {
            MountAccess::ReadOnly => b"read-only".as_slice(),
            MountAccess::ReadWrite => b"read-write".as_slice(),
        });
        digest.update([0]);
    }
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn validate_lease(record: &LeaseRecord) -> Result<(), SandboxError> {
    if record.version != LEASE_VERSION
        || !record.sid.starts_with("S-1-5-21-")
        || record.mounts.iter().any(|path| !path.is_absolute())
    {
        return Err(SandboxError::BackendUnavailable(
            "Windows ACL lease failed integrity validation".into(),
        ));
    }
    Ok(())
}

fn validate_authorization(record: &PersistentAuthorization) -> Result<(), SandboxError> {
    if record.version != AUTHORIZATION_VERSION
        || !record.sid.starts_with("S-1-5-21-")
        || record
            .mounts
            .iter()
            .any(|mount| !mount.source.is_absolute())
    {
        return Err(SandboxError::BackendUnavailable(
            "persistent authorization failed integrity validation".into(),
        ));
    }
    Ok(())
}

fn access_mask(access: MountAccess) -> u32 {
    use windows::Win32::Storage::FileSystem::{
        FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    match access {
        MountAccess::ReadOnly => FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
        MountAccess::ReadWrite => {
            FILE_GENERIC_READ.0
                | FILE_GENERIC_WRITE.0
                | FILE_GENERIC_EXECUTE.0
                | 0x0001_0000
                | 0x0000_0040
        }
    }
}

async fn grant_existing_tree(
    path: PathBuf,
    sid: String,
    access: MountAccess,
) -> Result<Vec<PathBuf>, SandboxError> {
    tokio::task::spawn_blocking(move || {
        let paths: Vec<PathBuf> = walkdir::WalkDir::new(&path)
            .follow_links(false)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                SandboxError::CapabilityUnavailable(format!(
                    "cannot snapshot mount before ACL grant: {error}"
                ))
            })?
            .into_iter()
            .map(|entry| entry.path().to_path_buf())
            .collect();
        windows_acl::grant_tree(&path, &sid, access_mask(access))?;
        Ok(paths)
    })
    .await
    .map_err(|error| SandboxError::CapabilityUnavailable(format!("ACL task failed: {error}")))?
}

async fn grant_root(path: PathBuf, sid: String, access: MountAccess) -> Result<bool, SandboxError> {
    let result = tokio::task::spawn_blocking(move || {
        windows_acl::grant_root(&path, &sid, access_mask(access))
    })
    .await
    .map_err(|error| SandboxError::CapabilityUnavailable(format!("ACL task failed: {error}")))?;
    optional_read_grant(result, access)
}

fn optional_read_grant(
    result: Result<(), SandboxError>,
    access: MountAccess,
) -> Result<bool, SandboxError> {
    match result {
        Ok(()) => Ok(true),
        Err(_) if access == MountAccess::ReadOnly => Ok(false),
        Err(error) => Err(error),
    }
}

async fn revoke_root(path: PathBuf, sid: String) -> Result<(), SandboxError> {
    tokio::task::spawn_blocking(move || windows_acl::revoke_root(&path, &sid))
        .await
        .map_err(|error| SandboxError::CapabilityUnavailable(format!("ACL task failed: {error}")))?
}
