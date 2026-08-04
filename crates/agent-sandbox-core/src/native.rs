#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(windows)]
use std::path::{Path, PathBuf};

use agent_sandbox_protocol::{CapabilityReport, EnforcementStatus, FeatureState};
#[cfg(windows)]
use agent_sandbox_protocol::{CommandSpec, FilesystemLeaseMode, MountAccess, NetworkMode};
#[cfg(windows)]
use sha2::{Digest, Sha256};

use crate::{SandboxError, ValidatedExecution, ValidatedPolicy};

#[derive(Debug, Clone)]
pub struct AuthorizationSpec {
    pub tenant_id: String,
    pub authorization_id: String,
}

#[derive(Debug, Clone)]
pub struct ProfileSpec {
    pub id: String,
}

impl ProfileSpec {
    pub fn trusted(id: &str) -> Result<Self, SandboxError> {
        match id {
            "system-minimal" | "node-default" | "python-default" | "rust-default" => {
                Ok(Self { id: id.to_string() })
            }
            _ => Err(SandboxError::InvalidPolicy(format!(
                "unknown trusted profile: {id}"
            ))),
        }
    }
}

#[derive(Debug)]
pub struct PreparedSandbox {
    pub policy: ValidatedPolicy,
    pub profile: ProfileSpec,
    pub report: CapabilityReport,
    pub fingerprint: String,
    #[cfg(windows)]
    platform: windows_backend::PreparedWindowsSandbox,
}

#[derive(Debug, Clone, Default)]
pub struct NativeBackend;

impl NativeBackend {
    pub async fn discover() -> Result<Self, SandboxError> {
        #[cfg(windows)]
        {
            windows_backend::probe()?;
            windows_backend::recover_journals().await?;
            Ok(Self)
        }
        #[cfg(not(windows))]
        {
            Err(SandboxError::BackendUnavailable(format!(
                "the native backend for {} is not implemented in this build",
                std::env::consts::OS
            )))
        }
    }

    pub fn report(&self) -> CapabilityReport {
        #[cfg(windows)]
        {
            windows_backend::report()
        }
        #[cfg(not(windows))]
        {
            Self::unavailable_report(format!(
                "the native backend for {} is not implemented in this build",
                std::env::consts::OS
            ))
        }
    }

    pub fn unavailable_report(reason: impl Into<String>) -> CapabilityReport {
        let features = feature_names()
            .into_iter()
            .map(|name| (name.to_string(), FeatureState::Unavailable))
            .collect();
        CapabilityReport {
            platform: std::env::consts::OS.into(),
            backend: "native".into(),
            status: EnforcementStatus::Unavailable,
            features,
            reasons: vec![reason.into()],
        }
    }

    pub async fn prepare(
        &self,
        sandbox_id: &str,
        policy: ValidatedPolicy,
        profile: ProfileSpec,
        authorization: AuthorizationSpec,
    ) -> Result<PreparedSandbox, SandboxError> {
        if !matches!(
            policy.original.backend,
            agent_sandbox_protocol::BackendPreference::Auto
                | agent_sandbox_protocol::BackendPreference::Native
        ) {
            return Err(SandboxError::CapabilityUnavailable(
                "the requested backend is not supported by this runtime".into(),
            ));
        }
        #[cfg(windows)]
        {
            let platform = windows_backend::prepare(sandbox_id, &policy, &authorization).await?;
            let report = self.report();
            let mut digest = Sha256::new();
            digest.update(policy.fingerprint.as_bytes());
            digest.update(profile.id.as_bytes());
            digest.update(platform.profile_name.as_bytes());
            let fingerprint = format!("sha256:{}", hex::encode(digest.finalize()));
            Ok(PreparedSandbox {
                policy,
                profile,
                report,
                fingerprint,
                platform,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (sandbox_id, policy, profile, authorization);
            Err(SandboxError::BackendUnavailable(
                "native backend unavailable".into(),
            ))
        }
    }

    pub async fn spawn(
        &self,
        sandbox: &PreparedSandbox,
        execution: &ValidatedExecution,
        stdin_pipe: bool,
    ) -> Result<NativeProcess, SandboxError> {
        #[cfg(windows)]
        {
            windows_backend::spawn(sandbox, execution, stdin_pipe).await
        }
        #[cfg(not(windows))]
        {
            let _ = (sandbox, execution, stdin_pipe);
            Err(SandboxError::BackendUnavailable(
                "native backend unavailable".into(),
            ))
        }
    }

    pub async fn revoke_authorization(
        &self,
        authorization: &AuthorizationSpec,
    ) -> Result<(), SandboxError> {
        #[cfg(windows)]
        {
            windows_backend::revoke_persistent_authorization(authorization).await
        }
        #[cfg(not(windows))]
        {
            let _ = authorization;
            Err(SandboxError::BackendUnavailable(
                "native backend unavailable".into(),
            ))
        }
    }

    pub async fn cleanup(&self, sandbox: &PreparedSandbox) -> Result<(), SandboxError> {
        #[cfg(windows)]
        {
            windows_backend::cleanup(&sandbox.platform).await
        }
        #[cfg(not(windows))]
        {
            let _ = sandbox;
            Ok(())
        }
    }
}

pub struct NativeProcess {
    pub stdin: Option<tokio::fs::File>,
    pub stdout: Option<tokio::fs::File>,
    pub stderr: Option<tokio::fs::File>,
    #[cfg(windows)]
    wait: tokio::task::JoinHandle<Result<i32, SandboxError>>,
    #[cfg(windows)]
    control: windows_backend::ProcessControl,
}

#[derive(Debug, Clone)]
pub struct NativeProcessControl {
    #[cfg(windows)]
    platform: windows_backend::ProcessControl,
}

impl NativeProcessControl {
    pub fn terminate(&self) {
        #[cfg(windows)]
        self.platform.terminate();
    }
}

impl NativeProcess {
    pub fn control(&self) -> NativeProcessControl {
        NativeProcessControl {
            #[cfg(windows)]
            platform: self.control.clone(),
        }
    }

    pub async fn wait(self) -> Result<i32, SandboxError> {
        #[cfg(windows)]
        {
            self.wait.await.map_err(|error| {
                SandboxError::Process(format!("process wait task failed: {error}"))
            })?
        }
        #[cfg(not(windows))]
        {
            Err(SandboxError::BackendUnavailable(
                "native backend unavailable".into(),
            ))
        }
    }

    pub fn terminate(&self) {
        self.control().terminate();
    }
}

fn feature_names() -> [&'static str; 8] {
    [
        "filesystemReadBoundary",
        "filesystemWriteBoundary",
        "networkDeny",
        "processTree",
        "memoryLimit",
        "cpuLimit",
        "processLimit",
        "filesystemRpc",
    ]
}

#[cfg(windows)]
mod windows_backend {
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};

    use agent_sandbox_protocol::ResourceLimits;
    use rappct::launch::{
        JobGuard, JobLimits, LaunchOptions, StdioConfig, launch_in_container_with_io,
    };
    use rappct::{AppContainerProfile, KnownCapability, SecurityCapabilitiesBuilder};
    use serde::{Deserialize, Serialize};

    use super::*;

    fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
        let mut message = error.to_string();
        let mut source = error.source();
        while let Some(current) = source {
            message.push_str(": ");
            message.push_str(&current.to_string());
            source = current.source();
        }
        message
    }
    use crate::windows_acl;

    const SYSTEM_CMD: &str = r"C:\Windows\System32\cmd.exe";
    const ACL_STRATEGY_LEGACY_TREE: u8 = 0;
    const ACL_STRATEGY_ROOT_INHERITED: u8 = 1;

    #[derive(Debug)]
    pub struct PreparedWindowsSandbox {
        pub profile_name: String,
        pub sid: String,
        profile: AppContainerProfile,
        journal: Option<PathBuf>,
        mounts: Vec<PathBuf>,
        acl_strategy: u8,
        persistent_profile: bool,
    }

    #[derive(Debug, Clone)]
    pub struct ProcessControl {
        job: Arc<Mutex<Option<JobGuard>>>,
    }

    impl ProcessControl {
        pub fn terminate(&self) {
            if let Ok(mut guard) = self.job.lock() {
                guard.take();
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AclJournal {
        profile_name: String,
        sid: String,
        mounts: Vec<PathBuf>,
        #[serde(default)]
        acl_strategy: u8,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    struct PersistentMount {
        source: PathBuf,
        access: MountAccess,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PersistentAuthorization {
        version: u8,
        state: String,
        capability_name: String,
        capability_sid: String,
        policy_fingerprint: String,
        mounts: Vec<PersistentMount>,
    }

    pub fn probe() -> Result<(), SandboxError> {
        if !Path::new(SYSTEM_CMD).is_file() {
            return Err(SandboxError::BackendUnavailable(
                "required Windows AppContainer support tools are unavailable".into(),
            ));
        }
        Ok(())
    }

    pub fn report() -> CapabilityReport {
        let mut features = BTreeMap::new();
        features.insert("filesystemReadBoundary".into(), FeatureState::Enforced);
        features.insert("filesystemWriteBoundary".into(), FeatureState::Enforced);
        features.insert("networkDeny".into(), FeatureState::Enforced);
        features.insert("processTree".into(), FeatureState::Enforced);
        features.insert("memoryLimit".into(), FeatureState::Enforced);
        features.insert("cpuLimit".into(), FeatureState::Limited);
        features.insert("processLimit".into(), FeatureState::Unavailable);
        features.insert("filesystemRpc".into(), FeatureState::Unavailable);
        CapabilityReport {
            platform: "windows".into(),
            backend: "windows-appcontainer".into(),
            status: EnforcementStatus::Limited,
            features,
            reasons: vec![
                "filesystem and network boundaries use AppContainer package capabilities".into(),
                "process-tree and memory limits use a kill-on-close Job Object".into(),
                "CPU is enforced as a job rate cap; an absolute CPU-time limit is not yet available".into(),
                "per-job process count is not yet enforced".into(),
            ],
        }
    }

    pub async fn recover_journals() -> Result<(), SandboxError> {
        let state_dir = state_directory()?;
        let mut entries = match tokio::fs::read_dir(&state_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(SandboxError::BackendUnavailable(format!(
                    "cannot inspect sandbox recovery journals: {error}"
                )));
            }
        };
        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            SandboxError::BackendUnavailable(format!("cannot read recovery journal: {error}"))
        })? {
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = tokio::fs::read(entry.path()).await.map_err(|error| {
                SandboxError::BackendUnavailable(format!("cannot read recovery journal: {error}"))
            })?;
            let record: AclJournal = serde_json::from_slice(&bytes).map_err(|error| {
                SandboxError::BackendUnavailable(format!("invalid recovery journal: {error}"))
            })?;
            if !record.profile_name.starts_with("agent.sandbox.")
                || !record.sid.starts_with("S-1-15-2-")
                || record.mounts.iter().any(|path| !path.is_absolute())
            {
                return Err(SandboxError::BackendUnavailable(
                    "recovery journal failed integrity validation".into(),
                ));
            }
            for mount in record.mounts.iter().rev() {
                revoke_mount(&record.sid, mount, record.acl_strategy).await?;
            }
            AppContainerProfile::ensure(
                &record.profile_name,
                "Agent Sandbox",
                Some("Ephemeral native agent sandbox"),
            )
            .and_then(|profile| profile.delete())
            .map_err(|error| {
                SandboxError::BackendUnavailable(format!(
                    "cannot recover AppContainer profile: {error}"
                ))
            })?;
            tokio::fs::remove_file(entry.path())
                .await
                .map_err(|error| {
                    SandboxError::BackendUnavailable(format!(
                        "cannot remove recovered journal: {error}"
                    ))
                })?;
        }
        recover_persistent_authorizations(&state_dir).await
    }

    async fn recover_persistent_authorizations(state_dir: &Path) -> Result<(), SandboxError> {
        let directory = state_dir.join("authorizations");
        let mut entries = match tokio::fs::read_dir(&directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(SandboxError::BackendUnavailable(format!(
                    "cannot inspect persistent authorizations: {error}"
                )));
            }
        };
        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            SandboxError::BackendUnavailable(format!(
                "cannot read persistent authorization directory: {error}"
            ))
        })? {
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = tokio::fs::read(entry.path()).await.map_err(|error| {
                SandboxError::BackendUnavailable(format!(
                    "cannot read persistent authorization: {error}"
                ))
            })?;
            let record: PersistentAuthorization =
                serde_json::from_slice(&bytes).map_err(|error| {
                    SandboxError::BackendUnavailable(format!(
                        "invalid persistent authorization: {error}"
                    ))
                })?;
            if record.version != 1
                || !record.capability_name.starts_with("agent.sandbox.")
                || !record.capability_sid.starts_with("S-1-15-2-")
                || record
                    .mounts
                    .iter()
                    .any(|mount| !mount.source.is_absolute())
            {
                return Err(SandboxError::BackendUnavailable(
                    "persistent authorization failed integrity validation".into(),
                ));
            }
            match record.state.as_str() {
                "active" => continue,
                "preparing" => {
                    for mount in record.mounts.iter().rev() {
                        let source = mount.source.clone();
                        let sid = record.capability_sid.clone();
                        tokio::task::spawn_blocking(move || {
                            windows_acl::revoke_root(&source, &sid)
                        })
                        .await
                        .map_err(|error| {
                            SandboxError::BackendUnavailable(format!(
                                "persistent authorization recovery task failed: {error}"
                            ))
                        })??;
                    }
                    AppContainerProfile::ensure(
                        &record.capability_name,
                        "Agent Sandbox",
                        Some("Persistent workspace sandbox"),
                    )
                    .and_then(|profile| profile.delete())
                    .map_err(|error| {
                        SandboxError::BackendUnavailable(format!(
                            "cannot recover persistent AppContainer profile: {error}"
                        ))
                    })?;
                    tokio::fs::remove_file(entry.path())
                        .await
                        .map_err(|error| {
                            SandboxError::BackendUnavailable(format!(
                                "cannot remove recovered persistent authorization: {error}"
                            ))
                        })?;
                }
                _ => {
                    return Err(SandboxError::BackendUnavailable(
                        "persistent authorization has an unknown state".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub async fn prepare(
        sandbox_id: &str,
        policy: &ValidatedPolicy,
        authorization: &AuthorizationSpec,
    ) -> Result<PreparedWindowsSandbox, SandboxError> {
        probe()?;
        let suffix: String = sandbox_id
            .chars()
            .filter(|value| value.is_ascii_alphanumeric())
            .take(32)
            .collect();
        let persistent = policy.original.filesystem.lease.mode == FilesystemLeaseMode::Persistent;
        let profile_name = if persistent {
            format!(
                "agent.sandbox.{}",
                persistent_authorization_hash(authorization)
                    .chars()
                    .take(24)
                    .collect::<String>()
            )
        } else {
            format!("agent.sandbox.{suffix}")
        };
        let profile = AppContainerProfile::ensure(
            &profile_name,
            "Agent Sandbox",
            Some("Ephemeral native agent sandbox"),
        )
        .map_err(|error| SandboxError::BackendUnavailable(error.to_string()))?;
        if persistent {
            prepare_persistent_authorization(
                policy,
                authorization,
                &profile_name,
                profile.sid.as_string(),
            )
            .await?;
            return Ok(PreparedWindowsSandbox {
                profile_name,
                sid: profile.sid.as_string().to_string(),
                profile,
                journal: None,
                mounts: Vec::new(),
                acl_strategy: ACL_STRATEGY_ROOT_INHERITED,
                persistent_profile: true,
            });
        }

        let state_dir = state_directory()?;
        tokio::fs::create_dir_all(&state_dir)
            .await
            .map_err(|error| {
                SandboxError::BackendUnavailable(format!("cannot create state directory: {error}"))
            })?;
        let journal = state_dir.join(format!("{suffix}.json"));
        let mounts: Vec<_> = policy
            .mounts
            .values()
            .map(|mount| mount.source.clone())
            .collect();
        let record = AclJournal {
            profile_name: profile_name.clone(),
            sid: profile.sid.as_string().to_string(),
            mounts: mounts.clone(),
            acl_strategy: ACL_STRATEGY_ROOT_INHERITED,
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| SandboxError::Internal(error.to_string()))?;
        tokio::fs::write(&journal, bytes).await.map_err(|error| {
            SandboxError::BackendUnavailable(format!("cannot persist ACL journal: {error}"))
        })?;

        let mut granted: Vec<PathBuf> = Vec::new();
        for mount in policy.mounts.values() {
            let result = grant_mount(&profile, &mount.source, mount.access).await;
            if let Err(error) = result {
                for path in granted.iter().rev() {
                    let _ = revoke_mount(&record.sid, path, record.acl_strategy).await;
                }
                let _ = profile.delete();
                let _ = tokio::fs::remove_file(&journal).await;
                return Err(error);
            }
            granted.push(mount.source.clone());
        }
        Ok(PreparedWindowsSandbox {
            profile_name,
            sid: record.sid,
            profile,
            journal: Some(journal),
            mounts,
            acl_strategy: record.acl_strategy,
            persistent_profile: false,
        })
    }

    fn persistent_authorization_hash(authorization: &AuthorizationSpec) -> String {
        let mut digest = Sha256::new();
        digest.update(authorization.tenant_id.as_bytes());
        digest.update([0]);
        digest.update(authorization.authorization_id.as_bytes());
        hex::encode(digest.finalize())
    }

    async fn prepare_persistent_authorization(
        policy: &ValidatedPolicy,
        authorization: &AuthorizationSpec,
        profile_name: &str,
        profile_sid: &str,
    ) -> Result<(), SandboxError> {
        let mounts: Vec<_> = policy
            .mounts
            .values()
            .map(|mount| PersistentMount {
                source: mount.source.clone(),
                access: mount.access,
            })
            .collect();
        let authorization_hash = persistent_authorization_hash(authorization);
        let capability_name = profile_name.to_string();
        let capability_sid = profile_sid.to_string();
        let mut policy_digest = Sha256::new();
        for mount in &mounts {
            policy_digest.update(mount.source.to_string_lossy().as_bytes());
            policy_digest.update([0]);
            policy_digest.update(match mount.access {
                MountAccess::ReadOnly => b"read-only".as_slice(),
                MountAccess::ReadWrite => b"read-write".as_slice(),
            });
            policy_digest.update([0]);
        }
        let policy_fingerprint = format!("sha256:{}", hex::encode(policy_digest.finalize()));
        let directory = state_directory()?.join("authorizations");
        tokio::fs::create_dir_all(&directory)
            .await
            .map_err(|error| {
                SandboxError::BackendUnavailable(format!(
                    "cannot create persistent authorization directory: {error}"
                ))
            })?;
        let path = directory.join(format!("{authorization_hash}.json"));
        if let Ok(bytes) = tokio::fs::read(&path).await {
            let record: PersistentAuthorization =
                serde_json::from_slice(&bytes).map_err(|error| {
                    SandboxError::BackendUnavailable(format!(
                        "invalid persistent authorization record: {error}"
                    ))
                })?;
            if record.version != 1
                || record.state != "active"
                || record.capability_name != capability_name
                || record.capability_sid != capability_sid
                || record.policy_fingerprint != policy_fingerprint
                || record.mounts != mounts
            {
                return Err(SandboxError::InvalidPolicy(
                    "persistent authorization does not match the requested workspace policy".into(),
                ));
            }
            return Ok(());
        }
        for mount in &mounts {
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
            version: 1,
            state: "preparing".into(),
            capability_name: capability_name.clone(),
            capability_sid: capability_sid.clone(),
            policy_fingerprint,
            mounts,
        };
        tokio::fs::write(
            &path,
            serde_json::to_vec(&record)
                .map_err(|error| SandboxError::Internal(error.to_string()))?,
        )
        .await
        .map_err(|error| {
            SandboxError::BackendUnavailable(format!(
                "cannot persist workspace authorization journal: {error}"
            ))
        })?;
        let mut granted: Vec<PathBuf> = Vec::new();
        for mount in &record.mounts {
            let source = mount.source.clone();
            let sid = capability_sid.clone();
            let mask = mount_access_mask(mount.access);
            let result =
                tokio::task::spawn_blocking(move || windows_acl::grant_root(&source, &sid, mask))
                    .await
                    .map_err(|error| {
                        SandboxError::CapabilityUnavailable(format!(
                            "persistent ACL grant task failed: {error}"
                        ))
                    })?;
            if let Err(error) = result {
                for source in granted.iter().rev() {
                    let source = source.clone();
                    let sid = capability_sid.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        windows_acl::revoke_root(&source, &sid)
                    })
                    .await;
                }
                let _ = tokio::fs::remove_file(&path).await;
                return Err(error);
            }
            granted.push(mount.source.clone());
        }
        record.state = "active".into();
        tokio::fs::write(
            &path,
            serde_json::to_vec(&record)
                .map_err(|error| SandboxError::Internal(error.to_string()))?,
        )
        .await
        .map_err(|error| {
            SandboxError::BackendUnavailable(format!(
                "cannot activate persistent workspace authorization: {error}"
            ))
        })?;
        Ok(())
    }

    pub async fn revoke_persistent_authorization(
        authorization: &AuthorizationSpec,
    ) -> Result<(), SandboxError> {
        let path = state_directory()?.join("authorizations").join(format!(
            "{}.json",
            persistent_authorization_hash(authorization)
        ));
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(SandboxError::BackendUnavailable(format!(
                    "cannot read persistent authorization for revocation: {error}"
                )));
            }
        };
        let record: PersistentAuthorization = serde_json::from_slice(&bytes).map_err(|error| {
            SandboxError::BackendUnavailable(format!(
                "invalid persistent authorization for revocation: {error}"
            ))
        })?;
        if record.version != 1
            || record.state != "active"
            || !record.capability_name.starts_with("agent.sandbox.")
            || !record.capability_sid.starts_with("S-1-15-2-")
            || record
                .mounts
                .iter()
                .any(|mount| !mount.source.is_absolute())
        {
            return Err(SandboxError::BackendUnavailable(
                "persistent authorization failed revocation integrity validation".into(),
            ));
        }
        for mount in record.mounts.iter().rev() {
            let source = mount.source.clone();
            let sid = record.capability_sid.clone();
            tokio::task::spawn_blocking(move || windows_acl::revoke_root(&source, &sid))
                .await
                .map_err(|error| {
                    SandboxError::BackendUnavailable(format!(
                        "persistent authorization revoke task failed: {error}"
                    ))
                })??;
        }
        AppContainerProfile::ensure(
            &record.capability_name,
            "Agent Sandbox",
            Some("Persistent workspace sandbox"),
        )
        .and_then(|profile| profile.delete())
        .map_err(|error| {
            SandboxError::BackendUnavailable(format!(
                "cannot delete persistent AppContainer profile: {error}"
            ))
        })?;
        tokio::fs::remove_file(path).await.map_err(|error| {
            SandboxError::BackendUnavailable(format!(
                "cannot remove persistent authorization record: {error}"
            ))
        })?;
        Ok(())
    }

    fn mount_access_mask(access: MountAccess) -> u32 {
        use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};
        match access {
            MountAccess::ReadOnly => FILE_GENERIC_READ.0,
            MountAccess::ReadWrite => {
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | 0x0001_0000 | 0x0000_0040
            }
        }
    }

    async fn grant_mount(
        profile: &AppContainerProfile,
        path: &Path,
        access: MountAccess,
    ) -> Result<(), SandboxError> {
        let mask = mount_access_mask(access);
        let path = path.to_path_buf();
        let sid = profile.sid.as_string().to_string();
        let grant_path = path.clone();
        let grant_sid = sid.clone();
        let result = tokio::task::spawn_blocking(move || {
            windows_acl::grant_tree(&grant_path, &grant_sid, mask)
        })
        .await
        .map_err(|error| {
            SandboxError::CapabilityUnavailable(format!("ACL grant task failed: {error}"))
        })?;
        if result.is_err() {
            let _ =
                tokio::task::spawn_blocking(move || windows_acl::revoke_root(&path, &sid)).await;
        }
        result
    }

    async fn revoke_mount(sid: &str, path: &Path, acl_strategy: u8) -> Result<(), SandboxError> {
        let path = path.to_path_buf();
        let sid = sid.to_string();
        tokio::task::spawn_blocking(move || match acl_strategy {
            ACL_STRATEGY_ROOT_INHERITED => windows_acl::revoke_root(&path, &sid),
            ACL_STRATEGY_LEGACY_TREE => windows_acl::revoke_tree(&path, &sid),
            _ => Err(SandboxError::CapabilityUnavailable(
                "unknown ACL recovery strategy".into(),
            )),
        })
        .await
        .map_err(|error| {
            SandboxError::CapabilityUnavailable(format!("ACL revoke task failed: {error}"))
        })?
    }

    pub async fn cleanup(platform: &PreparedWindowsSandbox) -> Result<(), SandboxError> {
        let mut failures = Vec::new();
        for mount in platform.mounts.iter().rev() {
            if let Err(error) = revoke_mount(&platform.sid, mount, platform.acl_strategy).await {
                failures.push(error.to_string());
            }
        }
        if !platform.persistent_profile {
            match platform.profile.clone().delete() {
                Ok(()) => {}
                Err(error) => failures.push(format!("cannot delete AppContainer profile: {error}")),
            }
        }
        if failures.is_empty() {
            if let Some(journal) = &platform.journal {
                tokio::fs::remove_file(journal).await.map_err(|error| {
                    SandboxError::Internal(format!("cannot remove ACL journal: {error}"))
                })?;
            }
            Ok(())
        } else {
            Err(SandboxError::Internal(format!(
                "sandbox cleanup incomplete; recovery journal retained: {}",
                failures.join("; ")
            )))
        }
    }

    pub async fn spawn(
        sandbox: &PreparedSandbox,
        execution: &ValidatedExecution,
        stdin_pipe: bool,
    ) -> Result<NativeProcess, SandboxError> {
        let workdir = native_workdir(&sandbox.policy, &execution.workdir)?;
        let (exe, cmdline) = command_line(&execution.command, &execution.environment)?;
        let profile = sandbox.platform.profile.clone();
        let mut capabilities = SecurityCapabilitiesBuilder::new(&profile.sid);
        if sandbox.policy.original.network.mode == NetworkMode::Host {
            capabilities = capabilities.with_known(&[KnownCapability::InternetClient]);
        }
        let capabilities = capabilities
            .build()
            .map_err(|error| SandboxError::CapabilityUnavailable(error.to_string()))?;
        let env = process_environment(&execution.environment, &workdir)?;
        let limits = execution.limits.clone();
        let launched = tokio::task::spawn_blocking(move || {
            launch_in_container_with_io(
                &capabilities,
                &LaunchOptions {
                    exe,
                    cmdline,
                    cwd: Some(workdir),
                    env: Some(env),
                    stdio: StdioConfig::Pipe,
                    join_job: Some(job_limits(&limits)),
                    ..Default::default()
                },
            )
            .map_err(|error| {
                SandboxError::Process(format!(
                    "failed to launch AppContainer process: {}",
                    error_chain(&error)
                ))
            })
        })
        .await
        .map_err(|error| SandboxError::Process(format!("launcher task failed: {error}")))??;

        let mut launched = launched;
        let stdin = if stdin_pipe {
            launched.stdin.take().map(tokio::fs::File::from_std)
        } else {
            launched.stdin.take();
            None
        };
        let stdout = launched.stdout.take().map(tokio::fs::File::from_std);
        let stderr = launched.stderr.take().map(tokio::fs::File::from_std);
        let job = Arc::new(Mutex::new(launched.job_guard.take()));
        let wait = tokio::task::spawn_blocking(move || {
            launched
                .wait(None)
                .map(|code| code as i32)
                .map_err(|error| {
                    SandboxError::Process(format!("failed while waiting for process: {error}"))
                })
        });
        Ok(NativeProcess {
            stdin,
            stdout,
            stderr,
            wait,
            control: ProcessControl { job },
        })
    }

    fn native_workdir(policy: &ValidatedPolicy, logical: &str) -> Result<PathBuf, SandboxError> {
        for mount in policy.mounts.values() {
            if logical == mount.destination
                || logical.starts_with(&format!("{}/", mount.destination))
            {
                let relative = logical
                    .strip_prefix(&mount.destination)
                    .unwrap_or("")
                    .trim_start_matches('/');
                let candidate = mount.source.join(relative.replace('/', "\\"));
                let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
                    SandboxError::InvalidPolicy(format!("execution cwd is unavailable: {error}"))
                })?;
                if !canonical.starts_with(&mount.source) || !canonical.is_dir() {
                    return Err(SandboxError::InvalidPolicy(
                        "execution cwd escaped its mount or is not a directory".into(),
                    ));
                }
                return Ok(to_win32_process_path(canonical));
            }
        }
        Err(SandboxError::InvalidPolicy(
            "execution cwd references an unknown mount".into(),
        ))
    }

    fn command_line(
        command: &CommandSpec,
        environment: &BTreeMap<String, String>,
    ) -> Result<(PathBuf, Option<String>), SandboxError> {
        match command {
            CommandSpec::Shell { script, .. } => Ok((
                PathBuf::from(SYSTEM_CMD),
                Some(format!("/D /S /C {script}")),
            )),
            CommandSpec::Exec { program, args } => {
                let exe = resolve_executable(program, environment)?;
                let mut command_line = vec![quote_windows_argument(&exe.to_string_lossy())];
                command_line.extend(args.iter().map(|arg| quote_windows_argument(arg)));
                Ok((exe, Some(command_line.join(" "))))
            }
        }
    }

    fn resolve_executable(
        program: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<PathBuf, SandboxError> {
        let path = environment
            .get("PATH")
            .cloned()
            .or_else(|| std::env::var("PATH").ok())
            .unwrap_or_else(|| r"C:\Windows\System32".into());
        let extensions = environment
            .get("PATHEXT")
            .cloned()
            .or_else(|| std::env::var("PATHEXT").ok())
            .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
        let has_extension = Path::new(program).extension().is_some();
        for directory in std::env::split_paths(&path) {
            if !directory.is_absolute() {
                continue;
            }
            if has_extension {
                let candidate = directory.join(program);
                if candidate.is_file() {
                    return std::fs::canonicalize(candidate)
                        .map(to_win32_process_path)
                        .map_err(|error| SandboxError::Process(error.to_string()));
                }
            } else {
                for extension in extensions.split(';').filter(|value| !value.is_empty()) {
                    let candidate = directory.join(format!("{program}{extension}"));
                    if candidate.is_file() {
                        return std::fs::canonicalize(candidate)
                            .map(to_win32_process_path)
                            .map_err(|error| SandboxError::Process(error.to_string()));
                    }
                }
            }
        }
        Err(SandboxError::Process(format!(
            "executable {program} was not found in the trusted PATH"
        )))
    }

    fn to_win32_process_path(path: PathBuf) -> PathBuf {
        let value = path.to_string_lossy();
        value
            .strip_prefix(r"\\?\")
            .map(PathBuf::from)
            .unwrap_or(path)
    }

    fn process_environment(
        requested: &BTreeMap<String, String>,
        workdir: &Path,
    ) -> Result<Vec<(OsString, OsString)>, SandboxError> {
        Ok(process_environment_with(requested, workdir, |name| {
            std::env::var_os(name)
        }))
    }

    fn process_environment_with(
        requested: &BTreeMap<String, String>,
        workdir: &Path,
        parent: impl Fn(&str) -> Option<OsString>,
    ) -> Vec<(OsString, OsString)> {
        let mut environment = BTreeMap::new();
        let mut insert = |name: &str, value: OsString| {
            environment
                .entry(name.to_ascii_lowercase())
                .or_insert_with(|| (OsString::from(name), value));
        };
        for (name, value) in requested {
            insert(name, OsString::from(value));
        }

        let windows_root = parent("SystemRoot").unwrap_or_else(|| OsString::from(r"C:\Windows"));
        let system_cmd = PathBuf::from(&windows_root)
            .join("System32")
            .join("cmd.exe");
        let system_path = PathBuf::from(&windows_root).join("System32");
        for (name, fallback) in [
            ("SystemRoot", windows_root.clone()),
            (
                "windir",
                parent("windir").unwrap_or_else(|| windows_root.clone()),
            ),
            (
                "ComSpec",
                parent("ComSpec").unwrap_or_else(|| system_cmd.into_os_string()),
            ),
            (
                "PATHEXT",
                parent("PATHEXT").unwrap_or_else(|| OsString::from(".COM;.EXE;.BAT;.CMD")),
            ),
            (
                "LOCALAPPDATA",
                parent("LOCALAPPDATA").unwrap_or_else(|| workdir.as_os_str().to_os_string()),
            ),
            (
                "TEMP",
                parent("TEMP").unwrap_or_else(|| workdir.as_os_str().to_os_string()),
            ),
            (
                "TMP",
                parent("TMP").unwrap_or_else(|| workdir.as_os_str().to_os_string()),
            ),
            (
                "PATH",
                parent("PATH").unwrap_or_else(|| system_path.into_os_string()),
            ),
        ] {
            insert(name, fallback);
        }
        for name in [
            "ALLUSERSPROFILE",
            "APPDATA",
            "CommonProgramFiles",
            "CommonProgramFiles(x86)",
            "CommonProgramW6432",
            "HOMEDRIVE",
            "HOMEPATH",
            "OS",
            "ProgramData",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramW6432",
            "PUBLIC",
            "SYSTEMDRIVE",
            "USERPROFILE",
        ] {
            if let Some(value) = parent(name) {
                insert(name, value);
            }
        }
        if let Some(prefix) = workdir.to_string_lossy().get(..2)
            && prefix.ends_with(':')
        {
            insert(
                &format!("={}", prefix.to_ascii_uppercase()),
                workdir.as_os_str().to_os_string(),
            );
        }
        environment.into_values().collect()
    }

    fn job_limits(limits: &ResourceLimits) -> JobLimits {
        let cpu_rate =
            ((limits.cpu_time_ms.saturating_mul(100)) / limits.wall_time_ms).clamp(1, 100) as u32;
        JobLimits {
            memory_bytes: Some(limits.memory_bytes.min(usize::MAX as u64) as usize),
            cpu_rate_percent: Some(cpu_rate),
            kill_on_job_close: true,
        }
    }

    fn quote_windows_argument(value: &str) -> String {
        let mut result = String::from("\"");
        let mut slashes = 0;
        for character in value.chars() {
            if character == '\\' {
                slashes += 1;
            } else if character == '"' {
                result.push_str(&"\\".repeat(slashes * 2 + 1));
                result.push('"');
                slashes = 0;
            } else {
                result.push_str(&"\\".repeat(slashes));
                slashes = 0;
                result.push(character);
            }
        }
        result.push_str(&"\\".repeat(slashes * 2));
        result.push('"');
        result
    }

    fn state_directory() -> Result<PathBuf, SandboxError> {
        if let Some(value) = std::env::var_os("AGENT_SANDBOX_STATE_DIR") {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(SandboxError::BackendUnavailable(
                    "AGENT_SANDBOX_STATE_DIR must be absolute".into(),
                ));
            }
            return Ok(path);
        }
        let base = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
            SandboxError::BackendUnavailable("LOCALAPPDATA is unavailable".into())
        })?;
        Ok(PathBuf::from(base).join("agent-sandbox").join("state"))
    }

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeMap;
        use std::error::Error;
        use std::ffi::OsString;
        use std::fmt::{Display, Formatter};
        use std::path::Path;

        use super::{error_chain, process_environment_with, quote_windows_argument};

        #[derive(Debug)]
        struct LaunchStageError(std::io::Error);

        impl Display for LaunchStageError {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("CreateProcessW failed")
            }
        }

        impl Error for LaunchStageError {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(&self.0)
            }
        }

        #[test]
        fn preserves_native_launch_error_sources() {
            let error = LaunchStageError(std::io::Error::from_raw_os_error(5));
            let message = error_chain(&error);
            assert!(message.starts_with("CreateProcessW failed: "));
            assert!(message.contains("os error 5"));
        }

        #[test]
        fn builds_required_environment_without_parent_variables() {
            let requested = BTreeMap::from([
                ("Path".to_string(), r"D:\tools".to_string()),
                ("CI".to_string(), "1".to_string()),
            ]);
            let environment =
                process_environment_with(&requested, Path::new(r"D:\workspace"), |_| None);
            let find = |name: &str| {
                environment
                    .iter()
                    .find(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.clone())
            };

            assert_eq!(find("PATH"), Some(OsString::from(r"D:\tools")));
            assert_eq!(find("SystemRoot"), Some(OsString::from(r"C:\Windows")));
            assert_eq!(
                find("ComSpec"),
                Some(OsString::from(r"C:\Windows\System32\cmd.exe"))
            );
            assert_eq!(find("LOCALAPPDATA"), Some(OsString::from(r"D:\workspace")));
            assert_eq!(find("TEMP"), Some(OsString::from(r"D:\workspace")));
            assert_eq!(find("=D:"), Some(OsString::from(r"D:\workspace")));
            assert_eq!(
                environment
                    .iter()
                    .filter(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case("PATH"))
                    .count(),
                1
            );
        }

        #[test]
        fn quotes_windows_arguments_with_backslashes_and_quotes() {
            assert_eq!(quote_windows_argument("plain"), "\"plain\"");
            assert_eq!(quote_windows_argument("a b"), "\"a b\"");
            assert_eq!(quote_windows_argument("a\\\"b"), "\"a\\\\\\\"b\"");
            assert_eq!(quote_windows_argument("tail\\"), "\"tail\\\\\"");
        }
    }
}
