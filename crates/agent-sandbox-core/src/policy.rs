use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use agent_sandbox_protocol::{
    CommandSpec, ErrorCategory, ExecutionLimits, LogicalPath, MountAccess, ProtocolError,
    ResourceLimits, SandboxPolicy,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_MOUNTS: usize = 16;
const MAX_ENV_KEYS: usize = 128;
const MAX_ENV_VALUE_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TEMP_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PROCESSES: u32 = 4096;
const MAX_WALL_TIME_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("requested capability is unavailable: {0}")]
    CapabilityUnavailable(String),
    #[error("sandbox backend is unavailable: {0}")]
    BackendUnavailable(String),
    #[error("process failed: {0}")]
    Process(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("internal sandbox error: {0}")]
    Internal(String),
}

impl SandboxError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPolicy(_) => "SANDBOX_POLICY_INVALID",
            Self::CapabilityUnavailable(_) => "SANDBOX_CAPABILITY_UNAVAILABLE",
            Self::BackendUnavailable(_) => "SANDBOX_BACKEND_UNAVAILABLE",
            Self::Process(_) => "SANDBOX_PROCESS_FAILED",
            Self::Protocol(_) => "SANDBOX_PROTOCOL_ERROR",
            Self::Internal(_) => "SANDBOX_INTERNAL_ERROR",
        }
    }

    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::InvalidPolicy(_) => ErrorCategory::PolicyViolation,
            Self::CapabilityUnavailable(_) | Self::BackendUnavailable(_) => {
                ErrorCategory::Capability
            }
            Self::Process(_) => ErrorCategory::Process,
            Self::Protocol(_) => ErrorCategory::Protocol,
            Self::Internal(_) => ErrorCategory::Internal,
        }
    }

    pub fn protocol_error(&self) -> ProtocolError {
        ProtocolError {
            code: self.code().to_string(),
            category: self.category(),
            retryable: matches!(self, Self::BackendUnavailable(_) | Self::Process(_)),
            message: self.to_string(),
            details: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedMount {
    pub name: String,
    pub source: PathBuf,
    pub access: MountAccess,
    pub destination: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedPolicy {
    pub original: SandboxPolicy,
    pub mounts: BTreeMap<String, ValidatedMount>,
    pub allowed_environment: BTreeSet<String>,
    pub inherited_environment: BTreeMap<String, String>,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedExecution {
    pub command: CommandSpec,
    pub workdir: String,
    pub environment: BTreeMap<String, String>,
    pub limits: ResourceLimits,
}

impl ValidatedPolicy {
    pub fn new(policy: SandboxPolicy) -> Result<Self, SandboxError> {
        if policy.schema_version != 1 {
            return Err(SandboxError::InvalidPolicy(
                "only policy schema version 1 is supported".into(),
            ));
        }
        validate_limits(&policy.limits)?;
        if policy.filesystem.temp_bytes == 0 || policy.filesystem.temp_bytes > MAX_TEMP_BYTES {
            return Err(SandboxError::InvalidPolicy(
                "tempBytes is outside the supported range".into(),
            ));
        }
        if policy.filesystem.mounts.is_empty() || policy.filesystem.mounts.len() > MAX_MOUNTS {
            return Err(SandboxError::InvalidPolicy(format!(
                "filesystem mounts must contain between 1 and {MAX_MOUNTS} entries"
            )));
        }

        let protected = validate_protected_roots(&policy.filesystem.protected_roots)?;
        let mut mounts = BTreeMap::new();
        for mount in &policy.filesystem.mounts {
            validate_mount_name(&mount.name)?;
            if mounts.contains_key(&mount.name) {
                return Err(SandboxError::InvalidPolicy(format!(
                    "duplicate mount name: {}",
                    mount.name
                )));
            }
            let requested = PathBuf::from(&mount.source);
            if !requested.is_absolute() {
                return Err(SandboxError::InvalidPolicy(format!(
                    "mount {} source must be absolute",
                    mount.name
                )));
            }
            reject_link_components(&requested)?;
            let source = std::fs::canonicalize(&requested).map_err(|error| {
                SandboxError::InvalidPolicy(format!(
                    "mount {} source is unavailable: {error}",
                    mount.name
                ))
            })?;
            if !source.is_dir() {
                return Err(SandboxError::InvalidPolicy(format!(
                    "mount {} source must be a directory",
                    mount.name
                )));
            }
            if source.to_string_lossy().contains(',') {
                return Err(SandboxError::InvalidPolicy(format!(
                    "mount {} source contains an unsupported comma",
                    mount.name
                )));
            }
            if protected.iter().any(|root| paths_overlap(&source, root)) {
                return Err(SandboxError::InvalidPolicy(format!(
                    "mount {} overlaps a protected root",
                    mount.name
                )));
            }
            let destination = format!("mount://{}", mount.name);
            mounts.insert(
                mount.name.clone(),
                ValidatedMount {
                    name: mount.name.clone(),
                    source,
                    access: mount.access,
                    destination,
                },
            );
        }

        let allowed_environment = validate_environment_keys(&policy.environment.allow_set)?;
        let inherited_keys = validate_environment_keys(&policy.environment.inherit)?;
        let mut inherited_environment = BTreeMap::new();
        for name in inherited_keys {
            if let Ok(value) = std::env::var(&name) {
                validate_environment_value(&name, &value)?;
                inherited_environment.insert(name, value);
            }
        }

        let canonical = serde_json::to_vec(&policy)
            .map_err(|error| SandboxError::Internal(error.to_string()))?;
        let fingerprint = format!("sha256:{}", hex::encode(Sha256::digest(canonical)));

        Ok(Self {
            original: policy,
            mounts,
            allowed_environment,
            inherited_environment,
            fingerprint,
        })
    }

    pub fn validate_execution(
        &self,
        command: CommandSpec,
        cwd: LogicalPath,
        environment: BTreeMap<String, String>,
        limits: ExecutionLimits,
    ) -> Result<ValidatedExecution, SandboxError> {
        let mount = self.mounts.get(&cwd.mount).ok_or_else(|| {
            SandboxError::InvalidPolicy("execution cwd references an unknown mount".into())
        })?;
        let relative = validate_relative_path(&cwd.path)?;
        let workdir = if relative.is_empty() {
            mount.destination.clone()
        } else {
            format!("{}/{}", mount.destination, relative.replace('\\', "/"))
        };

        match &command {
            CommandSpec::Exec { program, args } => {
                if program.is_empty()
                    || program.contains('\0')
                    || program.contains('/')
                    || program.contains('\\')
                {
                    return Err(SandboxError::InvalidPolicy(
                        "exec program must be a bare executable name".into(),
                    ));
                }
                if args.iter().any(|arg| arg.contains('\0')) {
                    return Err(SandboxError::InvalidPolicy(
                        "exec arguments cannot contain NUL".into(),
                    ));
                }
            }
            CommandSpec::Shell { script, .. } => {
                if script.is_empty() || script.len() > MAX_SCRIPT_BYTES || script.contains('\0') {
                    return Err(SandboxError::InvalidPolicy(
                        "shell script is empty, too large, or contains NUL".into(),
                    ));
                }
            }
        }

        let mut effective_environment = self.inherited_environment.clone();
        for (name, value) in environment {
            if !self.allowed_environment.contains(&name) {
                return Err(SandboxError::InvalidPolicy(format!(
                    "environment variable {name} is not allowed"
                )));
            }
            validate_environment_value(&name, &value)?;
            effective_environment.insert(name, value);
        }

        let limits = narrow_limits(&self.original.limits, &limits)?;
        Ok(ValidatedExecution {
            command,
            workdir,
            environment: effective_environment,
            limits,
        })
    }

    pub fn logical_mounts(&self) -> BTreeMap<String, String> {
        self.mounts
            .iter()
            .map(|(name, mount)| (name.clone(), mount.destination.clone()))
            .collect()
    }
}

fn validate_limits(limits: &ResourceLimits) -> Result<(), SandboxError> {
    if limits.wall_time_ms == 0 || limits.wall_time_ms > MAX_WALL_TIME_MS {
        return Err(SandboxError::InvalidPolicy(
            "wallTimeMs is outside the supported range".into(),
        ));
    }
    if limits.cpu_time_ms == 0 || limits.cpu_time_ms > MAX_WALL_TIME_MS {
        return Err(SandboxError::InvalidPolicy(
            "cpuTimeMs is outside the supported range".into(),
        ));
    }
    if limits.memory_bytes == 0 || limits.memory_bytes > MAX_MEMORY_BYTES {
        return Err(SandboxError::InvalidPolicy(
            "memoryBytes is outside the supported range".into(),
        ));
    }
    if limits.processes == 0 || limits.processes > MAX_PROCESSES {
        return Err(SandboxError::InvalidPolicy(
            "processes is outside the supported range".into(),
        ));
    }
    if limits.output_bytes == 0 || limits.output_bytes > MAX_OUTPUT_BYTES {
        return Err(SandboxError::InvalidPolicy(
            "outputBytes is outside the supported range".into(),
        ));
    }
    Ok(())
}

fn narrow_limits(
    maximum: &ResourceLimits,
    requested: &ExecutionLimits,
) -> Result<ResourceLimits, SandboxError> {
    macro_rules! narrowed {
        ($field:ident) => {{
            let value = requested.$field.unwrap_or(maximum.$field);
            if value == 0 || value > maximum.$field {
                return Err(SandboxError::InvalidPolicy(format!(
                    "execution {} must be non-zero and cannot exceed the sandbox limit",
                    stringify!($field)
                )));
            }
            value
        }};
    }
    Ok(ResourceLimits {
        wall_time_ms: narrowed!(wall_time_ms),
        cpu_time_ms: narrowed!(cpu_time_ms),
        memory_bytes: narrowed!(memory_bytes),
        processes: narrowed!(processes),
        output_bytes: narrowed!(output_bytes),
    })
}

fn validate_mount_name(name: &str) -> Result<(), SandboxError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(SandboxError::InvalidPolicy(
            "mount names must use 1-64 ASCII letters, digits, '-' or '_'".into(),
        ));
    }
    Ok(())
}

fn validate_environment_keys(names: &[String]) -> Result<BTreeSet<String>, SandboxError> {
    if names.len() > MAX_ENV_KEYS {
        return Err(SandboxError::InvalidPolicy(format!(
            "environment key list exceeds {MAX_ENV_KEYS} entries"
        )));
    }
    let mut result = BTreeSet::new();
    for name in names {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || sensitive_environment_name(name)
        {
            return Err(SandboxError::InvalidPolicy(format!(
                "environment variable {name} is invalid or sensitive"
            )));
        }
        result.insert(name.clone());
    }
    Ok(result)
}

fn sensitive_environment_name(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "NPM_TOKEN",
        "NODE_AUTH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "DOCKER_AUTH_CONFIG",
        "DATABASE_URL",
        "BASH_ENV",
        "ENV",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ];
    EXACT.contains(&name)
        || name.starts_with("DYLD_")
        || [
            "KEY",
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "PASSWD",
            "PRIVATE_KEY",
        ]
        .iter()
        .any(|suffix| name == *suffix || name.ends_with(&format!("_{suffix}")))
}

fn validate_environment_value(name: &str, value: &str) -> Result<(), SandboxError> {
    if value.len() > MAX_ENV_VALUE_BYTES || value.contains('\0') {
        return Err(SandboxError::InvalidPolicy(format!(
            "environment variable {name} is too large or contains NUL"
        )));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<String, SandboxError> {
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(SandboxError::InvalidPolicy(
            "execution cwd must be relative".into(),
        ));
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(SandboxError::InvalidPolicy(
                    "execution cwd cannot escape its mount".into(),
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

fn validate_protected_roots(values: &[String]) -> Result<Vec<PathBuf>, SandboxError> {
    let mut roots = Vec::new();
    for value in values {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(SandboxError::InvalidPolicy(
                "protected roots must be absolute".into(),
            ));
        }
        let normalized = std::fs::canonicalize(&path).unwrap_or(path);
        roots.push(normalized);
    }
    Ok(roots)
}

fn reject_link_components(path: &Path) -> Result<(), SandboxError> {
    let mut current = Some(path);
    while let Some(component) = current {
        if let Ok(metadata) = std::fs::symlink_metadata(component) {
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(SandboxError::InvalidPolicy(
                    "mount source contains a symbolic link or reparse point".into(),
                ));
            }
        }
        current = component.parent();
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        let left = left.to_string_lossy().to_lowercase();
        let right = right.to_string_lossy().to_lowercase();
        let separator = std::path::MAIN_SEPARATOR;
        left == right
            || left.starts_with(&format!("{right}{separator}"))
            || right.starts_with(&format!("{left}{separator}"))
    }
    #[cfg(not(windows))]
    {
        left.starts_with(right) || right.starts_with(left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_sandbox_protocol::{
        BackendPreference, EnvironmentPolicy, FilesystemPolicy, MountPolicy, NetworkPolicy,
        SandboxPolicy,
    };

    fn policy_for(path: &Path) -> SandboxPolicy {
        SandboxPolicy {
            schema_version: 1,
            backend: BackendPreference::Native,
            filesystem: FilesystemPolicy {
                mounts: vec![MountPolicy {
                    name: "workspace".into(),
                    source: path.to_string_lossy().into_owned(),
                    access: MountAccess::ReadWrite,
                }],
                protected_roots: Vec::new(),
                temp_bytes: 1024 * 1024,
            },
            network: NetworkPolicy::default(),
            environment: EnvironmentPolicy {
                inherit: Vec::new(),
                allow_set: vec!["CI".into()],
            },
            limits: ResourceLimits::default(),
        }
    }

    #[test]
    fn execution_cannot_expand_limits_or_escape_cwd() {
        let root = std::env::temp_dir();
        let policy = ValidatedPolicy::new(policy_for(&root)).expect("valid policy");
        let expanded = policy.validate_execution(
            CommandSpec::Exec {
                program: "node".into(),
                args: Vec::new(),
            },
            LogicalPath {
                mount: "workspace".into(),
                path: ".".into(),
            },
            BTreeMap::new(),
            ExecutionLimits {
                memory_bytes: Some(policy.original.limits.memory_bytes + 1),
                ..ExecutionLimits::default()
            },
        );
        assert!(expanded.is_err());

        let escaped = policy.validate_execution(
            CommandSpec::Exec {
                program: "node".into(),
                args: Vec::new(),
            },
            LogicalPath {
                mount: "workspace".into(),
                path: "../outside".into(),
            },
            BTreeMap::new(),
            ExecutionLimits::default(),
        );
        assert!(escaped.is_err());
    }

    #[test]
    fn sensitive_environment_is_rejected() {
        let root = std::env::temp_dir();
        let mut input = policy_for(&root);
        input.environment.allow_set.push("OPENAI_API_KEY".into());
        assert!(ValidatedPolicy::new(input).is_err());
    }

    #[test]
    fn protected_root_cannot_be_mounted() {
        let root = std::env::temp_dir();
        let mut input = policy_for(&root);
        input.filesystem.protected_roots = vec![root.to_string_lossy().into_owned()];
        assert!(ValidatedPolicy::new(input).is_err());
    }
}
