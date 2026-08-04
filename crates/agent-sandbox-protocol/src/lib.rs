use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 2;
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementStatus {
    Enforced,
    Limited,
    Unavailable,
    Bypassed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeatureState {
    Enforced,
    Limited,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityReport {
    pub platform: String,
    pub backend: String,
    pub status: EnforcementStatus,
    pub features: BTreeMap<String, FeatureState>,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendPreference {
    #[default]
    Auto,
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MountPolicy {
    pub name: String,
    pub source: String,
    pub access: MountAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FilesystemLeaseMode {
    #[default]
    Ephemeral,
    Persistent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FilesystemLeasePolicy {
    #[serde(default)]
    pub mode: FilesystemLeaseMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub mounts: Vec<MountPolicy>,
    #[serde(default)]
    pub protected_roots: Vec<String>,
    #[serde(default = "default_temp_bytes")]
    pub temp_bytes: u64,
    #[serde(default)]
    pub lease: FilesystemLeasePolicy,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            mounts: Vec::new(),
            protected_roots: Vec::new(),
            temp_bytes: default_temp_bytes(),
            lease: FilesystemLeasePolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    #[default]
    Deny,
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub mode: NetworkMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentPolicy {
    #[serde(default)]
    pub inherit: Vec<String>,
    #[serde(default)]
    pub allow_set: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutablePolicy {
    pub alias: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionPolicy {
    #[serde(default)]
    pub executables: Vec<ExecutablePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceLimits {
    #[serde(default = "default_wall_time_ms")]
    pub wall_time_ms: u64,
    #[serde(default = "default_cpu_time_ms")]
    pub cpu_time_ms: u64,
    #[serde(default = "default_memory_bytes")]
    pub memory_bytes: u64,
    #[serde(default = "default_processes")]
    pub processes: u32,
    #[serde(default = "default_output_bytes")]
    pub output_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            wall_time_ms: default_wall_time_ms(),
            cpu_time_ms: default_cpu_time_ms(),
            memory_bytes: default_memory_bytes(),
            processes: default_processes(),
            output_bytes: default_output_bytes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxPolicy {
    pub schema_version: u16,
    #[serde(default)]
    pub backend: BackendPreference,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub environment: EnvironmentPolicy,
    #[serde(default)]
    pub execution: ExecutionPolicy,
    #[serde(default)]
    pub limits: ResourceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxMetadata {
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub subject_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum CommandSpec {
    Exec {
        program: String,
        #[serde(default)]
        args: Vec<String>,
    },
    Shell {
        #[serde(default)]
        shell: ShellChoice,
        script: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ShellChoice {
    #[default]
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalPath {
    pub mount: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StdinMode {
    Pipe,
    #[default]
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionLimits {
    pub wall_time_ms: Option<u64>,
    pub cpu_time_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub processes: Option<u32>,
    pub output_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalKind {
    Terminate,
    Kill,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ClientMessage {
    Hello {
        protocol: ProtocolVersion,
        client: ClientInfo,
        nonce: String,
    },
    Probe {
        request_id: String,
    },
    CreateSandbox {
        request_id: String,
        tenant_id: String,
        profile: String,
        authorization_id: String,
        policy: SandboxPolicy,
        #[serde(default)]
        metadata: SandboxMetadata,
    },
    Spawn {
        request_id: String,
        sandbox_id: String,
        execution_id: String,
        command: CommandSpec,
        cwd: LogicalPath,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        stdin: StdinMode,
        #[serde(default)]
        limits: ExecutionLimits,
    },
    Stdin {
        execution_id: String,
        sequence: u64,
        base64: String,
    },
    CloseStdin {
        execution_id: String,
    },
    Signal {
        execution_id: String,
        signal: SignalKind,
    },
    CloseSandbox {
        request_id: String,
        sandbox_id: String,
    },
    RevokeAuthorization {
        request_id: String,
        tenant_id: String,
        authorization_id: String,
    },
    Shutdown {
        request_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Protocol,
    PolicyViolation,
    Capability,
    Resource,
    Process,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolError {
    pub code: String,
    pub category: ErrorCategory,
    pub retryable: bool,
    pub message: String,
    #[serde(default)]
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ServerMessage {
    HelloAck {
        protocol: ProtocolVersion,
        runtime_version: String,
        platform: String,
        features: Vec<String>,
        nonce: String,
    },
    ProbeResult {
        request_id: String,
        report: CapabilityReport,
    },
    SandboxCreated {
        request_id: String,
        sandbox_id: String,
        status: EnforcementStatus,
        mounts: BTreeMap<String, String>,
        policy_fingerprint: String,
        capabilities: CapabilityReport,
    },
    Queued {
        request_id: String,
        execution_id: String,
        position: u32,
    },
    Started {
        execution_id: String,
        status: EnforcementStatus,
    },
    Output {
        execution_id: String,
        stream: OutputStream,
        sequence: u64,
        base64: String,
    },
    Exit {
        execution_id: String,
        code: Option<i32>,
        signal: Option<String>,
        #[serde(default)]
        usage: BTreeMap<String, u64>,
    },
    SandboxClosed {
        request_id: String,
        sandbox_id: String,
    },
    AuthorizationRevoked {
        request_id: String,
        authorization_id: String,
    },
    ShutdownAck {
        request_id: String,
    },
    Error {
        request_id: Option<String>,
        execution_id: Option<String>,
        error: ProtocolError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

const fn default_wall_time_ms() -> u64 {
    600_000
}

const fn default_cpu_time_ms() -> u64 {
    480_000
}

const fn default_memory_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}

const fn default_processes() -> u32 {
    128
}

const fn default_output_bytes() -> u64 {
    50 * 1024 * 1024
}

const fn default_temp_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_security_fields() {
        let input = r#"{"type":"probe","requestId":"r","unsafe":true}"#;
        assert!(serde_json::from_str::<ClientMessage>(input).is_err());
    }

    #[test]
    fn policy_defaults_are_restrictive() {
        let policy: SandboxPolicy =
            serde_json::from_str(r#"{"schemaVersion":1,"filesystem":{"mounts":[]}}"#)
                .expect("valid policy");
        assert_eq!(policy.backend, BackendPreference::Auto);
        assert_eq!(policy.network.mode, NetworkMode::Deny);
        assert!(policy.environment.inherit.is_empty());
        assert!(policy.environment.allow_set.is_empty());
    }
}
