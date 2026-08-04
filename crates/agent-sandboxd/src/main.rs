use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use agent_sandbox_core::{NativeBackend, PreparedSandbox, ProfileSpec, SandboxError};
use agent_sandbox_protocol::{
    ClientMessage, ErrorCategory, MAX_CONTROL_MESSAGE_BYTES, OutputStream, PROTOCOL_MAJOR,
    PROTOCOL_MINOR, ProtocolError, ProtocolVersion, ServerMessage, SignalKind, StdinMode,
};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::{Mutex, mpsc, watch};
use uuid::Uuid;

const RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_STREAM_CHUNK_BYTES: usize = 16 * 1024;
const MAX_STDIN_CHUNK_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Debug, Parser)]
#[command(
    name = "agent-sandboxd",
    version,
    about = "Framework-neutral agent sandbox runtime"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandLine,
}

#[derive(Debug, Subcommand)]
enum CommandLine {
    /// Serve the versioned JSONL protocol over stdin/stdout.
    Child {
        #[arg(long)]
        parent_pid: Option<u32>,
    },
    /// Probe the locally installed isolation backend.
    Probe {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancelReason {
    Terminate,
    Kill,
    Timeout,
    OutputLimit,
    SandboxClosed,
    ClientClosed,
}

impl CancelReason {
    fn signal(self) -> &'static str {
        match self {
            Self::Terminate => "terminate",
            Self::Kill => "kill",
            Self::Timeout => "timeout",
            Self::OutputLimit => "output-limit",
            Self::SandboxClosed => "sandbox-closed",
            Self::ClientClosed => "client-closed",
        }
    }
}

struct SandboxRecord {
    prepared: Arc<PreparedSandbox>,
}

struct ExecutionControl {
    sandbox_id: String,
    stdin: Mutex<Option<tokio::fs::File>>,
    next_stdin_sequence: Mutex<u64>,
    cancel: watch::Sender<Option<CancelReason>>,
}

struct Daemon {
    backend: Option<NativeBackend>,
    report: agent_sandbox_protocol::CapabilityReport,
    sandboxes: Mutex<HashMap<String, SandboxRecord>>,
    executions: Mutex<HashMap<String, Arc<ExecutionControl>>>,
    events: mpsc::Sender<ServerMessage>,
}

impl Daemon {
    async fn new(events: mpsc::Sender<ServerMessage>) -> Self {
        match NativeBackend::discover().await {
            Ok(backend) => {
                let report = backend.report();
                Self {
                    backend: Some(backend),
                    report,
                    sandboxes: Mutex::new(HashMap::new()),
                    executions: Mutex::new(HashMap::new()),
                    events,
                }
            }
            Err(error) => Self {
                backend: None,
                report: NativeBackend::unavailable_report(error.to_string()),
                sandboxes: Mutex::new(HashMap::new()),
                executions: Mutex::new(HashMap::new()),
                events,
            },
        }
    }

    async fn send(&self, event: ServerMessage) {
        let _ = self.events.send(event).await;
    }

    async fn send_error(
        &self,
        request_id: Option<String>,
        execution_id: Option<String>,
        error: SandboxError,
    ) {
        self.send(ServerMessage::Error {
            request_id,
            execution_id,
            error: error.protocol_error(),
        })
        .await;
    }

    async fn create_sandbox(
        &self,
        request_id: String,
        tenant_id: String,
        profile_id: String,
        authorization_id: String,
        policy: agent_sandbox_protocol::SandboxPolicy,
    ) {
        if let Err(error) = validate_identifier("tenantId", &tenant_id)
            .and_then(|_| validate_identifier("authorizationId", &authorization_id))
        {
            self.send_error(Some(request_id), None, error).await;
            return;
        }
        let Some(backend) = &self.backend else {
            self.send_error(
                Some(request_id),
                None,
                SandboxError::BackendUnavailable(
                    self.report
                        .reasons
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "isolation backend is unavailable".into()),
                ),
            )
            .await;
            return;
        };
        let validated = match agent_sandbox_core::ValidatedPolicy::new(policy) {
            Ok(value) => value,
            Err(error) => {
                self.send_error(Some(request_id), None, error).await;
                return;
            }
        };
        let profile = match ProfileSpec::trusted(&profile_id) {
            Ok(value) => value,
            Err(error) => {
                self.send_error(Some(request_id), None, error).await;
                return;
            }
        };
        let sandbox_id = Uuid::new_v4().to_string();
        let mut prepared = match backend.prepare(&sandbox_id, validated, profile).await {
            Ok(value) => value,
            Err(error) => {
                self.send_error(Some(request_id), None, error).await;
                return;
            }
        };
        let mut digest = Sha256::new();
        digest.update(prepared.fingerprint.as_bytes());
        digest.update(tenant_id.as_bytes());
        digest.update(authorization_id.as_bytes());
        prepared.fingerprint = format!("sha256:{}", hex::encode(digest.finalize()));

        let mounts = prepared.policy.logical_mounts();
        let status = prepared.report.status;
        let capabilities = prepared.report.clone();
        let policy_fingerprint = prepared.fingerprint.clone();
        self.sandboxes.lock().await.insert(
            sandbox_id.clone(),
            SandboxRecord {
                prepared: Arc::new(prepared),
            },
        );
        self.send(ServerMessage::SandboxCreated {
            request_id,
            sandbox_id,
            status,
            mounts,
            policy_fingerprint,
            capabilities,
        })
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn spawn_execution(
        self: &Arc<Self>,
        request_id: String,
        sandbox_id: String,
        execution_id: String,
        command: agent_sandbox_protocol::CommandSpec,
        cwd: agent_sandbox_protocol::LogicalPath,
        env: BTreeMap<String, String>,
        stdin_mode: StdinMode,
        limits: agent_sandbox_protocol::ExecutionLimits,
    ) {
        if let Err(error) = validate_identifier("executionId", &execution_id) {
            self.send_error(Some(request_id), Some(execution_id), error)
                .await;
            return;
        }
        let Some(backend) = self.backend.clone() else {
            self.send_error(
                Some(request_id),
                Some(execution_id),
                SandboxError::BackendUnavailable("isolation backend is unavailable".into()),
            )
            .await;
            return;
        };
        let prepared = {
            let sandboxes = self.sandboxes.lock().await;
            let Some(record) = sandboxes.get(&sandbox_id) else {
                self.send_error(
                    Some(request_id),
                    Some(execution_id),
                    SandboxError::Protocol("unknown or closed sandbox ID".into()),
                )
                .await;
                return;
            };
            Arc::clone(&record.prepared)
        };
        let execution = match prepared
            .policy
            .validate_execution(command, cwd, env, limits)
        {
            Ok(value) => value,
            Err(error) => {
                self.send_error(Some(request_id), Some(execution_id), error)
                    .await;
                return;
            }
        };
        let (cancel, cancel_rx) = watch::channel(None);
        let control = Arc::new(ExecutionControl {
            sandbox_id,
            stdin: Mutex::new(None),
            next_stdin_sequence: Mutex::new(1),
            cancel,
        });
        let mut executions = self.executions.lock().await;
        if executions.contains_key(&execution_id) {
            drop(executions);
            self.send_error(
                Some(request_id),
                Some(execution_id.clone()),
                SandboxError::Protocol("duplicate execution ID".into()),
            )
            .await;
            return;
        }
        executions.insert(execution_id.clone(), Arc::clone(&control));
        drop(executions);
        self.send(ServerMessage::Queued {
            request_id,
            execution_id: execution_id.clone(),
            position: 0,
        })
        .await;

        let daemon = Arc::clone(self);
        tokio::spawn(async move {
            daemon
                .run_execution(
                    backend,
                    prepared,
                    execution,
                    execution_id,
                    stdin_mode,
                    control,
                    cancel_rx,
                )
                .await;
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_execution(
        self: Arc<Self>,
        backend: NativeBackend,
        prepared: Arc<PreparedSandbox>,
        execution: agent_sandbox_core::ValidatedExecution,
        execution_id: String,
        stdin_mode: StdinMode,
        control: Arc<ExecutionControl>,
        mut cancel_rx: watch::Receiver<Option<CancelReason>>,
    ) {
        let mut child = match backend
            .spawn(&prepared, &execution, stdin_mode == StdinMode::Pipe)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                self.send_error(None, Some(execution_id.clone()), error)
                    .await;
                self.executions.lock().await.remove(&execution_id);
                return;
            }
        };
        if stdin_mode == StdinMode::Pipe {
            *control.stdin.lock().await = child.stdin.take();
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let process_control = child.control();
        self.send(ServerMessage::Started {
            execution_id: execution_id.clone(),
            status: prepared.report.status,
        })
        .await;

        let (chunks_tx, chunks_rx) = mpsc::channel(32);
        let stdout_task = stdout.map(|stream| {
            tokio::spawn(read_output(stream, OutputStream::Stdout, chunks_tx.clone()))
        });
        let stderr_task = stderr.map(|stream| {
            tokio::spawn(read_output(stream, OutputStream::Stderr, chunks_tx.clone()))
        });
        drop(chunks_tx);
        let output_task = tokio::spawn(forward_output(
            execution_id.clone(),
            execution.limits.output_bytes,
            chunks_rx,
            self.events.clone(),
            control.cancel.clone(),
        ));

        let timeout = tokio::time::sleep(Duration::from_millis(execution.limits.wall_time_ms));
        tokio::pin!(timeout);
        let outcome = tokio::select! {
            status = child.wait() => ExecutionOutcome::Status(status),
            changed = cancel_rx.changed() => {
                let reason = if changed.is_ok() {
                    (*cancel_rx.borrow()).unwrap_or(CancelReason::ClientClosed)
                } else {
                    CancelReason::ClientClosed
                };
                ExecutionOutcome::Cancelled(reason)
            }
            _ = &mut timeout => ExecutionOutcome::Cancelled(CancelReason::Timeout),
        };

        let (code, signal) = match outcome {
            ExecutionOutcome::Status(Ok(code)) => (Some(code), None),
            ExecutionOutcome::Status(Err(error)) => {
                self.send_error(
                    None,
                    Some(execution_id.clone()),
                    SandboxError::Process(format!("failed while waiting for process: {error}")),
                )
                .await;
                (None, Some("wait-failed".into()))
            }
            ExecutionOutcome::Cancelled(reason) => {
                process_control.terminate();
                (None, Some(reason.signal().into()))
            }
        };
        *control.stdin.lock().await = None;
        if let Some(task) = stdout_task {
            let _ = task.await;
        }
        if let Some(task) = stderr_task {
            let _ = task.await;
        }
        let output_bytes = output_task.await.unwrap_or(0);
        self.send(ServerMessage::Exit {
            execution_id: execution_id.clone(),
            code,
            signal,
            usage: BTreeMap::from([("outputBytes".into(), output_bytes)]),
        })
        .await;
        self.executions.lock().await.remove(&execution_id);
    }

    async fn write_stdin(&self, execution_id: String, sequence: u64, encoded: String) {
        let Some(control) = self.executions.lock().await.get(&execution_id).cloned() else {
            self.send_error(
                None,
                Some(execution_id),
                SandboxError::Protocol("unknown execution ID".into()),
            )
            .await;
            return;
        };
        let bytes = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(value) if value.len() <= MAX_STDIN_CHUNK_BYTES => value,
            _ => {
                self.send_error(
                    None,
                    Some(execution_id),
                    SandboxError::Protocol("invalid or oversized stdin chunk".into()),
                )
                .await;
                return;
            }
        };
        let mut expected = control.next_stdin_sequence.lock().await;
        if sequence != *expected {
            self.send_error(
                None,
                Some(execution_id),
                SandboxError::Protocol(format!("stdin sequence mismatch: expected {}", *expected)),
            )
            .await;
            return;
        }
        let mut stdin = control.stdin.lock().await;
        let Some(stdin) = stdin.as_mut() else {
            self.send_error(
                None,
                Some(execution_id),
                SandboxError::Protocol("execution stdin is closed".into()),
            )
            .await;
            return;
        };
        if let Err(error) = stdin.write_all(&bytes).await {
            self.send_error(
                None,
                Some(execution_id),
                SandboxError::Process(format!("failed to write stdin: {error}")),
            )
            .await;
            return;
        }
        *expected += 1;
    }

    async fn close_stdin(&self, execution_id: String) {
        let Some(control) = self.executions.lock().await.get(&execution_id).cloned() else {
            return;
        };
        if let Some(mut stdin) = control.stdin.lock().await.take() {
            let _ = stdin.shutdown().await;
        }
    }

    async fn signal(&self, execution_id: String, signal: SignalKind) {
        let Some(control) = self.executions.lock().await.get(&execution_id).cloned() else {
            return;
        };
        let reason = match signal {
            SignalKind::Terminate => CancelReason::Terminate,
            SignalKind::Kill => CancelReason::Kill,
        };
        let _ = control.cancel.send(Some(reason));
    }

    async fn close_sandbox(&self, request_id: String, sandbox_id: String) {
        let record = self.sandboxes.lock().await.remove(&sandbox_id);
        let Some(record) = record else {
            self.send_error(
                Some(request_id),
                None,
                SandboxError::Protocol("unknown or already closed sandbox ID".into()),
            )
            .await;
            return;
        };
        let controls: Vec<_> = self
            .executions
            .lock()
            .await
            .values()
            .filter(|control| control.sandbox_id == sandbox_id)
            .cloned()
            .collect();
        for control in controls {
            let _ = control.cancel.send(Some(CancelReason::SandboxClosed));
        }
        if !self.wait_for_sandbox_executions(&sandbox_id).await {
            self.send_error(
                Some(request_id),
                None,
                SandboxError::Internal(
                    "process tree did not terminate; ACL lease was retained for recovery".into(),
                ),
            )
            .await;
            return;
        }
        if let Some(backend) = &self.backend {
            if let Err(error) = backend.cleanup(&record.prepared).await {
                self.send_error(Some(request_id), None, error).await;
                return;
            }
        }
        self.send(ServerMessage::SandboxClosed {
            request_id,
            sandbox_id,
        })
        .await;
    }

    async fn wait_for_sandbox_executions(&self, sandbox_id: &str) -> bool {
        for _ in 0..100 {
            if !self
                .executions
                .lock()
                .await
                .values()
                .any(|control| control.sandbox_id == sandbox_id)
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    async fn shutdown(&self, reason: CancelReason) {
        let records: Vec<_> = self
            .sandboxes
            .lock()
            .await
            .drain()
            .map(|(_, record)| record)
            .collect();
        let controls: Vec<_> = self.executions.lock().await.values().cloned().collect();
        for control in controls {
            let _ = control.cancel.send(Some(reason));
        }
        for _ in 0..100 {
            if self.executions.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if !self.executions.lock().await.is_empty() {
            return;
        }
        if let Some(backend) = &self.backend {
            for record in records {
                let _ = backend.cleanup(&record.prepared).await;
            }
        }
    }
}

enum ExecutionOutcome {
    Status(Result<i32, SandboxError>),
    Cancelled(CancelReason),
}

async fn read_output<R>(
    mut reader: R,
    stream: OutputStream,
    chunks: mpsc::Sender<(OutputStream, Vec<u8>)>,
) where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; MAX_STREAM_CHUNK_BYTES];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(length) => {
                if chunks
                    .send((stream, buffer[..length].to_vec()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

async fn forward_output(
    execution_id: String,
    output_limit: u64,
    mut chunks: mpsc::Receiver<(OutputStream, Vec<u8>)>,
    events: mpsc::Sender<ServerMessage>,
    cancel: watch::Sender<Option<CancelReason>>,
) -> u64 {
    let mut bytes = 0_u64;
    let mut sequence = 1_u64;
    while let Some((stream, chunk)) = chunks.recv().await {
        bytes = bytes.saturating_add(chunk.len() as u64);
        if bytes > output_limit {
            let _ = cancel.send(Some(CancelReason::OutputLimit));
            break;
        }
        let event = ServerMessage::Output {
            execution_id: execution_id.clone(),
            stream,
            sequence,
            base64: base64::engine::general_purpose::STANDARD.encode(chunk),
        };
        if events.send(event).await.is_err() {
            let _ = cancel.send(Some(CancelReason::ClientClosed));
            break;
        }
        sequence += 1;
    }
    bytes.min(output_limit)
}

fn validate_identifier(label: &str, value: &str) -> Result<(), SandboxError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.contains('\0')
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(SandboxError::Protocol(format!("invalid {label}")));
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        CommandLine::Probe { json } => run_probe(json).await,
        CommandLine::Child { parent_pid } => run_child(parent_pid).await,
    };
    if let Err(error) = result {
        eprintln!("agent-sandboxd: {error}");
        std::process::exit(1);
    }
}

async fn run_probe(json: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let report = match NativeBackend::discover().await {
        Ok(backend) => backend.report(),
        Err(error) => NativeBackend::unavailable_report(error.to_string()),
    };
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}

async fn run_child(
    parent_pid: Option<u32>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if parent_pid == Some(0) {
        return Err("parent PID must be greater than zero".into());
    }
    let (events_tx, events_rx) = mpsc::channel(256);
    let writer = tokio::spawn(write_events(events_rx));
    let daemon = Arc::new(Daemon::new(events_tx).await);
    let mut input = BufReader::new(tokio::io::stdin());

    let Some(first) = read_control_line(&mut input).await? else {
        return Ok(());
    };
    let hello: ClientMessage = serde_json::from_slice(&first)?;
    let (protocol, nonce) = match hello {
        ClientMessage::Hello {
            protocol,
            client,
            nonce,
        } => {
            validate_identifier("client name", &client.name)?;
            validate_identifier("client version", &client.version)?;
            validate_identifier("nonce", &nonce)?;
            (protocol, nonce)
        }
        _ => return Err("the first protocol message must be hello".into()),
    };
    if protocol.major != PROTOCOL_MAJOR {
        daemon
            .send(ServerMessage::Error {
                request_id: None,
                execution_id: None,
                error: ProtocolError {
                    code: "SANDBOX_PROTOCOL_VERSION_MISMATCH".into(),
                    category: ErrorCategory::Protocol,
                    retryable: false,
                    message: format!(
                        "protocol major {} is unsupported; expected {PROTOCOL_MAJOR}",
                        protocol.major
                    ),
                    details: BTreeMap::new(),
                },
            })
            .await;
        return Err("protocol major version mismatch".into());
    }
    let features = if daemon.backend.is_some() {
        vec![
            "process.exec".into(),
            "process.spawn".into(),
            "network.deny".into(),
            "filesystem.mounts".into(),
        ]
    } else {
        Vec::new()
    };
    daemon
        .send(ServerMessage::HelloAck {
            protocol: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            runtime_version: RUNTIME_VERSION.into(),
            platform: std::env::consts::OS.into(),
            features,
            nonce,
        })
        .await;

    while let Some(line) = read_control_line(&mut input).await? {
        let message = match serde_json::from_slice::<ClientMessage>(&line) {
            Ok(value) => value,
            Err(error) => {
                daemon
                    .send(ServerMessage::Error {
                        request_id: None,
                        execution_id: None,
                        error: ProtocolError {
                            code: "SANDBOX_PROTOCOL_INVALID_MESSAGE".into(),
                            category: ErrorCategory::Protocol,
                            retryable: false,
                            message: format!("invalid control message: {error}"),
                            details: BTreeMap::new(),
                        },
                    })
                    .await;
                continue;
            }
        };
        match message {
            ClientMessage::Hello { .. } => {
                daemon
                    .send_error(
                        None,
                        None,
                        SandboxError::Protocol("hello cannot be repeated".into()),
                    )
                    .await;
            }
            ClientMessage::Probe { request_id } => {
                daemon
                    .send(ServerMessage::ProbeResult {
                        request_id,
                        report: daemon.report.clone(),
                    })
                    .await;
            }
            ClientMessage::CreateSandbox {
                request_id,
                tenant_id,
                profile,
                authorization_id,
                policy,
                metadata: _,
            } => {
                daemon
                    .create_sandbox(request_id, tenant_id, profile, authorization_id, policy)
                    .await;
            }
            ClientMessage::Spawn {
                request_id,
                sandbox_id,
                execution_id,
                command,
                cwd,
                env,
                stdin,
                limits,
            } => {
                daemon
                    .spawn_execution(
                        request_id,
                        sandbox_id,
                        execution_id,
                        command,
                        cwd,
                        env,
                        stdin,
                        limits,
                    )
                    .await;
            }
            ClientMessage::Stdin {
                execution_id,
                sequence,
                base64,
            } => daemon.write_stdin(execution_id, sequence, base64).await,
            ClientMessage::CloseStdin { execution_id } => daemon.close_stdin(execution_id).await,
            ClientMessage::Signal {
                execution_id,
                signal,
            } => daemon.signal(execution_id, signal).await,
            ClientMessage::CloseSandbox {
                request_id,
                sandbox_id,
            } => daemon.close_sandbox(request_id, sandbox_id).await,
            ClientMessage::Shutdown { request_id } => {
                daemon.shutdown(CancelReason::ClientClosed).await;
                daemon.send(ServerMessage::ShutdownAck { request_id }).await;
                break;
            }
        }
    }
    daemon.shutdown(CancelReason::ClientClosed).await;
    drop(daemon);
    writer.await??;
    Ok(())
}

async fn read_control_line<R>(reader: &mut R) -> Result<Option<Vec<u8>>, SandboxError>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut line = Vec::new();
    let length = reader
        .read_until(b'\n', &mut line)
        .await
        .map_err(|error| SandboxError::Protocol(error.to_string()))?;
    if length == 0 {
        return Ok(None);
    }
    if line.len() > MAX_CONTROL_MESSAGE_BYTES {
        return Err(SandboxError::Protocol(
            "control message exceeds 1 MiB".into(),
        ));
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    if line.is_empty() {
        return Err(SandboxError::Protocol("empty control message".into()));
    }
    Ok(Some(line))
}

async fn write_events(
    mut events: mpsc::Receiver<ServerMessage>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut output = BufWriter::new(tokio::io::stdout());
    while let Some(event) = events.recv().await {
        let json = serde_json::to_vec(&event)?;
        output.write_all(&json).await?;
        output.write_all(b"\n").await?;
        output.flush().await?;
    }
    Ok(())
}
