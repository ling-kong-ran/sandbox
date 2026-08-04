# Agent Sandbox Runtime

A framework-neutral, local process sandbox for coding agents, IDEs, CI workers, and automation.

`agent-sandboxd` accepts immutable policies over a versioned JSONL protocol and runs untrusted child processes behind operating-system isolation. It does not require Docker, Podman, a VM image, or an installed service.

> Status: early `0.1.0` development release. The Windows backend is implemented and exercised by a real AppContainer integration suite. Linux and macOS builds currently fail closed with `status: unavailable`; their native backends are planned but are not represented as working.

## Security properties

The runtime is designed around these rules:

- **No silent host fallback.** If a required backend or capability is unavailable, sandbox creation fails.
- **Immutable capability.** Mounts, environment, network, and maximum resources are fixed when a sandbox is created. An execution can only narrow resource limits.
- **Default deny.** Policies default to no network, no inherited environment, and no writable path except explicit mounts.
- **Structured process boundary.** Commands, arguments, cwd, environment, stdin, and output are protocol fields rather than host-shell concatenation.
- **Complete process-tree ownership.** Cancellation, timeout, sandbox close, and daemon shutdown terminate the associated process tree.
- **Truthful capability reporting.** `enforced`, `limited`, `unavailable`, and `bypassed` are distinct states.

This runtime protects against untrusted repository scripts and model-generated commands. It does not protect against kernel vulnerabilities, a hostile administrator, or side effects produced by tools that a host application has not routed through the runtime.

## Current platform support

| Platform | Backend | State | Notes |
| --- | --- | --- | --- |
| Windows 10/11 | AppContainer + package-SID ACL leases + Job Object | `limited` | Filesystem and network boundaries, process-tree kill, and memory limit are enforced. CPU uses a Job rate cap. Per-job process count is not implemented yet. |
| Linux | Native backend planned | `unavailable` | Must add namespaces, Landlock, seccomp, and cgroup/rlimit conformance before enabling. |
| macOS | Native backend planned | `unavailable` | Must add Seatbelt, process-group supervision, and rlimit conformance before enabling. |

On Windows:

- ephemeral sandboxes receive a unique AppContainer profile and package SID;
- persistent managed workspaces reuse a stable package SID per tenant authorization while executions retain independent handles and Job Objects;
- package SIDs receive read-only or modify ACL entries only on declared mount trees;
- hard-link aliases and reparse targets are accepted only when every target remains inside the mount boundary;
- ephemeral ACL changes are journaled and revoked; persistent workspace authorizations are recorded and reused across daemon restarts;
- a later daemon recovers interrupted ephemeral leases and incomplete persistent enrollment after abrupt client death;
- `network: deny` grants no network capability;
- `network: host` grants outbound `InternetClient` and should be treated as a broad, explicit authorization;
- child stdio is inherited through an explicit handle list;
- a kill-on-close Job Object owns descendants and enforces memory/CPU controls.

## Repository layout

```text
crates/
  agent-sandbox-protocol/  Versioned protocol DTOs and stable errors
  agent-sandbox-core/      Policy validation and native backend
  agent-sandboxd/          JSONL supervisor executable
packages/node/
  src/                     Framework-neutral Node.js client
  test/                    Fake-daemon and real Windows conformance tests
schema/                    Published JSON Schema
```

The Rust crates and Node SDK contain no Pisper, Pi Coding Agent, model-provider, chat, or UI concepts.

## Build and test

Requirements:

- Rust 1.90 or newer
- Node.js 20 or newer
- Windows 10/11 for the real AppContainer suite

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
npm test
```

`npm test` always runs the protocol/client tests. The real Windows tests run when `target/debug/agent-sandboxd.exe` exists; otherwise they are explicitly skipped. They verify:

- AppContainer command execution and output streaming;
- denial of an unmounted sibling file;
- removal of a sensitive host environment variable;
- normal ACL/profile cleanup;
- journal recovery after the daemon is forcibly terminated.

Probe a build:

```bash
agent-sandboxd probe --json
```

Run child protocol mode:

```bash
agent-sandboxd child --parent-pid <pid>
```

Applications should normally let the SDK start child mode rather than invoking it directly.

## Node SDK example

```js
import { AgentSandboxClient } from '@agent-sandbox/client'

const client = await AgentSandboxClient.spawn({
  executable: 'C:\\absolute\\verified\\agent-sandboxd.exe',
  expectedSha256: 'optional-release-digest',
  client: { name: 'example-agent', version: '1.0.0' },
})

const report = await client.probe()
if (report.status === 'unavailable') throw new Error(report.reasons.join('; '))

const sandbox = await client.createSandbox({
  tenantId: 'local-user',
  profile: 'system-minimal',
  authorizationId: 'user-grant-123',
  policy: {
    schemaVersion: 1,
    backend: 'native',
    filesystem: {
      mounts: [
        {
          name: 'workspace',
          source: 'C:\\code\\project',
          access: 'read-write',
        },
        {
          name: 'host-toolchain',
          source: 'C:\\verified-toolchain',
          access: 'read-only',
        },
      ],
      protectedRoots: [],
      tempBytes: 64 * 1024 * 1024,
    },
    network: { mode: 'deny' },
    environment: { inherit: [], allowSet: ['CI'] },
    execution: {
      executables: [
        {
          alias: 'host-shell',
          path: 'C:\\verified-toolchain\\host-shell.exe',
          sha256: verifiedShellSha256,
        },
      ],
    },
    limits: {
      wallTimeMs: 60_000,
      cpuTimeMs: 45_000,
      memoryBytes: 512 * 1024 * 1024,
      processes: 32,
      outputBytes: 8 * 1024 * 1024,
    },
  },
})

const result = await sandbox.exec({
  command: { kind: 'exec', program: 'host-shell', args: ['-c', 'echo sandboxed'] },
  cwd: { mount: 'workspace', path: '.' },
  env: { CI: '1' },
  onOutput({ stream, bytes }) {
    process[stream === 'stdout' ? 'stdout' : 'stderr'].write(bytes)
  },
})

await sandbox.close()
await client.close()
```

The SDK requires an absolute daemon path and can verify a SHA-256 digest. It filters credential-like variables from the daemon environment by default. The runtime independently constructs a minimal child environment.

## Policy notes

- A policy must contain one to sixteen directory mounts.
- Mount sources must be absolute, existing directories and cannot overlap a declared protected root.
- Mount-source path components cannot be symbolic links or Windows reparse points.
- `filesystem.lease.mode: persistent` enrolls empty read-write managed directories under a stable `tenantId` and `authorizationId`; non-empty read-only toolchain mounts are allowed and can be upgraded without walking the workspace.
- Persistent enrollment is intentionally rejected for a non-empty unregistered read-write directory. Hosts must enroll before cloning or creating project files.
- Execution cwd is a logical mount plus a relative path; absolute paths and `..` are rejected.
- `execution.executables` binds a host-selected alias to a canonical executable inside a read-only mount and pins its SHA-256 digest.
- `exec.program` references an executable alias. The runtime validates and resolves that declaration; it does not discover host tools from `PATH`.
- `shell` remains the backend's minimal default shell for compatibility. Host integrations should prefer explicit executable aliases.
- Sensitive keys such as API keys, tokens, passwords, private keys, loader injection variables, and cloud credentials cannot be inherited or set.
- Output, stdin chunks, scripts, identifiers, and control messages have hard size limits.
- `restrictPolicy()` computes monotonic policy intersections for host adapters; the daemon still validates the resulting policy.

The names `node-default`, `python-default`, and `rust-default` are reserved trusted profile IDs in protocol v1. Hosts own toolchain selection; the runtime only validates explicit executable declarations and projects their read-only mounts.

## Protocol

Protocol v1 uses UTF-8 JSON Lines over child stdin/stdout. Binary process data is Base64 encoded. The first message is `hello`; the daemon echoes a 256-bit nonce and negotiates the protocol minor version. Security-sensitive structs reject unknown fields.

See [`schema/protocol-v1.schema.json`](schema/protocol-v1.schema.json) for the public message and policy schema.

Stable error families include:

- `SANDBOX_POLICY_INVALID`
- `SANDBOX_CAPABILITY_UNAVAILABLE`
- `SANDBOX_BACKEND_UNAVAILABLE`
- `SANDBOX_PROCESS_FAILED`
- `SANDBOX_PROTOCOL_ERROR`
- `SANDBOX_INTERNAL_ERROR`

## Integration responsibilities

A host application remains responsible for:

- deciding which user/admin source is allowed to grant mounts or network;
- intersecting untrusted project/task restrictions with that grant;
- mapping its own execution modes to sandboxed or explicitly bypassed execution;
- routing every relevant process entry point through the runtime;
- reporting partial coverage rather than claiming the entire agent is isolated;
- closing sandbox handles before closing the global client.

A host must never catch a sandbox failure and silently run the same command on the host.

## Known limitations

- Linux and macOS native isolation are not implemented yet.
- Windows process-count enforcement and absolute CPU-time accounting are incomplete, so the backend reports `limited`.
- Filesystem RPC, PTY, network broker/allowlists, and remote/VM backends are not implemented.
- Ephemeral Windows ACL projection validates the complete mount tree, so very large existing workspaces have proportional first-use cost. Managed persistent workspaces avoid that scan after empty-directory enrollment.
- Persistent authorization assumes the host controls enrollment and subsequent imports. A host must not relabel an arbitrary non-empty directory as managed.
- Parent-PID identity supervision is represented in the CLI but direct parent-handle death monitoring is not complete yet.

## License

MIT. See [`LICENSE`](LICENSE).
