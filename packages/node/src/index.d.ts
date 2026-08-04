export type EnforcementStatus = 'enforced' | 'limited' | 'unavailable' | 'bypassed'
export type FeatureState = 'enforced' | 'limited' | 'unavailable'

export interface CapabilityReport {
  platform: string
  backend: string
  status: EnforcementStatus
  features: Record<string, FeatureState>
  reasons: string[]
}

export interface SandboxPolicy {
  schemaVersion: 1
  backend?: 'auto' | 'native'
  filesystem: {
    mounts: Array<{
      name: string
      source: string
      access: 'read-only' | 'read-write'
    }>
    protectedRoots?: string[]
    tempBytes?: number
    lease?: { mode: 'ephemeral' | 'persistent' }
  }
  network?: { mode: 'deny' | 'host' }
  environment?: { inherit?: string[]; allowSet?: string[] }
  limits?: {
    wallTimeMs?: number
    cpuTimeMs?: number
    memoryBytes?: number
    processes?: number
    outputBytes?: number
  }
}

export interface OutputChunk {
  stream: 'stdout' | 'stderr'
  bytes: Buffer
  sequence: number
}

export interface ExecutionResult {
  exitCode: number | null
  signal: string | null
  usage: Readonly<Record<string, number>>
}

export interface SpawnInput {
  command:
    | { kind: 'exec'; program: string; args?: string[] }
    | { kind: 'shell'; shell?: 'default'; script: string }
  cwd: { mount: string; path: string }
  env?: Record<string, string>
  stdin?: 'pipe' | 'closed'
  limits?: Partial<NonNullable<SandboxPolicy['limits']>>
  onOutput?: (chunk: OutputChunk) => void
}

export interface ExecInput extends SpawnInput {
  signal?: AbortSignal
}

export interface ClientOptions {
  executable: string
  arguments?: string[]
  cwd?: string
  env?: NodeJS.ProcessEnv
  expectedProtocolMajor?: number
  expectedSha256?: string
  requestTimeoutMs?: number
  client?: { name: string; version: string }
  onDiagnostic?: (message: string) => void
}

export class AgentSandboxError extends Error {
  code: string
  category: string
  retryable: boolean
  details: Record<string, string>
}

export class SandboxProcess {
  readonly executionId: string
  readonly started: Promise<SandboxProcess>
  readonly done: Promise<ExecutionResult>
  onOutput(listener: (chunk: OutputChunk) => void): () => void
  write(bytes: Uint8Array | string): void
  closeStdin(): void
  terminate(): void
  kill(): void
}

export class SandboxHandle {
  readonly id: string
  readonly status: EnforcementStatus
  readonly mounts: Readonly<Record<string, string>>
  readonly policyFingerprint: string
  readonly capabilities: CapabilityReport
  spawn(input: SpawnInput): Promise<SandboxProcess>
  exec(input: ExecInput): Promise<ExecutionResult>
  close(): Promise<void>
}

export class AgentSandboxClient {
  static spawn(options: ClientOptions): Promise<AgentSandboxClient>
  readonly runtime: {
    protocol: Readonly<{ major: number; minor: number }>
    runtimeVersion: string
    platform: string
    features: readonly string[]
  }
  probe(): Promise<CapabilityReport>
  createSandbox(input: {
    tenantId: string
    profile: string
    authorizationId: string
    policy: SandboxPolicy
    metadata?: { subject?: string; subjectId?: string }
  }): Promise<SandboxHandle>
  revokeAuthorization(input: {
    tenantId: string
    authorizationId: string
  }): Promise<Readonly<{ authorizationId: string }>>
  close(): Promise<unknown>
}

export function restrictPolicy(
  grant: SandboxPolicy,
  ...restrictions: Array<
    | Partial<SandboxPolicy>
    | { source: string; policy: Partial<SandboxPolicy> }
    | null
    | undefined
  >
): {
  readonly policy: SandboxPolicy
  readonly provenance: ReadonlyArray<{ field: string; source: string }>
}
