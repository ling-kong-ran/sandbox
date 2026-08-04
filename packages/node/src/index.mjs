import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { isAbsolute } from 'node:path'
import { spawn as spawnChild } from 'node:child_process'

const PROTOCOL_MAJOR = 1
const PROTOCOL_MINOR = 0
const MAX_LINE_BYTES = 1024 * 1024
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000

export class AgentSandboxError extends Error {
  constructor(message, options = {}) {
    super(message, options)
    this.name = 'AgentSandboxError'
    this.code = options.code || 'SANDBOX_CLIENT_ERROR'
    this.category = options.category || 'internal'
    this.retryable = Boolean(options.retryable)
    this.details = options.details || {}
  }

  static fromProtocol(error) {
    return new AgentSandboxError(error?.message || 'Sandbox request failed', {
      code: error?.code,
      category: error?.category,
      retryable: error?.retryable,
      details: error?.details,
    })
  }
}

export class AgentSandboxClient {
  static async spawn(options) {
    const executable = String(options?.executable || '')
    if (!isAbsolute(executable)) {
      throw new AgentSandboxError('Sandbox executable path must be absolute', {
        code: 'SANDBOX_EXECUTABLE_INVALID',
      })
    }
    if (options.expectedSha256) {
      const contents = await readFile(executable)
      const actual = createHash('sha256').update(contents).digest('hex')
      if (actual.toLowerCase() !== String(options.expectedSha256).toLowerCase()) {
        throw new AgentSandboxError('Sandbox executable digest does not match', {
          code: 'SANDBOX_EXECUTABLE_DIGEST_MISMATCH',
        })
      }
    }
    const expectedProtocolMajor = options.expectedProtocolMajor ?? PROTOCOL_MAJOR
    const child = spawnChild(
      executable,
      [
        ...(options.arguments || []),
        'child',
        '--parent-pid',
        String(process.pid),
      ],
      {
        cwd: options.cwd,
        env: options.env || daemonEnvironment(process.env),
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      },
    )
    const client = new AgentSandboxClient(child, {
      expectedProtocolMajor,
      requestTimeoutMs: options.requestTimeoutMs,
      onDiagnostic: options.onDiagnostic,
    })
    await client.#handshake({
      name: options.client?.name || 'agent-sandbox-node',
      version: options.client?.version || '0.1.0',
    })
    return client
  }

  constructor(child, options = {}) {
    this.child = child
    this.expectedProtocolMajor = options.expectedProtocolMajor ?? PROTOCOL_MAJOR
    this.requestTimeoutMs = options.requestTimeoutMs || DEFAULT_REQUEST_TIMEOUT_MS
    this.onDiagnostic = options.onDiagnostic
    this.pending = new Map()
    this.executions = new Map()
    this.sandboxes = new Set()
    this.buffer = Buffer.alloc(0)
    this.closed = false
    this.hello = deferred()
    this.closePromise = new Promise((resolve) => {
      child.once('close', (code, signal) => {
        this.closed = true
        this.#failAll(
          new AgentSandboxError(`Sandbox daemon exited (code=${code}, signal=${signal})`, {
            code: 'SANDBOX_DAEMON_EXITED',
            retryable: true,
          }),
        )
        resolve({ code, signal })
      })
    })
    child.once('error', (error) => {
      this.#failAll(
        new AgentSandboxError(`Failed to launch sandbox daemon: ${error.message}`, {
          code: 'SANDBOX_DAEMON_LAUNCH_FAILED',
          cause: error,
          retryable: true,
        }),
      )
    })
    child.stdout.on('data', (chunk) => this.#acceptData(chunk))
    child.stderr.on('data', (chunk) => this.onDiagnostic?.(Buffer.from(chunk).toString('utf8')))
  }

  async #handshake(client) {
    const nonce = randomBytes(32).toString('hex')
    this.#write({
      type: 'hello',
      protocol: { major: this.expectedProtocolMajor, minor: PROTOCOL_MINOR },
      client,
      nonce,
    })
    const message = await withTimeout(
      this.hello.promise,
      this.requestTimeoutMs,
      'Sandbox handshake timed out',
    )
    if (message.nonce !== nonce || message.protocol?.major !== this.expectedProtocolMajor) {
      await this.close().catch(() => {})
      throw new AgentSandboxError('Sandbox handshake validation failed', {
        code: 'SANDBOX_PROTOCOL_VERSION_MISMATCH',
      })
    }
    this.runtime = {
      protocol: Object.freeze({ ...message.protocol }),
      runtimeVersion: message.runtimeVersion,
      platform: message.platform,
      features: Object.freeze([...(message.features || [])]),
    }
  }

  async probe() {
    const message = await this.#request({ type: 'probe' }, 'probeResult')
    return deepFreeze(message.report)
  }

  async createSandbox(input) {
    const message = await this.#request(
      {
        type: 'createSandbox',
        tenantId: input.tenantId,
        profile: input.profile,
        authorizationId: input.authorizationId,
        policy: input.policy,
        metadata: input.metadata || {},
      },
      'sandboxCreated',
    )
    const sandbox = new SandboxHandle(this, message)
    this.sandboxes.add(sandbox)
    return sandbox
  }

  async revokeAuthorization({ tenantId, authorizationId }) {
    const message = await this.#request(
      { type: 'revokeAuthorization', tenantId, authorizationId },
      'authorizationRevoked',
    )
    return deepFreeze({ authorizationId: message.authorizationId })
  }

  async close() {
    if (this.closed) return this.closePromise
    const sandboxes = [...this.sandboxes]
    await Promise.allSettled(sandboxes.map((sandbox) => sandbox.close()))
    try {
      await this.#request({ type: 'shutdown' }, 'shutdownAck')
    } catch {
      this.child.kill()
    }
    this.child.stdin.end()
    return withTimeout(this.closePromise, 5_000, 'Sandbox daemon did not exit')
  }

  async _spawn(sandboxId, input) {
    if (this.closed) throw daemonClosedError()
    if (!['exec', 'shell'].includes(input?.command?.kind)) {
      throw new AgentSandboxError('Sandbox command kind must be exec or shell', {
        code: 'SANDBOX_PROTOCOL_INVALID_MESSAGE',
        category: 'protocol',
      })
    }
    const executionId = randomUUID()
    const process = new SandboxProcess(this, executionId)
    if (input.onOutput) process.onOutput(input.onOutput)
    this.executions.set(executionId, process)
    const requestId = randomUUID()
    process.requestId = requestId
    this.#write({
      type: 'spawn',
      requestId,
      sandboxId,
      executionId,
      command: input.command,
      cwd: input.cwd,
      env: input.env || {},
      stdin: input.stdin || 'closed',
      limits: input.limits || {},
    })
    try {
      await withTimeout(
        process.started,
        this.requestTimeoutMs,
        'Sandbox execution did not start',
      )
      return process
    } catch (error) {
      this.executions.delete(executionId)
      throw error
    }
  }

  _writeExecution(message) {
    this.#write(message)
  }

  async _closeSandbox(sandbox, sandboxId) {
    await this.#request({ type: 'closeSandbox', sandboxId }, 'sandboxClosed')
    this.sandboxes.delete(sandbox)
  }

  #request(message, expectedType) {
    if (this.closed) return Promise.reject(daemonClosedError())
    const requestId = randomUUID()
    const pending = deferred()
    const timer = setTimeout(() => {
      this.pending.delete(requestId)
      pending.reject(
        new AgentSandboxError(`Sandbox ${message.type} request timed out`, {
          code: 'SANDBOX_REQUEST_TIMEOUT',
          retryable: true,
        }),
      )
    }, this.requestTimeoutMs)
    this.pending.set(requestId, { ...pending, expectedType, timer })
    try {
      this.#write({ ...message, requestId })
    } catch (error) {
      clearTimeout(timer)
      this.pending.delete(requestId)
      pending.reject(error)
    }
    return pending.promise
  }

  #write(message) {
    if (this.closed || !this.child.stdin.writable) throw daemonClosedError()
    const line = `${JSON.stringify(message)}\n`
    if (Buffer.byteLength(line) > MAX_LINE_BYTES) {
      throw new AgentSandboxError('Sandbox control message exceeds 1 MiB', {
        code: 'SANDBOX_PROTOCOL_MESSAGE_TOO_LARGE',
      })
    }
    this.child.stdin.write(line)
  }

  #acceptData(chunk) {
    this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)])
    if (this.buffer.length > MAX_LINE_BYTES && this.buffer.indexOf(0x0a) < 0) {
      this.child.kill()
      this.#failAll(
        new AgentSandboxError('Sandbox daemon emitted an oversized message', {
          code: 'SANDBOX_PROTOCOL_MESSAGE_TOO_LARGE',
        }),
      )
      return
    }
    let newline
    while ((newline = this.buffer.indexOf(0x0a)) >= 0) {
      const line = this.buffer.subarray(0, newline)
      this.buffer = this.buffer.subarray(newline + 1)
      if (line.length > MAX_LINE_BYTES) {
        this.child.kill()
        this.#failAll(
          new AgentSandboxError('Sandbox daemon emitted an oversized message', {
            code: 'SANDBOX_PROTOCOL_MESSAGE_TOO_LARGE',
          }),
        )
        return
      }
      try {
        this.#dispatch(JSON.parse(line.toString('utf8')))
      } catch (error) {
        this.child.kill()
        this.#failAll(
          new AgentSandboxError(`Invalid sandbox daemon message: ${error.message}`, {
            code: 'SANDBOX_PROTOCOL_INVALID_MESSAGE',
            cause: error,
          }),
        )
        return
      }
    }
  }

  #dispatch(message) {
    if (message.type === 'helloAck') {
      this.hello.resolve(message)
      return
    }
    if (message.type === 'error') {
      const error = AgentSandboxError.fromProtocol(message.error)
      if (message.requestId && this.pending.has(message.requestId)) {
        this.#settlePending(message.requestId, null, error)
      }
      if (message.executionId && this.executions.has(message.executionId)) {
        this.executions.get(message.executionId)._error(error)
      }
      if (!message.requestId && !message.executionId) this.onDiagnostic?.(error.message)
      return
    }
    if (message.requestId && this.pending.has(message.requestId)) {
      this.#settlePending(message.requestId, message)
    }
    if (message.executionId && this.executions.has(message.executionId)) {
      const process = this.executions.get(message.executionId)
      process._event(message)
      if (message.type === 'exit') this.executions.delete(message.executionId)
    }
  }

  #settlePending(requestId, message, error) {
    const pending = this.pending.get(requestId)
    if (!pending) return
    clearTimeout(pending.timer)
    this.pending.delete(requestId)
    if (error) {
      pending.reject(error)
      return
    }
    if (message.type !== pending.expectedType) {
      pending.reject(
        new AgentSandboxError(
          `Expected ${pending.expectedType} response, received ${message.type}`,
          { code: 'SANDBOX_PROTOCOL_UNEXPECTED_MESSAGE' },
        ),
      )
      return
    }
    pending.resolve(message)
  }

  #failAll(error) {
    this.hello.reject(error)
    for (const [requestId, pending] of this.pending) {
      clearTimeout(pending.timer)
      pending.reject(error)
      this.pending.delete(requestId)
    }
    for (const process of this.executions.values()) process._error(error)
    this.executions.clear()
  }
}

export class SandboxHandle {
  constructor(client, message) {
    this.client = client
    this.id = message.sandboxId
    this.status = message.status
    this.mounts = deepFreeze({ ...message.mounts })
    this.policyFingerprint = message.policyFingerprint
    this.capabilities = deepFreeze(message.capabilities)
    this.closed = false
    Object.defineProperties(this, {
      id: { writable: false },
      status: { writable: false },
      mounts: { writable: false },
      policyFingerprint: { writable: false },
      capabilities: { writable: false },
    })
  }

  async spawn(input) {
    if (this.closed) throw new AgentSandboxError('Sandbox is closed', { code: 'SANDBOX_CLOSED' })
    return this.client._spawn(this.id, input)
  }

  async exec(input) {
    const process = await this.spawn({ ...input, stdin: 'closed' })
    const abort = () => process.terminate()
    if (input.signal?.aborted) abort()
    input.signal?.addEventListener('abort', abort, { once: true })
    try {
      return await process.done
    } finally {
      input.signal?.removeEventListener('abort', abort)
    }
  }

  async close() {
    if (this.closed) return
    this.closed = true
    await this.client._closeSandbox(this, this.id)
  }
}

export class SandboxProcess {
  constructor(client, executionId) {
    this.client = client
    this.executionId = executionId
    this.inputSequence = 1
    this.outputSequence = 1
    this.outputListeners = new Set()
    this.startDeferred = deferred()
    this.doneDeferred = deferred()
    this.started = this.startDeferred.promise
    this.done = this.doneDeferred.promise
    this.started.catch(() => {})
    this.done.catch(() => {})
  }

  onOutput(listener) {
    this.outputListeners.add(listener)
    return () => this.outputListeners.delete(listener)
  }

  write(bytes) {
    const buffer = Buffer.from(bytes)
    if (buffer.length > 64 * 1024) {
      throw new AgentSandboxError('Sandbox stdin chunks cannot exceed 64 KiB', {
        code: 'SANDBOX_STDIN_CHUNK_TOO_LARGE',
      })
    }
    this.client._writeExecution({
      type: 'stdin',
      executionId: this.executionId,
      sequence: this.inputSequence++,
      base64: buffer.toString('base64'),
    })
  }

  closeStdin() {
    this.client._writeExecution({ type: 'closeStdin', executionId: this.executionId })
  }

  terminate() {
    this.client._writeExecution({
      type: 'signal',
      executionId: this.executionId,
      signal: 'terminate',
    })
  }

  kill() {
    this.client._writeExecution({
      type: 'signal',
      executionId: this.executionId,
      signal: 'kill',
    })
  }

  _event(message) {
    if (message.type === 'started') {
      this.startDeferred.resolve(this)
      return
    }
    if (message.type === 'output') {
      if (message.sequence !== this.outputSequence++) {
        this._error(
          new AgentSandboxError('Sandbox output sequence mismatch', {
            code: 'SANDBOX_PROTOCOL_SEQUENCE_MISMATCH',
          }),
        )
        this.kill()
        return
      }
      const chunk = {
        stream: message.stream,
        bytes: Buffer.from(message.base64, 'base64'),
        sequence: message.sequence,
      }
      for (const listener of this.outputListeners) listener(chunk)
      return
    }
    if (message.type === 'exit') {
      this.doneDeferred.resolve({
        exitCode: message.code,
        signal: message.signal,
        usage: deepFreeze(message.usage || {}),
      })
    }
  }

  _error(error) {
    this.startDeferred.reject(error)
    this.doneDeferred.reject(error)
  }
}

export function restrictPolicy(grant, ...restrictions) {
  let policy = structuredClone(grant)
  const provenance = []
  for (const [index, restriction] of restrictions.entries()) {
    if (!restriction) continue
    const source = restriction.source || `restriction-${index + 1}`
    const value = restriction.policy || restriction
    if (value.filesystem?.mounts) {
      const allowed = new Map(value.filesystem.mounts.map((mount) => [mount.name, mount]))
      policy.filesystem.mounts = policy.filesystem.mounts
        .filter((mount) => allowed.has(mount.name))
        .map((mount) => intersectMount(mount, allowed.get(mount.name)))
      provenance.push({ field: 'filesystem.mounts', source })
    }
    if (value.filesystem?.protectedRoots) {
      policy.filesystem.protectedRoots = [
        ...new Set([
          ...(policy.filesystem.protectedRoots || []),
          ...value.filesystem.protectedRoots,
        ]),
      ]
      provenance.push({ field: 'filesystem.protectedRoots', source })
    }
    if (value.network?.mode) {
      policy.network.mode = stricterNetwork(policy.network.mode, value.network.mode)
      provenance.push({ field: 'network.mode', source })
    }
    for (const field of ['inherit', 'allowSet']) {
      if (value.environment?.[field]) {
        const allowed = new Set(value.environment[field])
        policy.environment[field] = policy.environment[field].filter((name) => allowed.has(name))
        provenance.push({ field: `environment.${field}`, source })
      }
    }
    for (const field of [
      'wallTimeMs',
      'cpuTimeMs',
      'memoryBytes',
      'processes',
      'outputBytes',
    ]) {
      if (value.limits?.[field] != null) {
        policy.limits[field] = Math.min(policy.limits[field], value.limits[field])
        provenance.push({ field: `limits.${field}`, source })
      }
    }
    if (value.filesystem?.tempBytes != null) {
      policy.filesystem.tempBytes = Math.min(
        policy.filesystem.tempBytes,
        value.filesystem.tempBytes,
      )
      provenance.push({ field: 'filesystem.tempBytes', source })
    }
  }
  return deepFreeze({ policy, provenance })
}

function intersectMount(grant, restriction) {
  if (grant.source !== restriction.source) {
    throw new AgentSandboxError(`Restriction changed source for mount ${grant.name}`, {
      code: 'SANDBOX_POLICY_NOT_MONOTONIC',
      category: 'policy_violation',
    })
  }
  return {
    ...grant,
    access:
      grant.access === 'read-only' || restriction.access === 'read-only'
        ? 'read-only'
        : 'read-write',
  }
}

function stricterNetwork(left, right) {
  const order = { deny: 0, host: 1 }
  if (!(left in order) || !(right in order)) {
    throw new AgentSandboxError('Unknown network policy mode', {
      code: 'SANDBOX_POLICY_INVALID',
      category: 'policy_violation',
    })
  }
  return order[left] <= order[right] ? left : right
}

function daemonEnvironment(environment) {
  const result = {}
  const denied = /(?:^|_)(?:API_?KEY|ACCESS_?TOKEN|AUTH_?TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY)$/i
  for (const [name, value] of Object.entries(environment || {})) {
    if (value == null || denied.test(name)) continue
    result[name] = value
  }
  return result
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((resolveValue, rejectValue) => {
    resolve = resolveValue
    reject = rejectValue
  })
  return { promise, resolve, reject }
}

function withTimeout(promise, timeoutMs, message) {
  let timer
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new AgentSandboxError(message, {
            code: 'SANDBOX_REQUEST_TIMEOUT',
            retryable: true,
          }),
        ),
      timeoutMs,
    )
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

function daemonClosedError() {
  return new AgentSandboxError('Sandbox daemon is closed', {
    code: 'SANDBOX_DAEMON_CLOSED',
    retryable: true,
  })
}
