import assert from 'node:assert/strict'
import { access, mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import test from 'node:test'

import { AgentSandboxClient } from '../src/index.mjs'

const daemon = resolve('target/debug/agent-sandboxd.exe')

async function daemonExists() {
  try {
    await access(daemon)
    return true
  } catch {
    return false
  }
}

function policy(workspace) {
  return {
    schemaVersion: 1,
    backend: 'native',
    filesystem: {
      mounts: [{ name: 'workspace', source: workspace, access: 'read-write' }],
      protectedRoots: [],
      tempBytes: 64 * 1024 * 1024,
    },
    network: { mode: 'deny' },
    environment: { inherit: [], allowSet: [] },
    limits: {
      wallTimeMs: 15_000,
      cpuTimeMs: 10_000,
      memoryBytes: 256 * 1024 * 1024,
      processes: 16,
      outputBytes: 1024 * 1024,
    },
  }
}

test('Windows native backend executes in AppContainer and denies unmounted files', async (t) => {
  if (process.platform !== 'win32' || !(await daemonExists())) {
    t.skip('requires a locally built Windows agent-sandboxd')
    return
  }

  const testRoot = resolve('target/native-tests')
  const stateDirectory = resolve('target/native-test-state')
  await mkdir(testRoot, { recursive: true })
  await mkdir(stateDirectory, { recursive: true })
  const root = await mkdtemp(join(testRoot, 'execution-'))
  const workspace = join(root, 'workspace')
  const secret = join(root, 'outside-secret.txt')
  await mkdir(workspace)
  await writeFile(secret, 'must-not-be-readable')

  const diagnostics = []
  const client = await AgentSandboxClient.spawn({
    executable: daemon,
    env: {
      ...process.env,
      AGENT_SANDBOX_STATE_DIR: stateDirectory,
      OPENAI_API_KEY: 'sandbox-test-secret',
    },
    client: { name: 'native-conformance-test', version: '0.1.0' },
    onDiagnostic: (message) => {
      diagnostics.push(message)
      if (process.env.RAPPCT_DEBUG_LAUNCH) process.stderr.write(message)
    },
  })

  try {
    const report = await client.probe()
    assert.equal(report.backend, 'windows-appcontainer')
    assert.equal(report.features.networkDeny, 'enforced')
    assert.equal(report.features.filesystemReadBoundary, 'enforced')

    const sandbox = await client.createSandbox({
      tenantId: 'test-tenant',
      profile: 'system-minimal',
      authorizationId: 'test-authorization',
      policy: policy(workspace),
    })

    const output = []
    const success = await sandbox.exec({
      command: { kind: 'shell', shell: 'default', script: 'echo native-ok' },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: ({ bytes }) => output.push(bytes),
    })
    const successText = Buffer.concat(output).toString('utf8')
    assert.equal(success.exitCode, 0, successText)
    assert.match(successText, /native-ok/)

    const deniedOutput = []
    const denied = await sandbox.exec({
      command: {
        kind: 'shell',
        shell: 'default',
        script: `type "${secret}"`,
      },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: ({ bytes }) => deniedOutput.push(bytes),
    })
    assert.notEqual(denied.exitCode, 0)
    assert.doesNotMatch(Buffer.concat(deniedOutput).toString('utf8'), /must-not-be-readable/)

    const environmentOutput = []
    const environmentDenied = await sandbox.exec({
      command: {
        kind: 'shell',
        shell: 'default',
        script: 'set OPENAI_API_KEY',
      },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: ({ bytes }) => environmentOutput.push(bytes),
    })
    assert.notEqual(environmentDenied.exitCode, 0)
    assert.doesNotMatch(
      Buffer.concat(environmentOutput).toString('utf8'),
      /sandbox-test-secret/,
    )

    await sandbox.close()
  } finally {
    await client.close().catch(() => {})
    await rm(root, { recursive: true, force: true })
  }

  assert.deepEqual(diagnostics, [])
})
