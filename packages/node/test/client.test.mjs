import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import {
  AgentSandboxClient,
  AgentSandboxError,
  restrictPolicy,
} from '../src/index.mjs'

const fixture = fileURLToPath(new URL('./fixtures/fake-daemon.mjs', import.meta.url))

async function createClient() {
  return AgentSandboxClient.spawn({
    executable: process.execPath,
    arguments: [fixture],
    client: { name: 'node-client-test', version: '1.0.0' },
  })
}

function policy() {
  return {
    schemaVersion: 1,
    backend: 'native',
    filesystem: {
      mounts: [{ name: 'workspace', source: process.cwd(), access: 'read-write' }],
      protectedRoots: [],
      tempBytes: 1024 * 1024,
    },
    network: { mode: 'deny' },
    environment: { inherit: [], allowSet: ['CI'] },
    limits: {
      wallTimeMs: 10_000,
      cpuTimeMs: 8_000,
      memoryBytes: 256 * 1024 * 1024,
      processes: 16,
      outputBytes: 1024 * 1024,
    },
  }
}

test('client handshakes, probes, executes, streams output, and closes', async () => {
  const client = await createClient()
  try {
    assert.equal(client.runtime.protocol.major, 1)
    const report = await client.probe()
    assert.equal(report.status, 'enforced')
    assert.ok(Object.isFrozen(report))

    const sandbox = await client.createSandbox({
      tenantId: 'tenant-a',
      profile: 'node-default',
      authorizationId: 'grant-a',
      policy: policy(),
    })
    assert.equal(sandbox.mounts.workspace, '/workspace')
    assert.ok(Object.isFrozen(sandbox.mounts))

    const output = []
    const result = await sandbox.exec({
      command: { kind: 'shell', shell: 'default', script: 'printf test' },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: (chunk) => output.push(chunk.bytes.toString('utf8')),
    })
    assert.equal(result.exitCode, 0)
    assert.deepEqual(output, ['sandbox output\n'])
    await sandbox.close()
  } finally {
    await client.close()
  }
})

test('protocol errors retain stable code and category', async () => {
  const client = await createClient()
  try {
    await assert.rejects(
      client.createSandbox({
        tenantId: 'reject',
        profile: 'node-default',
        authorizationId: 'grant-a',
        policy: policy(),
      }),
      (error) =>
        error instanceof AgentSandboxError &&
        error.code === 'SANDBOX_POLICY_INVALID' &&
        error.category === 'policy_violation',
    )
  } finally {
    await client.close()
  }
})

test('policy restrictions are monotonic and preserve provenance', () => {
  const result = restrictPolicy(policy(), {
    source: 'project',
    policy: {
      filesystem: {
        mounts: [
          { name: 'workspace', source: process.cwd(), access: 'read-only' },
        ],
      },
      network: { mode: 'deny' },
      environment: { inherit: [], allowSet: [] },
      limits: { memoryBytes: 128 * 1024 * 1024 },
    },
  })
  assert.equal(result.policy.filesystem.mounts[0].access, 'read-only')
  assert.equal(result.policy.limits.memoryBytes, 128 * 1024 * 1024)
  assert.deepEqual(result.policy.environment.allowSet, [])
  assert.ok(result.provenance.some((entry) => entry.source === 'project'))
  assert.ok(Object.isFrozen(result))
})
