import assert from 'node:assert/strict'
import { access, mkdir, readFile, rm } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import { resolve } from 'node:path'
import test from 'node:test'

import { AgentSandboxClient } from '../src/index.mjs'

const daemon = resolve('target/debug/agent-sandboxd.exe')
const root = resolve('target/native-persistent-test')
const workspace = resolve(root, 'workspace')
const stateDirectory = resolve(root, 'state')

async function exists(path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

function request(authorizationId) {
  return {
    tenantId: 'persistent-tenant',
    profile: 'system-minimal',
    authorizationId,
    policy: {
      schemaVersion: 1,
      backend: 'native',
      filesystem: {
        mounts: [{ name: 'workspace', source: workspace, access: 'read-write' }],
        protectedRoots: [],
        tempBytes: 64 * 1024 * 1024,
        lease: { mode: 'persistent' },
      },
      network: { mode: 'deny' },
      environment: { inherit: [], allowSet: [] },
      limits: {
        wallTimeMs: 10_000,
        cpuTimeMs: 5_000,
        memoryBytes: 128 * 1024 * 1024,
        processes: 8,
        outputBytes: 1024 * 1024,
      },
    },
  }
}

async function client() {
  return AgentSandboxClient.spawn({
    executable: daemon,
    env: { ...process.env, AGENT_SANDBOX_STATE_DIR: stateDirectory },
    client: { name: 'persistent-test', version: '0.1.0' },
  })
}

test('Windows persistent workspace authorization survives daemon restart', async (t) => {
  if (process.platform !== 'win32' || !(await exists(daemon))) {
    t.skip('requires a locally built Windows agent-sandboxd')
    return
  }

  await rm(root, { recursive: true, force: true })
  await mkdir(workspace, { recursive: true })
  await mkdir(stateDirectory, { recursive: true })

  let runtime = await client()
  try {
    const sandbox = await runtime.createSandbox(request('workspace-one'))
    const result = await sandbox.exec({
      command: { kind: 'shell', shell: 'default', script: 'echo persistent>created.txt' },
      cwd: { mount: 'workspace', path: '.' },
      env: {},
    })
    assert.equal(result.exitCode, 0)
    await sandbox.close()
  } finally {
    await runtime.close()
  }
  assert.match(await readFile(resolve(workspace, 'created.txt'), 'utf8'), /persistent/)

  runtime = await client()
  try {
    const started = performance.now()
    const sandbox = await runtime.createSandbox(request('workspace-one'))
    const elapsedMs = performance.now() - started
    assert.ok(elapsedMs < 1_000, `persistent sandbox initialization took ${elapsedMs} ms`)
    await sandbox.close()
    await assert.rejects(
      runtime.createSandbox(request('workspace-two')),
      /empty managed directory/i,
    )
    assert.deepEqual(
      await runtime.revokeAuthorization({
        tenantId: 'persistent-tenant',
        authorizationId: 'workspace-one',
      }),
      { authorizationId: 'workspace-one' },
    )
    await assert.rejects(
      runtime.createSandbox(request('workspace-one')),
      /empty managed directory/i,
    )
  } finally {
    await runtime.close()
    await rm(root, { recursive: true, force: true })
  }
})
