import assert from 'node:assert/strict'
import { access, mkdir, readdir, rm } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import test from 'node:test'

import { AgentSandboxClient } from '../src/index.mjs'

const daemon = resolve('target/debug/agent-sandboxd.exe')
const stateDirectory = resolve('target/native-recovery-state')
const workspace = resolve('target/native-recovery-workspace')

async function exists(path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

const recoveryPolicy = {
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
    wallTimeMs: 10_000,
    cpuTimeMs: 5_000,
    memoryBytes: 128 * 1024 * 1024,
    processes: 8,
    outputBytes: 1024 * 1024,
  },
}

test('Windows native daemon recovers ACL journals after abrupt client death', async (t) => {
  if (process.platform !== 'win32' || !(await exists(daemon))) {
    t.skip('requires a locally built Windows agent-sandboxd')
    return
  }

  await mkdir(workspace, { recursive: true })
  await mkdir(stateDirectory, { recursive: true })
  for (const entry of await readdir(stateDirectory)) {
    await rm(join(stateDirectory, entry), { force: true })
  }

  const env = { ...process.env, AGENT_SANDBOX_STATE_DIR: stateDirectory }
  const abandoned = await AgentSandboxClient.spawn({
    executable: daemon,
    env,
    client: { name: 'recovery-test', version: '0.1.0' },
  })
  await abandoned.createSandbox({
    tenantId: 'recovery-tenant',
    profile: 'system-minimal',
    authorizationId: 'recovery-authorization',
    policy: recoveryPolicy,
  })
  assert.equal((await readdir(stateDirectory)).length, 1)

  abandoned.child.kill()
  await abandoned.closePromise

  const recovered = await AgentSandboxClient.spawn({
    executable: daemon,
    env,
    client: { name: 'recovery-probe', version: '0.1.0' },
  })
  try {
    assert.equal((await readdir(stateDirectory)).length, 0)
  } finally {
    await recovered.close()
    await rm(workspace, { recursive: true, force: true })
  }
})
