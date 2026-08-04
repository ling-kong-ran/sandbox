import assert from 'node:assert/strict'
import { access, link, mkdir, rm, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import test from 'node:test'

import { AgentSandboxClient } from '../src/index.mjs'

const daemon = resolve('target/debug/agent-sandboxd.exe')
const root = resolve('target/native-hardlink-test')
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

test('Windows native backend rejects pre-existing hard-link aliases', async (t) => {
  if (process.platform !== 'win32' || !(await exists(daemon))) {
    t.skip('requires a locally built Windows agent-sandboxd')
    return
  }

  await rm(root, { recursive: true, force: true })
  await mkdir(workspace, { recursive: true })
  await mkdir(stateDirectory, { recursive: true })
  const outside = resolve(root, 'outside.txt')
  await writeFile(outside, 'outside')
  await link(outside, resolve(workspace, 'alias.txt'))

  const client = await AgentSandboxClient.spawn({
    executable: daemon,
    env: { ...process.env, AGENT_SANDBOX_STATE_DIR: stateDirectory },
    client: { name: 'hardlink-test', version: '0.1.0' },
  })
  try {
    await assert.rejects(
      client.createSandbox({
        tenantId: 'hardlink-tenant',
        profile: 'system-minimal',
        authorizationId: 'hardlink-authorization',
        policy: {
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
        },
      }),
      (error) => error.code === 'SANDBOX_CAPABILITY_UNAVAILABLE',
    )
  } finally {
    await client.close()
    await rm(root, { recursive: true, force: true })
  }
})
