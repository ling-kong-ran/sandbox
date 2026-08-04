import assert from 'node:assert/strict'
import { access, link, mkdir, rm, symlink, writeFile } from 'node:fs/promises'
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

function sandboxRequest(workspacePath, authorizationId) {
  return {
    tenantId: 'hardlink-tenant',
    profile: 'system-minimal',
    authorizationId,
    policy: {
      schemaVersion: 1,
      backend: 'native',
      filesystem: {
        mounts: [{ name: 'workspace', source: workspacePath, access: 'read-write' }],
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
      client.createSandbox(sandboxRequest(workspace, 'hardlink-authorization')),
      (error) => error.code === 'SANDBOX_CAPABILITY_UNAVAILABLE',
    )
  } finally {
    await client.close()
    await rm(root, { recursive: true, force: true })
  }
})

test('Windows native backend allows hard links and junctions contained by the mount', async (t) => {
  if (process.platform !== 'win32' || !(await exists(daemon))) {
    t.skip('requires a locally built Windows agent-sandboxd')
    return
  }

  const localRoot = resolve('target/native-contained-alias-test')
  const localWorkspace = resolve(localRoot, 'workspace')
  const localState = resolve(localRoot, 'state')
  const target = resolve(localWorkspace, 'target')
  await rm(localRoot, { recursive: true, force: true })
  await mkdir(target, { recursive: true })
  await mkdir(localState, { recursive: true })
  await writeFile(resolve(target, 'content.txt'), 'contained')
  await link(resolve(target, 'content.txt'), resolve(localWorkspace, 'alias.txt'))
  await symlink(target, resolve(localWorkspace, 'junction'), 'junction')

  const client = await AgentSandboxClient.spawn({
    executable: daemon,
    env: { ...process.env, AGENT_SANDBOX_STATE_DIR: localState },
    client: { name: 'contained-alias-test', version: '0.1.0' },
  })
  try {
    const sandbox = await client.createSandbox(
      sandboxRequest(localWorkspace, 'contained-alias-authorization'),
    )
    assert.equal(sandbox.status, 'limited')
    await sandbox.close()
  } finally {
    await client.close()
    await rm(localRoot, { recursive: true, force: true })
  }
})

test('Windows native backend rejects junction targets outside the mount', async (t) => {
  if (process.platform !== 'win32' || !(await exists(daemon))) {
    t.skip('requires a locally built Windows agent-sandboxd')
    return
  }

  const localRoot = resolve('target/native-external-junction-test')
  const localWorkspace = resolve(localRoot, 'workspace')
  const localState = resolve(localRoot, 'state')
  const outside = resolve(localRoot, 'outside')
  await rm(localRoot, { recursive: true, force: true })
  await mkdir(localWorkspace, { recursive: true })
  await mkdir(localState, { recursive: true })
  await mkdir(outside, { recursive: true })
  await symlink(outside, resolve(localWorkspace, 'junction'), 'junction')

  const client = await AgentSandboxClient.spawn({
    executable: daemon,
    env: { ...process.env, AGENT_SANDBOX_STATE_DIR: localState },
    client: { name: 'external-junction-test', version: '0.1.0' },
  })
  try {
    await assert.rejects(
      client.createSandbox(sandboxRequest(localWorkspace, 'external-junction-authorization')),
      (error) => error.code === 'SANDBOX_CAPABILITY_UNAVAILABLE',
    )
  } finally {
    await client.close()
    await rm(localRoot, { recursive: true, force: true })
  }
})
