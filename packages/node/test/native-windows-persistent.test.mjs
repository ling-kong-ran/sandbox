import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { access, copyFile, mkdir, readFile, rm } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import { resolve } from 'node:path'
import test from 'node:test'

import { AgentSandboxClient } from '../src/index.mjs'

const daemon = resolve('target/debug/agent-sandboxd.exe')
const root = resolve('target/native-persistent-test')
const workspace = resolve(root, 'workspace')
const stateDirectory = resolve(root, 'state')
const toolchain = resolve(root, 'toolchain')

async function exists(path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

function request(authorizationId, executable = null) {
  return {
    tenantId: 'persistent-tenant',
    profile: 'system-minimal',
    authorizationId,
    policy: {
      schemaVersion: 1,
      backend: 'native',
      filesystem: {
        mounts: [
          { name: 'workspace', source: workspace, access: 'read-write' },
          ...(executable
            ? [{ name: 'toolchain', source: toolchain, access: 'read-only' }]
            : []),
        ],
        protectedRoots: [],
        tempBytes: 64 * 1024 * 1024,
        lease: { mode: 'persistent' },
      },
      network: { mode: 'deny' },
      environment: { inherit: [], allowSet: [] },
      execution: {
        executables: executable
          ? [{ alias: 'test-runtime', path: executable.path, sha256: executable.sha256 }]
          : [],
      },
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

  await mkdir(toolchain)
  const toolchainExecutable = resolve(toolchain, 'test-runtime.exe')
  await copyFile(daemon, toolchainExecutable)
  const executable = {
    path: toolchainExecutable,
    sha256: createHash('sha256').update(await readFile(toolchainExecutable)).digest('hex'),
  }

  runtime = await client()
  try {
    const started = performance.now()
    const sandbox = await runtime.createSandbox(request('workspace-one', executable))
    const elapsedMs = performance.now() - started
    assert.ok(elapsedMs < 3_000, `persistent toolchain migration took ${elapsedMs} ms`)
    const output = []
    const executed = await sandbox.exec({
      command: { kind: 'exec', program: 'test-runtime', args: ['probe', '--json'] },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: ({ bytes }) => output.push(bytes),
    })
    assert.equal(executed.exitCode, 0)
    assert.match(Buffer.concat(output).toString('utf8'), /windows-appcontainer/)
    await sandbox.close()
    const stableStarted = performance.now()
    const stable = await runtime.createSandbox(request('workspace-one', executable))
    const stableElapsedMs = performance.now() - stableStarted
    assert.ok(stableElapsedMs < 1_000, `stable toolchain reuse took ${stableElapsedMs} ms`)
    await stable.close()
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
