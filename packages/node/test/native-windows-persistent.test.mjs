import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { access, mkdir, readFile, rm } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
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

function request(executable) {
  return {
    tenantId: 'persistent-tenant',
    profile: 'system-minimal',
    authorizationId: 'workspace-one',
    policy: {
      schemaVersion: 1,
      backend: 'native',
      filesystem: {
        mounts: [
          { name: 'workspace', source: workspace, access: 'read-write' },
          { name: 'runtime', source: dirname(executable.path), access: 'read-only' },
        ],
        protectedRoots: [],
        tempBytes: 64 * 1024 * 1024,
        lease: { mode: 'persistent' },
      },
      network: { mode: 'deny' },
      environment: { inherit: ['PATH'], allowSet: [] },
      execution: {
        executables: [{ alias: 'node', path: executable.path, sha256: executable.sha256 }],
      },
      limits: {
        wallTimeMs: 10_000,
        cpuTimeMs: 5_000,
        memoryBytes: 256 * 1024 * 1024,
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
  const executablePath = resolve(process.execPath)
  const executable = {
    path: executablePath,
    sha256: createHash('sha256').update(await readFile(executablePath)).digest('hex'),
  }

  let runtime = await client()
  try {
    const sandbox = await runtime.createSandbox(request(executable))
    const result = await sandbox.exec({
      command: {
        kind: 'exec',
        program: 'node',
        args: ['-e', "require('node:fs').writeFileSync('created.txt', 'persistent')"],
      },
      cwd: { mount: 'workspace', path: '.' },
    })
    assert.equal(result.exitCode, 0)
    await sandbox.close()
  } finally {
    await runtime.close()
  }
  assert.equal(await readFile(resolve(workspace, 'created.txt'), 'utf8'), 'persistent')

  runtime = await client()
  try {
    const sandbox = await runtime.createSandbox(request(executable))
    const output = []
    const result = await sandbox.exec({
      command: { kind: 'exec', program: 'node', args: ['-e', "console.log('reused')"] },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: ({ bytes }) => output.push(bytes),
    })
    assert.equal(result.exitCode, 0)
    assert.match(Buffer.concat(output).toString('utf8'), /reused/)
    await sandbox.close()
    assert.deepEqual(
      await runtime.revokeAuthorization({
        tenantId: 'persistent-tenant',
        authorizationId: 'workspace-one',
      }),
      { authorizationId: 'workspace-one' },
    )
    await assert.rejects(runtime.createSandbox(request(executable)), /empty managed directory/i)
  } finally {
    await runtime.close()
    await rm(root, { recursive: true, force: true })
  }
})
