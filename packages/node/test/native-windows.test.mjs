import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { access, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
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

function policy(workspace, executable, sha256) {
  return {
    schemaVersion: 1,
    backend: 'native',
    filesystem: {
      mounts: [
        { name: 'workspace', source: workspace, access: 'read-write' },
        { name: 'runtime', source: dirname(executable), access: 'read-only' },
      ],
      protectedRoots: [],
      tempBytes: 64 * 1024 * 1024,
    },
    network: { mode: 'deny' },
    environment: { inherit: ['PATH'], allowSet: [] },
    execution: {
      executables: [{ alias: 'node', path: executable, sha256 }],
    },
    limits: {
      wallTimeMs: 15_000,
      cpuTimeMs: 10_000,
      memoryBytes: 256 * 1024 * 1024,
      processes: 16,
      outputBytes: 1024 * 1024,
    },
  }
}

test('Windows native backend confines an arbitrary host executable', async (t) => {
  if (process.platform !== 'win32' || !(await daemonExists())) {
    t.skip('requires a locally built Windows agent-sandboxd')
    return
  }

  const testRoot = resolve('target/native-tests')
  const stateDirectory = resolve('target/native-test-state')
  await mkdir(testRoot, { recursive: true })
  await rm(stateDirectory, { recursive: true, force: true })
  await mkdir(stateDirectory, { recursive: true })
  const root = await mkdtemp(join(testRoot, 'execution-'))
  const workspace = join(root, 'workspace')
  const secret = join(root, 'outside-secret.txt')
  await mkdir(workspace)
  await writeFile(secret, 'must-not-be-readable')

  const executable = resolve(process.execPath)
  const sha256 = createHash('sha256').update(await readFile(executable)).digest('hex')
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
    assert.equal(report.backend, 'windows-user-wfp-job')
    assert.equal(report.features.networkDeny, 'enforced')
    assert.equal(report.features.filesystemReadBoundary, 'limited')

    const sandbox = await client.createSandbox({
      tenantId: 'test-tenant',
      profile: 'system-minimal',
      authorizationId: 'test-authorization',
      policy: policy(workspace, executable, sha256),
    })

    const output = []
    const success = await sandbox.exec({
      command: {
        kind: 'exec',
        program: 'node',
        args: ['-e', "require('node:fs').writeFileSync('created.txt', 'native-ok'); console.log('native-ok')"],
      },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: ({ bytes }) => output.push(bytes),
    })
    const successText = Buffer.concat(output).toString('utf8')
    assert.equal(success.exitCode, 0, successText)
    assert.match(successText, /native-ok/)

    const deniedOutput = []
    const denied = await sandbox.exec({
      command: {
        kind: 'exec',
        program: 'node',
        args: ['-e', `process.stdout.write(require('node:fs').readFileSync(${JSON.stringify(secret)}, 'utf8'))`],
      },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: ({ bytes }) => deniedOutput.push(bytes),
    })
    const deniedText = Buffer.concat(deniedOutput).toString('utf8')
    if (report.features.filesystemReadBoundary === 'enforced') {
      assert.notEqual(denied.exitCode, 0)
      assert.doesNotMatch(deniedText, /must-not-be-readable/)
    } else {
      assert.equal(denied.exitCode, 0)
      assert.match(deniedText, /must-not-be-readable/)
    }

    const environmentOutput = []
    const environmentDenied = await sandbox.exec({
      command: {
        kind: 'exec',
        program: 'node',
        args: ['-e', "if (process.env.OPENAI_API_KEY) { console.log(process.env.OPENAI_API_KEY) } else { process.exit(1) }"],
      },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: ({ bytes }) => environmentOutput.push(bytes),
    })
    assert.notEqual(environmentDenied.exitCode, 0)
    assert.doesNotMatch(
      Buffer.concat(environmentOutput).toString('utf8'),
      /sandbox-test-secret/,
    )

    const memoryResult = await sandbox.exec({
      command: {
        kind: 'exec',
        program: 'node',
        args: ['-e', "Buffer.alloc(256 * 1024 * 1024, 1); setTimeout(() => {}, 10_000)"],
      },
      cwd: { mount: 'workspace', path: '.' },
      limits: { memoryBytes: 96 * 1024 * 1024 },
    })
    assert.notEqual(memoryResult.exitCode, 0)

    const processResult = await sandbox.exec({
      command: {
        kind: 'exec',
        program: 'node',
        args: [
          '-e',
          "const {spawn}=require('node:child_process'); for(let i=0;i<8;i++) spawn(process.execPath,['-e','setTimeout(()=>{},10000)']); setTimeout(()=>{},10000)",
        ],
      },
      cwd: { mount: 'workspace', path: '.' },
      limits: { processes: 2 },
    })
    assert.notEqual(processResult.exitCode, 0)

    const controller = new AbortController()
    const treeExecution = sandbox.exec({
      command: {
        kind: 'exec',
        program: 'node',
        args: [
          '-e',
          "const {spawn}=require('node:child_process'); const child=spawn(process.execPath,['-e',\"setTimeout(()=>require('node:fs').writeFileSync('escaped.txt','escaped'),1000)\"],{detached:true,stdio:'ignore'}); child.unref(); setTimeout(()=>{},10000)",
        ],
      },
      cwd: { mount: 'workspace', path: '.' },
      signal: controller.signal,
    })
    await new Promise((resolveWait) => setTimeout(resolveWait, 200))
    controller.abort()
    await treeExecution
    await new Promise((resolveWait) => setTimeout(resolveWait, 1_500))
    assert.equal(
      await access(join(workspace, 'escaped.txt')).then(
        () => true,
        () => false,
      ),
      false,
    )

    await sandbox.close()
  } finally {
    await client.close().catch(() => {})
    await rm(root, { recursive: true, force: true })
  }

  assert.deepEqual(diagnostics, [])
})
