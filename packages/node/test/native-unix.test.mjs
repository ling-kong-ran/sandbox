import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { access, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'

import { AgentSandboxClient } from '../src/index.mjs'

const daemon = resolve('target/debug/agent-sandboxd')

async function exists(path) {
  return access(path).then(
    () => true,
    () => false,
  )
}

test('Unix native backend confines arbitrary executables and denies network access', async (t) => {
  if (!['linux', 'darwin'].includes(process.platform) || !(await exists(daemon))) {
    t.skip('requires a locally built Linux or macOS agent-sandboxd')
    return
  }

  const root = await mkdtemp(join(process.cwd(), 'target', 'native-unix-'))
  const workspace = join(root, 'workspace')
  const secret = join(root, 'outside-secret.txt')
  const state = join(root, 'state')
  await Promise.all([mkdir(workspace), mkdir(state), writeFile(secret, 'outside-secret')])
  await writeFile(join(workspace, 'inside.txt'), 'inside-workspace')
  const executable = resolve(process.execPath)
  const sha256 = createHash('sha256').update(await readFile(executable)).digest('hex')
  const client = await AgentSandboxClient.spawn({
    executable: daemon,
    env: { ...process.env, AGENT_SANDBOX_STATE_DIR: state },
    client: { name: 'native-unix-conformance', version: '0.1.0' },
    onDiagnostic:
      process.env.AGENT_SANDBOX_DEBUG === '1'
        ? (message) => process.stderr.write(message)
        : undefined,
  })

  try {
    const report = await client.probe()
    assert.match(report.backend, /landlock|seatbelt/)
    assert.equal(report.status, 'enforced')
    for (const feature of [
      'filesystemReadBoundary',
      'filesystemWriteBoundary',
      'networkDeny',
      'processTree',
      'memoryLimit',
      'cpuLimit',
      'processLimit',
    ]) {
      assert.equal(report.features[feature], 'enforced', feature)
    }

    const sandboxPolicy = {
      schemaVersion: 1,
      backend: 'native',
      filesystem: {
        mounts: [
          { name: 'workspace', source: workspace, access: 'read-write' },
          { name: 'node-runtime', source: dirname(executable), access: 'read-only' },
        ],
        protectedRoots: [],
        tempBytes: 64 * 1024 * 1024,
        lease: { mode: 'ephemeral' },
      },
      network: { mode: 'deny' },
      environment: { inherit: ['PATH'], allowSet: [] },
      execution: {
        executables: [{ alias: 'node', path: executable, sha256 }],
      },
      limits: {
        wallTimeMs: 15_000,
        cpuTimeMs: 10_000,
        memoryBytes: 512 * 1024 * 1024,
        processes: 16,
        outputBytes: 1024 * 1024,
      },
    }
    const sandbox = await client.createSandbox({
      tenantId: 'unix-conformance',
      profile: 'system-minimal',
      authorizationId: 'arbitrary-node',
      policy: sandboxPolicy,
    })

    let output = ''
    const script = `
      const fs = require('node:fs');
      const net = require('node:net');
      const inside = fs.readFileSync('inside.txt', 'utf8');
      fs.writeFileSync('created.txt', 'created');
      let outsideDenied = false;
      try { fs.readFileSync(${JSON.stringify(secret)}, 'utf8') } catch (error) {
        outsideDenied = error && (error.code === 'EACCES' || error.code === 'EPERM');
      }
      const socket = net.createConnection({ host: '127.0.0.1', port: 9 });
      socket.once('connect', () => {
        console.log(JSON.stringify({ inside, outsideDenied, networkDenied: false }));
        socket.destroy();
      });
      socket.once('error', (error) => {
        console.log(JSON.stringify({ inside, outsideDenied, networkDenied: ['EACCES', 'EPERM'].includes(error.code) }));
      });
    `
    const result = await sandbox.exec({
      command: { kind: 'exec', program: 'node', args: ['-e', script] },
      cwd: { mount: 'workspace', path: '.' },
      onOutput: ({ bytes }) => {
        output += Buffer.from(bytes).toString('utf8')
      },
    })
    assert.equal(result.exitCode, 0, output)
    assert.deepEqual(JSON.parse(output.trim()), {
      inside: 'inside-workspace',
      outsideDenied: true,
      networkDenied: true,
    })
    assert.equal(await readFile(join(workspace, 'created.txt'), 'utf8'), 'created')
    await sandbox.close()

    const memorySandbox = await client.createSandbox({
      tenantId: 'unix-conformance',
      profile: 'system-minimal',
      authorizationId: 'memory-limit',
      policy: {
        ...sandboxPolicy,
        limits: { ...sandboxPolicy.limits, memoryBytes: 96 * 1024 * 1024 },
      },
    })
    const memoryResult = await memorySandbox.exec({
      command: {
        kind: 'exec',
        program: 'node',
        args: [
          '-e',
          "const chunks=[]; setInterval(()=>chunks.push(Buffer.alloc(8*1024*1024,1)),1)",
        ],
      },
      cwd: { mount: 'workspace', path: '.' },
    })
    assert.notEqual(memoryResult.exitCode, 0)
    await memorySandbox.close()

    const cpuSandbox = await client.createSandbox({
      tenantId: 'unix-conformance',
      profile: 'system-minimal',
      authorizationId: 'cpu-limit',
      policy: {
        ...sandboxPolicy,
        limits: { ...sandboxPolicy.limits, cpuTimeMs: 100 },
      },
    })
    const cpuStartedAt = Date.now()
    const cpuResult = await cpuSandbox.exec({
      command: { kind: 'exec', program: 'node', args: ['-e', 'for (;;) {}'] },
      cwd: { mount: 'workspace', path: '.' },
    })
    assert.notEqual(cpuResult.exitCode, 0)
    assert.ok(Date.now() - cpuStartedAt < 5_000)
    await cpuSandbox.close()

    const processSandbox = await client.createSandbox({
      tenantId: 'unix-conformance',
      profile: 'system-minimal',
      authorizationId: 'process-limit',
      policy: {
        ...sandboxPolicy,
        limits: { ...sandboxPolicy.limits, processes: 4 },
      },
    })
    const processResult = await processSandbox.exec({
      command: {
        kind: 'exec',
        program: 'node',
        args: [
          '-e',
          "const fs=require('node:fs'); const {spawn}=require('node:child_process'); fs.rmSync('process-started.log',{force:true}); const code=\"require('node:fs').appendFileSync('process-started.log',process.pid+'\\\\n');setTimeout(()=>{},10000)\"; for(let i=0;i<12;i++){const child=spawn(process.execPath,['-e',code]); child.on('error',()=>{})} setTimeout(()=>{const count=fs.existsSync('process-started.log')?fs.readFileSync('process-started.log','utf8').trim().split('\\n').length:0;process.exit(count)},2000)",
        ],
      },
      cwd: { mount: 'workspace', path: '.' },
    })
    assert.ok(processResult.exitCode < 4, `started descendants: ${processResult.exitCode}`)
    await processSandbox.close()

    const treeSandbox = await client.createSandbox({
      tenantId: 'unix-conformance',
      profile: 'system-minimal',
      authorizationId: 'process-tree',
      policy: sandboxPolicy,
    })
    const controller = new AbortController()
    const treeExecution = treeSandbox.exec({
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
    assert.equal(await exists(join(workspace, 'escaped.txt')), false)
    await treeSandbox.close()
  } finally {
    await client.close().catch(() => {})
    await rm(root, { recursive: true, force: true })
  }
})
