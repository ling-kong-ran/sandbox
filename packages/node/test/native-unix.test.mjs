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
  })

  try {
    const report = await client.probe()
    assert.match(report.backend, /landlock|seatbelt/)
    assert.equal(report.features.filesystemReadBoundary, 'enforced')
    assert.equal(report.features.networkDeny, 'enforced')

    const sandbox = await client.createSandbox({
      tenantId: 'unix-conformance',
      profile: 'system-minimal',
      authorizationId: 'arbitrary-node',
      policy: {
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
      },
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
  } finally {
    await client.close().catch(() => {})
    await rm(root, { recursive: true, force: true })
  }
})
