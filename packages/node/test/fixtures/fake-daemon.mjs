import { createInterface } from 'node:readline'

const interface_ = createInterface({ input: process.stdin })
const sandboxes = new Set()

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`)
}

interface_.on('line', (line) => {
  const message = JSON.parse(line)
  switch (message.type) {
    case 'hello':
      send({
        type: 'helloAck',
        protocol: { major: 1, minor: 0 },
        runtimeVersion: '0.1.0-test',
        platform: process.platform,
        features: ['process.exec', 'process.spawn'],
        nonce: message.nonce,
      })
      break
    case 'probe':
      send({
        type: 'probeResult',
        requestId: message.requestId,
        report: {
          platform: process.platform,
          backend: 'fake',
          status: 'enforced',
          features: { processTree: 'enforced' },
          reasons: [],
        },
      })
      break
    case 'createSandbox': {
      if (message.tenantId === 'reject') {
        send({
          type: 'error',
          requestId: message.requestId,
          executionId: null,
          error: {
            code: 'SANDBOX_POLICY_INVALID',
            category: 'policy_violation',
            retryable: false,
            message: 'rejected by fixture',
            details: {},
          },
        })
        break
      }
      const sandboxId = `sandbox-${sandboxes.size + 1}`
      sandboxes.add(sandboxId)
      send({
        type: 'sandboxCreated',
        requestId: message.requestId,
        sandboxId,
        status: 'enforced',
        mounts: { workspace: '/workspace' },
        policyFingerprint: `sha256:${'1'.repeat(64)}`,
        capabilities: {
          platform: process.platform,
          backend: 'fake',
          status: 'enforced',
          features: { processTree: 'enforced' },
          reasons: [],
        },
      })
      break
    }
    case 'spawn':
      send({
        type: 'queued',
        requestId: message.requestId,
        executionId: message.executionId,
        position: 0,
      })
      send({ type: 'started', executionId: message.executionId, status: 'enforced' })
      queueMicrotask(() => {
        send({
          type: 'output',
          executionId: message.executionId,
          stream: 'stdout',
          sequence: 1,
          base64: Buffer.from('sandbox output\n').toString('base64'),
        })
        send({
          type: 'exit',
          executionId: message.executionId,
          code: 0,
          signal: null,
          usage: { outputBytes: 15 },
        })
      })
      break
    case 'closeSandbox':
      sandboxes.delete(message.sandboxId)
      send({
        type: 'sandboxClosed',
        requestId: message.requestId,
        sandboxId: message.sandboxId,
      })
      break
    case 'shutdown':
      send({ type: 'shutdownAck', requestId: message.requestId })
      setImmediate(() => process.exit(0))
      break
  }
})
