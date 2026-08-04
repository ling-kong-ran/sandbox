import { spawn } from 'node:child_process'
import { readdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const directory = resolve('packages/node/test')
const tests = (await readdir(directory))
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => resolve(directory, name))

if (!tests.length) throw new Error('No Node test files were found.')

const child = spawn(process.execPath, ['--test', ...tests], { stdio: 'inherit' })
child.once('error', (error) => {
  console.error(error)
  process.exitCode = 1
})
child.once('exit', (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0)
})
