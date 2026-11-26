import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { copyFile, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

const source = path.resolve(process.argv[2])
const dir = await mkdtemp(path.join(tmpdir(), 'Hookbox launcher '))
const panel = 'http://127.0.0.1:8081'

async function exercise(port, existingToken) {
  const env = { ...process.env }
  delete env.HOOKBOX_ADMIN_SHA256
  if (existingToken) env.HOOKBOX_ADMIN_SHA256 = createHash('sha256').update(existingToken).digest('hex')
  const child = spawn(process.env.ComSpec, ['/d', '/c', `call "${path.join(dir, 'Start Hookbox.cmd')}"`], {
    cwd: tmpdir(), env, windowsVerbatimArguments: true, stdio: ['ignore', 'pipe', 'pipe'],
  })
  let output = '', logs = ''
  child.stdout.on('data', data => { output += data })
  child.stderr.on('data', data => { logs += data })
  try {
    for (let i = 0; !logs.includes('management=true'); i++) {
      assert.equal(child.exitCode, null, 'Launcher exited before the management port opened')
      assert.ok(i < 150, 'Timed out waiting for the management listener')
      await delay(100)
    }
    const match = output.match(/Manager sign-in token: ([A-Za-z0-9_-]+)/)
    if (existingToken) assert.equal(match, null, 'Must honor the preconfigured token')
    else assert.ok(match, 'Must display the session token')
    const token = existingToken || match[1]
    const health = await fetch(`http://127.0.0.1:${port}/healthz`)
    assert.equal((await health.json()).status, 'ok')
    assert.equal((await fetch(panel + '/')).status, 200)
    assert.equal((await fetch(panel + '/api/config')).status, 401)
    const reply = await fetch(panel + '/api/config', { headers: { Authorization: 'Bearer ' + token } })
    assert.equal(reply.status, 200)
    assert.equal(await reply.text(), await readFile(path.join(dir, 'config.yaml'), 'utf8'))
  } finally {
    if (child.exitCode === null) execFileSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' })
  }
}

try {
  for (const file of ['Start Hookbox.cmd', 'hookbox.exe', 'config.example.yaml']) {
    await copyFile(path.join(source, file), path.join(dir, file))
  }
  await exercise(8080)
  const example = await readFile(path.join(dir, 'config.example.yaml'), 'utf8')
  assert.equal(await readFile(path.join(dir, 'config.yaml'), 'utf8'), example)
  const custom = example.replace('port: 8080', 'port: 8090')
  assert.notEqual(custom, example)
  await writeFile(path.join(dir, 'config.yaml'), custom)
  await exercise(8090, randomBytes(32).toString('hex'))
  assert.equal(await readFile(path.join(dir, 'config.yaml'), 'utf8'), custom)
} finally {
  await rm(dir, { recursive: true, force: true, maxRetries: 5 })
}
