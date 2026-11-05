#!/usr/bin/env node
// ssh-helper: one process per operation. Request JSON on stdin, result JSON on stdout.
// Secrets never appear in argv; the mod passes references (dpapi:/keychain:/env:/file:/cmd:).

import { Client } from 'ssh2'
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import os from 'node:os'
import { spawn } from 'node:child_process'

const LIMIT = 4 * 1024 * 1024
const IS_WIN = process.platform === 'win32'

function err(code, message) {
  const e = new Error(message)
  e.code = code
  return e
}

function out(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n')
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', c => {
      data += c
      if (data.length > 32 * 1024 * 1024) reject(err('config', 'request too large'))
    })
    process.stdin.on('end', () => resolve(data))
    process.stdin.on('error', reject)
  })
}

function collector(limit = LIMIT) {
  const chunks = []
  let len = 0
  let truncated = false
  return {
    push(buf) {
      if (len >= limit) {
        truncated = true
        return
      }
      const take = buf.subarray(0, limit - len)
      chunks.push(take)
      len += take.length
      if (take.length < buf.length) truncated = true
    },
    text() {
      return Buffer.concat(chunks).toString('utf8')
    },
    get truncated() {
      return truncated
    },
  }
}

// ---------------------------------------------------------------- secrets

function psRun(script, input) {
  return new Promise((resolve, reject) => {
    const bin = IS_WIN ? 'powershell' : 'pwsh'
    const p = spawn(bin, ['-NoProfile', '-NonInteractive', '-Command', script], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let o = ''
    let e = ''
    p.stdout.on('data', d => (o += d))
    p.stderr.on('data', d => (e += d))
    p.on('error', () => reject(err('secret', `${bin} not found; DPAPI unavailable`)))
    p.on('close', code =>
      code === 0 ? resolve(o.trim()) : reject(err('secret', e.trim() || `${bin} exited ${code}`)),
    )
    p.stdin.end(input)
  })
}

const PS_PROTECT =
  "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd());" +
  " $p=[System.Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser');" +
  ' [Convert]::ToBase64String($p)'

const PS_UNPROTECT =
  "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd());" +
  " $p=[System.Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser');" +
  ' [Convert]::ToBase64String($p)'

async function dpapiProtect(text) {
  const b64 = Buffer.from(text, 'utf8').toString('base64')
  return psRun(PS_PROTECT, b64)
}

async function dpapiUnprotect(b64) {
  const b = await psRun(PS_UNPROTECT, b64.trim())
  return Buffer.from(b, 'base64').toString('utf8')
}

function runCmd(cmd, args, input) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] })
    let o = ''
    let e = ''
    p.stdout.on('data', d => (o += d))
    p.stderr.on('data', d => (e += d))
    p.on('error', () => reject(err('backend-missing', `${cmd} not found`)))
    p.on('close', code =>
      code === 0 ? resolve(o.trim()) : reject(err('secret', e.trim() || `${cmd} exited ${code}`)),
    )
    if (input !== undefined) p.stdin.end(input)
    else p.stdin.end()
  })
}

async function resolveSecret(ref, allowCmdSecrets) {
  if (ref === undefined || ref === null || ref === '') return undefined
  const s = String(ref)

  if (s.startsWith('dpapi:v1:')) {
    if (!IS_WIN) throw err('secret', 'dpapi reference on a non-Windows host')
    return dpapiUnprotect(s.slice('dpapi:v1:'.length))
  }
  if (s.startsWith('keychain:')) {
    const rest = s.slice('keychain:'.length)
    const slash = rest.indexOf('/')
    const service = slash < 0 ? rest : rest.slice(0, slash)
    const account = slash < 0 ? '' : rest.slice(slash + 1)
    return runCmd('security', ['find-generic-password', '-s', service, '-a', account, '-w'])
  }
  if (s.startsWith('secret-tool:')) {
    const attrs = s.slice('secret-tool:'.length).trim().split(/\s+/).filter(Boolean)
    return runCmd('secret-tool', ['lookup', ...attrs])
  }
  if (s.startsWith('env:')) {
    const name = s.slice(4)
    const v = process.env[name]
    if (v === undefined) throw err('secret', `environment variable ${name} is not set`)
    return v
  }
  if (s.startsWith('file:')) {
    const file = s.slice(5)
    const st = fs.statSync(file)
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
      throw err('secret', `${file} is readable by others (chmod 600 it)`)
    }
    return fs.readFileSync(file, 'utf8').split(/\r?\n/)[0]
  }
  if (s.startsWith('cmd:')) {
    if (!allowCmdSecrets) {
      throw err('config', 'cmd: secrets are disabled; set allowCmdSecrets in the plugin config')
    }
    return runCmd(IS_WIN ? 'cmd' : 'sh', IS_WIN ? ['/c', s.slice(4)] : ['-c', s.slice(4)])
  }
  return s
}

// ---------------------------------------------------------------- connection

function normaliseFingerprint(hash) {
  let buf
  if (Buffer.isBuffer(hash)) buf = hash
  else if (typeof hash === 'string' && /^[0-9a-f]{64}$/i.test(hash)) buf = Buffer.from(hash, 'hex')
  else return String(hash)
  return 'SHA256:' + buf.toString('base64')
}

function agentTarget() {
  if (process.env.SSH_AUTH_SOCK) return process.env.SSH_AUTH_SOCK
  if (IS_WIN) return 'pageant'
  throw err('auth', 'no ssh-agent: SSH_AUTH_SOCK is unset')
}

async function resolveAuth(cfg, opts, allowCmdSecrets) {
  const auth = cfg.auth ?? 'agent'
  const password = await resolveSecret(cfg.password, allowCmdSecrets)

  if (auth === 'password') {
    if (!password) throw err('config', `host uses password auth but has no password reference`)
    opts.password = password
    return
  }
  if (auth === 'keyboard-interactive') {
    if (!password) throw err('config', 'keyboard-interactive auth needs a password reference')
    opts.tryKeyboard = true
    opts._password = password
    return
  }
  if (auth === 'key') {
    const file = cfg.identityFile
    if (!file) throw err('config', 'auth=key needs identityFile')
    let key
    try {
      key = fs.readFileSync(file)
    } catch {
      throw err('config', `cannot read identity file ${file}`)
    }
    opts.privateKey = key
    const passphrase = await resolveSecret(cfg.passphrase, allowCmdSecrets)
    if (passphrase) opts.passphrase = passphrase
    return
  }
  opts.agent = cfg.agent ?? agentTarget()
}

function openSocket(conn, target) {
  return new Promise((resolve, reject) => {
    conn.forwardOut('127.0.0.1', 0, target.host, target.port ?? 22, (e, stream) =>
      e ? reject(err('network', `jump to ${target.host}: ${e.message}`)) : resolve(stream),
    )
  })
}

function connectOne(cfg, sock, allowCmdSecrets) {
  return new Promise((resolve, reject) => {
    const conn = new Client()
    const opts = {
      host: cfg.host,
      port: cfg.port ?? 22,
      username: cfg.user ?? os.userInfo().username,
      readyTimeout: cfg.readyTimeoutMs ?? 10_000,
      keepaliveInterval: 10_000,
      keepaliveCountMax: 3,
      hostHash: 'sha256',
    }
    if (cfg.algorithms) opts.algorithms = cfg.algorithms
    opts.hostVerifier = hash => {
      const fp = normaliseFingerprint(hash)
      conn._seenHostKey = fp
      if (cfg.hostKey) return fp === cfg.hostKey
      return true
    }
    if (sock) opts.sock = sock

    let settled = false
    conn.on('keyboard-interactive', (_n, _i, _l, prompts, finish) => {
      finish(prompts.map(() => opts._password ?? ''))
    })
    conn.on('ready', () => {
      settled = true
      resolve(conn)
    })
    conn.on('error', e => {
      if (settled) return
      const msg = e.message ?? String(e)
      let code = 'network'
      if (e.level === 'client-authentication' || /authentication/i.test(msg)) code = 'auth'
      else if (/verification failed|host key/i.test(msg)) code = 'hostkey'
      reject(err(code, msg))
    })

    resolveAuth(cfg, opts, allowCmdSecrets).then(() => {
      try {
        conn.connect(opts)
      } catch (e) {
        reject(err('config', e.message))
      }
    }, reject)
  })
}

async function connectChain(req) {
  const cfg = req.host
  if (!cfg || !cfg.host) throw err('config', 'request has no host')

  const jumps = []
  let sock
  const names = String(cfg.proxyJump ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)

  for (const name of names) {
    const j = req.jumpHosts?.[name]
    if (!j) throw err('config', `unknown jump host "${name}"`)
    const conn = await connectOne(j, sock, req.allowCmdSecrets)
    jumps.push(conn)
    sock = await openSocket(conn, cfg)
  }

  const conn = await connectOne(cfg, sock, req.allowCmdSecrets)
  return { conn, jumps, hostKey: conn._seenHostKey }
}

function closeAll(conn, jumps) {
  for (const j of jumps ?? []) {
    try {
      j.end()
    } catch {}
  }
  try {
    conn?.end()
  } catch {}
}

function withTimeout(promise, ms, onAbort) {
  let timer
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try {
        onAbort?.()
      } catch {}
      reject(err('timeout', `operation timed out after ${ms} ms`))
    }, ms)
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

// ---------------------------------------------------------------- ops

function quotePosix(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`
}

async function doExec(req) {
  if (req.sudo && req.sudoPassword) {
    req.sudoPasswordValue = await resolveSecret(req.sudoPassword, req.allowCmdSecrets)
  }
  const { conn, jumps, hostKey } = await connectChain(req)
  try {
    let command = req.command
    if (!command) throw err('config', 'exec needs a command')
    if (req.cwd) {
      command =
        req.remoteShell === 'powershell'
          ? `Set-Location -LiteralPath '${String(req.cwd).replace(/'/g, "''")}'; ${command}`
          : `cd ${quotePosix(req.cwd)} && ${command}`
    }
    if (req.sudo) {
      const user = req.sudoUser ? `-u ${quotePosix(req.sudoUser)} ` : ''
      command = `sudo -S -p '' ${user}sh -c ${quotePosix(command)}`
    }

    const stdout = collector()
    const stderr = collector()

    const done = new Promise((resolve, reject) => {
      const execOptions = { env: req.env }
      if (req.pty) execOptions.pty = { rows: 40, cols: 120, term: 'xterm-256color' }
      conn.exec(command, execOptions, (e, stream) => {
        if (e) return reject(err('remote-exit', e.message))
        if (req.sudoPasswordValue) stream.write(`${req.sudoPasswordValue}\n`)
        let code = null
        let signal = null
        stream.on('data', d => stdout.push(d))
        stream.stderr.on('data', d => stderr.push(d))
        stream.on('exit', (c, s) => {
          code = c
          signal = s
        })
        stream.on('close', () => resolve({ code, signal }))
        stream.on('error', e2 => reject(err('remote-exit', e2.message)))
      })
    })

    const ended = await withTimeout(done, req.timeoutMs ?? 120_000, () => {
      try {
        conn.end()
      } catch {}
    })

    return {
      ok: true,
      exitCode: ended.code,
      signal: ended.signal,
      stdout: stdout.text(),
      stderr: stderr.text(),
      isStdoutTruncated: stdout.truncated,
      isStderrTruncated: stderr.truncated,
      hostKey,
    }
  } finally {
    closeAll(conn, jumps)
  }
}

function sftpOf(conn) {
  return new Promise((resolve, reject) =>
    conn.sftp((e, sftp) => (e ? reject(err('network', `sftp: ${e.message}`)) : resolve(sftp))),
  )
}

function statSafe(sftp, p) {
  return new Promise(resolve => sftp.stat(p, (e, st) => resolve(e ? null : st)))
}

function mkdirp(sftp, dir) {
  return new Promise(resolve => {
    sftp.mkdir(dir, () => resolve())
  })
}

function readdirP(sftp, p) {
  return new Promise((resolve, reject) =>
    sftp.readdir(p, (e, l) => (e ? reject(err('network', `readdir ${p}: ${e.message}`)) : resolve(l))),
  )
}

function walkRemote(sftp, base, rel = '') {
  return readdirP(sftp, path.posix.join(base, rel)).then(async entries => {
    const out = []
    for (const entry of entries) {
      const childRel = rel ? `${rel}/${entry.filename}` : entry.filename
      if (entry.attrs.isDirectory()) {
        out.push({ rel: childRel, dir: true })
        out.push(...(await walkRemote(sftp, base, childRel)))
      } else if (entry.attrs.isFile()) {
        out.push({ rel: childRel, dir: false })
      }
    }
    return out
  })
}

function walkLocal(dir, rel = '') {
  const out = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const childRel = rel ? `${rel}/${entry.name}` : entry.name
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push({ rel: childRel, dir: true })
      out.push(...walkLocal(full, childRel))
    } else if (entry.isFile()) {
      out.push({ rel: childRel, dir: false, full })
    }
  }
  return out
}

// Items: a string targets one path; an array pairs by index, or drops every local
// file into the single remote directory (and vice versa).
function transferItems(req, direction) {
  const asList = value => (Array.isArray(value) ? value : value ? [value] : [])
  const locals = asList(req.local)
  const remotes = asList(req.remote)
  if (!locals.length || !remotes.length) throw err('config', 'local and remote are required')

  if (locals.length === remotes.length) {
    return locals.map((local, index) => ({ local, remote: remotes[index] }))
  }
  if (locals.length > 1 && remotes.length === 1) {
    const base = remotes[0]
    return locals.map(local => ({
      local,
      remote: direction === 'put' ? path.posix.join(base, path.basename(local)) : base,
    }))
  }
  if (remotes.length > 1 && locals.length === 1) {
    const base = locals[0]
    return remotes.map(remote => ({
      local: direction === 'get' ? path.posix.join(base, path.posix.basename(remote)) : base,
      remote,
    }))
  }
  throw err('config', 'local and remote lists must pair up or one side must be a directory')
}

function pump(readable, writable, deadline, onTick) {
  return new Promise((resolve, reject) => {
    let bytes = 0
    let settled = false
    const done = (fn, value) => {
      if (settled) return
      settled = true
      clearInterval(timer)
      fn(value)
    }
    const timer = setInterval(() => {
      if (deadline && Date.now() > deadline) {
        readable.destroy()
        writable.destroy()
        done(reject, err('timeout', 'transfer stopped at the time limit; run it again to resume'))
      }
    }, 250)

    readable.on('data', chunk => {
      bytes += chunk.length
      if (onTick) onTick(bytes)
    })
    readable.on('error', e => done(reject, err('network', e.message)))
    writable.on('error', e => done(reject, err('network', e.message)))
    writable.on('close', () => done(resolve, bytes))
    writable.on('finish', () => done(resolve, bytes))
    readable.pipe(writable)
  })
}

async function putFile(sftp, localPath, remotePath, opts) {
  const size = fs.statSync(localPath).size
  const existing = await statSafe(sftp, remotePath)
  const have = existing ? existing.size : 0

  if (have === size && !opts.restart) {
    return { local: localPath, remote: remotePath, status: 'skipped', bytes: size, total: size }
  }
  if (!opts.resume || opts.restart) {
    if (existing) await new Promise(r => sftp.unlink(remotePath, () => r()))
  }
  const offset = opts.resume && !opts.restart ? have : 0

  await mkdirp(sftp, path.posix.dirname(remotePath))
  const writable = sftp.createWriteStream(remotePath, { flags: offset > 0 ? 'a' : 'w' })
  const readable =
    offset > 0 ? fs.createReadStream(localPath, { start: offset }) : fs.createReadStream(localPath)
  const deadline = opts.maxMs ? Date.now() + opts.maxMs : 0
  await pump(readable, writable, deadline, sent =>
    opts.report?.('put', remotePath, offset + sent, size),
  )

  const after = await statSafe(sftp, remotePath)
  if (!after || after.size !== size) {
    throw err(
      'network',
      `${remotePath} is ${after ? after.size : 0} bytes after upload, expected ${size}; run it again to resume`,
    )
  }
  return {
    local: localPath,
    remote: remotePath,
    status: offset > 0 ? 'resumed' : 'done',
    from: offset,
    bytes: size - offset,
    total: size,
  }
}

async function getFile(sftp, remotePath, localPath, opts) {
  const remoteStat = await statSafe(sftp, remotePath)
  if (!remoteStat) throw err('config', `no such remote file: ${remotePath}`)
  const size = remoteStat.size

  fs.mkdirSync(path.dirname(localPath), { recursive: true })
  const have = fs.existsSync(localPath) ? fs.statSync(localPath).size : 0

  if (have === size && !opts.restart) {
    return { local: localPath, remote: remotePath, status: 'skipped', bytes: size, total: size }
  }
  if (!opts.resume || opts.restart) {
    if (fs.existsSync(localPath)) fs.unlinkSync(localPath)
  }
  const offset = opts.resume && !opts.restart ? have : 0

  const readable = sftp.createReadStream(remotePath, { start: offset })
  const writable = fs.createWriteStream(localPath, { flags: offset > 0 ? 'a' : 'w' })
  const deadline = opts.maxMs ? Date.now() + opts.maxMs : 0
  await pump(readable, writable, deadline, got =>
    opts.report?.('get', remotePath, offset + got, size),
  )

  const after = fs.statSync(localPath).size
  if (after !== size) {
    throw err(
      'network',
      `${localPath} is ${after} bytes after download, expected ${size}; run it again to resume`,
    )
  }
  return {
    local: localPath,
    remote: remotePath,
    status: offset > 0 ? 'resumed' : 'done',
    from: offset,
    bytes: size - offset,
    total: size,
  }
}

async function transfer(req, direction) {
  const { conn, jumps, hostKey } = await connectChain(req)
  let reportedAt = 0
  const opts = {
    resume: req.resume !== false,
    restart: req.restart === true,
    maxMs: req.maxMs ?? 0,
    report: (op, file, transferred, total) => {
      const now = Date.now()
      if (now - reportedAt < 200) return
      reportedAt = now
      out({ progress: true, op, file, transferred, total })
    },
  }

  try {
    const sftp = await sftpOf(conn)
    const items = transferItems(req, direction)
    const files = []
    let stop = null

    for (const item of items) {
      if (stop) {
        files.push({ ...item, status: 'stopped', reason: stop })
        continue
      }
      try {
        if (direction === 'put') {
          const local = path.resolve(item.local)
          const st = fs.statSync(local)
          if (st.isDirectory()) {
            if (!req.recursive) throw err('config', `${local} is a directory; pass recursive: true`)
            const entries = walkLocal(local)
            if (req.mkdirs !== false) {
              await mkdirp(sftp, item.remote)
              for (const entry of entries.filter(x => x.dir)) {
                await mkdirp(sftp, `${item.remote}/${entry.rel}`)
              }
            }
            for (const entry of entries.filter(x => !x.dir)) {
              files.push(await putFile(sftp, entry.full, `${item.remote}/${entry.rel}`, opts))
            }
          } else {
            files.push(await putFile(sftp, local, item.remote, opts))
          }
        } else {
          const stat = await statSafe(sftp, item.remote)
          if (!stat) throw err('config', `no such remote path: ${item.remote}`)
          if (stat.isDirectory()) {
            if (!req.recursive) throw err('config', `${item.remote} is a directory; pass recursive: true`)
            const local = path.resolve(item.local)
            const entries = await walkRemote(sftp, item.remote)
            for (const entry of entries.filter(x => x.dir)) {
              fs.mkdirSync(path.join(local, entry.rel), { recursive: true })
            }
            for (const entry of entries.filter(x => !x.dir)) {
              files.push(
                await getFile(sftp, `${item.remote}/${entry.rel}`, path.join(local, entry.rel), opts),
              )
            }
          } else {
            files.push(await getFile(sftp, item.remote, path.resolve(item.local), opts))
          }
        }
      } catch (error) {
        const code = error.code ?? 'network'
        files.push({ ...item, status: 'failed', code, message: error.message })
        if (code === 'network' || code === 'timeout' || code === 'auth') stop = code
      }
    }

    const incomplete = files.filter(f => f.status !== 'done' && f.status !== 'resumed' && f.status !== 'skipped')
    return { ok: true, files, incomplete: incomplete.length > 0, hostKey }
  } finally {
    closeAll(conn, jumps)
  }
}

async function doPut(req) {
  return transfer(req, 'put')
}

async function doGet(req) {
  return transfer(req, 'get')
}

function listen(server, host, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => resolve(server.address()))
  })
}

async function doTunnel(req) {
  const t = req.tunnel ?? {}
  const { conn, jumps } = await connectChain(req)
  const cleanups = []

  process.on('SIGTERM', () => shutdown(0))
  process.on('SIGINT', () => shutdown(0))
  conn.on('close', () => shutdown(0))

  function shutdown(code) {
    for (const fn of cleanups) {
      try {
        fn()
      } catch {}
    }
    closeAll(conn, jumps)
    setTimeout(() => process.exit(code), 50)
  }

  const bind = t.bindAddress ?? '127.0.0.1'

  if (t.type === 'local') {
    const server = net.createServer(sock => {
      conn.forwardOut(
        sock.remoteAddress ?? '127.0.0.1',
        sock.remotePort ?? 0,
        t.remoteHost ?? '127.0.0.1',
        t.remotePort,
        (e, ch) => {
          if (e) return sock.destroy()
          sock.pipe(ch).pipe(sock)
          sock.on('close', () => ch.destroy())
          ch.on('close', () => sock.destroy())
        },
      )
    })
    cleanups.push(() => server.close())
    const addr = await listen(server, bind, t.localPort ?? 0)
    return ready({ port: addr.port, bind, remoteHost: t.remoteHost, remotePort: t.remotePort })
  }

  if (t.type === 'dynamic') {
    const server = net.createServer(sock => socks(sock, conn))
    cleanups.push(() => server.close())
    const addr = await listen(server, bind, t.localPort ?? 1080)
    return ready({ port: addr.port, bind, socks5: true })
  }

  if (t.type === 'remote') {
    const port = await new Promise((resolve, reject) =>
      conn.forwardIn(bind, t.remotePort, (e, p) =>
        e ? reject(err('network', `remote forward: ${e.message}`)) : resolve(p),
      ),
    )
    conn.on('tcpip', (accept, reject, info) => {
      if (info.destPort !== port) return reject()
      const ch = accept()
      const s = net.connect(t.remoteHost ?? '127.0.0.1', t.remotePort)
      s.pipe(ch).pipe(s)
      s.on('error', () => ch.destroy())
    })
    cleanups.push(() => conn.unforwardIn(bind, port, () => {}))
    return ready({ port, bind, remoteForward: true })
  }

  throw err('config', `unknown tunnel type "${t.type}"`)
}

// Minimal SOCKS5 (CONNECT only, no auth): the listener is bound to loopback.
function socks(sock, conn) {
  let phase = 0
  let buf = Buffer.alloc(0)

  const onData = chunk => {
    buf = Buffer.concat([buf, chunk])
    if (phase === 0) {
      if (buf.length < 2) return
      const n = buf[1]
      if (buf.length < 2 + n) return
      buf = buf.subarray(2 + n)
      sock.write(Buffer.from([5, 0]))
      phase = 1
      if (buf.length) onData(Buffer.alloc(0))
      return
    }
    if (buf.length < 5) return
    const atyp = buf[3]
    let host
    let offset
    if (atyp === 1) {
      if (buf.length < 10) return
      host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`
      offset = 8
    } else if (atyp === 3) {
      const len = buf[4]
      if (buf.length < 5 + len + 2) return
      host = buf.subarray(5, 5 + len).toString('utf8')
      offset = 5 + len
    } else if (atyp === 4) {
      if (buf.length < 22) return
      const parts = []
      for (let i = 0; i < 8; i++) parts.push(buf.readUInt16BE(4 + i * 2).toString(16))
      host = parts.join(':')
      offset = 20
    } else {
      sock.destroy()
      return
    }
    const port = buf.readUInt16BE(offset)
    sock.removeListener('data', onData)
    conn.forwardOut('127.0.0.1', 0, host, port, (e, ch) => {
      if (e) {
        sock.end(Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]))
        return
      }
      sock.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
      if (buf.length > offset + 2) ch.write(buf.subarray(offset + 2))
      sock.pipe(ch).pipe(sock)
      sock.on('close', () => ch.destroy())
      ch.on('close', () => sock.destroy())
    })
  }

  sock.on('data', onData)
  sock.on('error', () => sock.destroy())
}

function ready(info) {
  out({ ok: true, ready: true, ...info })
  return { ok: true, ready: true, ...info, persistent: true }
}


function shq(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function jobDir(req) {
  const host = String(req.host?.host ?? 'host').replace(/[^A-Za-z0-9.-]/g, '_')
  return `/tmp/.ssh-tools/${host}/${req.job}`
}

function execCapture(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (e, stream) => {
      if (e) return reject(err('remote-exit', e.message))
      let out = ''
      let errText = ''
      stream.on('data', d => (out += d))
      stream.stderr.on('data', d => (errText += d))
      stream.on('close', code => resolve({ code, out, err: errText }))
    })
  })
}

function sftpPutText(sftp, remote, text, mode) {
  return new Promise((resolve, reject) => {
    const stream = sftp.createWriteStream(remote, mode ? { mode } : undefined)
    stream.on('error', e => reject(err('network', e.message)))
    stream.on('close', resolve)
    stream.end(text)
  })
}

function sftpReadText(sftp, remote) {
  return new Promise(resolve => {
    let out = ''
    const stream = sftp.createReadStream(remote)
    stream.on('data', d => (out += d))
    stream.on('error', () => resolve(null))
    stream.on('close', () => resolve(out))
    stream.on('end', () => resolve(out))
  })
}

function sftpMkdirs(sftp, dir) {
  const parts = dir.split('/').filter(Boolean)
  let current = ''
  return parts
    .reduce(
      (chain, part) =>
        chain.then(() => {
          current += `/${part}`
          return new Promise(resolve => sftp.mkdir(current, () => resolve()))
        }),
      Promise.resolve(),
    )
    .then(() => undefined)
}

const START_SH = [
  '#!/bin/sh',
  'DIR=$(dirname "$0")',
  'if command -v setsid >/dev/null 2>&1; then exec setsid sh "$DIR/boot.sh"; fi',
  'exec sh "$DIR/boot.sh"',
  '',
].join('\n')

const BOOT_SH = [
  '#!/bin/sh',
  'DIR=$(dirname "$0")',
  'if [ -f "$DIR/pw" ]; then',
  '  sudo -S -p \'\' sh "$DIR/cmd.sh" < "$DIR/pw"',
  '  code=$?',
  '  rm -f "$DIR/pw"',
  '  echo $code > "$DIR/exit"',
  '  exit $code',
  'fi',
  'sh "$DIR/cmd.sh"',
  '',
].join('\n')

async function doRun(req) {
  const { conn, jumps, hostKey } = await connectChain(req)
  try {
    const sftp = await sftpOf(conn)
    const dir = jobDir(req)
    await sftpMkdirs(sftp, dir)

    const script = [
      '#!/bin/sh',
      req.cwd ? `cd ${shq(req.cwd)} || exit 1` : '',
      req.command,
      `echo $? > ${shq(`${dir}/exit`)}`,
      '',
    ].join('\n')

    await sftpPutText(sftp, `${dir}/cmd.sh`, script)
    await sftpPutText(sftp, `${dir}/start.sh`, START_SH)
    await sftpPutText(sftp, `${dir}/boot.sh`, BOOT_SH)
    if (req.sudo && req.sudoPassword) {
      const pw = await resolveSecret(req.sudoPassword, req.allowCmdSecrets)
      await sftpPutText(sftp, `${dir}/pw`, `${pw}\n`, 0o600)
    }

    const line =
      `nohup sh ${shq(`${dir}/start.sh`)} > ${shq(`${dir}/out`)} 2>&1 ` +
      `& echo $! > ${shq(`${dir}/pid`)}; cat ${shq(`${dir}/pid`)}`

    const started = await execCapture(conn, line)
    const pid = started.out.trim().split(/\s+/).pop()
    if (!pid || !/^\d+$/.test(pid)) {
      throw err('remote-exit', started.err.trim() || 'the remote job did not start')
    }
    return { ok: true, job: req.job, dir, pid: Number(pid), hostKey }
  } finally {
    closeAll(conn, jumps)
  }
}

async function doLogs(req) {
  const { conn, jumps, hostKey } = await connectChain(req)
  try {
    const sftp = await sftpOf(conn)
    const dir = jobDir(req)
    const outPath = `${dir}/out`

    const deadline = req.waitSec ? Date.now() + req.waitSec * 1000 : 0
    let exitText = await sftpReadText(sftp, `${dir}/exit`)
    while (exitText === null && deadline && Date.now() < deadline) {
      await sleep(400)
      exitText = await sftpReadText(sftp, `${dir}/exit`)
    }

    const stat = await statSafe(sftp, outPath)
    if (!stat) throw err('config', `no such job output: ${outPath}`)
    const since = Math.max(0, Number(req.since ?? 0))
    const limit = Math.min(Number(req.maxBytes ?? 262144), LIMIT)
    const end = Math.min(stat.size, since + limit)

    let text = ''
    if (end > since) {
      text = await new Promise((resolve, reject) => {
        let out = ''
        const stream = sftp.createReadStream(outPath, { start: since, end: end - 1 })
        stream.on('data', d => (out += d))
        stream.on('error', e => reject(err('network', e.message)))
        stream.on('close', () => resolve(out))
        stream.on('end', () => resolve(out))
      })
    }

    return {
      ok: true,
      job: req.job,
      text,
      offset: end,
      size: stat.size,
      isTruncated: end < stat.size,
      exitCode: exitText === null ? null : Number(exitText.trim()),
      isRunning: exitText === null,
      hostKey,
    }
  } finally {
    closeAll(conn, jumps)
  }
}

async function doKill(req) {
  const { conn, jumps, hostKey } = await connectChain(req)
  try {
    const sftp = await sftpOf(conn)
    const dir = jobDir(req)
    const pidText = await sftpReadText(sftp, `${dir}/pid`)
    if (!pidText) throw err('config', `job ${req.job} has no pid file`)
    const pid = Number(pidText.trim())
    const signal = String(req.signal ?? 'TERM').replace(/[^A-Z]/gi, '') || 'TERM'
    const result = await execCapture(
      conn,
      `kill -${signal} -${pid} 2>/dev/null || kill -${signal} ${pid} 2>/dev/null; sleep 0.3; ` +
        `if kill -0 ${pid} 2>/dev/null; then echo alive; else echo dead; fi`,
    )
    const state = result.out.trim()
    if (state === 'dead' && (await sftpReadText(sftp, `${dir}/exit`)) === null) {
      const code = signal === 'KILL' ? 137 : 143
      await sftpPutText(sftp, `${dir}/exit`, `${code}
`)
    }
    return { ok: true, job: req.job, pid, state, hostKey }
  } finally {
    closeAll(conn, jumps)
  }
}

async function doRead(req) {
  const { conn, jumps, hostKey } = await connectChain(req)
  try {
    const sftp = await sftpOf(conn)
    const stat = await statSafe(sftp, req.path)
    if (!stat) throw err('config', `no such remote file: ${req.path}`)
    if (stat.isDirectory()) throw err('config', `${req.path} is a directory`)

    const limit = Math.min(Number(req.maxBytes ?? 262144), LIMIT)
    let start = Math.max(0, Number(req.offset ?? 0))
    if (req.tailBytes) start = Math.max(0, stat.size - Math.min(Number(req.tailBytes), limit))
    const end = Math.min(stat.size, start + limit)

    let text = ''
    if (end > start) {
      text = await new Promise((resolve, reject) => {
        let out = ''
        const stream = sftp.createReadStream(req.path, { start, end: end - 1 })
        stream.on('data', d => (out += d))
        stream.on('error', e => reject(err('network', e.message)))
        stream.on('close', () => resolve(out))
        stream.on('end', () => resolve(out))
      })
    }

    return {
      ok: true,
      path: req.path,
      text,
      offset: start,
      size: stat.size,
      isTruncated: end < stat.size || start > 0,
      hostKey,
    }
  } finally {
    closeAll(conn, jumps)
  }
}

async function doDoctor(req) {
  const backends = { dpapi: false, keychain: false, secretTool: false }
  if (IS_WIN) backends.dpapi = true
  for (const [key, bin] of [
    ['keychain', 'security'],
    ['secretTool', 'secret-tool'],
  ]) {
    backends[key] = await new Promise(resolve => {
      const p = spawn(bin, ['--help'], { stdio: 'ignore' })
      p.on('error', () => resolve(false))
      p.on('close', () => resolve(true))
    })
  }

  return {
    ok: true,
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    helper: 'ssh-helper',
    home: os.homedir(),
    sshAuthSock: process.env.SSH_AUTH_SOCK ?? null,
    backends,
  }
}

async function doCrypt(req) {
  if (req.action === 'protect') {
    if (!IS_WIN) throw err('secret', 'only DPAPI is implemented in the helper; use keychain: refs elsewhere')
    const b64 = await dpapiProtect(String(req.plaintext ?? ''))
    return { ok: true, ref: `dpapi:v1:${b64}` }
  }
  if (req.action === 'unprotect') {
    const value = await resolveSecret(String(req.ref ?? ''), req.allowCmdSecrets)
    return { ok: true, plaintext: value }
  }
  throw err('config', 'crypt needs action protect|unprotect')
}

// ---------------------------------------------------------------- main

const OPS = {
  exec: doExec,
  run: doRun,
  logs: doLogs,
  kill: doKill,
  read: doRead,
  put: doPut,
  get: doGet,
  tunnel: doTunnel,
  doctor: doDoctor,
  crypt: doCrypt,
}

async function main() {
  const op = process.argv[2]
  const fn = OPS[op]
  if (!fn) {
    out({ ok: false, code: 'config', message: `unknown op "${op}"` })
    process.exitCode = 2
    return
  }

  let req = {}
  try {
    const raw = await readStdin()
    req = raw.trim() ? JSON.parse(raw) : {}
  } catch (e) {
    out({ ok: false, code: 'config', message: `bad request: ${e.message}` })
    process.exitCode = 2
    return
  }

  try {
    const result = await fn(req)
    if (!result.persistent) out(result)
  } catch (e) {
    out({ ok: false, code: e.code ?? 'network', message: e.message ?? String(e) })
    process.exitCode = 1
  }
}

main()
