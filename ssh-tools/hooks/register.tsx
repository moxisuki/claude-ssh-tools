import type { EngineInterface, Register } from 'claude-code'

import {
  addIgnore,
  checkIgnored,
  hostPaths,
  loadConfig,
  readHostFile,
  removeHostEntry,
  resolveHome,
  resolveHost,
  saveHostEntry,
  writeHostFile,
  PROJECT_REL,
} from './lib/config'
import type { LoadedConfig } from './lib/config'
import {
  answer,
  fail,
  formatBytes,
  renderTransfer,
  describeEntry,
  hasSecret,
  isPlaintextSecret,
  renderExec,
  renderHosts,
} from './lib/format'
import { requireNode, resolveNode, runHelper, runHelperStreaming, spawnHelper } from './lib/helper'
import type { HostEntry, LoadedHost, Scope } from './lib/types'

const PLUGIN = 'ssh-tools'

declare function setTimeout(handler: () => void, ms: number): unknown
declare function clearTimeout(id: unknown): void

const PANE = 'ssh-tools'

const T = {
  list: 'mcp__ssh-tools__list',
  host: 'mcp__ssh-tools__host',
  wizard: 'mcp__ssh-tools__wizard',
  exec: 'mcp__ssh-tools__exec',
  upload: 'mcp__ssh-tools__put',
  download: 'mcp__ssh-tools__get',
  tunnel: 'mcp__ssh-tools__tunnel',
  doctor: 'mcp__ssh-tools__doctor',
  run: 'mcp__ssh-tools__run',
  logs: 'mcp__ssh-tools__logs',
  kill: 'mcp__ssh-tools__kill',
  read: 'mcp__ssh-tools__read',
} as const

interface Tunnel {
  id: string
  host: string
  type: string
  spec: string
  startedAt: number
  stream: ReturnType<typeof spawnHelper>
}

const TUNNELS = new Map<string, Tunnel>()
let tunnelSeq = 0

interface Job {
  id: string
  host: string
  command: string
  startedAt: number
  offset: number
}

const JOBS = new Map<string, Job>()
const PANEL: { hosts: LoadedHost[] } = { hosts: [] }

function invalidate($: EngineInterface): void {
  try {
    $.ui.invalidate('ui.render')
  } catch {
    // no drawing to repaint
  }
}

function clip(text: string, max: number): string {
  return text.length <= max
    ? text
    : `${text.slice(0, max)}\n[truncated ${text.length - max} chars]`
}

async function mapLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array(items.length)
  let next = 0
  const worker = async () => {
    for (;;) {
      const index = next
      next += 1
      if (index >= items.length) return
      out[index] = await fn(items[index] as T, index)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return out
}

function hostTargets(e: Record<string, unknown>, config: LoadedConfig): string[] {
  const group = str(e.group)
  if (group) {
    const names = [...config.effective.values()]
      .filter(host => (host.entry.groups ?? []).includes(group))
      .map(host => host.name)
    if (!names.length) throw new Error(`no hosts are in group "${group}"`)
    return names
  }
  if (Array.isArray(e.host)) {
    const names = e.host.filter((item): item is string => typeof item === 'string' && !!item.trim())
    if (!names.length) throw new Error('exec needs host or group')
    return names
  }
  const one = str(e.host)
  if (!one) throw new Error('exec needs host or group')
  return [one]
}

// ---------------------------------------------------------------- helpers

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined
}

function num(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function paths(value: unknown): string[] | undefined {
  if (typeof value === 'string') return value.trim() ? [value.trim()] : undefined
  if (Array.isArray(value)) {
    const list = value.filter((item): item is string => typeof item === 'string' && !!item.trim())
    return list.length === value.length && list.length ? list.map(item => item.trim()) : undefined
  }
  return undefined
}

function isRecord(value: unknown): value is Record<string, string> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function inputOf(e: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...e }
  delete copy.tool
  delete copy.tool_use_id
  delete copy.agentId
  delete copy.requestMeta
  return copy
}

function clamp(value: number, low: number, high: number): number {
  return Math.min(high, Math.max(low, value))
}

async function authorise(
  $: EngineInterface,
  name: string,
  input: unknown,
): Promise<string | null> {
  let decision: string = 'allow'
  try {
    const verdict = await $.tool.check({ tool: name, input })
    decision = verdict.decision
  } catch {
    decision = 'allow'
  }

  if (decision === 'deny') return `the session's permissions deny ${name}`
  if (decision === 'ask') {
    let picked: string
    try {
      picked = await $.ui.ask(`${name.replace(`mcp__${PLUGIN}__`, '')} — allow this call?`, [
        'Allow',
        'Deny',
      ])
    } catch {
      return 'this call needs confirmation, but nobody can be asked in this session'
    }
    if (picked !== 'Allow') return 'denied by you'
  }
  return null
}

function toHelperHost(entry: HostEntry): Record<string, unknown> {
  return {
    host: entry.host,
    port: entry.port ?? 22,
    user: entry.user,
    auth: entry.auth ?? 'agent',
    identityFile: entry.identityFile,
    passphrase: entry.passphrase,
    password: entry.password,
    proxyJump: entry.proxyJump,
    hostKey: entry.hostKey,
    algorithms: entry.algorithms,
    remoteShell: entry.remoteShell,
  }
}

function jumpMap(config: LoadedConfig): Record<string, Record<string, unknown>> {
  const map: Record<string, Record<string, unknown>> = {}
  for (const [name, host] of config.effective) map[name] = toHelperHost(host.entry)
  return map
}

function allowCmd(options: Record<string, unknown>): boolean {
  return options.allowCmdSecrets === true || options.allowCmdSecrets === 'true'
}

function timeoutSeconds(options: Record<string, unknown>, requested: unknown): number {
  const fallback = num(options.defaultTimeoutSec) ?? 120
  return clamp(num(requested) ?? fallback, 1, 590)
}

function nodeBin(options: Record<string, unknown>): unknown {
  return options.nodeBin
}

// ---------------------------------------------------------------- persistence

async function pinHostKey(
  $: EngineInterface,
  config: LoadedConfig,
  target: LoadedHost,
  fingerprint: unknown,
): Promise<void> {
  if (typeof fingerprint !== 'string' || !fingerprint) return
  if (target.entry.hostKey || target.scope === 'ssh-config') return
  const path = target.scope === 'project' ? config.files.project : config.files.global
  const file = await readHostFile($, path)
  const next = saveHostEntry(file, target.name, { hostKey: fingerprint })
  try {
    await writeHostFile($, path, next)
    target.entry.hostKey = fingerprint
  } catch (error) {
    $.ui.log(
      `pinned key for ${target.name} not saved: ${error instanceof Error ? error.message : String(error)}`,
      { to: 'debug' },
    )
  }
}

interface SaveInput {
  name: string
  scope: Scope
  entry: HostEntry
}

async function encryptIfPlain(
  $: EngineInterface,
  options: Record<string, unknown>,
  value: string | undefined,
): Promise<string | undefined> {
  if (!value) return undefined
  if (!isPlaintextSecret(value)) return value
  const node = await requireNode($, nodeBin(options))
  const result = await runHelper($, node, 'crypt', { action: 'protect', plaintext: value }, 30_000)
  if (!result.ok) {
    throw Object.assign(
      new Error(
        `cannot encrypt the secret: ${String(result.message ?? 'unknown error')}. ` +
          'On Windows DPAPI needs PowerShell; elsewhere store the secret with env:/file: instead.',
      ),
      { code: 'secret' },
    )
  }
  return String(result.ref)
}

async function persistHost(
  $: EngineInterface,
  options: Record<string, unknown>,
  input: SaveInput,
): Promise<{ path: string; git: string; entry: HostEntry }> {
  const config = await loadConfig($)
  const path = input.scope === 'project' ? config.files.project : config.files.global

  const entry: HostEntry = { ...input.entry }
  delete entry.hostKey
  const passphrase = await encryptIfPlain($, options, entry.passphrase)
  const password = await encryptIfPlain($, options, entry.password)
  if (passphrase) entry.passphrase = passphrase
  if (password) entry.password = password

  const file = await readHostFile($, path)
  const next = saveHostEntry(file, input.name, entry)
  await writeHostFile($, path, next)

  let git = ''
  if (input.scope === 'project') {
    const root = await $.session.root()
    const status = await checkIgnored($, root, PROJECT_REL)
    if (status.ignored) {
      git = `git: ignored (${PROJECT_REL})`
    } else {
      const reason = status.reason ?? 'not ignored'
      let picked = ''
      try {
        picked = await $.ui.ask(
          `${PROJECT_REL} is not in .gitignore. Add it? (${reason})`,
          ['Add it', 'Leave it'],
        )
      } catch {
        picked = ''
      }
      if (picked === 'Add it') {
        const added = await addIgnore($, root, PROJECT_REL)
        git = added.added
          ? `git: added ${PROJECT_REL} to .gitignore`
          : `git: NOT ignored (${added.reason ?? reason})`
      } else {
        git = `git: NOT ignored — add ${PROJECT_REL} to .gitignore before committing`
      }
    }
  } else {
    git = 'git: n/a (global file)'
  }

  return { path, git, entry }
}

function entryFrom(e: Record<string, unknown>, existing?: HostEntry): Partial<HostEntry> {
  const entry: Partial<HostEntry> = { ...existing }
  const host = str(e.host)
  if (host) entry.host = host
  const port = num(e.port)
  if (port !== undefined) entry.port = port
  const user = str(e.user)
  if (user) entry.user = user
  const auth = str(e.auth)
  if (auth === 'agent' || auth === 'key' || auth === 'password' || auth === 'keyboard-interactive') {
    entry.auth = auth
  }
  const identityFile = str(e.identityFile)
  if (identityFile) entry.identityFile = identityFile
  const passphrase = str(e.passphrase)
  if (passphrase) entry.passphrase = passphrase
  const password = str(e.password)
  if (password) entry.password = password
  const passwordEnv = str(e.passwordEnv)
  if (passwordEnv) entry.password = `env:${passwordEnv}`
  const proxyJump = str(e.proxyJump)
  if (proxyJump) entry.proxyJump = proxyJump
  const note = str(e.note)
  if (note) entry.note = note
  const remoteShell = str(e.remoteShell)
  if (remoteShell === 'posix' || remoteShell === 'powershell') entry.remoteShell = remoteShell
  const groups = Array.isArray(e.groups)
    ? e.groups.filter((item): item is string => typeof item === 'string' && !!item.trim())
    : (str(e.groups) ?? '').split(',').map(item => item.trim()).filter(Boolean)
  if (groups.length) entry.groups = groups.map(item => item.trim())
  const sudoUser = str(e.sudoUser)
  if (sudoUser) entry.sudoUser = sudoUser
  const sudoPassword = str(e.sudoPassword)
  if (sudoPassword) entry.sudoPassword = sudoPassword
  return entry
}

function describeSaved(name: string, entry: HostEntry, path: string, git: string): string {
  const secrets = [
    hasSecret(entry.password) ? 'hasPassword' : '',
    hasSecret(entry.passphrase) ? 'hasPassphrase' : '',
  ].filter(Boolean)
  return [
    `saved ${name}`,
    `  ${describeEntry({ ...entry, password: secrets.includes('hasPassword') ? entry.password : undefined, passphrase: secrets.includes('hasPassphrase') ? entry.passphrase : undefined })}`,
    `  file: ${path}`,
    `  ${git}`,
    '',
    `verify with: exec { "host": "${name}", "command": "echo ok" }`,
  ].join('\n')
}

// ---------------------------------------------------------------- tools

async function handleList($: EngineInterface, e: Record<string, unknown>) {
  const config = await loadConfig($)
  PANEL.hosts = config.all

  const name = str(e.name)
  if (name) {
    const host = config.effective.get(name)
    if (!host) return fail(`[config] unknown host "${name}"`)
    return answer(renderHosts({ ...config, all: [host] }))
  }

  const group = str(e.group)
  const scoped = group
    ? config.all.filter(host => (host.entry.groups ?? []).includes(group))
    : config.all

  const scope = str(e.scope)
  const filter: Scope | undefined =
    scope === 'global' || scope === 'project' || scope === 'ssh-config' ? scope : undefined

  if (group && !scoped.length) return fail(`[config] no hosts are in group "${group}"`)
  return answer(renderHosts({ ...config, all: scoped }, filter))
}

async function handleHost($: EngineInterface, e: Record<string, unknown>, options: Record<string, unknown>) {
  const action = str(e.action) ?? 'save'
  const name = str(e.name)
  if (!name) return fail('[config] host needs a name')

  const requested = str(e.scope)
  const scope: Scope = requested === 'project' ? 'project' : 'global'

  if (action === 'remove') {
    const config = await loadConfig($)
    const path = scope === 'project' ? config.files.project : config.files.global
    const file = await readHostFile($, path)
    const next = removeHostEntry(file, name)
    if (!next) {
      const other = config.effective.get(name)
      return answer(
        other
          ? `[config] "${name}" is not in the ${scope} file; it lives in ${other.scope}`
          : `[config] no host named "${name}"`,
      )
    }
    await writeHostFile($, path, next)
    return answer(`removed ${name} from ${path}`)
  }

  if (action === 'trust') {
    const config = await loadConfig($)
    const host = config.effective.get(name)
    if (!host) return fail(`[config] unknown host "${name}"`)
    const fingerprint = str(e.hostKey)
    if (!fingerprint) return fail(`[config] host trust needs hostKey (SHA256:…)`)
    const path = host.scope === 'project' ? config.files.project : config.files.global
    if (host.scope === 'ssh-config') {
      return fail('[config] ssh-config entries are read-only; save the host first')
    }
    const file = await readHostFile($, path)
    await writeHostFile($, path, saveHostEntry(file, name, { hostKey: fingerprint }))
    return answer(`pinned ${fingerprint} for ${name}`)
  }

  const config = await loadConfig($)
  const existing = config.effective.get(name)
  const entry = entryFrom(e, existing?.entry)
  if (!entry.host) return fail('[config] host save needs host')
  if (entry.port !== undefined && (entry.port < 1 || entry.port > 65535)) {
    return fail('[config] port must be 1-65535')
  }
  if (entry.auth === 'key' && !entry.identityFile) {
    return fail('[config] auth=key needs identityFile')
  }

  const saved = await persistHost($, options, { name, scope, entry: entry as HostEntry })
  return answer(describeSaved(name, saved.entry, saved.path, saved.git))
}

async function handleWizard($: EngineInterface, e: Record<string, unknown>, options: Record<string, unknown>) {
  const name = str(e.name)
  if (!name) return fail('[config] wizard needs a name (what you will call this host)')

  const config = await loadConfig($)
  const existing = config.effective.get(name)
  const entry = entryFrom(e, existing?.entry)
  if (!entry.host) return fail('[config] wizard needs host (address or IP)')
  if (entry.port !== undefined && (entry.port < 1 || entry.port > 65535)) {
    return fail('[config] port must be 1-65535')
  }
  if ((entry.auth ?? 'agent') === 'key' && !entry.identityFile) {
    return fail('[config] auth=key needs identityFile (or use auth=agent)')
  }

  const scopeAnswer = str(e.scope)
  let scope: Scope
  if (scopeAnswer === 'project' || scopeAnswer === 'global') {
    scope = scopeAnswer
  } else {
    let picked: string
    try {
      picked = await $.ui.ask('Where should this host be saved?', [
        'Project (.claude, this machine only)',
        'Global (~/.claude, every project)',
      ])
    } catch {
      return fail(
        '[config] nobody can be asked in this session; pass scope: "project" or "global"',
      )
    }
    scope = picked.startsWith('Project') ? 'project' : 'global'
  }

  const summary = [
    `name:   ${name}`,
    `host:   ${entry.host}`,
    `user:   ${entry.user ?? '(default)'}`,
    `port:   ${entry.port ?? 22}`,
    `auth:   ${entry.auth ?? 'agent'}`,
    entry.identityFile ? `key:    ${entry.identityFile}` : '',
    entry.password ? `secret: ${isPlaintextSecret(entry.password) ? 'password (will be encrypted)' : entry.password.startsWith('env:') ? entry.password : 'stored secret'}` : '',
    entry.proxyJump ? `via:    ${entry.proxyJump}` : '',
    `save:   ${scope === 'project' ? PROJECT_REL : '~/.claude/ssh-hosts.json'}`,
  ]
    .filter(Boolean)
    .join('\n')

  let confirmed: string
  try {
    confirmed = await $.ui.ask(`Save this host?\n\n${summary}`, ['Save', 'Cancel'])
  } catch {
    confirmed = 'Save'
  }
  if (confirmed !== 'Save') return answer('cancelled; nothing was written')

  const saved = await persistHost($, options, { name, scope, entry: entry as HostEntry })
  return answer(describeSaved(name, saved.entry, saved.path, saved.git))
}

interface ExecOutcome {
  name: string
  text: string
  isError: boolean
}

async function runExecOne(
  $: EngineInterface,
  config: LoadedConfig,
  node: string,
  name: string,
  e: Record<string, unknown>,
  options: Record<string, unknown>,
  seconds: number,
): Promise<ExecOutcome> {
  let target: LoadedHost
  try {
    target = resolveHost(config, name)
  } catch (error) {
    return { name, text: `[config] ${(error as Error).message}`, isError: true }
  }

  const started = Date.now()
  try {
    const result = await runHelper(
      $,
      node,
      'exec',
      {
        host: toHelperHost(target.entry),
        jumpHosts: jumpMap(config),
        command: str(e.command),
        cwd: str(e.cwd),
        env: isRecord(e.env) ? e.env : undefined,
        pty: e.pty === true,
        sudo: e.sudo === true,
        sudoUser: str(e.sudoUser),
        sudoPassword: target.entry.sudoPassword,
        timeoutMs: seconds * 1000,
        allowCmdSecrets: allowCmd(options),
      },
      seconds * 1000 + 15_000,
    )

    if (!result.ok) {
      return {
        name,
        text: `[${result.code ?? 'error'}] ${String(result.message ?? '')}`,
        isError: true,
      }
    }
    await pinHostKey($, config, target, result.hostKey)
    return {
      name,
      text: clip(renderExec(result), 16_000),
      isError: result.exitCode !== 0,
    }
  } catch (error) {
    return { name, text: `[error] ${(error as Error).message}`, isError: true }
  } finally {
    $.ui.log(`exec ${name} ${Date.now() - started}ms`, { to: 'debug' })
  }
}

async function handleExec(
  $: EngineInterface,
  e: Record<string, unknown>,
  options: Record<string, unknown>,
) {
  const command = str(e.command)
  if (!command) return fail('[config] exec needs command')

  const config = await loadConfig($)
  PANEL.hosts = config.all

  let names: string[]
  try {
    names = hostTargets(e, config)
  } catch (error) {
    return fail(`[config] ${(error as Error).message}`)
  }

  const blocked = await authorise($, T.exec, { host: e.host, group: e.group, command })
  if (blocked) return fail(`[denied] ${blocked}`)

  const node = await requireNode($, nodeBin(options))
  const seconds = timeoutSeconds(options, e.timeoutSec)

  $.ui.status(
    names.length > 1
      ? `ssh: ${names.length} hosts › ${(command.split('\n')[0] ?? '').slice(0, 40)}`
      : `ssh: ${names[0]} › ${(command.split('\n')[0] ?? '').slice(0, 48)}`,
  )
  try {
    const outcomes = await mapLimit(names, 4, name =>
      runExecOne($, config, node, name, e, options, seconds),
    )
    if (outcomes.length === 1) {
      const only = outcomes[0] as ExecOutcome
      return only.isError ? fail(only.text) : answer(only.text)
    }
    const text = outcomes.map(item => `== ${item.name} ==\n${item.text}`).join('\n\n')
    return outcomes.some(item => item.isError) ? fail(text) : answer(text)
  } finally {
    $.ui.status(undefined)
  }
}

function newJobId(): string {
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`
}

async function handleRun(
  $: EngineInterface,
  e: Record<string, unknown>,
  options: Record<string, unknown>,
) {
  const name = str(e.host)
  if (!name) return fail('[config] run needs host')
  const command = str(e.command)
  if (!command) return fail('[config] run needs command')

  const config = await loadConfig($)
  const target = resolveHost(config, name)
  const blocked = await authorise($, T.run, { host: name, command })
  if (blocked) return fail(`[denied] ${blocked}`)

  const node = await requireNode($, nodeBin(options))
  const job = str(e.job) ?? newJobId()

  const result = await runHelper(
    $,
    node,
    'run',
    {
      host: toHelperHost(target.entry),
      jumpHosts: jumpMap(config),
      job,
      command,
      cwd: str(e.cwd),
      sudo: e.sudo === true,
      sudoUser: str(e.sudoUser),
      sudoPassword: target.entry.sudoPassword,
      allowCmdSecrets: allowCmd(options),
    },
    60_000,
  )
  if (!result.ok) return fail(`[${result.code ?? 'error'}] ${String(result.message ?? '')}`)

  await pinHostKey($, config, target, result.hostKey)
  JOBS.set(job, { id: job, host: name, command, startedAt: Date.now(), offset: 0 })
  invalidate($)

  return answer(
    `job ${job} started on ${name} (pid ${String(result.pid)})\n` +
      `  dir: ${String(result.dir)}\n` +
      `  follow with: logs { "host": "${name}", "job": "${job}", "waitSec": 30 }`,
  )
}

async function handleLogs(
  $: EngineInterface,
  e: Record<string, unknown>,
  options: Record<string, unknown>,
) {
  const name = str(e.host)
  const job = str(e.job)
  if (!name || !job) return fail('[config] logs needs host and job')

  const config = await loadConfig($)
  const target = resolveHost(config, name)
  const node = await requireNode($, nodeBin(options))
  const tracked = JOBS.get(job)
  const since = num(e.since) ?? tracked?.offset ?? 0

  const result = await runHelper(
    $,
    node,
    'logs',
    {
      host: toHelperHost(target.entry),
      jumpHosts: jumpMap(config),
      job,
      since,
      waitSec: num(e.waitSec),
      maxBytes: num(e.maxBytes),
      allowCmdSecrets: allowCmd(options),
    },
    120_000,
  )
  if (!result.ok) return fail(`[${result.code ?? 'error'}] ${String(result.message ?? '')}`)

  if (tracked) tracked.offset = Number(result.offset ?? since)
  const state = result.isRunning ? 'running' : `exited ${String(result.exitCode)}`
  const head = `job ${job} on ${name}: ${state}  offset=${String(result.offset ?? since)} of ${String(result.size ?? 0)}`
  const body = String(result.text ?? '')
  const tail = result.isTruncated ? '\n[more output available: call logs again]' : ''

  return answer(`${head}\n--- output ---\n${body || '(no new output)'}${tail}`)
}

async function handleKill(
  $: EngineInterface,
  e: Record<string, unknown>,
  options: Record<string, unknown>,
) {
  const name = str(e.host)
  const job = str(e.job)
  if (!name || !job) return fail('[config] kill needs host and job')

  const config = await loadConfig($)
  const target = resolveHost(config, name)
  const node = await requireNode($, nodeBin(options))

  const result = await runHelper(
    $,
    node,
    'kill',
    {
      host: toHelperHost(target.entry),
      jumpHosts: jumpMap(config),
      job,
      signal: str(e.signal),
      allowCmdSecrets: allowCmd(options),
    },
    60_000,
  )
  if (!result.ok) return fail(`[${result.code ?? 'error'}] ${String(result.message ?? '')}`)

  JOBS.delete(job)
  invalidate($)
  return answer(`job ${job}: ${String(result.state ?? 'signalled')} (pid ${String(result.pid)})`)
}

async function handleRead(
  $: EngineInterface,
  e: Record<string, unknown>,
  options: Record<string, unknown>,
) {
  const name = str(e.host)
  const remotePath = str(e.path)
  if (!name || !remotePath) return fail('[config] read needs host and path')

  const config = await loadConfig($)
  const target = resolveHost(config, name)
  const node = await requireNode($, nodeBin(options))

  const result = await runHelper(
    $,
    node,
    'read',
    {
      host: toHelperHost(target.entry),
      jumpHosts: jumpMap(config),
      path: remotePath,
      offset: num(e.offset),
      tailBytes: num(e.tailBytes),
      maxBytes: num(e.maxBytes),
      allowCmdSecrets: allowCmd(options),
    },
    120_000,
  )
  if (!result.ok) return fail(`[${result.code ?? 'error'}] ${String(result.message ?? '')}`)

  const text = String(result.text ?? '')
  const head =
    `${remotePath}  ${String(result.size ?? 0)} bytes  from ${String(result.offset ?? 0)}` +
    (result.isTruncated ? '  [truncated]' : '')
  return answer(`${head}\n---\n${text}`)
}

async function handleTransfer(
  $: EngineInterface,
  e: Record<string, unknown>,
  options: Record<string, unknown>,
  direction: 'put' | 'get',
) {
  const name = str(e.host)
  if (!name) return fail(`[config] ${direction} needs host`)
  const local = paths(e.local)
  const remote = paths(e.remote)
  if (!local || !remote) return fail('[config] local and remote are required (a path or a list of paths)')

  const config = await loadConfig($)
  const target = resolveHost(config, name)

  const blocked = await authorise($, direction === 'put' ? T.upload : T.download, {
    host: name,
    local: e.local,
    remote: e.remote,
  })
  if (blocked) return fail(`[denied] ${blocked}`)

  const node = await requireNode($, nodeBin(options))
  const seconds = clamp(num(e.timeoutSec) ?? (Number(options.defaultTimeoutSec) || 120), 30, 590)

  $.ui.status(
    `ssh: ${name} › ${direction} ${local.length > 1 ? `${local.length} files` : basenameOf(local[0])}`,
  )
  try {
    const request = {
      host: toHelperHost(target.entry),
      jumpHosts: jumpMap(config),
      local,
      remote,
      recursive: e.recursive === true,
      mkdirs: e.mkdirs !== false,
      resume: e.resume !== false,
      restart: e.restart === true,
      maxMs: Math.max(5_000, seconds * 1000 - 15_000),
      allowCmdSecrets: allowCmd(options),
    }

    const arrow = direction === 'put' ? '↑' : '↓'
    const callId = typeof e.tool_use_id === 'string' ? e.tool_use_id : undefined
    const result = await runHelperStreaming($, node, direction, request, line => {
      const total = line.total ?? 0
      const sent = line.transferred ?? 0
      const pct = total > 0 ? Math.floor((sent / total) * 100) : 0
      const text = `ssh ${arrow} ${name} › ${basenameOf(line.file)} ${pct}% ${formatBytes(sent)} / ${formatBytes(total)}`
      $.ui.status(text)
      if (callId) {
        try {
          $.ui.notice(callId, text)
        } catch {
          // no open dialog to hang it under
        }
      }
    })
    if (!result.ok) return fail(`[${result.code ?? 'error'}] ${String(result.message ?? '')}`)
    await pinHostKey($, config, target, result.hostKey)

    const text = renderTransfer(name, direction, result)
    return result.incomplete ? fail(text) : answer(text)
  } finally {
    $.ui.status(undefined)
  }
}

function basenameOf(path: string | undefined): string {
  if (!path) return ''
  return path.replace(/\\/g, '/').split('/').pop() ?? path
}

function waitReady(stream: ReturnType<typeof spawnHelper>, ms: number) {
  return new Promise<{ ok: boolean; message: string; port?: number }>(resolve => {
    let buffer = ''
    let settled = false

    const finish = (value: { ok: boolean; message: string; port?: number }) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(value)
    }

    const timer = setTimeout(
      () => finish({ ok: false, message: `tunnel did not come up within ${ms} ms` }),
      ms,
    )

    void (async () => {
      let stderr = ''
      try {
        for await (const chunk of stream) {
          if (chunk.stream === 'stderr') {
            stderr += chunk.text
            continue
          }
          buffer += chunk.text
          let index = buffer.indexOf('\n')
          while (index >= 0) {
            const line = buffer.slice(0, index).trim()
            buffer = buffer.slice(index + 1)
            index = buffer.indexOf('\n')
            if (!line) continue
            try {
              const parsed = JSON.parse(line) as { ok?: boolean; ready?: boolean; port?: number; message?: string }
              if (parsed.ready) finish({ ok: true, message: line, port: parsed.port })
              else if (parsed.ok === false) finish({ ok: false, message: parsed.message ?? line })
            } catch {
              // ignore non-JSON lines
            }
          }
        }
        finish({ ok: false, message: stderr.trim() || 'the tunnel process exited' })
      } catch (error) {
        finish({ ok: false, message: error instanceof Error ? error.message : String(error) })
      }
    })()
  })
}

async function handleTunnel($: EngineInterface, e: Record<string, unknown>, options: Record<string, unknown>) {
  const action = str(e.action) ?? 'list'

  if (action === 'list') {
    if (!TUNNELS.size) return answer('no active tunnels')
    const now = Date.now()
    const rows = [...TUNNELS.values()].map(t => {
      const age = Math.round((now - t.startedAt) / 1000)
      return `${t.id}  ${t.type.padEnd(7)}  ${t.spec}  host=${t.host}  up=${age}s`
    })
    return answer(rows.join('\n'))
  }

  if (action === 'stop') {
    const id = str(e.id) ?? [...TUNNELS.keys()].pop()
    if (!id) return fail('[config] no active tunnels')
    const tunnel = TUNNELS.get(id)
    if (!tunnel) return fail(`[config] unknown tunnel "${id}"`)
    TUNNELS.delete(id)
    try {
      await tunnel.stream.return({ code: null, signal: 'SIGTERM' })
    } catch {
      // already gone
    }
    $.ui.status(TUNNELS.size ? `ssh: ${TUNNELS.size} tunnels` : undefined)
    return answer(`stopped tunnel ${id}`)
  }

  if (action !== 'start') return fail(`[config] unknown action "${action}"`)

  const name = str(e.host)
  if (!name) return fail('[config] tunnel start needs host')
  const type = str(e.type)
  if (type !== 'local' && type !== 'remote' && type !== 'dynamic') {
    return fail('[config] tunnel type must be local, remote or dynamic')
  }

  const config = await loadConfig($)
  const target = resolveHost(config, name)

  const blocked = await authorise($, T.tunnel, inputOf(e))
  if (blocked) return fail(`[denied] ${blocked}`)

  const node = await requireNode($, nodeBin(options))
  const localPort = num(e.localPort) ?? (type === 'dynamic' ? 1080 : 0)

  const request = {
    host: toHelperHost(target.entry),
    jumpHosts: jumpMap(config),
    allowCmdSecrets: allowCmd(options),
    tunnel: {
      type,
      bindAddress: str(e.bindAddress) ?? '127.0.0.1',
      localPort,
      remoteHost: str(e.remoteHost),
      remotePort: num(e.remotePort),
    },
  }

  const stream = spawnHelper($, node, 'tunnel', request)
  const ready = await waitReady(stream, 10_000)
  if (!ready.ok) {
    await stream.return({ code: null, signal: 'SIGTERM' }).catch(() => undefined)
    return fail(`[network] ${ready.message}`)
  }

  tunnelSeq += 1
  const id = `t${tunnelSeq}`
  const spec =
    type === 'dynamic'
      ? `socks5 ${str(e.bindAddress) ?? '127.0.0.1'}:${ready.port ?? localPort}`
      : type === 'local'
        ? `${str(e.bindAddress) ?? '127.0.0.1'}:${ready.port ?? localPort} → ${str(e.remoteHost) ?? '127.0.0.1'}:${String(num(e.remotePort) ?? '')}`
        : `remote :${ready.port ?? num(e.remotePort)} → ${str(e.remoteHost) ?? '127.0.0.1'}:${String(num(e.remotePort) ?? '')}`

  TUNNELS.set(id, { id, host: name, type, spec, startedAt: Date.now(), stream })
  $.ui.status(`ssh: ${TUNNELS.size} tunnel${TUNNELS.size === 1 ? '' : 's'}`)

  return answer(`tunnel ${id} up\n  ${type}  ${spec}\n  host=${name}`)
}

async function handleDoctor($: EngineInterface, e: Record<string, unknown>, options: Record<string, unknown>) {
  const lines: string[] = []
  const node = await resolveNode($, nodeBin(options))
  lines.push(node ? `node: ${node}` : 'node: NOT FOUND — ssh-tools cannot run the helper')

  if (node) {
    const info = await runHelper($, node, 'doctor', {}, 30_000)
    if (info.ok) {
      lines.push(`platform: ${String(info.platform)} ${String(info.arch)}`)
      lines.push(`node runtime: ${String(info.node)}`)
      const backends = info.backends as Record<string, boolean> | undefined
      if (backends) {
        lines.push(
          `secret backends: ${Object.entries(backends)
            .map(([key, value]) => `${key}=${value ? 'yes' : 'no'}`)
            .join(' ')}`,
        )
      }
      lines.push(`ssh-agent: ${info.sshAuthSock ? String(info.sshAuthSock) : 'not detected'}`)
    } else {
      lines.push(`helper: FAILED — ${String(info.code)}: ${String(info.message)}`)
    }
  }

  const config = await loadConfig($)
  for (const [label, path] of Object.entries(config.files)) {
    const exists = await $.fs.exists(path).catch(() => false)
    lines.push(`${label}: ${exists ? 'present' : 'missing'}  ${path}`)
  }

  const plain = config.all.filter(
    host =>
      host.scope !== 'ssh-config' &&
      (isPlaintextSecret(host.entry.password) || isPlaintextSecret(host.entry.passphrase)),
  )
  lines.push(
    plain.length
      ? `warning: plaintext secrets in ${plain.map(h => h.name).join(', ')} — re-save to encrypt them`
      : 'secrets: no plaintext secrets found',
  )

  const unpinned = config.all.filter(host => host.scope !== 'ssh-config' && !host.entry.hostKey)
  lines.push(
    unpinned.length
      ? `host keys: ${unpinned.length} host(s) not pinned yet (pinned on first connect): ${unpinned.map(h => h.name).join(', ')}`
      : 'host keys: all stored hosts are pinned',
  )

  lines.push(`hosts: ${config.all.length} (${[...config.effective.keys()].length} usable)`)
  lines.push(`active tunnels: ${TUNNELS.size}`)

  let version = 'unknown'
  try {
    const v = await $.session.version()
    version = v.version
  } catch {
    // engine without version
  }
  lines.push(`claude code: ${version}`)

  return answer(lines.join('\n'))
}

// ---------------------------------------------------------------- registration

function toolSpecs() {
  return [
    {
      name: 'list',
      description:
        'List configured SSH hosts with their scope (project, global, or ssh-config), auth method and connection details. Never reveals secrets.',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Only show this host' },
          scope: {
            type: 'string',
            enum: ['all', 'global', 'project', 'ssh-config'],
            description: 'Filter by where the host is defined',
          },
          group: { type: 'string', description: 'Only hosts tagged with this group' },
        },
      },
    },
    {
      name: 'host',
      description:
        'Save, remove or trust an SSH host. Saved hosts persist in a JSON file; passwords and passphrases are encrypted with the platform keystore (DPAPI on Windows).',
      inputSchema: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['save', 'remove', 'trust'], description: 'Default save' },
          scope: { type: 'string', enum: ['global', 'project'], description: 'Which file to write' },
          name: { type: 'string', description: 'Host alias used by every other tool' },
          host: { type: 'string', description: 'Address or IP' },
          port: { type: 'number', description: 'Default 22' },
          user: { type: 'string' },
          auth: {
            type: 'string',
            enum: ['agent', 'key', 'password', 'keyboard-interactive'],
          },
          identityFile: { type: 'string', description: 'Private key path (auth=key)' },
          passphrase: { type: 'string', description: 'Key passphrase; encrypted on save' },
          password: { type: 'string', description: 'Password; encrypted on save' },
          passwordEnv: { type: 'string', description: 'Read the password from this env var instead' },
          proxyJump: { type: 'string', description: 'Jump host alias' },
          groups: { type: 'array', items: { type: 'string' }, description: 'Tags for group fan-out' },
          sudoUser: { type: 'string', description: 'sudo target user, default root' },
          sudoPassword: { type: 'string', description: 'sudo password; encrypted on save' },
          note: { type: 'string', description: 'Free-form label shown by ssh_list' },
          hostKey: { type: 'string', description: 'For action=trust: SHA256:… fingerprint' },
        },
        required: ['name'],
      },
    },
    {
      name: 'wizard',
      description:
        'Guided host creation: validates the fields, asks where to save (project or global), confirms, writes the file, and keeps the project file out of git.',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          host: { type: 'string' },
          port: { type: 'number' },
          user: { type: 'string' },
          auth: { type: 'string', enum: ['agent', 'key', 'password', 'keyboard-interactive'] },
          identityFile: { type: 'string' },
          password: { type: 'string' },
          passwordEnv: { type: 'string' },
          proxyJump: { type: 'string' },
          note: { type: 'string' },
          scope: { type: 'string', enum: ['global', 'project'] },
        },
        required: ['name', 'host'],
      },
    },
    {
      name: 'exec',
      description:
        'Run a command on an SSH host and return exit code, stdout and stderr. Uses ssh2 directly: password, key, agent and keyboard-interactive all work, no local ssh binary needed.',
      inputSchema: {
        type: 'object',
        properties: {
          host: {
            oneOf: [
              { type: 'string' },
              { type: 'array', items: { type: 'string' } },
            ],
            description: 'Host alias, or several; runs them in parallel (4 at a time)',
          },
          group: { type: 'string', description: 'Run on every host in this group instead of naming hosts' },
          command: { type: 'string', description: 'Remote command' },
          timeoutSec: { type: 'number', description: 'Default 120, max 590' },
          cwd: { type: 'string', description: 'cd here before running' },
          env: { type: 'object', description: 'Extra environment variables' },
          pty: { type: 'boolean', description: 'Allocate a pseudo-terminal (sudo, installers, colour output)' },
          sudo: { type: 'boolean', description: 'Run through sudo -S using the host sudoPassword' },
          sudoUser: { type: 'string', description: 'sudo target user, default root' },
        },
        required: ['command'],
      },
      isDeferred: false,
    },
    {
      name: 'run',
      description:
        'Start a command on a host in the background and return a job id. Output goes to a file on the host; read it with logs, stop it with kill.',
      inputSchema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          command: { type: 'string' },
          cwd: { type: 'string' },
          sudo: { type: 'boolean' },
          sudoUser: { type: 'string' },
        },
        required: ['host', 'command'],
      },
    },
    {
      name: 'logs',
      description:
        'Read new output from a background job. Keeps its place, so calling it again returns only what is new. waitSec waits for the job to finish.',
      inputSchema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          job: { type: 'string' },
          since: { type: 'number', description: 'Byte offset; defaults to where the last call stopped' },
          waitSec: { type: 'number', description: 'Wait up to this long for the job to exit' },
          maxBytes: { type: 'number', description: 'Default 262144' },
        },
        required: ['host', 'job'],
      },
    },
    {
      name: 'kill',
      description: 'Stop a background job started with run.',
      inputSchema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          job: { type: 'string' },
          signal: { type: 'string', description: 'Default TERM' },
        },
        required: ['host', 'job'],
      },
    },
    {
      name: 'read',
      description:
        'Read a remote file without downloading it: a byte range, or the tail. Capped at 4 MiB per call.',
      inputSchema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          path: { type: 'string' },
          offset: { type: 'number', description: 'Start byte, default 0' },
          tailBytes: { type: 'number', description: 'Read the last N bytes instead' },
          maxBytes: { type: 'number', description: 'Default 262144, max 4194304' },
        },
        required: ['host', 'path'],
      },
    },
    {
      name: 'put',
      description: 'Upload one or many files or directories over SFTP. Resumes a partial upload from the remote size unless restart is set.',
      inputSchema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          local: {
            oneOf: [
              { type: 'string' },
              { type: 'array', items: { type: 'string' } },
            ],
            description: 'Local path, or a list. A list with one remote directory uploads into it.',
          },
          remote: {
            oneOf: [
              { type: 'string' },
              { type: 'array', items: { type: 'string' } },
            ],
            description: 'Remote path, or a list paired with local by index',
          },
          recursive: { type: 'boolean', description: 'Required for directories' },
          mkdirs: { type: 'boolean', description: 'Create remote directories (default true)' },
          resume: { type: 'boolean', description: 'Continue a partial file from its current size (default true)' },
          restart: { type: 'boolean', description: 'Ignore what is there and transfer from byte 0' },
          timeoutSec: { type: 'number', description: 'Default 120, max 590; a stopped transfer resumes next call' },
        },
        required: ['host', 'local', 'remote'],
      },
    },
    {
      name: 'get',
      description: 'Download one or many files or directories over SFTP. Resumes a partial download from the local size unless restart is set.',
      inputSchema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          remote: {
            oneOf: [
              { type: 'string' },
              { type: 'array', items: { type: 'string' } },
            ],
            description: 'Remote path, or a list. A list with one local directory downloads into it.',
          },
          local: {
            oneOf: [
              { type: 'string' },
              { type: 'array', items: { type: 'string' } },
            ],
            description: 'Local path, or a list paired with remote by index',
          },
          recursive: { type: 'boolean', description: 'Required for directories' },
          resume: { type: 'boolean', description: 'Continue a partial file from its current size (default true)' },
          restart: { type: 'boolean', description: 'Ignore what is there and transfer from byte 0' },
          timeoutSec: { type: 'number', description: 'Default 120, max 590; a stopped transfer resumes next call' },
        },
        required: ['host', 'remote', 'local'],
      },
    },
    {
      name: 'tunnel',
      description:
        'Start, stop or list SSH port forwardings: local (-L), remote (-R) and dynamic SOCKS5 (-D). Tunnels live until stopped or the session ends.',
      inputSchema: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['start', 'stop', 'list'] },
          host: { type: 'string' },
          type: { type: 'string', enum: ['local', 'remote', 'dynamic'] },
          bindAddress: { type: 'string', description: 'Default 127.0.0.1' },
          localPort: { type: 'number', description: '0 picks a free port' },
          remoteHost: { type: 'string' },
          remotePort: { type: 'number' },
          id: { type: 'string', description: 'For stop; defaults to the newest tunnel' },
        },
        required: ['action'],
      },
    },
    {
      name: 'doctor',
      description:
        'Diagnose the ssh-tools setup: node, helper, keystore backends, config files, plaintext secrets, pinned host keys and versions.',
      inputSchema: { type: 'object', properties: {} },
    },
  ]
}

export const register: Register = (on, options) => {
  const opts = options as Record<string, unknown>

  on('session.start', async ($, e, next) => {
    await loadConfig($)
      .then(config => {
        PANEL.hosts = config.all
      })
      .catch(() => undefined)

    const tools = toolSpecs()
    for (const spec of tools) {
      await $.tool.register({ ...spec, isDeferred: false })
    }

    await $.command.register({
      name: 'ssh',
      description: 'List SSH hosts and tunnels (/ssh add <name> <host> [user] to create one)',
      argumentHint: '[add <name> <host> [user]]',
    })
    await $.command.register({
      name: 'ssh-doctor',
      description: 'Check the ssh-tools setup',
    })

    return next(e)
  })

  on('session.end', async ($, e, next) => {
    for (const [id, tunnel] of TUNNELS) {
      TUNNELS.delete(id)
      await tunnel.stream.return({ code: null, signal: 'SIGTERM' }).catch(() => undefined)
    }
    $.ui.status(undefined)
    return next(e)
  })

  on('tool.call', { tool: T.list }, ($, e) => handleList($, e as Record<string, unknown>)).catch(
    ($, e, next) => (next.called ? next(e) : fail('[internal] ssh_list failed')),
  )

  on('tool.call', { tool: T.host }, ($, e) =>
    handleHost($, e as Record<string, unknown>, opts),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] ssh_host failed')))

  on('tool.call', { tool: T.wizard }, ($, e) =>
    handleWizard($, e as Record<string, unknown>, opts),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] ssh_wizard failed')))

  on('tool.call', { tool: T.exec }, ($, e) =>
    handleExec($, e as Record<string, unknown>, opts),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] ssh_exec failed')))

  on('tool.call', { tool: T.upload }, ($, e) =>
    handleTransfer($, e as Record<string, unknown>, opts, 'put'),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] ssh_put failed')))

  on('tool.call', { tool: T.download }, ($, e) =>
    handleTransfer($, e as Record<string, unknown>, opts, 'get'),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] ssh_get failed')))

  on('tool.call', { tool: T.tunnel }, ($, e) =>
    handleTunnel($, e as Record<string, unknown>, opts),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] ssh_tunnel failed')))

  on('tool.call', { tool: T.doctor }, ($, e) =>
    handleDoctor($, e as Record<string, unknown>, opts),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] ssh_doctor failed')))

  on('tool.call', { tool: T.run }, ($, e) =>
    handleRun($, e as Record<string, unknown>, opts),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] run failed')))

  on('tool.call', { tool: T.logs }, ($, e) =>
    handleLogs($, e as Record<string, unknown>, opts),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] logs failed')))

  on('tool.call', { tool: T.kill }, ($, e) =>
    handleKill($, e as Record<string, unknown>, opts),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] kill failed')))

  on('tool.call', { tool: T.read }, ($, e) =>
    handleRead($, e as Record<string, unknown>, opts),
  ).catch(($, e, next) => (next.called ? next(e) : fail('[internal] read failed')))

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const tunnels = [...TUNNELS.values()]
    const jobs = [...JOBS.values()].slice(-8)

    return (
      <Box flexDirection="column">
        <Text bold>ssh-tools</Text>
        <Text dimColor>{`hosts ${PANEL.hosts.length} · tunnels ${tunnels.length} · jobs ${jobs.length}`}</Text>
        {PANEL.hosts.length === 0 && <Text dimColor>no hosts configured</Text>}
        {PANEL.hosts
          .filter(host => !host.shadowed)
          .map(host => (
            <Text key={`host-${host.name}`}>
              {`${host.name}  ${host.scope}  ${host.entry.user ?? ''}@${host.entry.host}`}
            </Text>
          ))}
        {tunnels.length > 0 && <Text bold>tunnels</Text>}
        {tunnels.map(tunnel => (
          <Text key={tunnel.id}>{`${tunnel.id}  ${tunnel.type}  ${tunnel.spec}`}</Text>
        ))}
        {jobs.length > 0 && <Text bold>jobs</Text>}
        {jobs.map(job => (
          <Text key={job.id}>{`${job.id}  ${job.host}  ${job.command.slice(0, 40)}`}</Text>
        ))}
      </Box>
    )
  })

  on('command.run', { command: 'ssh' }, async ($, e) => {
    const args = (e.args ?? '').trim()
    const words = args.split(/\s+/).filter(Boolean)

    if (words[0] === 'add') {
      const [, name, host, user] = words
      if (!name || !host) return { text: 'usage: /ssh add <name> <host> [user]' }
      const answerText = await handleWizard(
        $,
        { name, host, user, auth: 'agent' } as Record<string, unknown>,
        opts,
      )
      return { text: textOf(answerText) }
    }

    const config = await loadConfig($)
    const first = words[0]
    if (first) {
      const host = config.effective.get(first)
      if (!host) return { text: `unknown host "${first}"` }
      return { text: `${host.name}  scope=${host.scope}\n  ${describeEntry(host.entry)}` }
    }

    PANEL.hosts = config.all
    void $.ui.open({ id: PANE, title: 'ssh' })

    let text = renderHosts(config)
    if (TUNNELS.size) {
      const rows = [...TUNNELS.values()].map(t => `  ${t.id}  ${t.type}  ${t.spec}`)
      text += `\n\nTunnels:\n${rows.join('\n')}`
    }
    return { text }
  })

  on('command.run', { command: 'ssh-doctor' }, async ($, e) => {
    const result = await handleDoctor($, {}, opts)
    return { text: textOf(result) }
  })
}

function textOf(result: { result?: unknown; deny?: string }): string {
  if (typeof result.deny === 'string') return result.deny
  const value = result.result
  if (typeof value === 'string') return value
  if (Array.isArray(value)) {
    return value
      .map(block =>
        typeof block === 'string' ? block : String((block as { text?: string }).text ?? ''),
      )
      .join('\n')
  }
  return ''
}
