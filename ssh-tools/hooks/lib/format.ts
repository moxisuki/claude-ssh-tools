import type { LoadedConfig } from './config'
import type { HostEntry, LoadedHost, Scope } from './types'

export function answer(text: string) {
  return { result: text }
}

export function fail(text: string) {
  return { deny: text }
}

export function hasSecret(value: unknown): boolean {
  return typeof value === 'string' && value.length > 0
}

export function isPlaintextSecret(value: unknown): boolean {
  if (typeof value !== 'string' || !value) return false
  return !/^(dpapi:|keychain:|secret-tool:|env:|file:|cmd:)/.test(value)
}

export function identity(entry: HostEntry): string {
  const user = entry.user ? `${entry.user}@` : ''
  const port = entry.port && entry.port !== 22 ? `:${entry.port}` : ''
  return `${user}${entry.host}${port}`
}

export function describeEntry(entry: HostEntry): string {
  const parts = [identity(entry)]
  parts.push(`auth=${entry.auth ?? 'agent'}`)
  if (entry.identityFile) parts.push(`key=${basename(entry.identityFile)}`)
  if (hasSecret(entry.password)) {
    parts.push(isPlaintextSecret(entry.password) ? 'hasPassword(plaintext)' : 'hasPassword')
  }
  if (hasSecret(entry.passphrase)) {
    parts.push(isPlaintextSecret(entry.passphrase) ? 'hasPassphrase(plaintext)' : 'hasPassphrase')
  }
  if (entry.proxyJump) parts.push(`via=${entry.proxyJump}`)
  if (entry.groups?.length) parts.push(`groups=${entry.groups.join(',')}`)
  if (entry.note) parts.push(entry.note)
  return parts.join('  ')
}

function basename(path: string): string {
  return path.replace(/\\/g, '/').split('/').pop() ?? path
}

function pad(value: string, width: number): string {
  return value.length >= width ? value : value + ' '.repeat(width - value.length)
}

export function renderHosts(config: LoadedConfig, scope?: Scope): string {
  const rows = config.all
    .filter(host => !scope || host.scope === scope)
    .map(host => {
      const label = host.shadowed ? `scope=${host.scope} (shadowed)` : `scope=${host.scope}`
      return {
        name: host.name,
        scope: label,
        detail: describeEntry(host.entry),
      }
    })

  if (!rows.length) {
    const where = scope ? ` in scope ${scope}` : ''
    return `No hosts configured${where}.\n\nFiles:\n${fileLines(config)}`
  }

  const nameWidth = Math.max(...rows.map(row => row.name.length))
  const scopeWidth = Math.max(...rows.map(row => row.scope.length))

  const body = rows
    .map(row => `${pad(row.name, nameWidth)}  ${pad(row.scope, scopeWidth)}  ${row.detail}`)
    .join('\n')

  return `${body}\n\nFiles:\n${fileLines(config)}`
}

function fileLines(config: LoadedConfig): string {
  return [
    `  project  ${config.files.project}`,
    `  global   ${config.files.global}`,
    '  ssh-config entries are read-only; save one with ssh_wizard to make it editable.',
  ].join('\n')
}

export function renderExec(result: Record<string, unknown>): string {
  const exit = result.exitCode
  const signal = result.signal ? ` signal=${String(result.signal)}` : ''
  const out = String(result.stdout ?? '')
  const err = String(result.stderr ?? '')
  const truncOut = result.isStdoutTruncated ? ' [stdout truncated at 4 MiB]' : ''
  const truncErr = result.isStderrTruncated ? ' [stderr truncated at 4 MiB]' : ''

  return [
    `exit=${String(exit)}${signal}`,
    `--- stdout ---${truncOut}`,
    out,
    `--- stderr ---${truncErr}`,
    err,
  ].join('\n')
}

export function formatBytes(value: unknown): string {
  const n = typeof value === 'number' ? value : 0
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`
}

interface TransferFile {
  local?: string
  remote?: string
  status?: string
  bytes?: number
  total?: number
  from?: number
  code?: string
  message?: string
  reason?: string
}

export function renderTransfer(
  host: string,
  direction: 'put' | 'get',
  result: Record<string, unknown>,
): string {
  const files = Array.isArray(result.files) ? (result.files as TransferFile[]) : []
  const verb = direction === 'put' ? 'uploaded' : 'downloaded'
  const good = files.filter(file => file.status === 'done' || file.status === 'resumed')
  const skipped = files.filter(file => file.status === 'skipped')
  const bad = files.filter(
    file => file.status === 'failed' || file.status === 'stopped' || !file.status,
  )

  const header = [
    `${verb} ${good.length} file${good.length === 1 ? '' : 's'}`,
    skipped.length ? `${skipped.length} already complete` : '',
    bad.length ? `${bad.length} not transferred` : '',
    `→ ${host}`,
  ]
    .filter(Boolean)
    .join(', ')

  const rows = files.map(file => {
    const name = direction === 'put' ? (file.remote ?? file.local ?? '') : (file.local ?? file.remote ?? '')
    const where = direction === 'put' ? name : file.remote
    switch (file.status) {
      case 'done':
        return `  done     ${where}  ${formatBytes(file.total ?? file.bytes)}`
      case 'resumed':
        return `  resumed  ${where}  +${formatBytes(file.bytes)} from ${formatBytes(file.from)} of ${formatBytes(file.total)}`
      case 'skipped':
        return `  skipped  ${where}  already ${formatBytes(file.total)}`
      case 'failed':
        return `  failed   ${where}  [${file.code ?? 'error'}] ${file.message ?? ''}`
      case 'stopped':
        return `  stopped  ${where}  not attempted after a ${file.reason ?? 'failure'}`
      default:
        return `  ${String(file.status ?? 'unknown')}  ${where}`
    }
  })

  const note = bad.length
    ? '\n\nRun the same call again to resume: a partial file continues from its current size.'
    : ''

  return [header, ...rows].join('\n') + note
}
