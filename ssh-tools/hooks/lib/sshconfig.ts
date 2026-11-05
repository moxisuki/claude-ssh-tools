import type { HostEntry } from './types'

type ReadFile = (path: string) => Promise<string | null>
type ListDir = (path: string) => Promise<string[]>

const KEY_MAP: Record<string, keyof HostEntry> = {
  hostname: 'host',
  user: 'user',
  port: 'port',
  identityfile: 'identityFile',
  proxyjump: 'proxyJump',
}

function stripComment(line: string): string {
  let quote = false
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    if (ch === '"') quote = !quote
    else if (ch === '#' && !quote) return line.slice(0, i)
  }
  return line
}

function expandHome(value: string, home: string): string {
  if (value.startsWith('~/')) return `${home}/${value.slice(2)}`
  return value
}

function isPattern(name: string): boolean {
  return name.includes('*') || name.includes('?') || name.includes('!')
}

export interface ParsedConfig {
  hosts: Record<string, HostEntry>
  defaults: Partial<HostEntry>
}

export async function parseSshConfig(
  read: ReadFile,
  list: ListDir,
  home: string,
): Promise<ParsedConfig> {
  const hosts: Record<string, HostEntry> = {}
  let defaults: Partial<HostEntry> = {}
  const seen = new Set<string>()

  async function loadFile(path: string, depth: number): Promise<void> {
    if (depth > 8 || seen.has(path)) return
    seen.add(path)

    const text = await read(path)
    if (text === null) return

    let current: string[] | null = null
    let currentIsPattern = false
    let inMatch = false

    for (const rawLine of text.split(/\r?\n/)) {
      const line = stripComment(rawLine).trim()
      if (!line) continue

      const match = /^([A-Za-z]+)\s*(?:=\s*)?(.*)$/.exec(line)
      if (!match) continue
      const key = (match[1] ?? '').toLowerCase()
      const value = (match[2] ?? '').trim().replace(/^"(.*)"$/, '$1')
      if (!value && key !== 'host') continue

      if (key === 'host') {
        inMatch = false
        const names = value.split(/\s+/).filter(Boolean)
        currentIsPattern = names.some(isPattern)
        current = currentIsPattern ? null : names
        if (currentIsPattern && names.includes('*') && names.length === 1) current = []
        for (const name of current ?? []) {
          if (!hosts[name]) hosts[name] = { host: name }
        }
        continue
      }

      if (key === 'match') {
        inMatch = true
        current = null
        continue
      }

      if (key === 'include') {
        for (const token of value.split(/\s+/).filter(Boolean)) {
          const target = expandHome(token, home)
          if (target.includes('*')) {
            const cut = target.lastIndexOf('/')
            const dir = cut < 0 ? '.' : target.slice(0, cut)
            const pattern = target.slice(cut + 1).replace(/\*/g, '')
            const entries = await list(dir).catch(() => [])
            for (const name of entries) {
              if (!name.startsWith(pattern)) continue
              await loadFile(`${dir}/${name}`, depth + 1)
            }
          } else {
            await loadFile(target, depth + 1)
          }
        }
        continue
      }

      if (inMatch) continue

      const field = KEY_MAP[key]
      if (!field) continue

      const apply = (target: Partial<HostEntry>) => {
        if (field === 'port') target.port = Number.parseInt(value, 10) || 22
        else if (field === 'host') target.host = value
        else if (field === 'user') target.user = value
        else if (field === 'identityFile') target.identityFile = expandHome(value, home)
        else if (field === 'proxyJump') target.proxyJump = (value.split(',')[0] ?? '').split('@').pop()
      }

      if (current === null) continue
      if (current.length === 0) {
        apply(defaults)
        continue
      }
      for (const name of current) {
        const entry = hosts[name] ?? (hosts[name] = { host: name })
        apply(entry)
      }
    }
  }

  await loadFile(`${home}/.ssh/config`, 0)

  for (const [name, entry] of Object.entries(hosts)) {
    if (!entry.host || entry.host === name) entry.host = name
    if (defaults.user && !entry.user) entry.user = defaults.user
    if (defaults.port && !entry.port) entry.port = defaults.port
    if (defaults.identityFile && !entry.identityFile) entry.identityFile = defaults.identityFile
  }

  return { hosts, defaults }
}
