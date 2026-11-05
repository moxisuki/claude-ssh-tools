import type { EngineInterface } from 'claude-code'

import { parseSshConfig } from './sshconfig'
import type { HostEntry, HostFile, HostFiles, LoadedHost, Scope } from './types'

export const HOSTS_VERSION = 1
export const PROJECT_REL = '.claude/ssh-hosts.local.json'

export interface LoadedConfig {
  all: LoadedHost[]
  effective: Map<string, LoadedHost>
  files: HostFiles
  defaults: Partial<HostEntry>
}

export async function resolveHome($: EngineInterface): Promise<string> {
  const win = await $.env.get('USERPROFILE')
  if (win) return win.replace(/\\/g, '/')
  const unix = await $.env.get('HOME')
  if (unix) return unix.replace(/\\/g, '/')
  throw new Error('cannot locate the home directory (USERPROFILE / HOME are unset)')
}

export async function hostPaths($: EngineInterface): Promise<HostFiles> {
  const home = await resolveHome($)
  const root = await $.session.root()
  return {
    global: `${home}/.claude/ssh-hosts.json`,
    project: `${root.replace(/\\/g, '/')}/${PROJECT_REL}`,
  }
}

export async function readHostFile($: EngineInterface, path: string): Promise<HostFile | null> {
  const text = await $.fs.read(path).catch(() => null)
  if (text === null) return null
  try {
    const parsed = JSON.parse(text) as HostFile
    if (!parsed || typeof parsed !== 'object' || !parsed.hosts) return null
    return { version: parsed.version ?? HOSTS_VERSION, defaults: parsed.defaults, hosts: parsed.hosts }
  } catch {
    return null
  }
}

export async function writeHostFile(
  $: EngineInterface,
  path: string,
  file: HostFile,
): Promise<void> {
  const existing = await $.fs.read(path).catch(() => null)
  if (existing !== null) {
    await $.fs.write(`${path}.bak`, existing).catch(() => undefined)
  }
  await $.fs.write(path, JSON.stringify(file, null, 2) + '\n')
  await tighten($, path)
}

async function tighten($: EngineInterface, path: string): Promise<void> {
  const isWindows = (await $.env.get('USERPROFILE')) !== undefined
  if (isWindows) {
    const user = await $.env.get('USERNAME')
    if (!user) return
    await $.process
      .run(['icacls', path, '/inheritance:r', '/grant:r', `${user}:F`], { timeoutMs: 10_000 })
      .catch(() => undefined)
    return
  }
  await $.process.run(['chmod', '600', path], { timeoutMs: 10_000 }).catch(() => undefined)
}

export async function loadConfig($: EngineInterface): Promise<LoadedConfig> {
  const files = await hostPaths($)
  const home = await resolveHome($)

  const globalFile = await readHostFile($, files.global)
  const projectFile = await readHostFile($, files.project)

  const sshConfig = await parseSshConfig(
    p => $.fs.read(p).catch(() => null),
    async dir => {
      const entries = await $.fs.list(dir).catch(() => [])
      return entries.map(entry => entry.name)
    },
    home,
  )

  const all: LoadedHost[] = []
  const push = (hosts: Record<string, HostEntry>, scope: Scope, defaults?: Partial<HostEntry>) => {
    for (const [name, entry] of Object.entries(hosts)) {
      all.push({ name, entry: { ...defaults, ...entry }, scope, shadowed: false })
    }
  }

  push(sshConfig.hosts, 'ssh-config')
  if (globalFile) push(globalFile.hosts, 'global', globalFile.defaults)
  if (projectFile) push(projectFile.hosts, 'project', projectFile.defaults)

  const effective = new Map<string, LoadedHost>()
  for (const host of all) {
    const previous = effective.get(host.name)
    if (previous) previous.shadowed = true
    effective.set(host.name, host)
  }

  return {
    all,
    effective,
    files,
    defaults: { ...sshConfig.defaults, ...(globalFile?.defaults ?? {}), ...(projectFile?.defaults ?? {}) },
  }
}

export function resolveHost(config: LoadedConfig, name: string): LoadedHost {
  const host = config.effective.get(name)
  if (host) return host
  const names = [...config.effective.keys()]
  const hint = names.length ? ` Known hosts: ${names.join(', ')}` : ' No hosts are configured.'
  throw Object.assign(new Error(`unknown host "${name}".${hint}`), { code: 'config' })
}

export function saveHostEntry(
  file: HostFile | null,
  name: string,
  entry: Partial<HostEntry>,
): HostFile {
  const base: HostFile = file ?? { version: HOSTS_VERSION, hosts: {} }
  return {
    ...base,
    version: HOSTS_VERSION,
    hosts: { ...base.hosts, [name]: { ...base.hosts[name], ...entry } as HostEntry },
  }
}

export function removeHostEntry(file: HostFile | null, name: string): HostFile | null {
  if (!file || !file.hosts[name]) return null
  const hosts = { ...file.hosts }
  delete hosts[name]
  return { ...file, hosts }
}

// ---------------------------------------------------------------- gitignore

function coversGitignore(text: string, rel: string): boolean {
  const target = rel.replace(/\\/g, '/')
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const pattern = line.replace(/^!/, '')
    if (pattern === target) return !line.startsWith('!')
    if (pattern.endsWith('/') && target.startsWith(pattern)) return !line.startsWith('!')
    if (pattern.includes('*')) {
      const regex = new RegExp(
        '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$',
      )
      if (regex.test(target)) return !line.startsWith('!')
    }
  }
  return false
}

export interface IgnoreStatus {
  ignored: boolean
  added: boolean
  reason?: string
}

export async function checkIgnored($: EngineInterface, root: string, rel: string): Promise<IgnoreStatus> {
  const path = `${root.replace(/\\/g, '/')}/.gitignore`
  const text = await $.fs.read(path).catch(() => null)
  if (text === null) return { ignored: false, added: false, reason: 'no .gitignore in the project' }
  if (coversGitignore(text, rel)) return { ignored: true, added: false }
  return { ignored: false, added: false, reason: `${rel} is not listed in .gitignore` }
}

export async function addIgnore(
  $: EngineInterface,
  root: string,
  rel: string,
): Promise<IgnoreStatus> {
  const path = `${root.replace(/\\/g, '/')}/.gitignore`
  const text = await $.fs.read(path).catch(() => null)
  if (text === null) return { ignored: false, added: false, reason: 'no .gitignore in the project' }
  if (coversGitignore(text, rel)) return { ignored: true, added: false }
  const prefix = text.length && !text.endsWith('\n') ? '\n' : ''
  await $.fs.write(path, `${text}${prefix}\n# ssh-tools local hosts\n${rel}\n`)
  return { ignored: true, added: true }
}
