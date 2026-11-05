export type Scope = 'global' | 'project' | 'ssh-config'

export type AuthKind = 'agent' | 'key' | 'password' | 'keyboard-interactive'

export interface HostEntry {
  host: string
  port?: number
  user?: string
  auth?: AuthKind
  identityFile?: string
  /** secret reference: dpapi:v1:… | keychain:… | secret-tool:… | env:NAME | file:PATH | cmd:CMD */
  passphrase?: string
  password?: string
  proxyJump?: string
  hostKey?: string
  groups?: string[]
  sudoUser?: string
  sudoPassword?: string
  note?: string
  algorithms?: Record<string, unknown>
  remoteShell?: 'posix' | 'powershell'
}

export interface HostFile {
  version: number
  defaults?: Partial<HostEntry>
  hosts: Record<string, HostEntry>
}

export interface LoadedHost {
  name: string
  entry: HostEntry
  scope: Scope
  shadowed: boolean
}

export interface HostFiles {
  global: string
  project: string
}

export interface HelperResult {
  ok: boolean
  code?: string
  message?: string
  [key: string]: unknown
}
