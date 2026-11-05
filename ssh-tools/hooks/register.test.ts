import { expect, test } from 'claude-code/testing'

const GLOBAL_PATH = 'C:/home/.claude/ssh-hosts.json'
const PROJECT_PATH = 'C:/repo/.claude/ssh-hosts.local.json'

const GLOBAL_FILE = JSON.stringify({
  version: 1,
  hosts: {
    prod: {
      host: '10.0.0.5',
      user: 'root',
      auth: 'key',
      identityFile: 'C:/home/.ssh/id_ed25519',
    },
    legacy: {
      host: '47.95.31.119',
      user: 'root',
      auth: 'password',
      password: 'dpapi:v1:U0VDUkVU',
    },
  },
})

const PROJECT_FILE = JSON.stringify({
  version: 1,
  hosts: {
    prod: { host: '10.0.0.9', user: 'deploy', auth: 'agent' },
  },
})

interface Mocks {
  run?: (argv: readonly string[], init: unknown) => Record<string, unknown>
  spawn?: (argv: readonly string[], input: string) => string
  check?: string
  askResult?: string
}

function boot(
  on: any,
  files: Record<string, string>,
  mocks: Mocks = {},
) {
  on('session.start', (_$: any, e: any) => ({ cwd: (e as { cwd?: string }).cwd ?? 'C:/repo' }))
  on('session.end', () => ({ value: undefined }) as any)
  on('tool.register', (_$: any, e: any) => ({ value: { tool: `mcp__ssh-tools__${(e as { name: string }).name}` } }))
  on('command.register', (_$: any, e: any) => ({ value: { command: (e as { name: string }).name } }))
  on('session.root', () => ({ value: 'C:/repo' }))
  on('env.get', (_$: any, e: any) => {
    const name = (e as { name: string }).name
    if (name === 'USERPROFILE') return { value: 'C:/home' }
    if (name === 'USERNAME') return { value: 'tester' }
    return { value: undefined }
  })
  on('fs.read', (_$: any, e: any) => {
    const path = (e as { path: string }).path
    return { value: files[path] ?? files[path.replace(/\\/g, '/')] ?? '' }
  })
  on('fs.write', () => ({ value: undefined }))
  on('fs.list', () => ({ value: [] }))
  on('fs.exists', (_$: any, e: any) => ({ value: (e as { path: string }).path in files }))
  on('fs.stat', () => ({ value: { kind: 'file', size: 1, mtimeMs: 0, isLink: false } }))
  on('tool.check', () => ({ decision: (mocks.check ?? 'allow') as 'allow' | 'ask' | 'deny' }))
  on('ui.status', () => ({ value: undefined }))

  on('process.spawn', async function* (_$: any, e: any) {
    const text = mocks.spawn ? mocks.spawn(e.argv, String(e.input ?? '')) : ''
    if (text) yield { stream: 'stdout', text }
    return { value: { code: 0, signal: null } }
  })

  on('process.run', (_$: any, e: any) => {
    const argv = (e as { argv: readonly string[] }).argv
    if (argv[1] === '--version') return { value: { exitCode: 0, stdout: 'v22.0.0', stderr: '' } }
    if (mocks.run) return { value: mocks.run(argv, (e as { init?: unknown }).init) }
    return { value: { exitCode: 0, stdout: '{"ok":true}', stderr: '' } }
  })
}

async function call($: any, name: string, input: Record<string, unknown> = {}) {
  const result = await $.tool.call({ tool: `mcp__ssh-tools__${name}`, ...input })
  const text = result.text ?? JSON.stringify(result.result ?? result)
  return { text, isError: result.isError === true || Boolean(result.deny) }
}

test('ssh_list merges project over global and marks the shadowed entry', async ($, on) => {
  boot(on, { [GLOBAL_PATH]: GLOBAL_FILE, [PROJECT_PATH]: PROJECT_FILE })
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  const { text } = await call($, 'list')

  expect(text).toContain('scope=project')
  expect(text).toContain('scope=global (shadowed)')
  expect(text).toContain('deploy@10.0.0.9')
})

test('ssh_list never prints a stored secret', async ($, on) => {
  boot(on, { [GLOBAL_PATH]: GLOBAL_FILE })
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  const { text } = await call($, 'list')

  expect(text).toContain('hasPassword')
  expect(text).not.toContain('dpapi:v1:')
  expect(text).not.toContain('U0VDUkVU')
})

test('ssh_exec sends the host and command to the helper and renders the exit', async ($, on) => {
  let seenArgv: readonly string[] = []
  let seenStdin = ''

  boot(
    on,
    { [GLOBAL_PATH]: GLOBAL_FILE },
    {
      run: (argv, init) => {
        seenArgv = argv
        seenStdin = String((init as { stdin?: string }).stdin ?? '')
        return {
          exitCode: 0,
          stdout: JSON.stringify({ ok: true, exitCode: 7, stdout: 'hello\n', stderr: 'warn\n' }),
          stderr: '',
        }
      },
    },
  )
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  const result = await call($, 'exec', { host: 'prod', command: 'echo hello' })

  expect(result.text).toContain('exit=7')
  expect(result.text).toContain('hello')
  expect(seenArgv[2]).toBe('exec')
  const request = JSON.parse(seenStdin) as { host: { host: string }; command: string }
  expect(request.host.host).toBe('10.0.0.5')
  expect(request.command).toBe('echo hello')
})

test('a denied permission check stops the call before the helper runs', async ($, on) => {
  let ran = false
  boot(
    on,
    { [GLOBAL_PATH]: GLOBAL_FILE },
    {
      check: 'deny',
      run: () => {
        ran = true
        return { exitCode: 0, stdout: '{"ok":true}', stderr: '' }
      },
    },
  )
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  const result = await call($, 'exec', { host: 'prod', command: 'id' })

  expect(ran).toBe(false)
  expect(result.text).toContain('denied')
})

test('ssh_wizard without a scope refuses when nobody can be asked', async ($, on) => {
  boot(on, { [GLOBAL_PATH]: GLOBAL_FILE })
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  const result = await call($, 'wizard', {
    name: 'newbox',
    host: '192.0.2.10',
    auth: 'agent',
  })

  expect(result.text).toContain('scope')
})

test('ssh_tunnel reports an empty registry and refuses to stop nothing', async ($, on) => {
  boot(on, { [GLOBAL_PATH]: GLOBAL_FILE })
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  const listed = await call($, 'tunnel', { action: 'list' })
  expect(listed.text).toContain('no active tunnels')

  const stopped = await call($, 'tunnel', { action: 'stop' })
  expect(stopped.text).toContain('no active tunnels')
})

test('put takes a list of paths and reports each file', async ($, on) => {
  let stdin = ''
  boot(
    on,
    { [GLOBAL_PATH]: GLOBAL_FILE },
    {
      spawn: (_argv, input) => {
        stdin = input
        return (
          JSON.stringify({
            ok: true,
            incomplete: false,
            files: [
              { local: 'C:/a.bin', remote: '/tmp/a.bin', status: 'done', bytes: 10, total: 10 },
              { local: 'C:/b.bin', remote: '/tmp/b.bin', status: 'resumed', bytes: 5, from: 5, total: 10 },
            ],
          }) + '\n'
        )
      },
    },
  )
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  const result = await call($, 'put', {
    host: 'prod',
    local: ['C:/a.bin', 'C:/b.bin'],
    remote: '/tmp',
  })

  const request = JSON.parse(stdin) as { local: string[]; remote: string[]; resume: boolean }
  expect(JSON.stringify(request.local)).toBe(JSON.stringify(['C:/a.bin', 'C:/b.bin']))
  expect(JSON.stringify(request.remote)).toBe(JSON.stringify(['/tmp']))
  expect(request.resume).toBe(true)
  expect(result.text).toContain('resumed')
  expect(result.text).toContain('/tmp/b.bin')
})

test('run starts a job and logs follows its output', async ($, on) => {
  const replies: Record<string, string> = {
    run: JSON.stringify({ ok: true, job: 'j1', dir: '/tmp/.ssh-tools/h/j1', pid: 4242 }),
    logs: JSON.stringify({
      ok: true,
      job: 'j1',
      text: 'building\ndone\n',
      offset: 14,
      size: 14,
      isRunning: false,
      exitCode: 0,
    }),
  }
  let op = ''

  boot(
    on,
    { [GLOBAL_PATH]: GLOBAL_FILE },
    {
      run: (argv) => {
        op = String(argv[2])
        return { exitCode: 0, stdout: replies[op] ?? '{"ok":true}', stderr: '' }
      },
    },
  )
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  const started = await call($, 'run', { host: 'prod', command: 'make build', job: 'j1' })
  expect(started.text).toContain('job j1')
  expect(started.text).toContain('4242')

  const followed = await call($, 'logs', { host: 'prod', job: 'j1' })
  expect(followed.text).toContain('exited 0')
  expect(followed.text).toContain('done')
  expect(op).toBe('logs')
})

test('read returns a remote file without downloading it', async ($, on) => {
  boot(
    on,
    { [GLOBAL_PATH]: GLOBAL_FILE },
    {
      run: () => ({
        exitCode: 0,
        stdout: JSON.stringify({
          ok: true,
          path: '/var/log/x.log',
          text: 'line one\n',
          offset: 0,
          size: 9,
          isTruncated: false,
        }),
        stderr: '',
      }),
    },
  )
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  const result = await call($, 'read', { host: 'prod', path: '/var/log/x.log' })
  expect(result.text).toContain('/var/log/x.log')
  expect(result.text).toContain('line one')
})

test('the ssh pane draws hosts on every surface', async ($, on) => {
  boot(on, { [GLOBAL_PATH]: GLOBAL_FILE })
  await $.session.start({ cwd: 'C:/repo', surface: 'terminal', isInteractive: true })

  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({
      plugin: 'ssh-tools',
      component: 'Pane',
      requestId: 'ssh-tools',
      props: {
        title: 'ssh',
        isFocused: false,
        bodyColumns: 60,
        placement: 'dock',
        scroll: { offset: 0, bodyRows: 20 },
        view: {},
      },
      surface,
    })

    const row = await ui.find({ type: 'Text', text: /prod/ })
    expect(row?.text).toContain('10.0.0.5')
    await ui.unmount()
  }
})
