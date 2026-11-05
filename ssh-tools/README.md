# ssh-tools

SSH for Claude Code: run commands, move files, and open tunnels on machines you already trust —
with hosts kept per project or globally, credentials encrypted at rest, and no local `ssh` binary required.

A Claude Code **mod** (a hooks-module plugin). It registers eight model-callable tools and two slash
commands, and runs a bundled Node helper that speaks SSH through [`ssh2`](https://github.com/mscdex/ssh2).

## Install

```
/plugin install ssh-tools --marketplace <owner>/<repo>
```

or, from a clone:

```
/plugin marketplace add <owner>/<repo>
/plugin install ssh-tools@<marketplace>
```

Local development:

```bash
claude --plugin-dir /path/to/ssh-tools
```

Requirements:

- **Node 18+** on `PATH` (the helper is bundled; no `npm install` on the user side)
- Claude Code 2.1.318 or newer (the mod API is early access and moves between releases)

## Tools

| Tool | What it does |
|---|---|
| `list` | Lists hosts with their scope (`project`, `global`, `ssh-config`), auth method and jump host. Never prints a secret. |
| `host` | `save`, `remove` or `trust` (pin a host key for) a host. |
| `wizard` | Guided creation: validates fields, asks where to save, confirms, writes, and keeps the project file out of git. |
| `exec` | Runs a command on one host, several in parallel, or a whole group; `pty` and `sudo` supported. |
| `run` | Starts a command in the background and returns a job id. |
| `logs` | Reads only what is new from a job, keeping its place; `waitSec` waits for it to finish. |
| `kill` | Stops a background job. |
| `read` | Reads a remote file (byte range or tail) without downloading it. |
| `put` | Uploads one file, many files, or a directory over SFTP. Streams with a live progress line and resumes a partial upload from the remote size. |
| `get` | Downloads one file, many files, or a directory. Resumes a partial download from the local size. |
| `tunnel` | `start` / `stop` / `list` local (`-L`), remote (`-R`) and dynamic SOCKS5 (`-D`) forwardings. |
| `doctor` | Diagnoses node, helper, keystore backend, config files, plaintext secrets, pinned keys and versions. |

Slash commands: `/ssh` (opens the panel, lists hosts and tunnels, or `/ssh add <name> <host> [user]`), `/ssh-doctor`.

## Hosts: two scopes

| Scope | File | Committed? |
|---|---|---|
| `project` | `<project>/.claude/ssh-hosts.local.json` | **No** — the wizard checks `.gitignore` and offers to add it |
| `global` | `%USERPROFILE%\.claude\ssh-hosts.json` (Windows) / `~/.claude/ssh-hosts.json` | Your choice |
| `ssh-config` | `~/.ssh/config`, parsed read-only | Already yours |

`project` overrides `global`; `list` marks a shadowed global entry as `scope=global (shadowed)`.
`~/.ssh/config` contributes `Host`, `HostName`, `User`, `Port`, `IdentityFile`, `ProxyJump` and `Include`.

```json
{
  "version": 1,
  "defaults": { "port": 22, "auth": "agent", "timeoutSec": 120 },
  "hosts": {
    "prod": {
      "host": "10.0.0.5",
      "user": "root",
      "auth": "key",
      "identityFile": "C:/Users/me/.ssh/id_ed25519",
      "proxyJump": "bastion",
      "note": "production"
    },
    "legacy": {
      "host": "47.95.31.119",
      "user": "root",
      "auth": "password",
      "password": "dpapi:v1:AQAAANCMnd8BFdERjHoAwE/Cl+s..."
    }
  }
}
```

## Authentication

| `auth` | Backend | Notes |
|---|---|---|
| `agent` | ssh2 agent | `SSH_AUTH_SOCK` on Unix; Pageant on Windows |
| `key` | `identityFile` + optional `passphrase` | A passphrase is supplied directly, so no agent is needed |
| `password` | ssh2 | Works headless; no terminal required |
| `keyboard-interactive` | ssh2 | Answers prompts with the stored password |

Passwords and passphrases accept a reference instead of a literal:

| Reference | Backend |
|---|---|
| `dpapi:v1:<base64>` | Windows DPAPI, current user |
| `keychain:<service>/<account>` | macOS `security` |
| `secret-tool:<attrs>` | Linux libsecret |
| `env:NAME` | Environment variable, nothing on disk |
| `file:<path>` | First line of a file; Unix mode must be `0600` |
| `cmd:<command>` | stdout of a local command — **off by default** (`allowCmdSecrets`) |
| plain text | Read only, reported by `doctor` and flagged by `list` |

Writing a host with a plaintext secret encrypts it before it reaches the file. Secrets travel to the
helper on **stdin**, never in argv, environment variables or temp files.

## Hosts, groups, pty and sudo

Tag hosts with `groups` and run a command across all of them:

```jsonc
exec { "group": "web", "command": "systemctl reload nginx" }
exec { "host": ["prod", "staging"], "command": "df -h /" }
```

`pty: true` allocates a pseudo-terminal for commands that behave differently without one.
`sudo: true` runs through `sudo -S` using the host's `sudoPassword` (a secret reference like any other):

```jsonc
host { "action": "save", "name": "prod", "sudoPassword": "env:PROD_SUDO" }
exec { "host": "prod", "command": "systemctl restart nginx", "sudo": true, "pty": true }
```

## Background jobs

`run` starts the command with `nohup` under its own session, writes every script to
`/tmp/.ssh-tools/<host>/<job>/` on the server, and returns a job id. `logs` reads from a saved byte
offset, so repeated calls return only new output. `kill` signals the process group.

```jsonc
run  { "host": "prod", "command": "apt-get update && apt-get -y upgrade" }
logs { "host": "prod", "job": "abc123", "waitSec": 30 }
kill { "host": "prod", "job": "abc123" }
```

## Panel

`/ssh` opens a pane showing hosts, live tunnels and jobs. It repaints when any of them change.

## Transfers

Pass one path or a list. A list against a single directory drops every file into it; two lists pair
by index.

```jsonc
{ "host": "prod", "local": ["build/app.tgz", "build/web.tgz"], "remote": "/srv/releases" }
{ "host": "prod", "remote": ["/srv/a.log", "/srv/b.log"], "local": "C:/logs" }
```

Every transfer is resumable. The helper compares the source and target sizes and continues from the
shorter one, so an interrupted or time-limited transfer picks up where it stopped:

- `resume` (default `true`) continues from the current target size
- `restart: true` ignores what is there and starts at byte 0
- a size mismatch after transfer is reported as a failure, never silently accepted
- `timeoutSec` (max 590) stops the helper cleanly — rerun the same call to resume

A progress line (`ssh ↑ prod › app.tgz 42% 12.3 MiB / 29.1 MiB`) is shown under the tool call while
it runs, and in the status line.

## Host keys

The first connection records the server fingerprint in `hostKey` (trust on first use). Every later
connection verifies it and refuses on mismatch — a changed key means a rebuilt server or a
man-in-the-middle. Re-pin deliberately:

```
host { "action": "trust", "name": "prod", "hostKey": "SHA256:..." }
```

## Security model

A hook that answers a tool call itself bypasses the engine's permission dialog, so ssh-tools builds
its own gate: before every executable action it asks `$.tool.check`, honours `deny`, and turns `ask`
into a confirmation dialog. Calls it cannot confirm are refused rather than run.

Other measures: no shell interpolation (ssh2 takes strings and objects), host aliases are validated,
`cmd:` secrets are opt-in, and every host file is chmod `600` / ACL-restricted after writing.

## Troubleshooting

Run `/ssh-doctor` first. Common results:

- `node: NOT FOUND` — install Node 18+ or set `nodeBin` in the plugin config.
- `auth` — the key is missing, the passphrase is wrong, or the server rejects the method.
- `hostkey` — pin the new fingerprint with `host trust` after verifying it out of band.
- `timeout` — raise `timeoutSec` (max 590) or check reachability.

## Development

```bash
npm install
npm run build        # bundles helper/src/index.mjs -> helper/ssh-helper.cjs
npm run typecheck    # needs .claude-plugin/types or the tsconfig paths in this repo
claude plugin validate .
claude plugin test .
```

## 中文快速开始

```
/ssh add prod 10.0.0.5 root          # 创建主机，向导会问保存到项目还是全局
exec { "host": "prod", "command": "uname -a" }
put  { "host": "prod", "local": "./build.tgz", "remote": "/tmp/build.tgz" }
tunnel { "action": "start", "host": "prod", "type": "dynamic", "localPort": 1080 }
tunnel { "action": "stop" }
```

项目级配置写在 `.claude/ssh-hosts.local.json`，向导会检查 `.gitignore`，密码用 DPAPI 加密后落盘。

## License

MIT.
