# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-05

### Added

- Eight tools: `list`, `host`, `wizard`, `exec`, `put`, `get`, `tunnel`, `doctor`.
- Slash commands `/ssh` and `/ssh-doctor`.
- Project (`.claude/ssh-hosts.local.json`) and global (`~/.claude/ssh-hosts.json`) host scopes, merged
  with project precedence, plus read-only `~/.ssh/config` entries.
- Password, key, agent and keyboard-interactive authentication through ssh2, with no local `ssh` binary.
- Credential references: DPAPI, macOS Keychain, libsecret, `env:`, `file:`, opt-in `cmd:`.
- Host key trust-on-first-use with per-host pinning.
- SFTP uploads and downloads, one file or many, with per-file results.
- Resumable transfers: a partial file continues from its current size; `restart` forces byte 0.
- Live transfer progress under the tool call and in the status line.
- Local, remote and dynamic SOCKS5 tunnels with explicit stop and session-end cleanup.
- Background jobs: `run`, `logs` (incremental), `kill`.
- `read` for remote files without downloading.
- `pty` and `sudo` options on `exec`.
- Host groups and parallel multi-host `exec`.
- `/ssh` opens a pane with hosts, tunnels and jobs.
- Permission gate through `$.tool.check`, with an interactive confirmation fallback.
- `.gitignore` check when writing the project host file.

[0.1.0]: https://github.com/OWNER/ssh-tools/releases/tag/v0.1.0
