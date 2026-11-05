# Claude-Mod-ssh

[ssh-tools](ssh-tools/README.md) — a Claude Code mod that gives the model SSH: commands, transfers, tunnels, background jobs.

## 安装

```
/plugin install ssh-tools --marketplace moxisuki/claude-ssh-tools
```

本地开发：`claude --plugin-dir ssh-tools`

需要 Node 18+（helper 已打包，无需 npm install），Claude Code ≥ 2.1.318。

## 工具

| 工具 | 用途 |
|---|---|
| `list` / `host` / `wizard` | 主机清单、增删改、创建向导 |
| `exec` | 执行命令；支持多主机、分组、`pty`、`sudo` |
| `run` / `logs` / `kill` | 后台任务：启动、增量读日志、终止 |
| `read` | 直接读远端文件，不下载 |
| `put` / `get` | 多文件上传下载，断点续传，进度显示 |
| `tunnel` | 本地 / 远程 / SOCKS5 转发 |
| `doctor` | 环境自检 |

`/ssh` 打开面板（主机 · 隧道 · 任务），`/ssh-doctor` 自检。

## 要点

- 主机分项目级 `.claude/ssh-hosts.local.json` 与全局 `~/.claude/ssh-hosts.json`，项目级自动检查 `.gitignore`
- 密码 / 口令用 DPAPI、Keychain、libsecret 加密落盘，或以 `env:` / `file:` / `cmd:` 引用
- 认证走 ssh2：password、key、agent、keyboard-interactive，不依赖系统 ssh
- 主机指纹首次连接固定，之后强校验

## 开发

```bash
cd ssh-tools
npm install
npm run build          # 打包 helper
npm run typecheck
claude plugin validate .
claude plugin test .
```

## 许可

MIT
