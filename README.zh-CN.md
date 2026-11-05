# claude-ssh-tools

**给 Claude Code 的 SSH** —— 主机、命令、传输、隧道、后台任务，一个可安装的 mod。

[English](README.md) · [插件文档](ssh-tools/README.md)

## 安装

```
/plugin install ssh-tools --marketplace moxisuki/claude-ssh-tools
```

或者先加市场再按名安装：

```
/plugin marketplace add moxisuki/claude-ssh-tools
/plugin install ssh-tools@claude-ssh-tools
```

要求：**Node 18+**，Claude Code **2.1.318+**。SSH helper 已经打包在插件里，用户端不需要
`npm install`，也没有发布到 npm。

## 能力

| 工具 | 作用 |
|---|---|
| `list` | 主机清单，标出作用域（项目 / 全局 / ssh-config）、认证方式、分组 |
| `host` | 保存、删除、固定主机密钥 |
| `wizard` | 创建主机：校验、询问保存位置、保证不进 git |
| `exec` | 执行命令——单机、多机并行、按分组；支持 `pty`、`sudo` |
| `run` / `logs` / `kill` | 后台任务：启动、增量跟日志、终止 |
| `read` | 直接读远端文件，不下载 |
| `put` / `get` | 多文件上传下载，断点续传，实时进度 |
| `tunnel` | 本地（`-L`）、远程（`-R`）、动态 SOCKS5（`-D`）转发 |
| `doctor` | 环境自检：node、密钥库、配置文件、指纹状态 |

斜杠命令：`/ssh` 打开面板（主机 · 隧道 · 任务），`/ssh-doctor` 自检。

## 主机与凭据

| 作用域 | 文件 | 是否入库 |
|---|---|---|
| 项目 | `.claude/ssh-hosts.local.json` | 不入库——写入时检查 `.gitignore` |
| 全局 | `~/.claude/ssh-hosts.json` | 由你决定 |
| ssh-config | `~/.ssh/config` | 只读 |

项目级覆盖全局同名条目，被覆盖的全局条目在 `list` 里标 `(shadowed)`。
密码与口令以引用形式存储——Windows 用 DPAPI，macOS 用 Keychain，Linux 用 libsecret——也可以用
`env:`、`file:` 或需显式开启的 `cmd:`。明文在落盘前就会加密。

认证直接走 ssh2：password、key、agent、keyboard-interactive 都能在无终端环境工作，不依赖系统 `ssh`。
主机指纹首次连接时固定，之后每次校验。

## 安全

mod 自己答复工具调用会绕过引擎的权限弹窗，所以 ssh-tools 在执行前主动询问 `$.tool.check`，
尊重 `deny`，把 `ask` 变成确认对话框。秘密只经 helper 的 stdin 传递，不进 argv、不进环境变量。

## 开发

```bash
cd ssh-tools
npm install
npm run build        # 把 helper/src/index.mjs 打包成 helper/ssh-helper.cjs
npm run typecheck    # 需要引擎在 .claude-plugin/types 铺好的类型
claude plugin validate .
claude plugin test .
```

## 许可

MIT
