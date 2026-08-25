# HexStrike AI 依赖与环境维护

本项目包含两个不同运行环境，依赖必须分开管理：

1. **Kali 工具执行端**：`server.py:8888`，负责调用安全工具；
2. **UI / Agent 编排端**：Flask-SocketIO 后端、LLMClient、MCP STDIO bridge 和 React 前端。

不要把 Kali 的安全工具依赖与 UI 端 Python 包混到同一个环境里。

## 1. 依赖文件

| 文件 | 用途 |
|---|---|
| `requirements-kali.txt` | Kali 服务端启动所需 Python 包 |
| `requirements-kali-optional.txt` | CTF / 逆向场景的重型可选包（pwntools、angr） |
| `kali-tools.json` | Kali 外部安全工具清单、APT 映射、外部安装说明、更新策略 |
| `scripts/check_kali_dependencies.py` | 只读检查 Python 包和安全工具是否可用 |
| `scripts/install_kali_dependencies.sh` | 分 profile 安装；默认 dry-run，必须加 `--apply` 才执行 |
| `scripts/snapshot_kali_environment.py` | 记录 Python 包版本、工具路径、APT 版本和二进制哈希 |
| `UI/backend/requirements.txt` | UI 后端 + Agent + MCP 依赖 |
| `UI/frontend/package.json` | React 运行依赖与 Node/npm 版本约束 |
| `UI/frontend/package-lock.json` | 前端精确依赖锁文件，部署时使用 `npm ci` |
| `UI/frontend/.nvmrc` | 推荐 Node 版本 |

## 2. Kali Python 环境

建议使用 Kali rolling + Python 3.11/3.12。不要向系统 Python 全局安装包：

```bash
cd /path/to/hexstrike-ai-master
python3 -m venv .venv-kali
source .venv-kali/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-kali.txt
python -m playwright install chromium
```

CTF / 逆向功能需要时再安装：

```bash
python -m pip install -r requirements-kali-optional.txt
```

`mitmproxy`、`playwright`、`angr` 等依赖较重，也容易受 Python 版本影响，所以与 Kali 系统 Python 隔离非常重要。

## 3. Kali 安全工具分档

默认推荐只装 `core,web`：

```bash
python3 scripts/check_kali_dependencies.py --profiles core,web
bash scripts/install_kali_dependencies.sh --profiles core,web
```

第二条命令默认只打印将执行的命令。确认无误后才真正安装：

```bash
bash scripts/install_kali_dependencies.sh \
  --profiles core,web \
  --update \
  --apply
```

完整 profile：

- `core`：服务最小核心与常用 CLI；
- `web`：Web 渗透与漏洞扫描；
- `network_ad`：网络、SMB、AD；
- `password`：口令与哈希；
- `binary_reverse`：Pwn / 逆向；
- `forensics`：取证与隐写；
- `cloud_container`：云与容器；
- `osint`：情报搜集；
- `exploitation`：Metasploit / ExploitDB；
- `wireless`：无线与抓包。

安装所有 APT 映射包：

```bash
bash scripts/install_kali_dependencies.sh --all --update --apply
```

不建议第一次就 `--all`：工具多、冲突概率高、安装耗时长，而且很多场景根本用不到。

## 4. 非 APT 工具

部分工具应从官方发行版、Go、Ruby gem、pipx 或容器安装，不能稳定地写进普通 APT/Python requirements：

- ProjectDiscovery：`nuclei`、`httpx`、`katana`、`subfinder`；
- Go 工具：`dalfox`、`gau`、`waybackurls`；
- Python CLI：`arjun`、`paramspider`、`autorecon`、`checkov`，建议 pipx；
- Ruby：`evil-winrm`、`one_gadget`、`zsteg`；
- 云/容器：Prowler、Trivy、Falco、Clair，部分更适合容器或官方仓库；
- Ghidra、Volatility 3 等存在特殊命令名和运行目录。

具体说明在 `kali-tools.json` 的 `external_install_notes` 中。尤其注意：项目需要的是 ProjectDiscovery 的 `httpx` 二进制，**不是同名 Python 包**。

## 5. 依赖检查

检查默认核心 + Web：

```bash
python3 scripts/check_kali_dependencies.py
```

检查指定 profile：

```bash
python3 scripts/check_kali_dependencies.py --profiles core,web,network_ad
```

检查全部并严格返回非零退出码：

```bash
python3 scripts/check_kali_dependencies.py --profiles all --strict
```

机器可读输出：

```bash
python3 scripts/check_kali_dependencies.py --profiles all --json
```

## 6. 工具升级与版本治理

Kali rolling 和安全工具更新很快，但不能在正式测试前盲目全量升级。推荐流程：

1. **升级前快照**：

   ```bash
   .venv-kali/bin/python scripts/snapshot_kali_environment.py \
     --profiles core,web \
     --output snapshots/before-update.json
   ```

2. 执行系统或工具升级：

   ```bash
   sudo apt update
   sudo apt full-upgrade
   nuclei -update
   nuclei -update-templates
   ```

3. 对外部二进制按官方渠道逐类升级；不要混用多个来源覆盖同一个命令。

4. 重新检查：

   ```bash
   .venv-kali/bin/python scripts/check_kali_dependencies.py --profiles core,web --strict
   ```

5. 在 DVWA / Juice Shop / VulnHub 等授权靶场跑冒烟测试。

6. 生成升级后快照并与升级前 diff：

   ```bash
   .venv-kali/bin/python scripts/snapshot_kali_environment.py \
     --profiles core,web \
     --output snapshots/after-update.json
   diff -u snapshots/before-update.json snapshots/after-update.json
   ```

只有靶场验证通过后，才把环境作为新的 known-good 基线。

## 7. UI 后端依赖

在 UI 主机上使用独立虚拟环境：

```bash
cd UI/backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

当前实际依赖已包含：

- Flask / Flask-SocketIO / Flask-Cors；
- `requests`（LLM HTTP 客户端）；
- `mcp`（STDIO MCP 客户端与 FastMCP bridge）；
- `numpy`（GraphRAG 强化学习优化器）；
- LangGraph / LangChain。

`eventlet` 已移出必装清单，因为 `app.py` 当前明确使用 `async_mode='threading'`。

## 8. React 前端依赖

建议 Node 22；项目包含 `.nvmrc`：

```bash
cd UI/frontend
nvm use
npm ci
npm run dev
```

生产构建验证：

```bash
npm run build
```

部署时优先 `npm ci`，不要使用 `npm install` 随意刷新锁文件。依赖升级应单独开分支，先执行：

```bash
npm audit
npm outdated
npm run build
```

不要直接运行 `npm audit fix --force`，它可能跨主版本升级并破坏现有前端。

## 9. 统一 Web 启动（推荐）

正式运行时，React 构建产物由 Flask 同源托管，不需要分别运行 Vite 和 Flask，也不需要 CLI 中转：

```text
1. Kali：.venv-kali/bin/python server.py --port 8888
2. 验证：curl http://<KALI_IP>:8888/health
3. UI 主机：配置 LLM 与 HEXSTRIKE_SERVER_URL
4. 首次：python run.py --build-ui
5. 后续：python run.py
6. 浏览器：http://localhost:5000
```

前端依赖未安装时：

```bash
python run.py --install-ui --build-ui
```

CLI 已降为可选 headless 入口：

```bash
python run.py --headless --server-url http://<KALI_IP>:8888
```

开发 React 时才使用 Vite，并显式配置后端：

```bash
cd UI/frontend
VITE_BACKEND_URL=http://localhost:5000 npm run dev
```

当前 `hexstrike_mcp.py` 由 `HexstrikeMcpClient` 按调用拉起，因此不要手工重复常驻启动；统一启动器会设置：

```bash
export HEXSTRIKE_MCP_AUTOSTART=0
```
