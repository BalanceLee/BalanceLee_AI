<div align="center">
  <img src="images/logo.png" alt="BalanceLeeAI Logo" width="200" >
</div>

# BalanceLeeAI

[中文](README_CN.md) | [English](README.md)

## ⬇️ Quick Start (Windows)

Pre-built Windows binaries live in the **Releases** section (each >100MB, so they're not tracked in git).

1. Go to [**Releases**](../../releases/latest) and download from the latest release:
   - `balancelee-ai.exe`
   - `server.exe`
2. Drop both files into this project root (next to `config.yaml`).
3. Edit `config.yaml` and fill in your API keys (all blanked out by default).
4. Double-click `balancelee-ai.exe` to launch.

## 🔧 Build from Source

Requires **Go 1.25+**. Inside this repo:

```bash
go build -o balancelee-ai.exe ./cmd/server
```

For mainland China users behind a slow `go mod download`, set a proxy first:

```bash
go env -w GOPROXY=https://goproxy.cn,direct
```

---

<div align="center">

### System Dashboard Overview

<table>
<tr>
<td width="50%" align="center">
<strong>Light Mode</strong><br/>
<img src="./images/dashboard.png" alt="System Dashboard (Light)" width="100%">
</td>
<td width="50%" align="center">
<strong>Dark Mode</strong><br/>
<img src="./images/dark.png" alt="System Dashboard (Dark)" width="100%">
</td>
</tr>
</table>
*The dashboard provides a comprehensive overview of system runtime status, security vulnerabilities, tool usage, and knowledge base, helping users quickly understand the platform's core features and current state.*
