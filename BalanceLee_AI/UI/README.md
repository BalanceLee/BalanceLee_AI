# HexStrike AI - Web UI

专业级渗透测试平台 - React + Flask + WebSocket 实时通信

## 🎯 功能特性

- ✅ ChatGPT风格的对话界面
- ✅ 实时终端输出显示
- ✅ 漂亮的漏洞卡片展示
- ✅ EXP代码一键复制
- ✅ WebSocket实时通信
- ✅ 前后端分离架构

## 📁 目录结构

```
UI/
├── backend/              # Flask后端
│   ├── app.py           # Flask主应用
│   ├── orchestrator_wrapper.py  # 包装器
│   └── requirements.txt
│
└── frontend/            # React前端
    ├── src/
    │   ├── components/  # React组件
    │   ├── App.jsx
    │   └── main.jsx
    ├── package.json
    └── vite.config.js
```

## 🚀 快速开始

### 1. 统一启动（推荐）

从项目根目录运行：

```bash
# 首次或前端代码变更后
python run.py --install-ui --build-ui

# 后续启动
python run.py
```

React、Flask API 与 Socket.IO 将统一运行在 `http://localhost:5000`，不需要 CLI 中转，也不需要分别启动 Vite 与 Flask。

### 2. 前端开发模式（可选）

仅在修改 React 时使用：

```bash
cd UI/frontend
VITE_BACKEND_URL=http://localhost:5000 npm run dev
```

开发页面运行在 `http://localhost:5173`，后端仍为 `http://localhost:5000`。

### 3. 访问应用

正式模式打开: `http://localhost:5000`

## ⚙️ 配置

### 后端配置

在 `backend/app.py` 中修改：

```python
# 端口配置
socketio.run(app, host='0.0.0.0', port=5000)
```

### 前端配置

正式模式使用同源 Socket.IO，无需配置地址。开发模式通过环境变量指定：

```bash
VITE_BACKEND_URL=http://localhost:5000 npm run dev
```

### HexStrike服务端配置

设置环境变量：

```bash
# Windows
set HEXSTRIKE_SERVER_URL=http://127.0.0.1:8888

# Linux/Mac
export HEXSTRIKE_SERVER_URL=http://127.0.0.1:8888
```

## 📡 WebSocket事件

### 客户端 → 服务端

- `start_pentest` - 开始渗透测试
- `user_choice` - 用户选择（继续/停止/报告）
- `stop_pentest` - 停止测试

### 服务端 → 客户端

- `connected` - 连接成功
- `ai_message` - AI回复
- `ai_thinking` - AI思考中
- `tool_start` - 工具开始执行
- `tool_complete` - 工具执行完成
- `terminal_output` - 终端输出
- `vulnerability_found` - 发现漏洞
- `pause_for_input` - 暂停等待用户
- `test_complete` - 测试完成
- `error` - 错误

## 🎨 界面预览

### 左侧：对话面板
- 用户输入
- AI回复
- 工具执行状态
- 漏洞卡片展示
- EXP代码显示

### 右侧：终端面板
- 实时日志流
- 工具执行输出
- 进度指示
- 自动滚动

## 🔧 开发说明

### 添加新的WebSocket事件

1. 在 `backend/orchestrator_wrapper.py` 中添加 `emit()` 调用
2. 在 `frontend/src/App.jsx` 中添加事件监听器
3. 更新UI组件处理新事件

### 修改样式

所有CSS文件在 `frontend/src/` 和 `frontend/src/components/` 目录下

### 调试

- 后端日志：查看终端输出
- 前端日志：打开浏览器开发者工具 Console

## 📦 生产部署

### 构建前端

```bash
cd frontend
npm run build
```

构建产物在 `frontend/dist/` 目录

### 部署方式

1. **分离部署**：前端用Nginx，后端用Gunicorn
2. **集成部署**：Flask serve前端静态文件

## ⚠️ 注意事项

1. 确保 Kali 端 `server.py` 已在 8888 端口启动
2. 确保LLM API配置正确（OpenAI/DeepSeek等）
3. WebSocket需要稳定的网络连接
4. 长时间运行建议使用生产级WSGI服务器

## 🐛 常见问题

### 前端无法连接后端

检查：
- 后端是否启动
- BACKEND_URL配置是否正确
- 防火墙是否阻止5000端口

### 工具执行失败

检查：
- HexStrike服务端是否启动
- HEXSTRIKE_SERVER_URL环境变量是否设置
- 工具是否正确安装

### WebSocket断开

- 检查网络连接
- 查看后端日志
- 尝试刷新页面重新连接

## 📝 TODO

- [ ] 添加会话历史记录
- [ ] 支持导出PDF报告
- [ ] 添加用户认证
- [ ] 支持多用户隔离
- [ ] 添加工具配置界面
- [ ] 优化移动端体验

## 📄 License

MIT License
