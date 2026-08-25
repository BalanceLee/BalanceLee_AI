# HexStrike LLM驱动的知识顾问系统 - 启动指南

## 🎯 系统概述

HexStrike现在集成了**LLM驱动的知识顾问系统**，这是一个革命性的AI辅助渗透测试框架。

### 核心理念：LLM Agent主导决策

- **🧠 LLM Agent = 船长**：拥有完全的决策权
- **📚 知识系统 = 顾问**：只提供建议和分析，不强制执行
- **🎯 目标**：让AI Agent能够自主思考和决策，而不是被规则束缚

## 🚀 快速启动

### 1. 启动HexStrike服务器

```bash
cd hexstrike-ai-master
.venv-kali/bin/python server.py --port 8888
```

服务器将在 `http://127.0.0.1:8888` 启动

### 2. 启动MCP客户端（用于AI Agent通信）

```bash
cd hexstrike-ai-master
python hexstrike_mcp.py
```

MCP服务器将为AI Agent提供工具接口

### 3. 测试Advisory系统

```bash
# 测试API端点
curl -X POST http://127.0.0.1:8888/api/advisory/provide \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://example.com",
    "context": {
      "current_phase": "discovery",
      "has_login_page": true,
      "technology_stack": ["PHP", "MySQL"]
    }
  }'
```

## 🧠 系统架构

### 多层智能决策架构

```
┌─────────────────────────────────────────────────────────────┐
│                    LLM Agent (决策者)                        │
│  "我要选择哪些工具？基于建议，我的推理是..."                    │
└─────────────────────────────────────────────────────────────┘
                              ↑
                         建议 (非命令)
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  知识顾问系统 (建议者)                        │
├─────────────────┬─────────────────┬─────────────────────────┤
│   GraphRAG      │  指纹识别引擎    │    路径模式匹配          │
│  (知识图谱)      │ (技术栈检测)     │   (历史成功路径)         │
├─────────────────┼─────────────────┼─────────────────────────┤
│  强化学习优化器   │   上下文分析     │    安全警告系统          │
│ (Multi-Armed    │  (阶段感知)      │   (WAF/IDS检测)         │
│   Bandit)       │                 │                        │
└─────────────────┴─────────────────┴─────────────────────────┘
```

### 核心组件

1. **AdvisorySystem** - 主控制器
2. **WebFingerprintExtractor** - 网页指纹识别
3. **PentestPathPattern** - 攻击路径模式匹配
4. **ToolSelectionBandit** - 强化学习优化器
5. **GraphRAG** - 知识图谱推理

## 🛠️ MCP工具使用

### get_pentest_advisory 工具

AI Agent可以通过MCP调用此工具获取建议：

```python
# AI Agent调用示例
result = get_pentest_advisory(
    target_url="https://target.com",
    current_phase="discovery",
    technology_stack="PHP,MySQL",
    has_login_page=True,
    executed_tools="nmap_scan,gobuster_scan"
)
```

### 返回的建议格式

```json
{
  "success": true,
  "advisory": {
    "current_situation": {
      "target": "https://target.com",
      "current_phase": "discovery",
      "discoveries": {...},
      "technology": {...}
    },
    "all_available_tools": [...],  // 所有工具，不过滤
    "recommendations": {
      "high_confidence": [
        {
          "tool_name": "sqlmap_scan",
          "advisory_score": 15.2,
          "reasons": [
            "Login forms are common SQL injection targets",
            "指纹特征匹配: has_login_form",
            "路径模式匹配: SQL Injection Discovery & Exploitation"
          ],
          "confidence": 0.85,
          "source": "Hybrid(GraphRAG+Fingerprint+PathPattern+RL)",
          "warnings": ["⚠️ This is an aggressive tool. Use with caution."]
        }
      ],
      "medium_confidence": [...],
      "low_confidence": [...],
      "exploratory": [...]
    },
    "knowledge": {
      "penetration_testing_principles": [...],
      "current_phase_guidance": {...},
      "vulnerability_indicators": [...],
      "common_attack_vectors": [...]
    },
    "warnings": [
      "⚠️ WAF detected: Cloudflare. Aggressive scanning may trigger blocking."
    ],
    "alerts": [
      "ℹ️ Technology stack not identified yet. Consider using fingerprinting tools first."
    ],
    "historical_paths": [
      {
        "name": "SQL Injection Discovery & Exploitation",
        "path": ["arjun_scan", "sqlmap_scan", "sqlmap_exploit"],
        "success_rate": 0.68,
        "match_score": 0.85,
        "next_tools": ["arjun_scan", "sqlmap_scan"]
      }
    ]
  }
}
```

## 🎯 LLM Agent使用指南

### 正确的使用方式

```
✅ 好的做法：
"基于advisory建议，我看到sqlmap_scan有高置信度(0.85)，
原因包括'Login forms are common SQL injection targets'。
考虑到目标有登录页面，我决定使用sqlmap_scan进行SQL注入测试。"

❌ 错误的做法：
"系统推荐了sqlmap_scan，所以我执行它。"
```

### LLM Agent决策流程

1. **获取建议** - 调用 `get_pentest_advisory`
2. **分析建议** - 查看recommendations、warnings、knowledge
3. **自主推理** - 基于建议和自己的判断
4. **做出决策** - 选择工具并解释原因
5. **执行工具** - 调用相应的工具
6. **反馈学习** - 系统会记录结果用于优化

## 🔧 配置选项

### Advisory系统配置

在 `advisory_system.py` 中可以调整：

```python
self.config = {
    "provide_all_tools": True,      # 提供全部工具
    "max_recommendations": 30,       # 最多推荐数量
    "min_confidence": 0.3,          # 最低置信度
    "use_fingerprinting": True,     # 启用指纹识别
    "use_path_patterns": True,      # 启用路径模式
    "use_rl_optimization": True,    # 启用强化学习
}
```

### 强化学习配置

```python
# 在 rl_optimizer.py 中
self.exploration_rate = 0.15  # 探索率 (ε-greedy)
self.confidence_level = 2.0   # UCB置信水平
```

## 📊 监控和调试

### 查看系统状态

```bash
# 检查服务器健康状态
curl http://127.0.0.1:8888/health

# 查看缓存统计
curl http://127.0.0.1:8888/api/cache/stats
```

### 日志监控

系统会输出详细的彩色日志：

```
🧠 Advisory provided for https://target.com - 25 tool suggestions
✅ Advisory generated successfully
  📊 Total suggestions: 25
  🎯 High confidence: 8, Medium confidence: 12
  ⚠️  Warnings: 2
    • WAF detected: Cloudflare. Aggressive scanning may trigger blocking.
  ℹ️  Alerts: 1
    • Technology stack not identified yet.
```

## 🚨 重要注意事项

### 1. 系统哲学
- **这不是自动化扫描器** - 这是AI Agent的智能顾问
- **LLM必须解释决策** - 不能只是"系统推荐了X"
- **建议可以被忽略** - LLM有完全的决策权

### 2. 安全考虑
- 系统会检测WAF并给出警告
- 攻击性工具会有明确标记
- 提供安全测试的最佳实践建议

### 3. 性能优化
- 使用缓存减少重复计算
- 强化学习会随时间改进建议质量
- 指纹识别提高上下文准确性

## 🔄 系统更新

当前版本：**v2.3.0** (集成Advisory System)

### 更新内容
- ✅ LLM驱动的知识顾问系统
- ✅ 多层智能决策架构
- ✅ 网页指纹识别引擎
- ✅ 攻击路径模式匹配
- ✅ 强化学习优化器
- ✅ MCP工具集成

## 🆘 故障排除

### 常见问题

1. **Advisory系统导入失败**
   ```
   解决方案：确保所有新模块都在GraphRAG目录中
   检查：ls hexstrike-ai-master/GraphRAG/
   应该看到：advisory_system.py, fingerprint_engine.py, path_patterns.py, rl_optimizer.py
   ```

2. **MCP工具不可用**
   ```
   解决方案：确保 server.py 正在 8888 端口运行
   测试：curl http://127.0.0.1:8888/health
   ```

3. **建议质量不高**
   ```
   解决方案：系统需要学习时间，多次使用后会改进
   调整：降低exploration_rate以减少随机性
   ```

## 📞 支持

如有问题，请检查：
1. 服务器日志输出
2. MCP客户端连接状态
3. API端点响应
4. 系统健康检查

---

**记住：这个系统的目标是增强LLM Agent的决策能力，而不是替代它的思考过程！**