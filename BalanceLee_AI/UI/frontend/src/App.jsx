import { useState, useEffect, useReducer, useRef } from 'react'
import io from 'socket.io-client'
import ChatPanel from './components/ChatPanel'
import TerminalPanel from './components/TerminalPanel'
import ConfigPanel from './components/ConfigPanel'
import UserQuestionModal from './components/UserQuestionModal'
import { initialRuntimeState, runtimeEventReducer, applyRuntimeEvents } from './runtime/eventReducer'
import './App.css'

// 正式运行时 React 由 Flask 同源托管；开发模式可用 VITE_BACKEND_URL 指向后端。
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || undefined

function App() {
  const [socket, setSocket] = useState(null)
  const [connected, setConnected] = useState(false)
  const [messages, setMessages] = useState([])
  const [terminalLogs, setTerminalLogs] = useState([])
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [isRunning, setIsRunning] = useState(false)
  const [waitingForUser, setWaitingForUser] = useState(false)
  const [currentTool, setCurrentTool] = useState(null)
  const [currentQuestion, setCurrentQuestion] = useState(null)
  const [runtimeState, dispatchRuntimeEvent] = useReducer(runtimeEventReducer, initialRuntimeState)
  const lastRuntimeSeqRef = useRef(0)
  const [config, setConfig] = useState({
    graphrag: true,
    phaseAware: true,
    maxRounds: 50,
    timeout: 300
  })

  useEffect(() => {
    // 连接WebSocket
    const newSocket = io(BACKEND_URL, {
      transports: ['websocket', 'polling'],
      path: '/socket.io'
    })

    newSocket.on('connect', () => {
      console.log('WebSocket已连接')
      setConnected(true)
      addTerminalLog('✅ 已连接到 HexStrike Web 服务', 'success')
      
      // 连接后请求配置，并尝试补发断线期间的统一事件。
      newSocket.emit('get_config')
      newSocket.emit('runtime_resume', { after_seq: lastRuntimeSeqRef.current }, (data) => {
        if (data?.success && Array.isArray(data.events)) {
          data.events.forEach(event => dispatchRuntimeEvent(event))
          lastRuntimeSeqRef.current = Math.max(lastRuntimeSeqRef.current, Number(data.last_seq || 0))
        }
      })
    })

    newSocket.on('disconnect', () => {
      console.log('WebSocket已断开')
      setConnected(false)
      addTerminalLog('❌ 与服务端断开连接', 'error')
    })

    newSocket.on('connected', (data) => {
      console.log('会话ID:', data.session_id)
      addTerminalLog(`会话已建立: ${data.session_id}`, 'info')
    })

    // 新版统一运行时事件。兼容期内旧事件仍会同时到达。
    newSocket.on('runtime_event', (event) => {
      dispatchRuntimeEvent(event)
      lastRuntimeSeqRef.current = Math.max(lastRuntimeSeqRef.current, Number(event?.seq || 0))
      if (event?.seq && event.seq % 10 === 0) {
        newSocket.emit('runtime_ack', { last_seq: event.seq })
      }
    })

    // AI消息
    newSocket.on('ai_message', (data) => {
      addMessage('ai', data.message, data.timestamp)
    })

    // AI思考中
    newSocket.on('ai_thinking', (data) => {
      addMessage('ai', `🧠 ${data.message}`, null, true)
    })

    // 工具开始
    newSocket.on('tool_start', (data) => {
      setCurrentTool(data.tool_name)
      addMessage('tool', `🔧 执行工具: ${data.tool_name}`, data.timestamp)
      addTerminalLog(`[${data.timestamp}] 🔧 执行工具: ${data.tool_name}`, 'info')
      addTerminalLog(`[${data.timestamp}] 📝 参数: ${JSON.stringify(data.parameters, null, 2)}`, 'info')
    })

    // 工具完成
    newSocket.on('tool_complete', (data) => {
      setCurrentTool(null)
      const status = data.success ? '✅ 成功' : '❌ 失败'
      addMessage('tool', `${status}: ${data.tool_name}`, data.timestamp)
      addTerminalLog(`[${data.timestamp}] ${status}: ${data.tool_name}`, data.success ? 'success' : 'error')
    })

    // 终端输出
    newSocket.on('terminal_output', (data) => {
      addTerminalLog(data.output, data.stream === 'stderr' ? 'error' : 'info')
    })

    // 发现漏洞
    newSocket.on('vulnerability_found', (data) => {
      setVulnerabilities(prev => [...prev, data])
      addMessage('vuln', `🚨 发现漏洞: ${data.vuln_type} [${data.severity}]`, data.timestamp)
      addTerminalLog(`[${data.timestamp}] 🎯 发现漏洞: ${data.vuln_type}`, 'warning')
    })

    // 暂停等待用户
    newSocket.on('pause_for_input', (data) => {
      setWaitingForUser(true)
      setIsRunning(false)
      addMessage('system', `⏸️ ${data.reason}\n请选择下一步操作`, null)
    })

    // 测试完成
    newSocket.on('test_complete', (data) => {
      setIsRunning(false)
      setWaitingForUser(false)
      
      // 【关键】只在渗透测试时显示"测试完成"
      if (data.summary?.type === 'pentest') {
        addMessage('system', '✅ 测试完成', null)
      }
      
      if (data.report) {
        addTerminalLog('\n' + data.report, 'success')
      }
    })
    
    // 对话历史已清空
    newSocket.on('chat_history_cleared', (data) => {
      addTerminalLog('✅ ' + data.message, 'success')
    })
    
    // 配置状态更新
    newSocket.on('config_status', (data) => {
      setConfig({
        graphrag: data.enable_graphrag,
        phaseAware: data.enable_phase_aware,
        maxRounds: data.max_rounds,
        timeout: data.timeout
      })
    })

    // 【新增】用户询问
    newSocket.on('user_question', (data) => {
      console.log('收到用户询问:', data)
      setCurrentQuestion(data)
      addMessage('system', `🤔 AI 需要您的意见：${data.question}`, null)
      addTerminalLog(`[${new Date().toLocaleTimeString()}] 🤔 AI 询问用户`, 'warning')
    })

    // 错误
    newSocket.on('error', (data) => {
      addMessage('error', `❌ 错误: ${data.message}`, null)
      addTerminalLog(`❌ 错误: ${data.message}`, 'error')
      setIsRunning(false)
    })

    setSocket(newSocket)

    return () => {
      newSocket.close()
    }
  }, [])

  const addMessage = (type, content, timestamp, isThinking = false) => {
    setMessages(prev => [...prev, {
      id: Date.now() + Math.random(),
      type,
      content,
      timestamp: timestamp || new Date().toLocaleTimeString(),
      isThinking
    }])
  }

  const addTerminalLog = (text, level = 'info') => {
    setTerminalLogs(prev => [...prev, {
      id: Date.now() + Math.random(),
      text,
      level,
      timestamp: new Date().toLocaleTimeString()
    }])
  }

  const handleSendMessage = (message) => {
    if (!socket || !connected) {
      alert('未连接到服务端')
      return
    }

    // 添加用户消息
    addMessage('user', message, null)
    addTerminalLog(`[用户] ${message}`, 'info')

    // 发送到后端
    socket.emit('start_pentest', {
      target: message,
      message: message
    })

    setIsRunning(true)
    setVulnerabilities([])
  }

  const handleUserChoice = (choice) => {
    if (!socket) return

    socket.emit('user_choice', { choice })
    setWaitingForUser(false)

    if (choice === 'continue') {
      setIsRunning(true)
      addMessage('system', '▶️ 继续测试...', null)
    } else if (choice === 'stop') {
      addMessage('system', '⏹️ 停止测试', null)
    } else if (choice === 'report') {
      addMessage('system', '📊 生成报告...', null)
    }
  }

  const handleStop = () => {
    if (!socket) return
    socket.emit('stop_pentest')
    setIsRunning(false)
    addMessage('system', '⏹️ 已停止测试', null)
  }

  const handleClearMessages = () => {
    if (window.confirm('确定要清空所有对话记录吗？')) {
      setMessages([])
      setVulnerabilities([])
      
      // 【新增】通知后端清空历史
      if (socket) {
        socket.emit('clear_chat_history')
      }
    }
  }

  const handleClearTerminal = () => {
    setTerminalLogs([])
  }

  const handleUserResponse = (askId, response) => {
    console.log('用户响应:', askId, response)

    if (!socket || !connected) {
      addTerminalLog(`[${new Date().toLocaleTimeString()}] ❌ Web 服务未连接`, 'error')
      return
    }

    socket.timeout(10000).emit(
      'user_question_response',
      { ask_id: askId, response },
      (error, data) => {
        if (error) {
          addTerminalLog(`[${new Date().toLocaleTimeString()}] ❌ 响应超时: ${error.message || error}`, 'error')
          return
        }
        if (data?.success) {
          addMessage('user', `💬 您的回复: ${response.text}`, null)
          addTerminalLog(`[${new Date().toLocaleTimeString()}] ✅ 用户已回复`, 'success')
          setCurrentQuestion(null)
        } else {
          addTerminalLog(`[${new Date().toLocaleTimeString()}] ❌ 响应失败: ${data?.error || '未知错误'}`, 'error')
        }
      }
    )
  }

  const handleCloseQuestion = () => {
    // 用户关闭询问，发送默认响应"继续"
    if (currentQuestion) {
      handleUserResponse(currentQuestion.ask_id, {
        choice: '继续',
        text: '继续',
        timestamp: Date.now()
      })
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>🔥 Balance_Lee AI</h1>
        <div className="status">
          <span className={`status-dot ${connected ? 'connected' : 'disconnected'}`}></span>
          <span>{connected ? '已连接' : '未连接'}</span>
        </div>
      </header>

      <div className="app-content">
        <ChatPanel
          messages={messages}
          vulnerabilities={vulnerabilities}
          onSendMessage={handleSendMessage}
          onUserChoice={handleUserChoice}
          onClearMessages={handleClearMessages}
          isRunning={isRunning}
          waitingForUser={waitingForUser}
          onStop={handleStop}
        />
        <div className="right-panel">
          <ConfigPanel config={config} />
          <TerminalPanel
            logs={terminalLogs}
            currentTool={currentTool}
            isRunning={isRunning}
            onClearLogs={handleClearTerminal}
          />
        </div>
      </div>

      {/* 用户询问模态框 */}
      {currentQuestion && (
        <UserQuestionModal
          question={currentQuestion.question}
          options={currentQuestion.options}
          context={currentQuestion.context}
          askId={currentQuestion.ask_id}
          onRespond={handleUserResponse}
          onClose={handleCloseQuestion}
        />
      )}
    </div>
  )
}

export default App
