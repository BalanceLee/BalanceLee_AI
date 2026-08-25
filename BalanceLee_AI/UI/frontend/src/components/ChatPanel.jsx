import { useState, useRef, useEffect } from 'react'
import VulnCard from './VulnCard'
import './ChatPanel.css'

function ChatPanel({ messages, vulnerabilities, onSendMessage, onUserChoice, onClearMessages, isRunning, waitingForUser, onStop }) {
  const [input, setInput] = useState('')
  const messagesEndRef = useRef(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const handleSubmit = (e) => {
    e.preventDefault()
    if (input.trim() && !isRunning) {
      onSendMessage(input.trim())
      setInput('')
    }
  }

  const handleClear = () => {
    if (window.confirm('确定要清空所有对话记录吗？')) {
      onClearMessages()
    }
  }

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <h3 className="chat-title">💬 对话</h3>
        <button onClick={handleClear} className="btn-clear-chat" title="清空对话">
          🗑️ 清空
        </button>
      </div>
      
      <div className="messages-container">
        {messages.map((msg) => (
          <div key={msg.id} className={`message message-${msg.type}`}>
            <div className="message-header">
              <span className="message-icon">
                {msg.type === 'user' && '👤'}
                {msg.type === 'ai' && '🤖'}
                {msg.type === 'tool' && '🔧'}
                {msg.type === 'vuln' && '🚨'}
                {msg.type === 'system' && 'ℹ️'}
                {msg.type === 'error' && '❌'}
              </span>
              <span className="message-time">{msg.timestamp}</span>
            </div>
            <div className="message-content">
              {msg.isThinking ? (
                <span className="thinking">
                  {msg.content}
                  <span className="dots">
                    <span>.</span><span>.</span><span>.</span>
                  </span>
                </span>
              ) : (
                <pre>{msg.content}</pre>
              )}
            </div>
          </div>
        ))}

        {/* 漏洞卡片 */}
        {vulnerabilities.length > 0 && (
          <div className="vulnerabilities-section">
            <h3>🚨 发现的漏洞 ({vulnerabilities.length})</h3>
            {vulnerabilities.map((vuln, index) => (
              <VulnCard key={index} vulnerability={vuln} />
            ))}
          </div>
        )}

        {/* 等待用户选择 */}
        {waitingForUser && (
          <div className="user-choice-panel">
            <p>⏸️ 发现漏洞，请选择下一步操作：</p>
            <div className="choice-buttons">
              <button onClick={() => onUserChoice('continue')} className="btn btn-primary">
                ▶️ 继续测试
              </button>
              <button onClick={() => onUserChoice('report')} className="btn btn-secondary">
                📊 生成报告
              </button>
              <button onClick={() => onUserChoice('stop')} className="btn btn-danger">
                ⏹️ 停止测试
              </button>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <form className="input-form" onSubmit={handleSubmit}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="输入目标URL或指令..."
          disabled={isRunning}
          className="input-box"
        />
        <button
          type="submit"
          disabled={isRunning || !input.trim()}
          className="btn btn-send"
        >
          {isRunning ? '⏳ 运行中...' : '🚀 发送'}
        </button>
        {isRunning && (
          <button
            type="button"
            onClick={onStop}
            className="btn btn-stop"
          >
            ⏹️ 停止
          </button>
        )}
      </form>
    </div>
  )
}

export default ChatPanel
