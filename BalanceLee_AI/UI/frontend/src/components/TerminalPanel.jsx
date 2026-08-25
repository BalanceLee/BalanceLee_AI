import { useRef, useEffect, useState } from 'react'
import './TerminalPanel.css'

function TerminalPanel({ logs, currentTool, isRunning, onClearLogs }) {
  const logsEndRef = useRef(null)
  const [autoScroll, setAutoScroll] = useState(true)

  const scrollToBottom = () => {
    if (autoScroll) {
      logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }

  useEffect(() => {
    scrollToBottom()
  }, [logs])

  const handleClear = () => {
    if (onClearLogs && window.confirm('确定要清空终端日志吗？')) {
      onClearLogs()
    }
  }

  const getLevelClass = (level) => {
    const map = {
      'info': 'log-info',
      'success': 'log-success',
      'warning': 'log-warning',
      'error': 'log-error'
    }
    return map[level] || 'log-info'
  }

  return (
    <div className="terminal-panel">
      <div className="terminal-header">
        <span className="terminal-title">📟 实时终端输出</span>
        <div className="terminal-controls">
          <label className="auto-scroll-toggle">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
            自动滚动
          </label>
          <button onClick={handleClear} className="btn-clear" title="清空日志">
            🗑️ 清空
          </button>
        </div>
      </div>

      {currentTool && (
        <div className="current-tool">
          <span className="tool-indicator">🔧</span>
          <span>正在执行: {currentTool}</span>
          <span className="spinner"></span>
        </div>
      )}

      <div className="terminal-logs">
        {logs.map((log) => (
          <div key={log.id} className={`log-line ${getLevelClass(log.level)}`}>
            {log.text}
          </div>
        ))}
        {logs.length === 0 && (
          <div className="log-empty">
            等待任务开始...
          </div>
        )}
        <div ref={logsEndRef} />
      </div>

      {isRunning && (
        <div className="terminal-status">
          <span className="status-indicator"></span>
          <span>测试进行中...</span>
        </div>
      )}
    </div>
  )
}

export default TerminalPanel
