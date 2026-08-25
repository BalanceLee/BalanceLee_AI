import './ConfigPanel.css'

function ConfigPanel({ config }) {
  return (
    <div className="config-panel">
      <div className="config-header">
        <h3 className="config-title">📊 当前配置</h3>
      </div>
      
      <div className="config-content">
        <div className="config-section">
          <h4>🔧 功能开关</h4>
          <div className="config-items">
            <div className="config-item">
              <span className="config-label">GraphRAG</span>
              <span className={`config-status ${config.graphrag ? 'active' : 'inactive'}`}>
                {config.graphrag ? '✅ 已启用' : '❌ 未启用'}
              </span>
            </div>
            <div className="config-item">
              <span className="config-label">Phase-Aware</span>
              <span className={`config-status ${config.phaseAware ? 'active' : 'inactive'}`}>
                {config.phaseAware ? '✅ 已启用' : '❌ 未启用'}
              </span>
            </div>
          </div>
        </div>
        
        <div className="config-section">
          <h4>⚙️ 性能参数</h4>
          <div className="config-items">
            <div className="config-item">
              <span className="config-label">最大轮次</span>
              <span className="config-value">{config.maxRounds || 50}</span>
            </div>
            <div className="config-item">
              <span className="config-label">超时时间</span>
              <span className="config-value">{config.timeout || 300}秒</span>
            </div>
          </div>
        </div>
        
        <div className="config-hint">
          <p>💡 提示：输入"开启/关闭 GraphRAG"或"开启/关闭 Phase-Aware"来切换配置</p>
        </div>
      </div>
    </div>
  )
}

export default ConfigPanel
