import { useState } from 'react'
import './VulnCard.css'

function VulnCard({ vulnerability }) {
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)

  const getSeverityClass = (severity) => {
    const map = {
      'CRITICAL': 'severity-critical',
      'HIGH': 'severity-high',
      'MEDIUM': 'severity-medium',
      'LOW': 'severity-low',
      'INFO': 'severity-info'
    }
    return map[severity] || 'severity-info'
  }

  const handleCopyExploit = () => {
    if (vulnerability.exploit_code) {
      navigator.clipboard.writeText(vulnerability.exploit_code)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div className={`vuln-card ${getSeverityClass(vulnerability.severity)}`}>
      <div className="vuln-header" onClick={() => setExpanded(!expanded)}>
        <div className="vuln-title">
          <span className="vuln-icon">🚨</span>
          <span className="vuln-type">{vulnerability.vuln_type}</span>
          <span className={`vuln-severity ${getSeverityClass(vulnerability.severity)}`}>
            {vulnerability.severity}
          </span>
        </div>
        <span className="expand-icon">{expanded ? '▼' : '▶'}</span>
      </div>

      {expanded && (
        <div className="vuln-body">
          <div className="vuln-info">
            <p><strong>描述:</strong> {vulnerability.description}</p>
            <p><strong>置信度:</strong> {(vulnerability.confidence * 100).toFixed(0)}%</p>
            {vulnerability.affected_url && (
              <p><strong>URL:</strong> <code>{vulnerability.affected_url}</code></p>
            )}
            {vulnerability.payload && (
              <div className="vuln-payload">
                <strong>Payload:</strong>
                <pre>{vulnerability.payload}</pre>
              </div>
            )}
          </div>

          {vulnerability.exploit_code && (
            <div className="vuln-exploit">
              <div className="exploit-header">
                <strong>💻 EXP代码:</strong>
                <button onClick={handleCopyExploit} className="btn-copy">
                  {copied ? '✅ 已复制' : '📋 复制'}
                </button>
              </div>
              <pre className="exploit-code">{vulnerability.exploit_code}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default VulnCard
