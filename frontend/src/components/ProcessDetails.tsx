import React from 'react'
import type { ProcessData } from './Dashboard'
import './ProcessDetails.css'

interface ProcessDetailsProps {
  process: ProcessData
  onClose: () => void
}

const ProcessDetails: React.FC<ProcessDetailsProps> = ({ process, onClose }) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'critical': return '#ef4444'
      case 'warning': return '#eab308'
      default: return '#22c55e'
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header" style={{ borderLeftColor: getStatusColor(process.status) }}>
          <div>
            <h2>{process.name}</h2>
            <p className="process-id">PID: {process.pid}</p>
          </div>
          <button onClick={onClose} className="close-btn">×</button>
        </div>

        <div className="modal-body">
          <div className="detail-section">
            <h3>Overview</h3>
            <div className="detail-grid">
              <div className="detail-item">
                <label>Process ID</label>
                <span className="mono">{process.pid}</span>
              </div>
              <div className="detail-item">
                <label>Parent PID</label>
                <span className="mono">{process.ppid}</span>
              </div>
              <div className="detail-item">
                <label>User</label>
                <span>{process.user}</span>
              </div>
              <div className="detail-item">
                <label>Parent Process</label>
                <span>{process.parent_name}</span>
              </div>
              <div className="detail-item">
                <label>Executable</label>
                <span className="mono" style={{ wordBreak: 'break-all' }}>{process.exe || 'N/A'}</span>
              </div>
              <div className="detail-item">
                <label>CWD</label>
                <span className="mono" style={{ wordBreak: 'break-all' }}>{process.cwd || 'N/A'}</span>
              </div>
              <div className="detail-item">
                <label>SHA256</label>
                <span className="mono" style={{ wordBreak: 'break-all', fontSize: '0.8em' }}>{process.sha256 || 'N/A'}</span>
              </div>
            </div>
          </div>

          <div className="detail-section">
            <h3>Threat Scores</h3>
            <div className="scores-grid">
              <div className="score-item" style={{ borderLeftColor: getStatusColor(process.status) }}>
                <label>Total Score</label>
                <span className="score-value" style={{ color: getStatusColor(process.status) }}>
                  {process.total_score.toFixed(2)}
                </span>
              </div>
              <div className="score-item">
                <label>Heuristic Score</label>
                <span className="score-value">{process.heuristic_score.toFixed(2)}</span>
              </div>
              <div className="score-item">
                <label>ML Score</label>
                <span className="score-value">{process.ml_score.toFixed(2)}</span>
              </div>
            </div>
          </div>

          <div className="detail-section">
            <h3>Resource Usage</h3>
            <div className="resource-bars">
              <div className="resource-item">
                <div className="resource-header">
                  <label>CPU Usage</label>
                  <span>{process.cpu_percent.toFixed(1)}%</span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-fill"
                    style={{
                      width: `${Math.min(process.cpu_percent, 100)}%`,
                      backgroundColor: process.cpu_percent > 80 ? '#ef4444' : process.cpu_percent > 50 ? '#eab308' : '#22c55e'
                    }}
                  />
                </div>
              </div>
              <div className="resource-item">
                <div className="resource-header">
                  <label>Connections</label>
                  <span>{process.conns_outbound ?? 0}</span>
                </div>
                <div className="detail-item">
                  <label style={{ fontSize: '0.8em', color: '#666' }}>Remote Ports: {(process.remote_ports || []).join(', ') || 'None'}</label>
                </div>
              </div>
            </div>
          </div>

          <div className="detail-section">
            <h3>Detection Reasons</h3>
            <div className="reasons-list">
              {process.reasons.length > 0 ? (
                process.reasons.map((reason, index) => (
                  <div key={index} className="reason-item">
                    <span className="reason-score" style={{
                      backgroundColor: reason.score >= 3 ? 'rgba(239, 68, 68, 0.2)' :
                        reason.score >= 2 ? 'rgba(234, 179, 8, 0.2)' :
                          'rgba(34, 197, 94, 0.2)',
                      color: reason.score >= 3 ? '#ef4444' :
                        reason.score >= 2 ? '#eab308' :
                          '#22c55e'
                    }}>
                      {reason.score.toFixed(1)}
                    </span>
                    <span className="reason-text">{reason.reason}</span>
                  </div>
                ))
              ) : (
                <p className="no-data">No specific reasons detected</p>
              )}
            </div>
          </div>

          <div className="detail-section">
            <h3>Command Line</h3>
            <div className="cmdline-box">
              <code>
                {Array.isArray(process.cmdline)
                  ? process.cmdline.join(' ')
                  : (process.cmdline || 'N/A')}
              </code>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ProcessDetails
