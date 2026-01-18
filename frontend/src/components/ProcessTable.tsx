import React, { useState } from 'react'
import type { ProcessData } from './Dashboard'
import ProcessDetails from './ProcessDetails'
import './ProcessTable.css'

interface ProcessTableProps {
  processes: ProcessData[]
  loading: boolean
}

const ProcessTable: React.FC<ProcessTableProps> = ({ processes, loading }) => {
  const [selectedProcess, setSelectedProcess] = useState<ProcessData | null>(null)
  const [sortField, setSortField] = useState<keyof ProcessData>('total_score')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')

  const handleSort = (field: keyof ProcessData) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortOrder('desc')
    }
  }

  const sortedProcesses = [...processes].sort((a, b) => {
    const aVal = a[sortField]
    const bVal = b[sortField]
    
    if (typeof aVal === 'number' && typeof bVal === 'number') {
      return sortOrder === 'asc' ? aVal - bVal : bVal - aVal
    }
    
    if (typeof aVal === 'string' && typeof bVal === 'string') {
      return sortOrder === 'asc' 
        ? aVal.localeCompare(bVal)
        : bVal.localeCompare(aVal)
    }
    
    return 0
  })

  const getStatusClass = (status: string) => {
    switch (status) {
      case 'critical': return 'badge-critical'
      case 'warning': return 'badge-warning'
      default: return 'badge-normal'
    }
  }

  const getScoreClass = (score: number) => {
    if (score >= 8) return 'score-critical'
    if (score >= 5) return 'score-warning'
    return 'score-normal'
  }

  if (loading && processes.length === 0) {
    return (
      <div className="process-table-container">
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Loading processes...</p>
        </div>
      </div>
    )
  }

  if (processes.length === 0) {
    return (
      <div className="process-table-container">
        <div className="empty-state">
          <svg width="64" height="64" viewBox="0 0 24 24" fill="none">
            <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" />
          </svg>
          <h3>All Clear!</h3>
          <p>No suspicious processes detected</p>
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="process-table-container">
        <div className="table-header">
          <h2>Suspicious Processes ({processes.length})</h2>
        </div>

        <div className="table-wrapper">
          <table className="process-table">
            <thead>
              <tr>
                <th onClick={() => handleSort('total_score')}>
                  Score {sortField === 'total_score' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('pid')}>
                  PID {sortField === 'pid' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('name')}>
                  Name {sortField === 'name' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('user')}>
                  User {sortField === 'user' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th>Parent</th>
                <th onClick={() => handleSort('cpu_percent')}>
                  CPU% {sortField === 'cpu_percent' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('mem_mb')}>
                  Memory {sortField === 'mem_mb' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th>Status</th>
                <th>Reasons</th>
              </tr>
            </thead>
            <tbody>
              {sortedProcesses.map((proc) => (
                <tr 
                  key={proc.pid}
                  onClick={() => setSelectedProcess(proc)}
                  className="clickable"
                >
                  <td>
                    <span className={`score-badge ${getScoreClass(proc.total_score)}`}>
                      {proc.total_score.toFixed(1)}
                    </span>
                  </td>
                  <td className="mono">{proc.pid}</td>
                  <td className="process-name">{proc.name}</td>
                  <td>{proc.user}</td>
                  <td className="parent-name">{proc.parent_name}</td>
                  <td>{proc.cpu_percent.toFixed(1)}%</td>
                  <td>{proc.mem_mb.toFixed(1)} MB</td>
                  <td>
                    <span className={`badge ${getStatusClass(proc.status)}`}>
                      {proc.status.toUpperCase()}
                    </span>
                  </td>
                  <td className="reasons-cell">
                    {proc.reasons.length > 0 && (
                      <div className="reasons-preview">
                        {proc.reasons[0].reason}
                        {proc.reasons.length > 1 && (
                          <span className="more-badge">+{proc.reasons.length - 1}</span>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selectedProcess && (
        <ProcessDetails 
          process={selectedProcess}
          onClose={() => setSelectedProcess(null)}
        />
      )}
    </>
  )
}

export default ProcessTable
