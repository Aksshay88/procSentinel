import React, { useState, useEffect } from 'react'
import axios from 'axios'
import StatsCards from './StatsCards'
import ProcessTable from './ProcessTable'
import './Dashboard.css'

interface DashboardProps {
  token: string
  username: string
  onLogout: () => void
}

export interface ProcessData {
  pid: number
  ppid: number
  name: string
  user: string
  parent_name: string
  total_score: number
  heuristic_score: number
  ml_score: number
  cpu_percent: number
  mem_mb: number
  reasons: Array<{ score: number; reason: string }>
  cmdline: string
  status: 'normal' | 'warning' | 'critical'
}

export interface StatsData {
  total_processes: number
  critical: number
  warning: number
  normal: number
  model_loaded: boolean
  timestamp: string
}

const Dashboard: React.FC<DashboardProps> = ({ token, username, onLogout }) => {
  const [processes, setProcesses] = useState<ProcessData[]>([])
  const [stats, setStats] = useState<StatsData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [refreshInterval, setRefreshInterval] = useState(5)

  const api = axios.create({
    baseURL: 'http://localhost:5001',
    // Temporarily disable auth header to test UI
    // headers: {
    //   Authorization: `Bearer ${token}`
    // }
  })

  const fetchData = async () => {
    setLoading(true)
    setError('')
    
    try {
      const [processesRes, statsRes] = await Promise.all([
        api.get('/api/processes'),
        api.get('/api/stats')
      ])
      
      setProcesses(processesRes.data.processes || [])
      setStats(statsRes.data)
    } catch (err: any) {
      // Temporarily disable auto-logout for testing
      // if (err.response?.status === 401) {
      //   onLogout()
      // } else {
        setError(err.response?.data?.message || err.message || 'Failed to fetch data - check if backend is running on port 5001')
      // }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(fetchData, refreshInterval * 1000)
      return () => clearInterval(interval)
    }
  }, [autoRefresh, refreshInterval])

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div className="header-content">
          <div className="header-left">
            <h1>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none">
                <path d="M12 2L2 7v10c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-10-5z" fill="#3b82f6" />
              </svg>
              ProcSentinel
            </h1>
            <span className="subtitle">Process Monitoring Dashboard</span>
          </div>
          
          <div className="header-right">
            <div className="user-info">
              <span className="username">{username}</span>
              <button onClick={onLogout} className="logout-btn">Logout</button>
            </div>
          </div>
        </div>
        
        <div className="controls">
          <button onClick={fetchData} disabled={loading} className="refresh-btn">
            {loading ? '🔄 Loading...' : '🔄 Refresh'}
          </button>
          
          <label className="auto-refresh">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-refresh
          </label>
          
          <select 
            value={refreshInterval} 
            onChange={(e) => setRefreshInterval(Number(e.target.value))}
            disabled={!autoRefresh}
            className="interval-select"
          >
            <option value={3}>3s</option>
            <option value={5}>5s</option>
            <option value={10}>10s</option>
            <option value={30}>30s</option>
          </select>
        </div>
      </header>

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      <div className="dashboard-content">
        <StatsCards stats={stats} />
        <ProcessTable processes={processes} loading={loading} />
      </div>
    </div>
  )
}

export default Dashboard
