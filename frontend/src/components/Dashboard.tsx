import React, { useState, useEffect, useCallback } from 'react'
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
  mem_mb?: number // Optional now as backend doesn't always send it
  conns_outbound: number
  remote_ports: number[]
  reasons: Array<{ score: number; reason: string }>
  cmdline: string | string[]
  exe?: string
  cwd?: string
  sha256?: string
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

type ViewMode = 'all' | 'suspicious'

const Dashboard: React.FC<DashboardProps> = ({ username, onLogout }) => {
  const [processes, setProcesses] = useState<ProcessData[]>([])
  const [stats, setStats] = useState<StatsData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [refreshInterval, setRefreshInterval] = useState(5)

  // New state for filters
  const [viewMode, setViewMode] = useState<ViewMode>('all')
  const [minScore, setMinScore] = useState<number>(3.0)

  const api = axios.create({
    baseURL: 'http://localhost:8080',
  })

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      // Determine which endpoint to call based on view mode
      const processEndpoint = viewMode === 'suspicious'
        ? `/api/suspicious?min_score=${minScore}`
        : '/api/processes'

      const [processesRes, statsRes] = await Promise.all([
        api.get(processEndpoint),
        api.get('/api/stats')
      ])

      // Handle list response vs direct array? Backend seems to return list directly for some, dict for others?
      // Checking backend code: 
      // /api/processes -> returns list of dicts directly? No, wait.
      // api_server.py: 
      // return jsonify({'processes': findings ...}) for /api/processes?
      // BUT typical simplified backend in procwatch/api.py (which is used by start_api.sh) returns LIST directly for get_all_processes??
      // Let's re-read procwatch/api.py carefully.
      // The APIHandler.do_GET -> self.send_json(processes) where processes = self.api.get_all_processes() (which returns a LIST)
      // So it is a direct array. The previous frontend code expected { data: { processes: [] } } which matched api_server.py but NOT procwatch/api.py.
      // Since `start_api.sh` runs `procwatch.py api` -> `procwatch/api.py`, we should expect a direct ARRAY.

      const processData = Array.isArray(processesRes.data) ? processesRes.data : processesRes.data.processes || []
      setProcesses(processData)
      setStats(statsRes.data)
    } catch (err: any) {
      console.error(err)
      setError(err.response?.data?.message || err.message || 'Failed to fetch data. Ensure backend is running on port 8080.')
    } finally {
      setLoading(false)
    }
  }, [viewMode, minScore])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(fetchData, refreshInterval * 1000)
      return () => clearInterval(interval)
    }
  }, [autoRefresh, refreshInterval, fetchData])

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
          <div className="control-group">
            <button
              className={`view-btn ${viewMode === 'all' ? 'active' : ''}`}
              onClick={() => setViewMode('all')}
            >
              🔄 All Processes
            </button>
            <button
              className={`view-btn ${viewMode === 'suspicious' ? 'active' : ''}`}
              onClick={() => setViewMode('suspicious')}
            >
              ⚠️ Suspicious Only
            </button>
          </div>

          <div className="control-group">
            <label htmlFor="min-score">Min Score:</label>
            <input
              type="number"
              id="min-score"
              value={minScore}
              step="0.5"
              min="0"
              onChange={(e) => setMinScore(parseFloat(e.target.value))}
              className="score-input"
            />
          </div>

          <div className="control-group right">
            <button onClick={fetchData} disabled={loading} className="refresh-btn">
              {loading ? '...' : 'Refresh'}
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
            </select>
          </div>
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
