import React, { useState } from 'react'
import axios from 'axios'
import './Login.css'

interface LoginProps {
  onLogin: (token: string, username: string) => void
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const response = await axios.post('http://localhost:5001/api/login', {
        username,
        password
      })
      onLogin(response.data.token, response.data.username)
    } catch (err: any) {
      console.error('Login error:', err)
      setError(err.response?.data?.message || err.message || 'Login failed - check if backend is running')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      <div className="login-box">
        <div className="login-header">
          <div className="logo">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7v10c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-10-5z" fill="#3b82f6" />
              <path d="M12 9v6m0 0l-3-3m3 3l3-3" stroke="white" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </div>
          <h1>ProcSentinel</h1>
          <p>Process Monitoring & Security</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              required
              autoFocus
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              required
            />
          </div>

          <button type="submit" disabled={loading} className="login-button">
            {loading ? 'Logging in...' : 'Login'}
          </button>

          <div className="login-info">
            <small>Default: admin / admin123</small>
          </div>
        </form>
      </div>
    </div>
  )
}

export default Login
