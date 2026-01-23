import { useState } from 'react'
import './App.css'
// import Login from './components/Login'
import Dashboard from './components/Dashboard'

function App() {
  // Temporarily bypass login to show UI directly
  const [token] = useState<string>('demo-token')
  const [username] = useState<string>('admin')

  // const [token, setToken] = useState<string | null>(localStorage.getItem('token'))
  // const [username, setUsername] = useState<string | null>(localStorage.getItem('username'))

  // useEffect(() => {
  //   if (token) {
  //     localStorage.setItem('token', token)
  //   } else {
  //     localStorage.removeItem('token')
  //   }
  // }, [token])

  // useEffect(() => {
  //   if (username) {
  //     localStorage.setItem('username', username)
  //   } else {
  //     localStorage.removeItem('username')
  //   }
  // }, [username])

  // const handleLogin = (newToken: string, newUsername: string) => {
  //   setToken(newToken)
  //   setUsername(newUsername)
  // }

  const handleLogout = () => {
    // setToken(null)
    // setUsername(null)
    console.log('Logout clicked')
  }

  return (
    <div className="app">
      {/* {!token ? (
        <Login onLogin={handleLogin} />
      ) : ( */}
      <Dashboard token={token} username={username || ''} onLogout={handleLogout} />
      {/* )} */}
    </div>
  )
}

export default App
