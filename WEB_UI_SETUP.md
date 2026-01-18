# ProcSentinel Web UI Setup Guide

This document explains how to run the new React + TypeScript web UI for ProcSentinel.

## 📋 Overview

The new web UI consists of:
- **Backend**: Flask REST API server (`api_server.py`)
- **Frontend**: React + TypeScript dashboard (`frontend/`)

## 🚀 Quick Start

### Step 1: Install Dependencies

```bash
# Backend dependencies
pip3 install flask flask-cors pyjwt

# Frontend dependencies
cd frontend
npm install
cd ..
```

### Step 2: Start the Backend API

```bash
python3 api_server.py
```

The API will start on `http://localhost:5000`

### Step 3: Start the Frontend

```bash
cd frontend
npm run dev
```

The UI will be available at `http://localhost:5173`

### Step 4: Login

Open your browser to http://localhost:5173

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

## 🎨 UI Features

### Color-Coded Threat Levels
- 🟢 **Green** (Normal): Threat score < 5
- 🟡 **Yellow** (Warning): Threat score 5-8
- 🔴 **Red** (Critical): Threat score >= 8

### Dashboard Components
1. **Stats Cards**: Overview of total/normal/warning/critical processes
2. **Process Table**: Sortable list of suspicious processes
3. **Process Details**: Click any row for detailed information
4. **Auto-Refresh**: Configurable intervals (3s, 5s, 10s, 30s)

## 🔐 Authentication

The system uses JWT token-based authentication:
- Tokens are stored in browser localStorage
- Tokens expire after 24 hours
- Simple username/password authentication

### Adding More Users

Edit `api_server.py`:

```python
USERS = {
    "admin": hashlib.sha256("admin123".encode()).hexdigest(),
    "user2": hashlib.sha256("password123".encode()).hexdigest(),
}
```

## 🔧 Configuration

### Backend (api_server.py)

```python
# Change secret key (line 22)
SECRET_KEY = "your-secret-key-here"

# Change port (line 239)
app.run(host='0.0.0.0', port=5000, debug=True)
```

### Frontend (Dashboard.tsx)

```typescript
// Change API URL (line 43)
baseURL: 'http://localhost:5000',

// Change refresh intervals (line 113)
<option value={3}>3s</option>
<option value={5}>5s</option>
```

## 📊 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Authenticate user |
| GET | `/api/processes` | Get all suspicious processes |
| GET | `/api/stats` | Get system statistics |
| GET | `/api/process/:pid` | Get specific process details |
| GET | `/api/health` | Health check |

### Example API Calls

```bash
# Login
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Get processes (with token)
curl http://localhost:5000/api/processes \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## 🏗️ Architecture

```
┌──────────────────────────────────────────────┐
│          Browser (localhost:5173)            │
│                                              │
│  ┌────────────────────────────────────────┐ │
│  │  React + TypeScript Frontend           │ │
│  │  - Login Component                     │ │
│  │  - Dashboard Component                 │ │
│  │  - ProcessTable Component              │ │
│  │  - ProcessDetails Modal                │ │
│  └──────────────┬─────────────────────────┘ │
└─────────────────┼───────────────────────────┘
                  │ HTTP REST API + JWT
                  │
┌─────────────────▼───────────────────────────┐
│       Flask API Server (port 5000)          │
│  ┌────────────────────────────────────────┐ │
│  │  /api/login - Authentication           │ │
│  │  /api/processes - Process data         │ │
│  │  /api/stats - Statistics               │ │
│  └──────────────┬─────────────────────────┘ │
└─────────────────┼───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│          ProcWatch Core Engine              │
│  - Process scanning (proc.py)               │
│  - Heuristic scoring (heuristics.py)        │
│  - ML anomaly detection (ml.py)             │
│  - Network monitoring (network.py)          │
└─────────────────────────────────────────────┘
```

## 🛠️ Development

### Building for Production

```bash
cd frontend
npm run build
```

Built files will be in `frontend/dist/`

### Preview Production Build

```bash
cd frontend
npm run preview
```

## ⚠️ Security Notes

**For Production Deployment:**

1. **Change the secret key** in `api_server.py`
2. **Use HTTPS** with proper SSL/TLS certificates
3. **Implement proper password hashing** (bcrypt, argon2)
4. **Store users in a database** (not hardcoded)
5. **Add rate limiting** to prevent brute force
6. **Configure CORS properly** for your domain
7. **Use environment variables** for secrets
8. **Enable CSRF protection**
9. **Add logging and monitoring**
10. **Regular security updates**

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Check what's using port 5000
lsof -i :5000

# Kill the process
kill -9 <PID>

# Or change the port in api_server.py
```

### CORS Errors

Make sure:
1. Backend is running on port 5000
2. Frontend is accessing `http://localhost:5000`
3. CORS is enabled in `api_server.py` (line 19)

### Authentication Fails

1. Check browser console for errors
2. Verify backend is running
3. Clear browser localStorage: `localStorage.clear()`
4. Check network tab in DevTools

### No Processes Showing

1. Make sure you have processes to monitor
2. Check min_score threshold (default: 3.0)
3. Verify backend is scanning correctly
4. Check API response in Network tab

## 📁 Project Structure

```
procSentinel/
├── api_server.py              # Flask REST API
├── frontend/                  # React frontend
│   ├── src/
│   │   ├── App.tsx           # Main app component
│   │   ├── components/
│   │   │   ├── Login.tsx     # Login page
│   │   │   ├── Dashboard.tsx # Main dashboard
│   │   │   ├── StatsCards.tsx    # Stats overview
│   │   │   ├── ProcessTable.tsx  # Process list
│   │   │   └── ProcessDetails.tsx # Detail modal
│   │   ├── App.css
│   │   └── index.css
│   ├── package.json
│   └── README.md
├── procwatch/                 # Core engine
│   ├── cli.py
│   ├── proc.py
│   ├── heuristics.py
│   └── ...
└── WEB_UI_SETUP.md           # This file
```

## 🎓 Usage Tips

1. **Auto-refresh**: Enable for continuous monitoring
2. **Sort columns**: Click column headers to sort
3. **Process details**: Click any row for full details
4. **Color coding**: Quick visual threat assessment
5. **Logout**: Always logout when done

## 📝 Credits

Built with:
- React 18 + TypeScript
- Vite (build tool)
- Axios (HTTP client)
- Flask (Python API)
- ProcWatch (core engine)

---

For more information, see:
- Main README: `README.md`
- Frontend README: `frontend/README.md`
- Original guide: `GUIDE.md`
