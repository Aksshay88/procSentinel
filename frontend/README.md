# ProcSentinel Frontend

Modern TypeScript + React frontend for ProcSentinel process monitoring system with authentication and real-time monitoring.

## Features

✨ **Modern UI**
- Clean, responsive dashboard design
- Dark theme with color-coded threat levels
- Real-time process monitoring
- Auto-refresh capabilities

�� **Color Grading System**
- 🟢 **Green**: Normal processes (score < 5)
- 🟡 **Yellow**: Warning level (score 5-8)
- 🔴 **Red**: Critical threats (score >= 8)

🔐 **Authentication**
- Simple login system
- JWT token-based auth
- Session persistence

📊 **Admin Dashboard**
- Process monitoring table
- Statistics cards
- Detailed process information
- Sortable columns
- Real-time updates

## Quick Start

### 1. Start Backend API Server

```bash
# From project root
python3 api_server.py
```

Default credentials: `admin` / `admin123`

### 2. Start Frontend

```bash
cd frontend
npm run dev
```

Visit http://localhost:5173

## Architecture

Frontend (React/TS) ↔ Flask API ↔ ProcWatch Engine

## License

Part of the ProcSentinel project
