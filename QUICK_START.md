# 🚀 ProcSentinel Web UI - Quick Start

## One-Command Setup

### 1. Start Backend API
```bash
python3 api_server.py
```
Runs on: http://localhost:5000

### 2. Start Frontend (New Terminal)
```bash
cd frontend
npm run dev
```
Runs on: http://localhost:5173

### 3. Login
- Open: http://localhost:5173
- Username: `admin`
- Password: `admin123`

## ✨ Features

- 🎨 Color-coded threats (🟢 Green, 🟡 Yellow, 🔴 Red)
- 📊 Real-time monitoring dashboard
- 🔐 JWT authentication
- 🔄 Auto-refresh (3s/5s/10s/30s)
- 📱 Responsive design

## 📁 Files Created

```
procSentinel/
├── api_server.py           ← Backend Flask API
├── frontend/               ← React + TypeScript UI
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── Login.tsx
│   │   │   ├── Dashboard.tsx
│   │   │   ├── StatsCards.tsx
│   │   │   ├── ProcessTable.tsx
│   │   │   └── ProcessDetails.tsx
│   │   └── ...
│   └── package.json
├── WEB_UI_SETUP.md        ← Detailed docs
└── QUICK_START.md         ← This file
```

## 🎨 Color Scheme

| Threat Level | Color | Score Range |
|--------------|-------|-------------|
| Normal       | 🟢 Green | < 5 |
| Warning      | 🟡 Yellow | 5-8 |
| Critical     | 🔴 Red | ≥ 8 |

## 🔧 Customize

**Change API URL**: `frontend/src/components/Dashboard.tsx` (line 43)  
**Add Users**: `api_server.py` (lines 25-27)  
**Change Colors**: `frontend/src/App.css`

## 📝 Notes

- Backend MUST be running for frontend to work
- Default port 5000 (backend) and 5173 (frontend)
- Data refreshes every 5 seconds by default
- Uses process monitoring from existing ProcWatch engine

For full documentation, see `WEB_UI_SETUP.md`
