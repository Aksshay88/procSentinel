# ProcWatch API Implementation Summary

## What Was Created

### 1. REST API Server (`procwatch/api.py`)
A complete HTTP API server that exposes all ProcWatch functionality through JSON endpoints:

**Key Features:**
- Real-time process monitoring via HTTP
- JSON-formatted responses for all data
- ML model integration for anomaly detection
- Heuristic scoring with configurable thresholds
- CORS support for web access

**Endpoints:**
- `GET /api/processes` - List all processes with scores
- `GET /api/suspicious` - Filter suspicious processes (with min_score parameter)
- `GET /api/process/{pid}` - Get detailed info for specific process
- `GET /api/stats` - System-wide statistics
- `GET /api` - API documentation

### 2. Web UI (`webui.html`)
A modern, responsive single-page web application:

**Features:**
- Real-time process monitoring dashboard
- Statistics panel showing total processes, suspicious count, etc.
- Color-coded scoring (green/yellow/red)
- Sortable process table
- Detailed modal view for individual processes
- Auto-refresh capability (5-second intervals)
- Responsive design for desktop and mobile
- Beautiful gradient UI with smooth animations

**User Actions:**
- View all processes or filter suspicious ones
- Adjust minimum score threshold
- Click any process for detailed information
- Enable auto-refresh for continuous monitoring

### 3. CLI Integration
Added new `api` command to the main CLI:

```bash
procwatch api [--host HOST] [--port PORT] [--config CONFIG] [--model MODEL]
```

### 4. Documentation
- `API_README.md` - Complete API documentation with examples
- Updated main `README.md` with API section
- Integration examples for Python, JavaScript, Bash

## How to Use

### Start the API Server
```bash
python3 procwatch.py api
# Server starts on http://0.0.0.0:8080
```

### Access Web UI
1. Open `webui.html` in any modern browser
2. Click "All Processes" or "Suspicious Only" to load data
3. Click any row to see detailed process information
4. Enable auto-refresh for real-time monitoring

### Use the API Programmatically

**Python:**
```python
import requests
response = requests.get('http://localhost:8080/api/suspicious')
processes = response.json()
```

**curl:**
```bash
curl http://localhost:8080/api/stats | jq .
```

**JavaScript:**
```javascript
fetch('http://localhost:8080/api/processes')
  .then(res => res.json())
  .then(data => console.log(data));
```

## API Response Format

Each process includes:
```json
{
  "pid": 1234,
  "name": "process_name",
  "total_score": 5.7,
  "heuristic_score": 4,
  "ml_score": 0.85,
  "reasons": [{"score": 4, "reason": "High CPU usage"}],
  "cpu_pct": 15.2,
  "conns_outbound": 2,
  "remote_ports": [443, 80],
  "exe": "/usr/bin/process",
  "cmdline": ["process", "arg1"],
  "user": "1000",
  "sha256": "abc123...",
  "timestamp": "2026-01-11T16:30:00Z"
}
```

## Benefits

1. **Remote Monitoring** - Monitor processes from any device with a browser
2. **Integration** - Easy integration with other tools via REST API
3. **Visualization** - User-friendly web interface for non-technical users
4. **Automation** - Scriptable API for automated monitoring/alerting
5. **Real-time** - Live updates with auto-refresh capability
6. **Cross-platform Access** - Web UI works on any OS with a browser

## Architecture

```
┌─────────────┐
│   Web UI    │ (webui.html - Browser)
│  JavaScript │
└──────┬──────┘
       │ HTTP/JSON
       ▼
┌─────────────┐
│  API Server │ (api.py - Python)
│  HTTPServer │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  ProcWatch  │ (Core modules)
│   Engine    │
│             │
│ - proc.py   │ Process analysis
│ - features  │ Feature extraction
│ - heuristic │ Scoring
│ - ml.py     │ ML models
│ - network   │ Network connections
└─────────────┘
```

## Security Considerations

- API runs without authentication (add reverse proxy for production)
- Read-only access to process information
- CORS enabled for web access
- Consider firewall rules if exposing to network
- No process manipulation through API (read-only)

## Future Enhancements

Potential additions:
- WebSocket support for live streaming updates
- Authentication/authorization
- Process killing via API (with auth)
- Historical data and trends
- Alerting/notification system
- Export to CSV/PDF
- Dashboard customization
- Multi-host monitoring
