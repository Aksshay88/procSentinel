# ProcWatch API

REST API server for ProcWatch process monitoring with a modern web UI.

## Quick Start

### Start the API Server

```bash
# Basic usage (binds to 0.0.0.0:8080)
python3 procwatch.py api

# Custom host and port
python3 procwatch.py api --host localhost --port 9000

# With ML model
python3 procwatch.py api --model ~/.local/share/procwatch/model.json

# With config file
python3 procwatch.py api --config ~/.procwatch.yaml
```

### Access the Web UI

1. Start the API server
2. Open `webui.html` in your browser (or visit http://localhost:8080/api for endpoint info)
3. Update the API_BASE URL in webui.html if using custom host/port

## API Endpoints

### GET /api/processes
Returns all running processes with their scores and analysis.

**Response:**
```json
[
  {
    "pid": 1234,
    "ppid": 1,
    "name": "process_name",
    "parent_name": "systemd",
    "user": "1000",
    "exe": "/usr/bin/process",
    "cwd": "/home/user",
    "cmdline": ["process", "arg1"],
    "cpu_pct": 15.2,
    "conns_outbound": 2,
    "remote_ports": [443, 80],
    "sha256": "abc123...",
    "heuristic_score": 4,
    "ml_score": 0.85,
    "total_score": 5.7,
    "reasons": [
      {"score": 4, "reason": "High CPU usage"}
    ],
    "timestamp": "2026-01-11T16:30:00Z"
  }
]
```

### GET /api/suspicious
Returns only processes above the minimum score threshold.

**Query Parameters:**
- `min_score` (optional): Override default minimum score (default from config)

**Example:**
```bash
curl "http://localhost:8080/api/suspicious?min_score=5.0"
```

### GET /api/process/{pid}
Returns detailed information for a specific process, including environment variables.

**Example:**
```bash
curl "http://localhost:8080/api/process/1234"
```

### GET /api/stats
Returns system-wide statistics.

**Response:**
```json
{
  "total_processes": 247,
  "suspicious_count": 3,
  "min_score_threshold": 3.0,
  "ml_model_loaded": true,
  "timestamp": "2026-01-11T16:30:00Z"
}
```

## Web UI Features

- **Real-time Monitoring**: View all processes or filter suspicious ones
- **Auto-refresh**: Enable 5-second auto-refresh for continuous monitoring
- **Process Details**: Click any process to see detailed information
- **Visual Scoring**: Color-coded scores (green/yellow/red)
- **Statistics Dashboard**: Live stats on total processes, suspicious count, etc.
- **Responsive Design**: Works on desktop and mobile browsers

## Example Usage

### Fetch all processes with curl
```bash
curl http://localhost:8080/api/processes | jq '.[0]'
```

### Monitor suspicious processes
```bash
watch -n 5 'curl -s http://localhost:8080/api/suspicious | jq length'
```

### Get specific process details
```bash
curl http://localhost:8080/api/process/$(pgrep firefox) | jq .
```

### Use with jq for filtering
```bash
# Show top 5 processes by score
curl -s http://localhost:8080/api/processes | jq 'sort_by(.total_score) | reverse | .[0:5]'

# Show all processes with network connections
curl -s http://localhost:8080/api/processes | jq '.[] | select(.conns_outbound > 0)'

# Count processes by user
curl -s http://localhost:8080/api/processes | jq 'group_by(.user) | map({user: .[0].user, count: length})'
```

## CORS Support

The API includes CORS headers (`Access-Control-Allow-Origin: *`) allowing access from any web page.

## Security Notes

- The API runs without authentication by default
- Consider using a reverse proxy (nginx/Apache) for production
- Restrict access with firewall rules if exposed to network
- The API only provides read-only access to process information

## Integration Examples

### Python Client
```python
import requests

# Get suspicious processes
response = requests.get('http://localhost:8080/api/suspicious')
processes = response.json()

for proc in processes:
    print(f"PID {proc['pid']}: {proc['name']} - Score: {proc['total_score']}")
```

### JavaScript/Node.js
```javascript
fetch('http://localhost:8080/api/stats')
  .then(res => res.json())
  .then(stats => console.log(stats));
```

### Bash Script
```bash
#!/bin/bash
# Alert if suspicious count > threshold
THRESHOLD=5
COUNT=$(curl -s http://localhost:8080/api/stats | jq .suspicious_count)

if [ "$COUNT" -gt "$THRESHOLD" ]; then
    echo "ALERT: $COUNT suspicious processes detected!"
fi
```

## Troubleshooting

**Port already in use:**
```bash
python3 procwatch.py api --port 8081
```

**Can't access from another machine:**
- Check firewall settings
- Ensure binding to 0.0.0.0 (not localhost)
- Verify network connectivity

**Web UI not loading data:**
- Check API server is running
- Update API_BASE URL in webui.html
- Check browser console for errors
- Verify CORS headers in response
