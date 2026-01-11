# Complete ProcWatch Setup Guide

## 📁 Files Overview

### Core Application
- **`procwatch/`** - Main application modules
- **`procwatch.py`** - Entry point script

### API & Web Interface
- **`procwatch/api.py`** - REST API server implementation
- **`webui.html`** - Modern web UI for monitoring
- **`start_api.sh`** - Convenience script to start API server

### Configuration
- **`procwatch.yaml`** - **Sample configuration file** (newly created)
- **`CONFIG_GUIDE.md`** - Complete configuration documentation

### Documentation
- **`README.md`** - Main project documentation
- **`API_README.md`** - API endpoint documentation
- **`API_IMPLEMENTATION.md`** - Technical implementation details
- **`CONFIG_GUIDE.md`** - Configuration reference guide

## 🚀 Getting Started

### Step 1: Install Dependencies

```bash
# Required
pip3 install pyyaml

# Optional (for enhanced features)
pip3 install psutil         # Better CPU/memory stats
pip3 install scikit-learn   # ML isolation forest model
```

### Step 2: Configure ProcWatch

```bash
# Copy sample config to home directory
cp procwatch.yaml ~/.procwatch.yaml

# Edit to customize for your environment
nano ~/.procwatch.yaml
```

### Step 3: Train Baseline Model (Optional)

```bash
# Train on normal system behavior for 5 minutes
procwatch train --duration 300 --config ~/.procwatch.yaml

# Model saved to ~/.local/share/procwatch/model.json
```

### Step 4: Start Using ProcWatch

**Option A: Command-Line Scanning**
```bash
# Single scan
procwatch scan --config ~/.procwatch.yaml

# Continuous monitoring every 10 seconds
procwatch scan --interval 10 --config ~/.procwatch.yaml
```

**Option B: Web Interface + API**
```bash
# Start API server
./start_api.sh

# Or manually
python3 procwatch.py api --config ~/.procwatch.yaml

# Open webui.html in browser
firefox webui.html
```

## 🎯 Quick Usage Examples

### 1. Basic Process Scanning
```bash
# Scan once with default config
procwatch scan

# Scan with custom threshold
procwatch scan --min-score 5.0

# Continuous monitoring
procwatch scan --interval 10
```

### 2. Using the Web UI
```bash
# Start API server on port 8080
procwatch api

# Open webui.html in any browser
# The UI provides:
# - Real-time process monitoring
# - Statistics dashboard
# - Color-coded threat levels
# - Detailed process information
# - Auto-refresh capability
```

### 3. Using the REST API
```bash
# Get system statistics
curl http://localhost:8080/api/stats | python3 -m json.tool

# Get all processes
curl http://localhost:8080/api/processes | python3 -m json.tool

# Get suspicious processes only
curl http://localhost:8080/api/suspicious | python3 -m json.tool

# Get specific process details
curl http://localhost:8080/api/process/1234 | python3 -m json.tool

# Filter by custom threshold
curl "http://localhost:8080/api/suspicious?min_score=5.0" | python3 -m json.tool
```

### 4. Advanced Monitoring
```bash
# Dump artifacts of suspicious processes
procwatch scan --dump /var/log/procwatch/dumps

# Kill suspicious processes automatically (USE WITH CAUTION!)
procwatch scan --kill-on-alert --min-score 8.0

# Stop after first detection
procwatch scan --stop-on-alert

# Use custom model
procwatch scan --model /path/to/model.json
```

## 📊 Configuration Examples

### High Security Server
```yaml
# ~/.procwatch.yaml
min_score: 2.0
cpu_high: 70.0
ml_weight: 3.0

weights:
  deleted_exe: 5
  memfd_exe: 5
  tmp_exe: 4
  wx_mem: 4
  unusual_parent: 4
  ptraced: 5

ports: "3333,4444,5555,6666,7777,31337"

whitelist:
  names:
    - sshd
    - systemd
```

### Development Workstation
```yaml
# ~/.procwatch.yaml
min_score: 5.0
cpu_high: 95.0
ml_weight: 1.5

weights:
  tmp_exe: 0
  short_cmdline: 0

whitelist:
  patterns:
    - "python*"
    - "node*"
    - "/home/*/projects/*"
```

### Container Environment
```yaml
# ~/.procwatch.yaml
min_score: 4.0

weights:
  no_tty: 0

whitelist:
  names:
    - dockerd
    - containerd
    - kubelet
  patterns:
    - "kube-*"
    - "docker-*"
```

## 🔧 Integration Examples

### Python Script
```python
import requests

# Monitor suspicious processes
response = requests.get('http://localhost:8080/api/suspicious')
processes = response.json()

for proc in processes:
    if proc['total_score'] >= 7.0:
        print(f"CRITICAL: {proc['name']} (PID {proc['pid']}) - Score: {proc['total_score']}")
```

### Bash Monitoring Script
```bash
#!/bin/bash
while true; do
    COUNT=$(curl -s http://localhost:8080/api/stats | jq .suspicious_count)
    if [ "$COUNT" -gt 5 ]; then
        echo "ALERT: $COUNT suspicious processes detected!"
        # Send notification, email, etc.
    fi
    sleep 60
done
```

### Systemd Service (Auto-start API)
```ini
# /etc/systemd/system/procwatch.service
[Unit]
Description=ProcWatch API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/procwatch
ExecStart=/usr/bin/python3 /opt/procwatch/procwatch.py api --config /etc/procwatch.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable with:
```bash
sudo systemctl enable procwatch
sudo systemctl start procwatch
```

## 📈 Monitoring Best Practices

### 1. Baseline Training
```bash
# Train during normal operations (no attacks)
procwatch train --duration 600 --interval 5

# Use the trained model
procwatch scan --model ~/.local/share/procwatch/model.json
```

### 2. Threshold Tuning
```bash
# Start permissive, observe for a day
procwatch scan --min-score 5.0 --interval 300 > baseline.log

# Gradually lower threshold
procwatch scan --min-score 3.0 --interval 300

# Find optimal balance between detection and false positives
```

### 3. Whitelist Management
```bash
# Identify false positives
procwatch scan --interval 60 | grep -E "^\s+[3-5]" | awk '{print $3}' | sort | uniq -c

# Add to whitelist in config file
# Test again to verify reduction
```

### 4. Continuous Monitoring
```bash
# Log to file with timestamps
procwatch scan --interval 300 | tee -a /var/log/procwatch/scan.log

# Rotate logs
logrotate -f /etc/logrotate.d/procwatch
```

## 🛡️ Security Considerations

- **Run as root** - Required to see all processes
- **Network exposure** - API server binds to 0.0.0.0 by default
- **Authentication** - API has no authentication (add reverse proxy for production)
- **False positives** - Tune config to reduce false alerts
- **Kill flag** - Use `--kill-on-alert` with extreme caution

## 🐛 Troubleshooting

### Config not loading
```bash
# Check file exists
ls -la ~/.procwatch.yaml

# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('~/.procwatch.yaml'.replace('~', '$HOME')))"

# Verify it's being loaded
procwatch scan --config ~/.procwatch.yaml 2>&1 | grep "Loaded config"
```

### API not accessible
```bash
# Check if running
ps aux | grep "procwatch.py api"

# Check port binding
netstat -tlnp | grep 8080

# Test locally
curl http://localhost:8080/api/stats
```

### Too many false positives
1. Increase `min_score` in config
2. Add processes to whitelist
3. Reduce weights for problematic heuristics
4. Train ML model on your environment

### No suspicious processes detected
1. Decrease `min_score`
2. Increase heuristic weights
3. Check if whitelist is too broad
4. Verify processes are running

## 📚 Further Reading

- **`README.md`** - Project overview and features
- **`API_README.md`** - REST API endpoint reference
- **`CONFIG_GUIDE.md`** - Detailed configuration options
- **`API_IMPLEMENTATION.md`** - Technical architecture

## 🎉 Summary

You now have a fully configured process monitoring system with:

✅ **CLI tool** for command-line scanning  
✅ **REST API** for programmatic access  
✅ **Web UI** for visual monitoring  
✅ **Config file** with comprehensive options  
✅ **Documentation** for all features  
✅ **Examples** for common use cases  

Start monitoring with:
```bash
./start_api.sh
# Then open webui.html in your browser
```

Happy monitoring! 🔍
