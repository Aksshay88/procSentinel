# ProcWatch Configuration Guide

## Quick Start

Copy the sample config to your home directory:
```bash
cp procwatch.yaml ~/.procwatch.yaml
```

Use the config file:
```bash
# With scan command
procwatch scan --config ~/.procwatch.yaml

# With API server
procwatch api --config ~/.procwatch.yaml

# With training
procwatch train --config ~/.procwatch.yaml
```

## Configuration Hierarchy

1. **Built-in defaults** - Defined in `procwatch/config.py`
2. **Config file** - Overrides defaults (YAML format)
3. **Command-line flags** - Override everything

## Key Configuration Sections

### 1. Scoring Thresholds

| Setting | Default | Description |
|---------|---------|-------------|
| `min_score` | 3.0 | Minimum total score to flag as suspicious |
| `cpu_high` | 90.0 | CPU% threshold for high CPU detection |
| `ml_weight` | 2.0 | Weight multiplier for ML anomaly scores |
| `topk` | 20 | Number of top processes to display |

**Score Calculation:**
```
total_score = heuristic_score + (ml_weight × ml_score)
```

### 2. Heuristic Weights

Control how much each detection rule contributes:

**Critical Issues (Weight 4-5):**
- `deleted_exe`: Deleted executable (fileless malware)
- `memfd_exe`: Memory file descriptor execution
- `tmp_exe`: Running from /tmp or /dev/shm

**Moderate Issues (Weight 2-3):**
- `wx_mem`: Writable+executable memory
- `ptraced`: Being debugged
- `unusual_parent`: Suspicious parent process
- `watched_port`: Connected to monitored port

**Minor Issues (Weight 1):**
- `high_cpu`: High CPU usage
- `empty_cmdline`: Empty command line
- `many_conns`: Many network connections

**Disable a heuristic:** Set weight to 0

### 3. Network Monitoring

```yaml
ports: "3333,4444,5555,6666,7777,8888"
```

Monitors connections to these ports. Common backdoor ports include:
- 3333-9999: Common C2 channels
- 14444, 31337, 33333: Known malware ports

### 4. Whitelist

Reduce false positives by whitelisting trusted processes:

```yaml
whitelist:
  names:           # Exact process names
    - systemd
    - sshd
  
  users:           # User IDs or names
    - "1000"
  
  patterns:        # Glob patterns
    - /usr/bin/*
    - "systemd-*"
  
  hashes:          # SHA256 of executables
    - "abc123..."
  
  paths:           # Exact executable paths
    - /opt/app/service
```

**Whitelist Behavior:**
- Reduces scores by 3 points (configurable)
- Does NOT reduce high-severity issues (score ≥ 5)
- Adds "(whitelisted)" suffix to reasons

## Configuration Examples

### High Security Environment

Strict detection with low threshold:

```yaml
min_score: 2.0
cpu_high: 70.0
ml_weight: 3.0

weights:
  deleted_exe: 5
  memfd_exe: 5
  tmp_exe: 4
  wx_mem: 4
  unusual_parent: 4

# Minimal whitelist
whitelist:
  names: []
  users: []
```

### Development Environment

Relaxed detection for dev machines:

```yaml
min_score: 5.0
cpu_high: 95.0
ml_weight: 1.5

weights:
  tmp_exe: 0          # Devs often run from /tmp
  short_cmdline: 0
  obfuscated_cmdline: 0

whitelist:
  patterns:
    - "python*"
    - "node*"
    - "npm*"
    - "/home/*/dev/*"
```

### Production Server

Focus on network and privilege issues:

```yaml
min_score: 3.0
ports: "22,80,443,3306,5432,6379"

weights:
  watched_port: 4
  many_conns: 2
  unusual_parent: 4
  ptraced: 5

whitelist:
  names:
    - nginx
    - postgres
    - redis-server
    - mysqld
```

### Container Environment

Optimized for Docker/Kubernetes:

```yaml
min_score: 4.0

weights:
  no_tty: 0          # Containers often have no TTY
  unusual_parent: 2  # Different parent relationships

whitelist:
  names:
    - dockerd
    - containerd
    - kubelet
    - pause
  patterns:
    - "kube-*"
    - "docker-*"
```

## Environment-Specific Ports

### Web Servers
```yaml
ports: "80,443,8080,8443,3000,5000,9000"
```

### Databases
```yaml
ports: "3306,5432,6379,27017,9042,7000,7001"
```

### Development
```yaml
ports: "3000,4200,5000,8000,8080,8888,9000"
```

### Backdoor Detection
```yaml
ports: "1337,3333,4444,5555,6666,7777,8888,9999,31337,33333"
```

## Command-Line Overrides

Override config file settings:

```bash
# Override min_score
procwatch scan --config myconfig.yaml --min-score 5.0

# Override model path
procwatch api --config myconfig.yaml --model /path/to/model.json

# Override interval
procwatch scan --config myconfig.yaml --interval 10
```

## Tuning Tips

### 1. Calibrate Threshold
```bash
# See what would be detected
procwatch scan --min-score 1.0 | less

# Adjust based on false positives
procwatch scan --min-score 3.0
procwatch scan --min-score 5.0
```

### 2. Test Whitelist
```bash
# Before whitelist
procwatch scan > before.txt

# After whitelist (in config)
procwatch scan > after.txt

# Compare
diff before.txt after.txt
```

### 3. Measure False Positives
```bash
# Monitor for 1 hour
procwatch scan --interval 60 --config ~/.procwatch.yaml | tee results.log

# Count unique suspicious processes
grep -E "^\s+[0-9]+" results.log | awk '{print $2}' | sort -u | wc -l
```

### 4. Profile Your Environment
```bash
# Train baseline model
procwatch train --duration 300 --config ~/.procwatch.yaml

# Scan using trained model
procwatch scan --model ~/.local/share/procwatch/model.json
```

## Config File Locations

ProcWatch looks for config in these locations (in order):

1. `--config` flag path
2. `~/.procwatch.yaml`
3. `~/.config/procwatch/config.yaml`
4. Built-in defaults

## Validation

Check if your config is valid:

```bash
# PyYAML syntax check
python3 -c "import yaml; yaml.safe_load(open('procwatch.yaml'))"

# Test with procwatch
procwatch scan --config procwatch.yaml --interval 0
```

## Common Issues

**"PyYAML not installed"**
```bash
pip3 install pyyaml
```

**Config not loading**
```bash
# Check file path
ls -la ~/.procwatch.yaml

# Check YAML syntax
yamllint procwatch.yaml
```

**Too many false positives**
- Increase `min_score`
- Add to whitelist
- Reduce weights for specific heuristics

**Missing detections**
- Decrease `min_score`
- Increase `ml_weight`
- Increase weights for relevant heuristics

## API Server Configuration

The API server uses the same config file for scoring logic:

```bash
procwatch api --config ~/.procwatch.yaml --port 8080
```

This affects:
- `min_score` threshold in `/api/suspicious` endpoint
- Heuristic weights in scoring
- Whitelist rules
- ML model weight

HTTP-specific settings (host, port) are command-line only.

## See Also

- `README.md` - Main documentation
- `API_README.md` - API documentation
- `procwatch/config.py` - Default configuration code
