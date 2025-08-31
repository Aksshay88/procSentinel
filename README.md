# Procwatch 

Procwatch is a lightweight Linux process monitoring tool designed to flag suspicious activity based on heuristics. It periodically inspects running processes, assigns risk scores, and can take configurable actions such as alerting, killing, or dumping process artifacts.

## Features

* **Heuristics-based Detection**:

  * Deleted executables still running
  * Processes executing from `/tmp` or `/dev/shm`
  * Writable + Executable (W+X) memory regions
  * Ptrace usage
  * High CPU usage
  * Empty command-line arguments
  * Suspicious outbound network connections (e.g., high ports, non-standard destinations)
* **Risk Scoring**: Each heuristic contributes to a weighted score.
* **Actions**:

  * Alert (log suspicious processes)
  * Kill suspicious processes (`--kill-on-alert`)
  * Stop scanning after first alert (`--stop-on-alert`)
  * Dump process artifacts (`--dump`) for forensic review
* **Artifacts Dumped**:

  * Executable path
  * Command line
  * Environment variables
  * Memory maps
  * File descriptors
* **Configuration**:

  * YAML-based config file for weights, thresholds, whitelists
  * Default config built-in, can be extended via `~/.procwatch.yaml`

## Requirements

* Python 3.8+
* Linux system with `/proc`
* Optional: `psutil` for enhanced CPU/memory stats

## Installation

Clone the repo and install dependencies:

```bash
pip install pyyaml psutil
```

## Usage

Basic scan (single run):

```bash
python3 procwatch.py
```

Continuous monitoring every 10s:

```bash
python3 procwatch.py --interval 10
```

Kill flagged processes:

```bash
python3 procwatch.py --kill-on-alert
```

Dump artifacts of flagged processes:

```bash
python3 procwatch.py --dump
```

Combine options:

```bash
python3 procwatch.py --interval 5 --dump --kill-on-alert
```

## Config Example (`~/.procwatch.yaml`)

```yaml
scan_interval: 10
cpu_threshold: 50.0
weights:
  deleted_exe: 5
  tmp_exe: 4
  wx_mem: 4
  ptrace: 5
  high_cpu: 3
  empty_cmdline: 2
  suspicious_port: 4
whitelist:
  exe_paths:
    - "/usr/bin/legit_tool"
  users:
    - "trusted_user"
```

## Roadmap

* Add JSONL logging for structured alerts
* Add ML-assisted anomaly scoring
* Expand heuristics (fileless execution, privilege escalation attempts)
* Systemd integration for persistent monitoring

## Disclaimer

Procwatch is a research/educational tool. Use with caution in production systems. Killing or dumping processes may impact running services.

