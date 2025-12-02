# Procwatch Guide

## Introduction

Procwatch is a lightweight, heuristic-based process monitoring tool for Linux. It is designed to identify suspicious processes running on your system by analyzing various process attributes and assigning a risk score. When a process's score exceeds a configurable threshold, `procwatch` can alert you, kill the process, and/or dump its artifacts for later forensic analysis.

## How it Works

Procwatch operates in two main modes: `scan` and `train`.

### Scan Mode

In `scan` mode, `procwatch` performs the following steps:

1.  **Process Collection**: It iterates through all running processes in the `/proc` filesystem.
2.  **Analysis**: For each process, it gathers information about its executable, command line, memory maps, parent process, environment variables, resource usage, and network connections.
3.  **Heuristic Scoring**: It applies a set of heuristics to each process to identify suspicious characteristics. Each heuristic that matches adds a weighted score to the process's total risk score. The weights for each heuristic are configurable.
4.  **ML Scoring**: If a trained model is available, `procwatch` will also calculate an anomaly score based on the process's features. This score is then multiplied by a configurable weight and added to the total score.
5.  **Action**: If a process's total score exceeds the configured `min_score`, it is flagged as a finding. Based on the command-line arguments, `procwatch` can:
    *   Print an alert to the console.
    *   Kill the process.
    *   Dump the process's artifacts to a directory.
    *   Stop the scan.

### Train Mode

In `train` mode, `procwatch` collects feature data from all running processes for a specified duration. It then uses this data to train a baseline model for anomaly detection. This model can then be used in `scan` mode to improve the detection of suspicious processes. Two types of models are supported: a simple `ZScoreModel` and a more advanced `IsolationForestModel` from `scikit-learn`.

---

## Features

Procwatch uses a combination of heuristics and machine learning to detect suspicious processes.

### Heuristic-based Detection

The following heuristics are used to score processes. The weights for each of these are configurable in the `procwatch.yaml` file.

*   **Deleted Executable**: The process's executable file has been deleted from disk while the process is still running. This is a common technique used by malware to hide its presence.
*   **Fileless Execution (memfd)**: The process is running from a `memfd` file descriptor, which is a form of fileless execution.
*   **Running from Temp Directory**: The process is running from a temporary directory such as `/tmp`, `/var/tmp`, or `/dev/shm`. These directories are often used by malware to store and execute payloads.
*   **World-Writable Executable**: The process's executable file is world-writable, which means any user on the system can modify it.
*   **W+X Memory Regions**: The process has memory regions that are both writable and executable. This is a common characteristic of shellcode and other in-memory threats.
*   **Empty Command Line**: The process has an empty command line, which can be an indicator of process tampering.
*   **Short Command Line**: The process has a very short command line, which can be used to hide malicious activity.
*   **Obfuscated Command Line**: The command line contains "base64", which could indicate obfuscation.
*   **Code Execution in Command Line**: The command line contains "eval" or "exec", which could indicate that code is being executed from the command line.
*   **Name/Argv Mismatch**: The process name is different from the first argument in the command line (`argv[0]`). This can be a sign of process masquerading.
*   **Unusual Parent Process**: The process has a parent process that is not its typical parent. For example, `bash` running as a child of `apache2`.
*   **LD_PRELOAD/LD_LIBRARY_PATH**: The process has the `LD_PRELOAD` or `LD_LIBRARY_PATH` environment variables set, which can be used to load malicious libraries.
*   **Ptraced**: The process is being traced by another process using `ptrace`. This can be used for debugging, but also for malicious purposes like code injection.
*   **High CPU Usage**: The process is consuming a high amount of CPU, which could indicate malicious activity like cryptomining.
*   **Running without a TTY**: A shell or interpreter (like `bash` or `python`) is running without a terminal, which could be a sign of a reverse shell.
*   **Outbound to Watched Port**: The process has an outbound network connection to a port on a configurable watch list.
*   **Many Outbound Connections**: The process has a large number of outbound network connections.
*   **No Executable Path**: The process has no executable path. This is common for kernel threads, but can also be a sign of a malicious process.

### Machine Learning-based Detection

If you train a model, `procwatch` can use it to calculate an anomaly score for each process. This score is based on a set of features extracted from the process, including:

*   CPU usage
*   Memory usage
*   Number of threads
*   Number of open file descriptors
*   Number of network connections
*   And more...

The anomaly score is then multiplied by a configurable weight and added to the heuristic score to get the total risk score.

### Actions

When a suspicious process is found, `procwatch` can take the following actions:

*   **Alert**: Print a detailed alert to the console.
*   **Kill**: Kill the process using `SIGKILL`.
*   **Dump**: Dump the process's artifacts to a directory for forensic analysis.
*   **Stop**: Stop the scan after the first alert.

---

## Usage

Procwatch is a command-line tool with two main subcommands: `scan` and `train`.

### `scan`

The `scan` command is used to scan the system for suspicious processes.

```bash
python3 procwatch.py scan [OPTIONS]
```

**Options:**

*   `--interval <SECONDS>`: Run the scan every `<SECONDS>` seconds. If not specified, a single scan is performed.
*   `--config <PATH>`: Path to a custom YAML configuration file.
*   `--model <PATH>`: Path to a trained ML model.
*   `--min-score <FLOAT>`: Override the `min_score` from the config file.
*   `--stop-on-alert`: Stop the scan after the first suspicious process is found.
*   `--kill-on-alert`: Kill any suspicious processes that are found.
*   `--dump <DIRECTORY>`: Dump artifacts of suspicious processes to the specified directory.

**Examples:**

Run a single scan:
```bash
python3 procwatch.py scan
```

Run a continuous scan every 10 seconds:
```bash
python3 procwatch.py scan --interval 10
```

Kill any suspicious processes found:
```bash
python3 procwatch.py scan --kill-on-alert
```

Dump artifacts of suspicious processes to `/tmp/procwatch_dumps`:
```bash
python3 procwatch.py scan --dump /tmp/procwatch_dumps
```

### `train`

The `train` command is used to create a baseline model for the machine learning-based detection.

```bash
python3 procwatch.py train [OPTIONS]
```

**Options:**

*   `--duration <SECONDS>`: The duration of the training in seconds. The default is 60 seconds.
*   `--interval <SECONDS>`: The sampling interval during training. The default is 5.0 seconds.
*   `--config <PATH>`: Path to a custom YAML configuration file.
*   `--model <PATH>`: Path to save the trained model. The default is `~/.local/share/procwatch/model.json`.

**Example:**

Train a model for 120 seconds:
```bash
python3 procwatch.py train --duration 120
```

---

## Configuration

Procwatch can be configured using a YAML file. By default, it looks for `~/.procwatch.yaml`, but you can specify a different path using the `--config` option.

The default configuration is as follows:

```yaml
min_score: 2
cpu_high: 90.0
ports: "3333,4444,5555,6666,7777,14444,33333"
topk: 20
ml_weight: 2.0
use_sklearn: false
weights:
    deleted_exe: 4
    memfd_exe: 4
    tmp_exe: 3
    world_writable_exe: 2
    wx_mem: 3
    empty_cmdline: 2
    short_cmdline: 1
    obfuscated_cmdline: 2
    code_exec_cmdline: 1
    name_argv_mismatch: 1
    unusual_parent: 3
    ld_preload: 2
    ptraced: 3
    high_cpu: 1
    no_tty: 3
    watched_port: 2
    many_conns: 1
    no_exe: 1
whitelist:
    names: ["systemd", "kthreadd", "kworker", "sshd", "cron", "bash", "NetworkManager", "journald"]
    users: ["root"]
    patterns: ["/usr/*", "/bin/*", "/sbin/*", "(sd-pam)"]
    hashes: []
    paths: []
```

**Options:**

*   `min_score`: The minimum total score for a process to be considered suspicious.
*   `cpu_high`: The CPU usage percentage above which a process is considered to have high CPU usage.
*   `ports`: A comma-separated list of ports to watch for outbound connections.
*   `topk`: The maximum number of findings to report in a single scan.
*   `ml_weight`: The weight to apply to the machine learning anomaly score.
*   `use_sklearn`: Whether to use the `IsolationForestModel` from `scikit-learn` for training. If `false`, a simpler `ZScoreModel` is used.
*   `weights`: A dictionary of weights for each heuristic.
*   `whitelist`: A set of rules to whitelist processes, users, paths, and executable hashes.

## Dumping Artifacts

When you use the `--dump` option, `procwatch` will create a directory for each suspicious process that it finds. The directory will be named `<PID>_<TIMESTAMP>` and will contain the following files:

*   `cmdline`: The process's command line.
*   `environ`: The process's environment variables.
*   `exe`: A copy of the process's executable file.
*   `exe.error`: If there was an error copying the executable, this file will contain the error message.
*   `maps`: The process's memory maps.
*   `fds`: The process's open file descriptors.

These artifacts can be used for further investigation and forensic analysis.
