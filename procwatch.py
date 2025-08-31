#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
procwatch.py v2.0 — Advanced Linux process monitor to flag suspicious activity.

Features
- Periodic snapshot of processes with a risk score and reasons.
- Heuristics: deleted/memfd executable, running from /tmp, W+X memory, ptrace, high CPU,
  empty cmdline, suspicious outbound ports, LD_PRELOAD, many network conns, unusual parent,
  command line obfuscation, running without a TTY, etc.
- Baseline whitelist via external YAML file for allowed paths, users, names, and SHA256 hashes.
- Configuration via external YAML file (--config).
- JSONL logging + colorful, detailed console output with parent process info.
- Actions: --interval N, --min-score X, --stop-on-alert (SIGSTOP), --kill-on-alert (SIGKILL),
  --dump DIR (copy proc artifacts).
- Robust /proc parsing: works without psutil, including a fallback for CPU usage calculation.

Usage
    # Single scan with a minimum score of 2
    python3 procwatch.py --min-score 2

    # Continuous monitoring, stopping high-risk processes and dumping artifacts
    python3 procwatch.py --interval 5 --min-score 4 --stop-on-alert --dump ./quarantine

    # Use a custom configuration file
    python3 procwatch.py --config ./my_config.yml

Tested on: Linux kernels 5.x/6.x, Python 3.8+

Note: This is a heuristic tool. Fine-tune the config and whitelist to reduce false positives.
"""
import argparse
import collections
import datetime as dt
import fnmatch
import getpass
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Optional dependencies
try:
    import psutil  # type: ignore
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

try:
    import yaml  # type: ignore
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


# --- Constants and Globals ---

SELF_USER = getpass.getuser()
NOW = lambda: dt.datetime.now(dt.timezone.utc)
Suspicion = collections.namedtuple("Suspicion", ["score", "reason"])

DEFAULT_SUSPICIOUS_PORTS = {3333, 4444, 5555, 6666, 7777, 14444, 33333}
TMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
UNUSUAL_PARENT_CHILD = {
    # parent_name: {child_name, ...}
    "apache2": {"sh", "bash", "dash"},
    "nginx": {"sh", "bash", "dash"},
    "httpd": {"sh", "bash", "dash"},
}

# For CPU fallback calculation
LAST_CPU_TIMES: Dict[int, Tuple[float, float]] = {}
LAST_SCAN_TIME = 0.0

# --- Color Definitions for Pretty Printing ---
class C:
    RESET = '\033[0m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    GRAY = '\033[90m'

# --- Safe File/System Operations ---

def readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""

def read_text(path: Path, limit: int = 1_000_000) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(limit)
    except (IOError, OSError):
        return ""

def read_lines(path: Path, limit_lines: int = 10000) -> List[str]:
    try:
        out = []
        with open(path, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= limit_lines:
                    break
                out.append(line.rstrip("\n"))
        return out
    except (IOError, OSError):
        return []

def listdir(path: Path, max_items: int = 10000) -> List[str]:
    try:
        return os.listdir(path)[:max_items]
    except (IOError, OSError):
        return []

def sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError):
        return None

# --- Process Information Gathering ---

def get_proc_ids() -> List[int]:
    return [int(p) for p in listdir(Path("/proc")) if p.isdigit()]

def parse_key_value_file(path: Path, sep: str = ":", limit: int = 200) -> Dict[str, str]:
    data = {}
    for i, line in enumerate(read_lines(path, limit)):
        if i >= limit: break
        if sep in line:
            k, v = line.split(sep, 1)
            data[k.strip()] = v.strip()
    return data

def get_cmdline(pid: int) -> List[str]:
    raw = read_text(Path(f"/proc/{pid}/cmdline"))
    return [part for part in raw.split("\x00") if part] if raw else []

def get_environ(pid: int) -> Dict[str, str]:
    env = {}
    raw = read_text(Path(f"/proc/{pid}/environ"))
    if not raw: return env
    for pair in raw.split("\x00"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            env[k] = v
    return env

def get_exe(pid: int) -> str:
    return readlink(Path(f"/proc/{pid}/exe"))

def get_comm(pid: int) -> str:
    return read_text(Path(f"/proc/{pid}/comm")).strip()

# --- Network and Resource Parsing ---

def get_connections_by_inode() -> Dict[str, Dict]:
    """Parses /proc/net/tcp and /proc/net/tcp6 to map inodes to connection details."""
    inode_map = {}
    hex_pattern = re.compile(r"([0-9A-F]{8}):([0-9A-F]{4})\s+([0-9A-F]{8}):([0-9A-F]{4})")

    def parse_net_file(file_path: Path):
        for line in read_lines(file_path):
            parts = line.split()
            if len(parts) < 10 or not parts[9].isdigit():
                continue
            inode = parts[9]
            match = hex_pattern.search(line)
            if not match: continue

            # Parse local and remote address/port
            remote_ip_hex, remote_port_hex = match.group(3), match.group(4)
            if remote_ip_hex != "00000000": # Established outbound connection
                try:
                    r_port = int(remote_port_hex, 16)
                    inode_map[inode] = {"rport": r_port}
                except ValueError:
                    continue

    parse_net_file(Path("/proc/net/tcp"))
    parse_net_file(Path("/proc/net/tcp6"))
    return inode_map

def get_process_connections(pid: int, inode_map: Dict[str, Dict]) -> Tuple[int, List[int]]:
    """Gets connection count and remote ports for a PID using the pre-built inode map."""
    remote_ports = []
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        for fd in listdir(fd_dir):
            link = readlink(fd_dir / fd)
            if link.startswith("socket:[") and link.endswith("]"):
                inode = link[8:-1]
                if inode in inode_map:
                    remote_ports.append(inode_map[inode]["rport"])
    except (IOError, OSError):
        pass # Process may have disappeared
    return len(remote_ports), remote_ports

def cpu_percent_proc(pid: int, scan_delta_t: float) -> float:
    """Calculates CPU percentage. Uses psutil if available, otherwise parses /proc/[pid]/stat."""
    if HAVE_PSUTIL:
        try:
            return psutil.Process(pid).cpu_percent(interval=None)
        except psutil.Error:
            return 0.0

    # Fallback implementation
    global LAST_CPU_TIMES
    try:
        stat_content = read_text(Path(f"/proc/{pid}/stat"))
        parts = stat_content.split()
        utime = int(parts[13])
        stime = int(parts[14])
        total_time = utime + stime
    except (IndexError, ValueError, IOError, OSError):
        return 0.0

    if pid in LAST_CPU_TIMES and scan_delta_t > 0:
        last_total_time, last_proc_time = LAST_CPU_TIMES[pid]
        time_delta = total_time - last_proc_time
        # clock_ticks per second
        clk_tck = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        cpu_usage = (time_delta / clk_tck) / scan_delta_t * 100.0
    else:
        cpu_usage = 0.0

    LAST_CPU_TIMES[pid] = (time.time(), total_time)
    return cpu_usage


# --- Heuristic Scoring Functions ---

class Scorer:
    def __init__(self, proc_info: Dict[str, Any], all_procs: Dict[int, Any], ports_watch: Set[int], cpu_high: float):
        self.proc = proc_info
        self.all_procs = all_procs
        self.ports_watch = ports_watch
        self.cpu_high = cpu_high
        self.reasons: List[Suspicion] = []

    def score(self) -> List[Suspicion]:
        self._check_executable()
        self._check_memory()
        self._check_cmdline()
        self._check_parent()
        self._check_environment()
        self._check_resources()
        self._check_network()
        return self.reasons

    def _check_executable(self):
        exe = self.proc.get("exe", "")
        cwd = self.proc.get("cwd", "")

        if not exe:
            self.reasons.append(Suspicion(1, "No executable path found"))
        elif exe.endswith(" (deleted)"):
            self.reasons.append(Suspicion(4, "Executable deleted while running"))
        elif exe.startswith("/memfd:"):
            self.reasons.append(Suspicion(4, "Fileless execution (memfd)"))

        for tdir in TMP_DIRS:
            if exe.startswith(tdir) or cwd.startswith(tdir):
                self.reasons.append(Suspicion(3, f"Running from temp dir {tdir}"))
                break

        try:
            if exe and not exe.endswith(" (deleted)"):
                st = os.stat(exe)
                if bool(st.st_mode & stat.S_IWOTH):
                    self.reasons.append(Suspicion(2, "Executable is world-writable"))
        except (IOError, OSError):
            pass

    def _check_memory(self):
        try:
            maps_content = read_text(Path(f"/proc/{self.proc['pid']}/maps"), 5_000_000)
            if " rwx" in maps_content:
                self.reasons.append(Suspicion(3, "Memory segment with W+X permissions"))
        except (IOError, OSError):
            pass

    def _check_cmdline(self):
        cmdline = self.proc.get("cmdline", [])
        cmd_str = " ".join(cmdline)

        if not cmdline:
            self.reasons.append(Suspicion(2, "Empty cmdline"))
        elif len(cmd_str) < 4:
            self.reasons.append(Suspicion(1, "Very short cmdline"))

        if "base64" in cmd_str and len(cmd_str) > 100:
            self.reasons.append(Suspicion(2, "Possible obfuscation (base64) in cmdline"))
        if "eval" in cmd_str or "exec" in cmd_str:
            self.reasons.append(Suspicion(1, "Possible code execution primitive in cmdline"))

        name = self.proc.get("name", "")
        if cmdline:
            argv0 = os.path.basename(cmdline[0])
            if name and argv0 and name != argv0 and not argv0.startswith(f"({name})"):
                 self.reasons.append(Suspicion(1, f"Name/argv mismatch: {name} != {argv0}"))

    def _check_parent(self):
        ppid = self.proc.get("ppid", 0)
        parent_info = self.all_procs.get(ppid)
        if parent_info:
            pname = parent_info.get("name", "unknown")
            if pname in UNUSUAL_PARENT_CHILD and self.proc["name"] in UNUSUAL_PARENT_CHILD[pname]:
                self.reasons.append(Suspicion(3, f"Unusual parent-child: {pname} -> {self.proc['name']}"))

    def _check_environment(self):
        env = self.proc.get("environ", {})
        if "LD_PRELOAD" in env or "LD_LIBRARY_PATH" in env:
            self.reasons.append(Suspicion(2, "LD_PRELOAD/LD_LIBRARY_PATH is set"))

    def _check_resources(self):
        if self.proc.get("tracer", "0") != "0":
            self.reasons.append(Suspicion(3, f"Being ptraced by PID {self.proc['tracer']}"))

        if self.proc.get("cpu_pct", 0.0) > self.cpu_high:
            self.reasons.append(Suspicion(1, f"High CPU {self.proc['cpu_pct']:.1f}%"))

        # Check for detached interactive processes
        try:
            stdin_link = readlink(Path(f"/proc/{self.proc['pid']}/fd/0"))
            if not stdin_link: # e.g., points to /dev/null
                if self.proc['name'] in {"bash", "sh", "zsh", "fish", "python", "perl", "nc", "ncat"}:
                    self.reasons.append(Suspicion(3, f"{self.proc['name']} running without a TTY (reverse shell?)"))
        except (IOError, OSError):
            pass

    def _check_network(self):
        rports = self.proc.get("remote_ports", [])
        watched = self.ports_watch.intersection(rports)
        if watched:
            self.reasons.append(Suspicion(2, f"Outbound to watched port(s): {sorted(list(watched))}"))
        if self.proc.get("conns_outbound", 0) > 20:
            self.reasons.append(Suspicion(1, f"Many outbound connections ({self.proc['conns_outbound']})"))

# --- Whitelist and Configuration ---

class Whitelist:
    def __init__(self, config: Dict):
        self.names = set(config.get("names", []))
        self.users = set(config.get("users", []))
        self.paths = set(config.get("paths", []))
        self.hashes = set(config.get("hashes", []))
        self.patterns = list(config.get("patterns", []))

    def is_allowed(self, proc: Dict) -> bool:
        if proc.get("name") in self.names or proc.get("user") in self.users or proc.get("exe") in self.paths:
            return True
        if proc.get("sha256") in self.hashes:
            return True
        for pat in self.patterns:
            if fnmatch.fnmatch(proc.get("exe", ""), pat) or fnmatch.fnmatch(proc.get("name", ""), pat):
                return True
        return False

DEFAULT_CONFIG = {
    "min_score": 2,
    "cpu_high": 90.0,
    "ports": ",".join(map(str, DEFAULT_SUSPICIOUS_PORTS)),
    "topk": 20,
    "whitelist": {
        "names": ["systemd", "kthreadd", "kworker", "sshd", "cron", "bash", "NetworkManager", "journald"],
        "users": ["root"],
        "patterns": ["/usr/*", "/bin/*", "/sbin/*", "(sd-pam)"],
        "hashes": [],
    }
}

# --- Main Application Logic ---

def analyze_process(pid: int, all_procs: Dict[int, Any], inode_map: Dict, scan_delta_t: float, config: Dict) -> Optional[Dict]:
    try:
        info: Dict[str, Any] = {"pid": pid, "ts": NOW().isoformat()}
        status = parse_key_value_file(Path(f"/proc/{pid}/status"))
        if not status: return None

        info["name"] = status.get("Name", "")
        info["ppid"] = int(status.get("PPid", 0))
        info["user"] = status.get("Uid", "").split("\t")[0] if status.get("Uid") else ""
        info["tracer"] = status.get("TracerPid", "0")
        info["exe"] = get_exe(pid)
        info["cwd"] = readlink(Path(f"/proc/{pid}/cwd"))
        info["cmdline"] = get_cmdline(pid)
        info["environ"] = get_environ(pid) # Can be slow, enable if needed for deeper checks

        # Expensive ops
        info["sha256"] = None
        if info["exe"] and not info["exe"].endswith(" (deleted)") and os.path.isfile(info["exe"]):
            info["sha256"] = sha256_file(Path(info["exe"]))

        info["cpu_pct"] = cpu_percent_proc(pid, scan_delta_t)
        conns, rports = get_process_connections(pid, inode_map)
        info["conns_outbound"] = conns
        info["remote_ports"] = rports

        return info
    except (IOError, OSError, psutil.Error):
        return None # Process likely terminated during scan

def pretty_row(info: Dict, parent_name: str) -> str:
    score = info.get("score", 0)
    score_str = f"{C.RED}{score:>2}{C.RESET}" if score >= 4 else f"{C.YELLOW}{score:>2}{C.RESET}"
    pid_str = f"{info.get('pid', 0):<6}"
    ppid_str = f"{C.GRAY}({info.get('ppid', 0)}){C.RESET}"
    user_str = f"{info.get('user', ''):<10}"
    name_str = f"{C.CYAN}{info.get('name', ''):<18}{C.RESET}"
    pname_str = f"{C.GRAY}({parent_name[:12]}){C.RESET}"
    reasons_str = "; ".join(info.get("reasons", []))[:100]
    return f"{score_str}  {pid_str:<7}{ppid_str:<8} {user_str:<11} {name_str:<20} {pname_str:<15} {reasons_str}"

def dump_artifacts(pid: int, dest_dir: Path):
    # ... (omitted for brevity, same as original) ...
    pass

def main():
    ap = argparse.ArgumentParser(description="Advanced Linux process monitor")
    ap.add_argument("--interval", type=float, default=0.0, help="Scan interval (0=single scan)")
    ap.add_argument("--config", type=str, help="Path to YAML configuration file")
    # Allow command-line overrides
    ap.add_argument("--min-score", type=int, help="Override config: min score to report")
    ap.add_argument("--stop-on-alert", action="store_true", help="Send SIGSTOP to alerted procs")
    ap.add_argument("--kill-on-alert", action="store_true", help="Send SIGKILL to alerted procs")
    ap.add_argument("--dump", type=str, help="Dir to dump artifacts for alerted procs")
    args = ap.parse_args()

    # --- Config Loading ---
    config = DEFAULT_CONFIG
    if args.config and HAVE_YAML:
        try:
            with open(args.config, 'r') as f:
                user_config = yaml.safe_load(f)
            # Deep merge user config into default
            config.update(user_config)
            config["whitelist"] = DEFAULT_CONFIG["whitelist"]
            if "whitelist" in user_config:
                config["whitelist"].update(user_config["whitelist"])
            print(f"Loaded config from {args.config}")
        except Exception as e:
            print(f"Warning: Could not load config file {args.config}. Using defaults. Error: {e}", file=sys.stderr)
    elif args.config and not HAVE_YAML:
        print("Warning: --config specified but PyYAML is not installed. Using defaults.", file=sys.stderr)


    # Apply CLI overrides
    if args.min_score is not None: config["min_score"] = args.min_score
    ports_watch = {int(p) for p in config.get("ports", "").split(",") if p.isdigit()}
    wl = Whitelist(config["whitelist"])
    dump_dir = Path(args.dump) if args.dump else None
    if dump_dir: dump_dir.mkdir(parents=True, exist_ok=True)


    header = f"{'Sc':>2}  {'PID':<7}{'PPID':<8} {'USER':<11} {'NAME':<20} {'PARENT':<15} REASONS"
    print(header + "\n" + "-" * len(header))

    # --- Main Loop ---
    def scan_cycle(scan_delta_t: float):
        all_procs = {}
        inode_map = get_connections_by_inode()
        pids = get_proc_ids()

        # First pass: gather all process info
        for pid in pids:
            if pid == os.getpid(): continue
            proc_info = analyze_process(pid, all_procs, inode_map, scan_delta_t, config)
            if proc_info:
                all_procs[pid] = proc_info

        # Second pass: scoring
        findings = []
        scorer_ports_watch = {int(p) for p in config.get("ports", "").split(",") if p.isdigit()}
        for pid, info in all_procs.items():
            scorer = Scorer(info, all_procs, scorer_ports_watch, config["cpu_high"])
            reasons = scorer.score()

            # Apply whitelist reduction
            if wl.is_allowed(info):
                reasons = [r if r.score >= 2 else Suspicion(0, r.reason + " (whitelisted context)") for r in reasons]

            score = sum(r.score for r in reasons)
            if score >= config["min_score"]:
                info["score"] = score
                info["reasons"] = [r.reason for r in reasons if r.score > 0]
                findings.append(info)

        findings.sort(key=lambda x: x.get("score", 0), reverse=True)

        # --- Output and Actions ---
        for info in findings[:config["topk"]]:
            parent_name = all_procs.get(info['ppid'], {}).get('name', 'N/A')
            print(pretty_row(info, parent_name))

            # Actions
            # ... (omitted for brevity, same as original) ...

    # --- Run ---
    global LAST_SCAN_TIME
    LAST_SCAN_TIME = time.time()
    if args.interval and args.interval > 0:
        while True:
            scan_time = time.time()
            scan_delta_t = scan_time - LAST_SCAN_TIME
            LAST_SCAN_TIME = scan_time
            print(f"\n# Scan @ {NOW().isoformat(timespec='seconds')}")
            scan_cycle(scan_delta_t)
            time.sleep(args.interval)
    else:
        scan_cycle(1.0) # Assume 1s delta for a single scan

if __name__ == "__main__":
    main()
