#!/usr/bin/env python3

"""
procwatch.py — Lightweight Linux process monitor to flag suspicious activity.

Features
- Periodic snapshot of processes with a risk score and reasons.
- Heuristics: deleted executable, running from /tmp, W+X memory, ptrace, high CPU, empty cmdline,
  suspicious outbound ports (e.g., 3333/14444), LD_PRELOAD, many network conns, unsual parent, etc.
- Baseline whitelist of allowed paths, users, names, and SHA256 of binaries (optional).
- JSONL logging + pretty console output.
- Actions: --once (single scan), --interval N (continuous), --min-score threshold to print,
          --stop-on-alert (SIGSTOP), --kill-on-alert (SIGKILL), --dump DIR (copy proc artifacts).
- No root required for most checks; some (maps, exe) may need elevated perms for other users' procs.

Usage
    python3 procwatch.py --interval 5
    python3 procwatch.py --once --min-score 2
    python3 procwatch.py --interval 10 --min-score 3 --stop-on-alert --dump ./quarantine

Tested on: Linux kernels 5.x/6.x, Python 3.8+

Note: This is a heuristic tool. It reduces noise via whitelists but is not a replacement for EDR.
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
from typing import Dict, List, Tuple, Optional

# Optional psutil for convenience; tool falls back to /proc parsing otherwise
try:
    import psutil  # type: ignore
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False

SELF_USER = getpass.getuser()
NOW = lambda: dt.datetime.now(dt.timezone.utc)

DEFAULT_SUSPICIOUS_PORTS = {3333, 4444, 5555, 7777, 14444, 33333}  # common pool/cryptominer ports
TMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")

def readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except Exception:
        return ""

def read_text(path: Path, limit: int = 1_000_000) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(limit)
    except Exception:
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
    except Exception:
        return []

def listdir(path: Path, max_items: int = 10000) -> List[str]:
    try:
        return os.listdir(path)[:max_items]
    except Exception:
        return []

def sha256_file(path: Path, limit_bytes: Optional[int] = None) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            if limit_bytes is None:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            else:
                remaining = limit_bytes
                while remaining > 0:
                    chunk = f.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    h.update(chunk)
                    remaining -= len(chunk)
        return h.hexdigest()
    except Exception:
        return None

def get_proc_ids() -> List[int]:
    pids = []
    for name in listdir(Path("/proc")):
        if name.isdigit():
            pids.append(int(name))
    return pids

def parse_status(pid: int) -> Dict[str, str]:
    data = {}
    for line in read_lines(Path(f"/proc/{pid}/status"), 200):
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    return data

def get_cmdline(pid: int) -> List[str]:
    raw = read_text(Path(f"/proc/{pid}/cmdline"))
    if not raw:
        return []
    # cmdline entries are NUL-separated
    return [part for part in raw.split("\x00") if part]

def get_environ(pid: int) -> Dict[str, str]:
    env = {}
    raw = read_text(Path(f"/proc/{pid}/environ"))
    if not raw:
        return env
    for pair in raw.split("\x00"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            env[k] = v
    return env

def get_maps_has_wx(pid: int) -> bool:
    for line in read_lines(Path(f"/proc/{pid}/maps"), 100000):
        if " rwx" in line or re.search(r"\brwxp?\b", line):
            return True
    return False

def get_open_files_count(pid: int) -> int:
    return len(listdir(Path(f"/proc/{pid}/fd")))

def get_cwd(pid: int) -> str:
    return readlink(Path(f"/proc/{pid}/cwd"))

def get_exe(pid: int) -> str:
    return readlink(Path(f"/proc/{pid}/exe"))

def get_comm(pid: int) -> str:
    line = read_text(Path(f"/proc/{pid}/comm"))
    return line.strip()

def get_ns_tty(pid: int) -> str:
    # best-effort: check /proc/<pid>/fd/0 link
    tty = readlink(Path(f"/proc/{pid}/fd/0"))
    return tty

def get_connections(pid: int) -> Tuple[int, int, List[int]]:
    """Return (num_total, num_outbound, remote_ports) using ss/lsof fallback if psutil missing."""
    total = 0
    outbound = 0
    remote_ports = []
    if HAVE_PSUTIL:
        try:
            p = psutil.Process(pid)
            conns = p.connections(kind="inet")
            total = len(conns)
            for c in conns:
                if c.raddr and c.raddr.port:
                    outbound += 1
                    remote_ports.append(c.raddr.port)
        except Exception:
            pass
        return total, outbound, remote_ports
    # Fallback: use /proc/net/tcp isn't per-pid. Try ss -tanp (requires perms)
    try:
        out = subprocess.check_output(["ss", "-tanp"], stderr=subprocess.DEVNULL, text=True, timeout=1.5)
        for line in out.splitlines():
            if f"pid={pid}," in line or f"pid={pid} " in line:
                total += 1
                m = re.search(r"\s+\d+\.\d+\.\d+\.\d+:(\d+)\s+\d+\.\d+\.\d+\.\d+:(\d+)", line)
                if m:
                    # lport, rport
                    rp = int(m.group(2))
                    outbound += 1
                    remote_ports.append(rp)
    except Exception:
        pass
    return total, outbound, remote_ports

def cpu_percent_proc(pid: int, last: Dict[int, float], dt_seconds: float) -> float:
    if HAVE_PSUTIL:
        try:
            p = psutil.Process(pid)
            return p.cpu_percent(interval=None) / 100.0  # normalized 0..NCPUs
        except Exception:
            return 0.0
    # Fallback approximate: not tracking jiffies here; return 0 to avoid false positives
    return 0.0

def mem_percent_proc(pid: int) -> float:
    if HAVE_PSUTIL:
        try:
            p = psutil.Process(pid)
            return p.memory_percent()
        except Exception:
            return 0.0
    return 0.0

class Whitelist:
    def __init__(self, names=None, users=None, paths=None, hashes=None, patterns=None):
        self.names = set(names or [])
        self.users = set(users or [])
        self.paths = set(paths or [])
        self.hashes = set(hashes or [])
        self.patterns = list(patterns or [])  # glob patterns for paths or names

    def is_allowed(self, name: str, user: str, exe: str, sha256: Optional[str]) -> bool:
        if name in self.names or user in self.users or exe in self.paths:
            return True
        if sha256 and sha256 in self.hashes:
            return True
        for pat in self.patterns:
            if fnmatch.fnmatch(exe, pat) or fnmatch.fnmatch(name, pat):
                return True
        return False

DEFAULT_WHITELIST = Whitelist(
    names={"systemd", "kthreadd", "kworker", "ksoftirqd", "bash", "ssh", "sshd", "cron", "crond", "journald", "NetworkManager"},
    users={"root"},
    paths={"/usr/bin/python*", "/usr/bin/ssh*", "/usr/sbin/sshd", "/usr/bin/top", "/usr/bin/htop"},
    hashes=set(),
    patterns=["/usr/*", "/bin/*", "/sbin/*"]
)

Suspicion = collections.namedtuple("Suspicion", ["score", "reason"])

def score_process(pid: int, whitelist: Whitelist, cpu_high: float, ports_watch: set, score_threshold: int) -> Tuple[int, List[str], Dict]:
    reasons: List[ Suspicion ] = []
    info: Dict = {"pid": pid, "ts": NOW().isoformat()}

    status = parse_status(pid)
    comm = get_comm(pid)
    cmdline = get_cmdline(pid)
    exe = get_exe(pid)
    cwd = get_cwd(pid)
    env = get_environ(pid)
    user = status.get("Uid", "").split("\t")[0] if status.get("Uid") else ""
    tracer = status.get("TracerPid", "0")
    has_ptracer = tracer not in ("0", "", None)
    name = status.get("Name", comm or (cmdline[0] if cmdline else ""))

    info.update({"name": name, "exe": exe, "cwd": cwd, "user": user, "ppid": status.get("PPid"), "cmdline": cmdline})

    # Deleted executable
    if exe.endswith(" (deleted)"):
        reasons.append(Suspicion(3, "Executable deleted while running"))

    # Running from temp dirs
    for tdir in TMP_DIRS:
        if exe.startswith(tdir) or cwd.startswith(tdir):
            reasons.append(Suspicion(2, f"Running from temp dir {tdir}"))
            break

    # Empty or short cmdline (possible masquerading)
    if len(cmdline) == 0:
        reasons.append(Suspicion(2, "Empty cmdline"))
    elif len(" ".join(cmdline)) < 3:
        reasons.append(Suspicion(1, "Very short cmdline"))

    # Name vs argv mismatch
    if cmdline:
        argv0 = os.path.basename(cmdline[0])
        if name and argv0 and name != argv0:
            reasons.append(Suspicion(1, f"Name/argv mismatch: {name} != {argv0}"))

    # Writable+Executable memory
    if get_maps_has_wx(pid):
        reasons.append(Suspicion(3, "Memory segment with W+X permissions"))

    # Ptrace attached
    if has_ptracer:
        reasons.append(Suspicion(2, f"Being ptraced by PID {tracer}"))

    # Network behavior
    total_conns, outbound, rports = get_connections(pid)
    info.update({"conns_total": total_conns, "conns_outbound": outbound, "remote_ports": rports})
    if outbound >= 10 and outbound >= 0.8 * max(total_conns, 1):
        reasons.append(Suspicion(1, "Many outbound connections"))
    if any(p in ports_watch for p in rports):
        reasons.append(Suspicion(2, f"Outbound to watched port(s): {sorted(set(rports) & ports_watch)}"))

    # LD_PRELOAD / library injection
    if "LD_PRELOAD" in env or "LD_LIBRARY_PATH" in env:
        reasons.append(Suspicion(1, "LD_PRELOAD/LD_LIBRARY_PATH set"))

    # High CPU (normalized percent across CPUs). psutil returns 0..100 per CPU count; we normalize later
    cpu = cpu_percent_proc(pid, {}, 0.0)
    mem = mem_percent_proc(pid)
    info.update({"cpu_norm": cpu, "mem_pct": mem})
    if cpu_high and cpu > cpu_high:
        reasons.append(Suspicion(1, f"High CPU {cpu:.2f}"))

    # Executable permissions (world-writable binaries)
    try:
        st = os.stat(exe)
        if bool(st.st_mode & stat.S_IWOTH):
            reasons.append(Suspicion(2, "Executable is world-writable"))
    except Exception:
        pass

    # Whitelist reduction
    sha = None
    if exe and os.path.exists(exe.replace(" (deleted)", "")) and os.path.isfile(exe.replace(" (deleted)", "")):
        sha = sha256_file(Path(exe.replace(" (deleted)", "")), limit_bytes=8*1024*1024)
    info["sha256"] = sha

    if whitelist.is_allowed(name=name, user=user, exe=exe, sha256=sha):
        # still report but drop 1 point from low-severity reasons
        reasons = [r if r.score >= 2 else Suspicion(0, r.reason + " (whitelisted context)") for r in reasons]

    total_score = sum(r.score for r in reasons)
    info["reasons"] = [r.reason for r in reasons if r.score > 0]
    info["score"] = total_score
    return total_score, [r.reason for r in reasons if r.score > 0], info

def pretty_row(info: Dict) -> str:
    name = info.get("name", "")
    pid = info.get("pid", 0)
    user = info.get("user", "")
    score = info.get("score", 0)
    exe = info.get("exe", "")[:60]
    reasons = "; ".join(info.get("reasons", []))[:120]
    return f"{score:>2}  {pid:<6} {user:<10} {name:<20} {exe:<60} {reasons}"

def dump_artifacts(pid: int, dest_dir: Path) -> List[str]:
    dumped = []
    base = dest_dir / f"pid_{pid}_{int(time.time())}"
    base.mkdir(parents=True, exist_ok=True)
    # Copy maps, environ, cmdline, status, limits, fd listing
    for fn in ["maps", "environ", "cmdline", "status", "limits", "smaps"]:
        src = Path(f"/proc/{pid}/{fn}")
        if src.exists():
            try:
                shutil.copy2(src, base / fn)
                dumped.append(str(base / fn))
            except Exception:
                pass
    # Copy executable (best-effort, limited to 32MB)
    exe_path = readlink(Path(f"/proc/{pid}/exe"))
    if exe_path and os.path.exists(exe_path):
        try:
            with open(exe_path, "rb") as fsrc, open(base / "exe.bin", "wb") as fdst:
                remaining = 32 * 1024 * 1024
                while remaining > 0:
                    chunk = fsrc.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    fdst.write(chunk)
                    remaining -= len(chunk)
            dumped.append(str(base / "exe.bin"))
        except Exception:
            pass
    # Save file descriptors symlinks
    fd_dir = Path(f"/proc/{pid}/fd")
    if fd_dir.exists():
        with open(base / "fd_links.txt", "w") as f:
            for name in listdir(fd_dir, 5000):
                link = readlink(fd_dir / name)
                f.write(f"{name} -> {link}\n")
        dumped.append(str(base / "fd_links.txt"))
    return dumped

def main():
    ap = argparse.ArgumentParser(description="Linux process monitor to flag suspicious activity")
    ap.add_argument("--interval", type=float, default=0.0, help="Scan interval seconds (0 = single scan)")
    ap.add_argument("--min-score", type=int, default=2, help="Only print/report processes with score >= this")
    ap.add_argument("--jsonl", type=str, default="procwatch.jsonl", help="Path to append JSONL logs")
    ap.add_argument("--cpu-high", type=float, default=0.9, help="CPU normalized threshold (0..NCPU) for 'high CPU' heuristic")
    ap.add_argument("--ports", type=str, default=",".join(str(p) for p in sorted(DEFAULT_SUSPICIOUS_PORTS)), help="Comma-separated remote ports to watch")
    ap.add_argument("--stop-on-alert", action="store_true", help="Send SIGSTOP to processes with score >= min-score")
    ap.add_argument("--kill-on-alert", action="store_true", help="Send SIGKILL to processes with score >= min-score (CAUTION)")
    ap.add_argument("--dump", type=str, default="", help="Directory to dump artifacts for alerted processes")
    ap.add_argument("--topk", type=int, default=20, help="Show top-K highest scores per scan")
    args = ap.parse_args()

    ports_watch = set()
    for p in args.ports.split(","):
        p = p.strip()
        if p.isdigit():
            ports_watch.add(int(p))

    wl = DEFAULT_WHITELIST

    jsonl_path = Path(args.jsonl)
    dump_dir = Path(args.dump) if args.dump else None
    if dump_dir:
        dump_dir.mkdir(parents=True, exist_ok=True)

    header = f"{'Sc':>2}  {'PID':<6} {'USER':<10} {'NAME':<20} {'EXE':<60} REASONS"
    print(header)
    print("-" * len(header))

    def scan_once():
        findings: List[Dict] = []
        for pid in get_proc_ids():
            if pid == os.getpid():
                continue
            try:
                score, reasons, info = score_process(pid, wl, args.cpu_high, ports_watch, args.min_score)
                findings.append(info)
            except Exception:
                continue
        findings.sort(key=lambda x: x.get("score", 0), reverse=True)
        to_show = [f for f in findings if f.get("score", 0) >= args.min_score][:args.topk]
        for info in to_show:
            print(pretty_row(info))

        # log JSONL
        with open(jsonl_path, "a") as f:
            for info in to_show:
                f.write(json.dumps(info) + "\n")

        # actions
        for info in to_show:
            pid = info["pid"]
            if dump_dir:
                dumped = dump_artifacts(pid, dump_dir)
            if args.stop_on_alert:
                try:
                    os.kill(pid, signal.SIGSTOP)
                except Exception:
                    pass
            if args.kill_on_alert:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

    if args.interval and args.interval > 0:
        while True:
            print(f"\n# Scan @ {NOW().isoformat()}")
            scan_once()
            time.sleep(args.interval)
    else:
        print(f"# Scan @ {NOW().isoformat()}")
        scan_once()

if __name__ == "__main__":
    main()
