import os
from pathlib import Path
from typing import Dict, List, Tuple
import time

from .utils import read_text, read_lines, readlink, listdir
from .models import ProcInfo, now_iso

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

LAST_CPU_TIMES: Dict[int, Tuple[float, float]] = {}

def get_proc_ids() -> List[int]:
    return [int(p) for p in listdir(Path("/proc")) if p.isdigit()]

def parse_key_value_file(path: Path, sep: str = ":", limit: int = 200) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for i, line in enumerate(read_lines(path, limit)):
        if i >= limit:
            break
        if sep in line:
            k, v = line.split(sep, 1)
            data[k.strip()] = v.strip()
    return data

def get_cmdline(pid: int) -> List[str]:
    raw = read_text(Path(f"/proc/{pid}/cmdline"))
    return [part for part in raw.split("\x00") if part] if raw else []

def get_environ(pid: int) -> Dict[str, str]:
    env: Dict[str, str] = {}
    raw = read_text(Path(f"/proc/{pid}/environ"))
    if not raw:
        return env
    for pair in raw.split("\x00"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            env[k] = v
    return env

def get_exe(pid: int) -> str:
    return readlink(Path(f"/proc/{pid}/exe"))

def cpu_percent_proc(pid: int, scan_delta_t: float) -> float:
    if HAVE_PSUTIL:
        import psutil  # type: ignore
        try:
            return psutil.Process(pid).cpu_percent(interval=None)
        except psutil.Error:
            return 0.0

    global LAST_CPU_TIMES
    try:
        stat_content = read_text(Path(f"/proc/{pid}/stat"))
        parts = stat_content.split()
        utime = int(parts[13])
        stime = int(parts[14])
        total_time = utime + stime
    except Exception:
        return 0.0

    if pid in LAST_CPU_TIMES and scan_delta_t > 0:
        _, last_total = LAST_CPU_TIMES[pid]
        time_delta = total_time - last_total
        clk_tck = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        cpu_usage = (time_delta / clk_tck) / scan_delta_t * 100.0
    else:
        cpu_usage = 0.0

    LAST_CPU_TIMES[pid] = (time.time(), total_time)
    return cpu_usage

def analyze_process(pid: int, inode_map: Dict[str, Dict], scan_delta_t: float) -> ProcInfo | None:
    from .utils import sha256_file  # avoid circular import
    from .network import get_process_connections

    try:
        status = parse_key_value_file(Path(f"/proc/{pid}/status"))
        if not status:
            return None

        info = ProcInfo(
            pid=pid,
            ts=now_iso(),
            name=status.get("Name", ""),
            ppid=int(status.get("PPid", 0)),
            user=status.get("Uid", "").split("\t")[0] if status.get("Uid") else "",
            tracer=status.get("TracerPid", "0"),
        )

        info.exe = get_exe(pid)
        info.cwd = readlink(Path(f"/proc/{pid}/cwd"))
        info.cmdline = get_cmdline(pid)
        info.environ = {}  # optionally load later; can be expensive

        if info.exe and not info.exe.endswith(" (deleted)") and os.path.isfile(info.exe):
            info.sha256 = sha256_file(Path(info.exe))

        info.cpu_pct = cpu_percent_proc(pid, scan_delta_t)
        conns, rports = get_process_connections(pid, inode_map)
        info.conns_outbound = conns
        info.remote_ports = rports
        return info
    except Exception:
        return None
