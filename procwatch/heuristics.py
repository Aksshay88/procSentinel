import os
import stat
from typing import Dict, List, Set

from .models import ProcInfo, Suspicion
from .utils import read_text, readlink
from .utils import C

TMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
UNUSUAL_PARENT_CHILD = {
    "apache2": {"sh", "bash", "dash"},
    "nginx": {"sh", "bash", "dash"},
    "httpd": {"sh", "bash", "dash"},
}

SUSP_DEFAULT_WATCH_PORTS = {3333, 4444, 5555, 6666, 7777, 14444, 33333}

class HeuristicScorer:
    def __init__(self, ports_watch: Set[int], cpu_high: float = 90.0, weights: Dict[str, int] | None = None):
        self.ports_watch = ports_watch
        self.cpu_high = cpu_high
        self.weights = weights or {}

    def score_proc(self, proc: ProcInfo, all_procs: Dict[int, ProcInfo]) -> List[Suspicion]:
        reasons: List[Suspicion] = []
        self._check_executable(proc, reasons)
        self._check_memory(proc, reasons)
        self._check_cmdline(proc, reasons)
        self._check_parent(proc, all_procs, reasons)
        self._check_environment(proc, reasons)
        self._check_resources(proc, reasons)
        self._check_network(proc, reasons)
        return reasons

    def _check_executable(self, proc: ProcInfo, reasons: List[Suspicion]):
        exe = proc.exe or ""
        cwd = proc.cwd or ""
        if not exe:
            reasons.append(Suspicion(self.weights.get("no_exe", 1), "No executable path found"))
        elif exe.endswith(" (deleted)"):
            reasons.append(Suspicion(self.weights.get("deleted_exe", 4), "Executable deleted while running"))
        elif exe.startswith("/memfd:"):
            reasons.append(Suspicion(self.weights.get("memfd_exe", 4), "Fileless execution (memfd)"))

        for tdir in TMP_DIRS:
            if exe.startswith(tdir) or cwd.startswith(tdir):
                reasons.append(Suspicion(self.weights.get("tmp_exe", 3), f"Running from temp dir {tdir}"))
                break

        try:
            if exe and not exe.endswith(" (deleted)"):
                st = os.stat(exe)
                if bool(st.st_mode & stat.S_IWOTH):
                    reasons.append(Suspicion(self.weights.get("world_writable_exe", 2), "Executable is world-writable"))
        except Exception:
            pass

    def _check_memory(self, proc: ProcInfo, reasons: List[Suspicion]):
        try:
            maps_content = read_text(Path(f"/proc/{proc.pid}/maps"), 5_000_000)  # type: ignore[name-defined]
            if " rwx" in maps_content:
                reasons.append(Suspicion(self.weights.get("wx_mem", 3), "Memory segment with W+X permissions"))
        except Exception:
            pass

    def _check_cmdline(self, proc: ProcInfo, reasons: List[Suspicion]):
        cmdline = proc.cmdline or []
        cmd_str = " ".join(cmdline)
        if not cmdline:
            reasons.append(Suspicion(self.weights.get("empty_cmdline", 2), "Empty cmdline"))
        elif len(cmd_str) < 4:
            reasons.append(Suspicion(self.weights.get("short_cmdline", 1), "Very short cmdline"))

        if "base64" in cmd_str and len(cmd_str) > 100:
            reasons.append(Suspicion(self.weights.get("obfuscated_cmdline", 2), "Possible obfuscation (base64) in cmdline"))
        if "eval" in cmd_str or "exec" in cmd_str:
            reasons.append(Suspicion(self.weights.get("code_exec_cmdline", 1), "Possible code execution primitive in cmdline"))

        name = proc.name
        if cmdline:
            argv0 = os.path.basename(cmdline[0])
            if name and argv0 and name != argv0 and not argv0.startswith(f"({name})"):
                reasons.append(Suspicion(self.weights.get("name_argv_mismatch", 1), f"Name/argv mismatch: {name} != {argv0}"))

    def _check_parent(self, proc: ProcInfo, all_procs: Dict[int, ProcInfo], reasons: List[Suspicion]):
        parent = all_procs.get(proc.ppid)
        if parent:
            pname = parent.name
            if pname in UNUSUAL_PARENT_CHILD and proc.name in UNUSUAL_PARENT_CHILD[pname]:
                reasons.append(Suspicion(self.weights.get("unusual_parent", 3), f"Unusual parent-child: {pname} -> {proc.name}"))

    def _check_environment(self, proc: ProcInfo, reasons: List[Suspicion]):
        env = proc.environ or {}
        if "LD_PRELOAD" in env or "LD_LIBRARY_PATH" in env:
            reasons.append(Suspicion(self.weights.get("ld_preload", 2), "LD_PRELOAD/LD_LIBRARY_PATH is set"))

    def _check_resources(self, proc: ProcInfo, reasons: List[Suspicion]):
        if proc.tracer != "0":
            reasons.append(Suspicion(self.weights.get("ptraced", 3), f"Being ptraced by PID {proc.tracer}"))
        if proc.cpu_pct > self.cpu_high:
            reasons.append(Suspicion(self.weights.get("high_cpu", 1), f"High CPU {proc.cpu_pct:.1f}%"))

        try:
            stdin_link = readlink(Path(f"/proc/{proc.pid}/fd/0"))  # type: ignore[name-defined]
            if not stdin_link:
                if proc.name in {"bash", "sh", "zsh", "fish", "python", "perl", "nc", "ncat"}:
                    reasons.append(Suspicion(self.weights.get("no_tty", 3), f"{proc.name} running without a TTY (reverse shell?)"))
        except Exception:
            pass

    def _check_network(self, proc: ProcInfo, reasons: List[Suspicion]):
        watched = self.ports_watch.intersection(proc.remote_ports or [])
        if watched:
            reasons.append(Suspicion(self.weights.get("watched_port", 2), f"Outbound to watched port(s): {sorted(list(watched))}"))
        if proc.conns_outbound > 20:
            reasons.append(Suspicion(self.weights.get("many_conns", 1), f"Many outbound connections ({proc.conns_outbound})"))
