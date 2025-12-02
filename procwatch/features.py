from __future__ import annotations
from typing import Dict, List, Tuple
import math
import os

from .models import ProcInfo

# Simple feature names so we can keep consistent order
FEATURE_NAMES = [
    "cpu_pct",
    "conns_outbound",
    "unique_remote_ports",
    "cmd_len",
    "argv0_len",
    "exe_depth",
    "is_tmp",
    "is_deleted",
    "is_memfd",
    "user_is_root",
]

def path_depth(p: str) -> int:
    if not p:
        return 0
    return len([x for x in p.split("/") if x])

def extract_features(proc: ProcInfo) -> List[float]:
    cmd_str = " ".join(proc.cmdline or [])
    argv0 = os.path.basename(proc.cmdline[0]) if proc.cmdline else ""
    exe = proc.exe or ""
    user = proc.user or ""

    cpu = float(proc.cpu_pct)
    conns = float(proc.conns_outbound)
    unique_ports = float(len(set(proc.remote_ports or [])))
    cmd_len = float(len(cmd_str))
    argv0_len = float(len(argv0))
    exe_d = float(path_depth(exe))
    is_tmp = 1.0 if exe.startswith(("/tmp", "/var/tmp", "/dev/shm")) else 0.0
    is_deleted = 1.0 if exe.endswith(" (deleted)") else 0.0
    is_memfd = 1.0 if exe.startswith("/memfd:") else 0.0
    user_is_root = 1.0 if user == "0" or user == "root" else 0.0

    return [
        cpu,
        conns,
        unique_ports,
        cmd_len,
        argv0_len,
        exe_d,
        is_tmp,
        is_deleted,
        is_memfd,
        user_is_root,
    ]
