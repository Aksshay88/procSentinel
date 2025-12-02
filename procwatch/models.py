from dataclasses import dataclass, field
from typing import Any, Dict, List
import datetime as dt

@dataclass
class Suspicion:
    score: int
    reason: str

@dataclass
class ProcInfo:
    pid: int
    ts: str
    name: str = ""
    ppid: int = 0
    user: str = ""
    tracer: str = "0"
    exe: str = ""
    cwd: str = ""
    cmdline: List[str] = field(default_factory=list)
    environ: Dict[str, str] = field(default_factory=dict)
    sha256: str | None = None
    cpu_pct: float = 0.0
    conns_outbound: int = 0
    remote_ports: List[int] = field(default_factory=list)

    # runtime scoring fields
    heuristic_reasons: List[Suspicion] = field(default_factory=list)
    heuristic_score: int = 0
    ml_score: float = 0.0          # raw anomaly score (0..1 or -1..1 -> normalized)
    total_score: float = 0.0       # combined score

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()
