from dataclasses import dataclass, field
from typing import Dict, List, Set
import fnmatch

from .models import ProcInfo

@dataclass
class Whitelist:
    names: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    paths: Set[str] = field(default_factory=set)
    hashes: Set[str] = field(default_factory=set)
    patterns: List[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, cfg: Dict) -> "Whitelist":
        wl = cfg.get("whitelist", {})
        return cls(
            names=set(wl.get("names", [])),
            users=set(wl.get("users", [])),
            paths=set(wl.get("paths", [])),
            hashes=set(wl.get("hashes", [])),
            patterns=list(wl.get("patterns", [])),
        )

    def is_allowed(self, proc: ProcInfo) -> bool:
        if proc.name in self.names:
            return True
        if proc.user in self.users:
            return True
        if proc.exe in self.paths:
            return True
        if proc.sha256 and proc.sha256 in self.hashes:
            return True
        for pat in self.patterns:
            if fnmatch.fnmatch(proc.exe or "", pat) or fnmatch.fnmatch(proc.name or "", pat):
                return True
        return False
