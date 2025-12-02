from __future__ import annotations
from typing import Any, Dict
from pathlib import Path
import sys

try:
    import yaml  # type: ignore
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

DEFAULT_CONFIG: Dict[str, Any] = {
    "min_score": 2,
    "cpu_high": 90.0,
    "ports": "3333,4444,5555,6666,7777,14444,33333",
    "topk": 20,
    "ml_weight": 2.0,
    "use_sklearn": False,
    "weights": {
        "deleted_exe": 4,
        "memfd_exe": 4,
        "tmp_exe": 3,
        "world_writable_exe": 2,
        "wx_mem": 3,
        "empty_cmdline": 1,
        "short_cmdline": 1,
        "obfuscated_cmdline": 2,
        "code_exec_cmdline": 1,
        "name_argv_mismatch": 1,
        "unusual_parent": 3,
        "ld_preload": 2,
        "ptraced": 3,
        "high_cpu": 1,
        "no_tty": 3,
        "watched_port": 2,
        "many_conns": 1,
        "no_exe": 1,
    },
    "whitelist": {
        "names": ["systemd", "kthreadd", "kworker", "sshd", "cron", "bash", "NetworkManager", "journald"],
        "users": ["root"],
        "patterns": ["/usr/*", "/bin/*", "/sbin/*", "(sd-pam)", "kworker*", "ksoftirqd*", "rcu*", "migration*", "idle_inject*", "cpuhp*", "pool_workqueue_release*", "systemd-userwor*", "dbus-broker-lau*", "systemd-timesyn*", "systemd-resolve*", "systemd-journal*"],
        "hashes": [],
        "paths": [],
    },
}

def load_config(path: str | None) -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG.copy()
    if path and HAVE_YAML:
        try:
            data = yaml.safe_load(Path(path).read_text()) or {}
            # shallow merge, then deep merge whitelist
            wl_default = cfg["whitelist"].copy()
            wl_user = data.get("whitelist", {})
            cfg.update({k: v for k, v in data.items() if k != "whitelist"})
            wl_default.update(wl_user or {})
            cfg["whitelist"] = wl_default
            print(f"Loaded config from {path}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Could not load config {path}: {e}", file=sys.stderr)
    elif path and not HAVE_YAML:
        print("Warning: --config specified but PyYAML is not installed. Using defaults.", file=sys.stderr)
    return cfg
