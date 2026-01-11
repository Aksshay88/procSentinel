from __future__ import annotations
import argparse
from pathlib import Path
import os
import signal
import shutil
import sys
import time
from typing import Dict, List

from .config import load_config
from .models import ProcInfo, Suspicion
from .proc import get_proc_ids, analyze_process
from .network import get_connections_by_inode
from .heuristics import HeuristicScorer, WHITELIST_SCORE_REDUCTION, WHITELIST_HIGH_SEVERITY_THRESHOLD
from .whitelist import Whitelist
from .features import extract_features
from .ml import choose_model, ZScoreModel, IsolationForestModel
from .utils import C, read_text

MODEL_DEFAULT_PATH = Path(os.path.expanduser("~/.local/share/procwatch/model.json"))

def pretty_row(proc: ProcInfo, parent_name: str) -> str:
    score = proc.total_score
    color = C.RED if score >= 6 else C.YELLOW
    score_str = f"{color}{score:>4.1f}{C.RESET}"
    pid_str = f"{proc.pid:<6}"
    ppid_str = f"{C.GRAY}({proc.ppid}){C.RESET}"
    user_str = f"{proc.user:<10}"
    name_str = f"{C.CYAN}{proc.name:<18}{C.RESET}"
    pname_str = f"{C.GRAY}({parent_name[:12]}){C.RESET}"
    reasons_str = "; ".join(r.reason for r in proc.heuristic_reasons)[:100]
    return f"{score_str}  {pid_str:<7}{ppid_str:<8} {user_str:<11} {name_str:<20} {pname_str:<15} {reasons_str}"

def dump_artifacts(proc: ProcInfo, dump_dir: Path) -> None:
    ts = int(time.time())
    pdir = dump_dir / f"{proc.pid}_{ts}"
    try:
        pdir.mkdir(parents=True)
        (pdir / "cmdline").write_text(" ".join(proc.cmdline))
        (pdir / "environ").write_text("\n".join(f"{k}={v}" for k, v in proc.environ.items()))
        if proc.exe:
            try:
                shutil.copy(proc.exe, pdir / "exe")
            except Exception as e:
                (pdir / "exe.error").write_text(str(e))
        
        maps = read_text(f"/proc/{proc.pid}/maps")
        if maps:
            (pdir / "maps").write_text(maps)
            
        fds = []
        for fd_path in Path(f"/proc/{proc.pid}/fd").iterdir():
            try:
                link = os.readlink(fd_path)
                fds.append(f"{fd_path.name} -> {link}")
            except Exception:
                pass
        (pdir / "fds").write_text("\n".join(fds))

        print(f"Dumped artifacts to {pdir}", file=sys.stderr)
    except Exception as e:
        print(f"Could not dump artifacts for {proc.pid}: {e}", file=sys.stderr)


def collect_snapshot(scan_delta_t: float) -> Dict[int, ProcInfo]:
    inode_map = get_connections_by_inode()
    all_procs: Dict[int, ProcInfo] = {}
    for pid in get_proc_ids():
        if pid == os.getpid():
            continue
        info = analyze_process(pid, inode_map, scan_delta_t)
        if info:
            all_procs[pid] = info
    return all_procs

def cmd_train(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    duration = args.duration
    use_sklearn = cfg.get("use_sklearn", False)
    model = choose_model(use_sklearn)
    features: List[List[float]] = []

    print(f"Training baseline for {duration}s...", file=sys.stderr)
    start = time.time()
    last_scan = start
    while time.time() - start < duration:
        now = time.time()
        delta = max(now - last_scan, 1.0)
        last_scan = now
        snapshot = collect_snapshot(delta)
        for proc in snapshot.values():
            features.append(extract_features(proc))
        time.sleep(args.interval)

    model.fit(features)
    model_path = Path(args.model) if args.model else MODEL_DEFAULT_PATH
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model.save(model_path)
    print(f"Saved baseline model to {model_path}")

def cmd_scan(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    if args.min_score is not None:
        cfg["min_score"] = args.min_score

    wl = Whitelist.from_config(cfg)
    ports_watch = {int(p) for p in cfg.get("ports", "").split(",") if p.isdigit()}
    hscorer = HeuristicScorer(ports_watch, cpu_high=cfg["cpu_high"], weights=cfg.get("weights"))
    ml_weight = float(cfg.get("ml_weight", 2.0))
    dump_dir = Path(args.dump) if args.dump else None
    if dump_dir:
        dump_dir.mkdir(parents=True, exist_ok=True)

    # Load ML model
    model_path = Path(args.model) if args.model else MODEL_DEFAULT_PATH
    model = None
    if model_path.exists():
        try:
            # try both types
            try:
                model = IsolationForestModel.load(model_path)
            except Exception:
                model = ZScoreModel.load(model_path)
            print(f"Loaded ML model from {model_path}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: failed to load model {model_path}: {e}", file=sys.stderr)

    header = f"{'Sc':>4}  {'PID':<7}{'PPID':<8} {'USER':<11} {'NAME':<20} {'PARENT':<15} REASONS"
    print(header + "\n" + "-" * len(header))

    last_scan = time.time()
    def scan_once():
        nonlocal last_scan
        now = time.time()
        delta = max(now - last_scan, 1.0)
        last_scan = now

        all_procs = collect_snapshot(delta)

        findings: List[ProcInfo] = []
        for pid, proc in all_procs.items():
            # heuristics
            reasons = hscorer.score_proc(proc, all_procs)
            # apply whitelist dampening - more aggressive reduction for whitelisted processes
            if wl.is_allowed(proc):
                # Reduce scores for whitelisted processes - keep high-severity issues but dampen others
                reasons = [
                    Suspicion(max(0, r.score - WHITELIST_SCORE_REDUCTION), r.reason + " (whitelisted)") 
                    if r.score < WHITELIST_HIGH_SEVERITY_THRESHOLD else r 
                    for r in reasons
                ]

            proc.heuristic_reasons = [r for r in reasons if r.score > 0]
            proc.heuristic_score = sum(r.score for r in reasons)

            # ML
            if model is not None:
                x = extract_features(proc)
                proc.ml_score = model.anomaly_score(x)  # 0..1
            else:
                proc.ml_score = 0.0

            proc.total_score = proc.heuristic_score + ml_weight * proc.ml_score

            if proc.total_score >= cfg["min_score"]:
                findings.append(proc)

        findings.sort(key=lambda p: p.total_score, reverse=True)
        for proc in findings[: cfg["topk"]]:
            parent_name = all_procs.get(proc.ppid, ProcInfo(0, "")).name if proc.ppid in all_procs else "N/A"
            print(pretty_row(proc, parent_name))
            
            if dump_dir:
                dump_artifacts(proc, dump_dir)

            if args.kill_on_alert:
                try:
                    os.kill(proc.pid, signal.SIGKILL)
                    print(f"Killed process {proc.pid}", file=sys.stderr)
                except Exception as e:
                    print(f"Failed to kill process {proc.pid}: {e}", file=sys.stderr)

            if args.stop_on_alert:
                print("Stopping on alert.", file=sys.stderr)
                sys.exit(0)

    if args.interval > 0:
        while True:
            print(f"\n# Scan @ {time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())}")
            scan_once()
            time.sleep(args.interval)
    else:
        scan_once()


def cmd_api(args: argparse.Namespace) -> None:
    from .api import run_api_server
    run_api_server(args.host, args.port, args.config, args.model)

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="procwatch v3 - modular + ML")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_train = sub.add_parser("train", help="Train baseline anomaly model")
    p_train.add_argument("--duration", type=int, default=60, help="Training duration in seconds")
    p_train.add_argument("--interval", type=float, default=5.0, help="Sampling interval during training")
    p_train.add_argument("--config", type=str, help="Config YAML")
    p_train.add_argument("--model", type=str, help="Path to save model")
    p_train.set_defaults(func=cmd_train)

    p_scan = sub.add_parser("scan", help="Scan processes")
    p_scan.add_argument("--interval", type=float, default=0.0, help="Scan interval (0=single scan)")
    p_scan.add_argument("--config", type=str, help="Config YAML")
    p_scan.add_argument("--model", type=str, help="Path to load model")
    p_scan.add_argument("--min-score", type=float, help="Override: minimum total score to report")
    p_scan.add_argument("--stop-on-alert", action="store_true")
    p_scan.add_argument("--kill-on-alert", action="store_true")
    p_scan.add_argument("--dump", type=str, help="Dump artifacts directory")
    p_scan.set_defaults(func=cmd_scan)

    p_api = sub.add_parser("api", help="Run REST API server")
    p_api.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    p_api.add_argument("--port", type=int, default=8080, help="Port to bind to")
    p_api.add_argument("--config", type=str, help="Config YAML")
    p_api.add_argument("--model", type=str, help="Path to load model")
    p_api.set_defaults(func=cmd_api)

    return ap

def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
