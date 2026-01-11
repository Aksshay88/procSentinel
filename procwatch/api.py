#!/usr/bin/env python3
from __future__ import annotations
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from .config import load_config
from .models import ProcInfo, Suspicion
from .proc import get_proc_ids, analyze_process
from .network import get_connections_by_inode
from .heuristics import HeuristicScorer, WHITELIST_SCORE_REDUCTION, WHITELIST_HIGH_SEVERITY_THRESHOLD
from .whitelist import Whitelist
from .features import extract_features
from .ml import IsolationForestModel, ZScoreModel

MODEL_DEFAULT_PATH = Path(os.path.expanduser("~/.local/share/procwatch/model.json"))

class ProcWatchAPI:
    def __init__(self, config_path: str | None = None, model_path: str | None = None):
        self.cfg = load_config(config_path)
        self.wl = Whitelist.from_config(self.cfg)
        self.ports_watch = {int(p) for p in self.cfg.get("ports", "").split(",") if p.isdigit()}
        self.hscorer = HeuristicScorer(self.ports_watch, cpu_high=self.cfg["cpu_high"], weights=self.cfg.get("weights"))
        self.ml_weight = float(self.cfg.get("ml_weight", 2.0))
        self.last_scan_time = time.time()
        
        # Load ML model
        model_file = Path(model_path) if model_path else MODEL_DEFAULT_PATH
        self.model = None
        if model_file.exists():
            try:
                try:
                    self.model = IsolationForestModel.load(model_file)
                except Exception:
                    self.model = ZScoreModel.load(model_file)
                print(f"Loaded ML model from {model_file}")
            except Exception as e:
                print(f"Warning: failed to load model {model_file}: {e}")

    def collect_snapshot(self, scan_delta_t: float) -> Dict[int, ProcInfo]:
        inode_map = get_connections_by_inode()
        all_procs: Dict[int, ProcInfo] = {}
        for pid in get_proc_ids():
            if pid == os.getpid():
                continue
            info = analyze_process(pid, inode_map, scan_delta_t)
            if info:
                all_procs[pid] = info
        return all_procs

    def score_processes(self, all_procs: Dict[int, ProcInfo]) -> List[Dict[str, Any]]:
        results = []
        for pid, proc in all_procs.items():
            reasons = self.hscorer.score_proc(proc, all_procs)
            
            if self.wl.is_allowed(proc):
                reasons = [
                    Suspicion(max(0, r.score - WHITELIST_SCORE_REDUCTION), r.reason + " (whitelisted)") 
                    if r.score < WHITELIST_HIGH_SEVERITY_THRESHOLD else r 
                    for r in reasons
                ]

            proc.heuristic_reasons = [r for r in reasons if r.score > 0]
            proc.heuristic_score = sum(r.score for r in reasons)

            if self.model is not None:
                x = extract_features(proc)
                proc.ml_score = self.model.anomaly_score(x)
            else:
                proc.ml_score = 0.0

            proc.total_score = proc.heuristic_score + self.ml_weight * proc.ml_score

            parent_name = all_procs.get(proc.ppid, ProcInfo(0, "")).name if proc.ppid in all_procs else "N/A"
            
            results.append({
                "pid": proc.pid,
                "ppid": proc.ppid,
                "name": proc.name,
                "parent_name": parent_name,
                "user": proc.user,
                "exe": proc.exe,
                "cwd": proc.cwd,
                "cmdline": proc.cmdline,
                "cpu_pct": proc.cpu_pct,
                "conns_outbound": proc.conns_outbound,
                "remote_ports": proc.remote_ports,
                "sha256": proc.sha256,
                "heuristic_score": proc.heuristic_score,
                "ml_score": proc.ml_score,
                "total_score": proc.total_score,
                "reasons": [{"score": r.score, "reason": r.reason} for r in proc.heuristic_reasons],
                "timestamp": proc.ts
            })
        
        return results

    def get_all_processes(self) -> List[Dict[str, Any]]:
        """Get all processes with scores"""
        now = time.time()
        delta = max(now - self.last_scan_time, 1.0)
        self.last_scan_time = now
        
        all_procs = self.collect_snapshot(delta)
        return self.score_processes(all_procs)

    def get_suspicious_processes(self, min_score: float | None = None) -> List[Dict[str, Any]]:
        """Get processes above minimum score threshold"""
        threshold = min_score if min_score is not None else self.cfg["min_score"]
        all_results = self.get_all_processes()
        suspicious = [p for p in all_results if p["total_score"] >= threshold]
        suspicious.sort(key=lambda p: p["total_score"], reverse=True)
        return suspicious

    def get_process_by_pid(self, pid: int) -> Dict[str, Any] | None:
        """Get detailed info for a specific process"""
        now = time.time()
        delta = max(now - self.last_scan_time, 1.0)
        
        inode_map = get_connections_by_inode()
        proc = analyze_process(pid, inode_map, delta)
        
        if not proc:
            return None
        
        all_procs = self.collect_snapshot(delta)
        results = self.score_processes({pid: proc})
        
        if results:
            result = results[0]
            # Add environment variables for detailed view
            from .proc import get_environ
            result["environ"] = get_environ(pid)
            return result
        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get system-wide statistics"""
        all_procs = self.get_all_processes()
        suspicious = [p for p in all_procs if p["total_score"] >= self.cfg["min_score"]]
        
        return {
            "total_processes": len(all_procs),
            "suspicious_count": len(suspicious),
            "min_score_threshold": self.cfg["min_score"],
            "ml_model_loaded": self.model is not None,
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }


class APIHandler(BaseHTTPRequestHandler):
    api: ProcWatchAPI = None
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        try:
            if path == "/api/processes":
                # Get all processes
                processes = self.api.get_all_processes()
                self.send_json(processes)
            
            elif path == "/api/suspicious":
                # Get suspicious processes
                min_score = float(params["min_score"][0]) if "min_score" in params else None
                suspicious = self.api.get_suspicious_processes(min_score)
                self.send_json(suspicious)
            
            elif path.startswith("/api/process/"):
                # Get specific process by PID
                pid = int(path.split("/")[-1])
                proc = self.api.get_process_by_pid(pid)
                if proc:
                    self.send_json(proc)
                else:
                    self.send_error(404, "Process not found")
            
            elif path == "/api/stats":
                # Get statistics
                stats = self.api.get_stats()
                self.send_json(stats)
            
            elif path == "/" or path == "/api":
                # API documentation
                self.send_json({
                    "endpoints": {
                        "/api/processes": "GET - List all processes with scores",
                        "/api/suspicious": "GET - List suspicious processes (accepts ?min_score=X)",
                        "/api/process/{pid}": "GET - Get detailed info for specific process",
                        "/api/stats": "GET - Get system statistics"
                    }
                })
            
            else:
                self.send_error(404, "Endpoint not found")
        
        except Exception as e:
            self.send_error(500, str(e))
    
    def send_json(self, data: Any):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def log_message(self, format, *args):
        print(f"{self.address_string()} - [{self.log_date_time_string()}] {format % args}")


def run_api_server(host: str = "0.0.0.0", port: int = 8080, config: str | None = None, model: str | None = None):
    """Run the API server"""
    APIHandler.api = ProcWatchAPI(config, model)
    server = HTTPServer((host, port), APIHandler)
    print(f"ProcWatch API server running on http://{host}:{port}")
    print(f"Available endpoints:")
    print(f"  - GET /api/processes - All processes")
    print(f"  - GET /api/suspicious - Suspicious processes")
    print(f"  - GET /api/process/{{pid}} - Specific process")
    print(f"  - GET /api/stats - Statistics")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()
