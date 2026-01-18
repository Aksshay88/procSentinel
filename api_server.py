#!/usr/bin/env python3
"""
API server for ProcSentinel - provides REST API for process monitoring
"""
from __future__ import annotations
from flask import Flask, jsonify, request
from flask_cors import CORS
import time
import os
from pathlib import Path
from typing import Dict, List, Optional
import hashlib
import jwt
from datetime import datetime, timedelta
from functools import wraps

from procwatch.config import load_config
from procwatch.models import ProcInfo, Suspicion
from procwatch.proc import get_proc_ids, analyze_process
from procwatch.network import get_connections_by_inode
from procwatch.heuristics import HeuristicScorer, WHITELIST_SCORE_REDUCTION, WHITELIST_HIGH_SEVERITY_THRESHOLD
from procwatch.whitelist import Whitelist
from procwatch.features import extract_features
from procwatch.ml import IsolationForestModel, ZScoreModel

app = Flask(__name__)
CORS(app)

# Simple authentication - in production, use proper password hashing and database
SECRET_KEY = "procsentinel-secret-key-change-in-production"
app.config['SECRET_KEY'] = SECRET_KEY

# Simple user store (username -> password hash)
USERS = {
    "admin": hashlib.sha256("admin123".encode()).hexdigest()
}

MODEL_PATH = Path(os.path.expanduser("~/.local/share/procwatch/model.json"))
CONFIG_PATH = None
last_scan_time = time.time()
cached_procs: Dict[int, ProcInfo] = {}


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data['username']
        except Exception as e:
            return jsonify({'message': 'Token is invalid', 'error': str(e)}), 401
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/api/login', methods=['POST'])
def login():
    """Simple login endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if username in USERS and USERS[username] == password_hash:
        token = jwt.encode({
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({'token': token, 'username': username})
    
    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/api/processes', methods=['GET'])
# @token_required  # Temporarily disabled for testing
def get_processes():
    """Get current process list with threat scores"""
    # current_user = 'admin'  # Temporary for testing
    global last_scan_time, cached_procs
    
    # Load configuration
    cfg = load_config(CONFIG_PATH)
    min_score = float(request.args.get('min_score', cfg.get('min_score', 3.0)))
    
    # Scan processes
    now = time.time()
    delta = max(now - last_scan_time, 1.0)
    last_scan_time = now
    
    inode_map = get_connections_by_inode()
    all_procs: Dict[int, ProcInfo] = {}
    
    for pid in get_proc_ids():
        if pid == os.getpid():
            continue
        info = analyze_process(pid, inode_map, delta)
        if info:
            all_procs[pid] = info
    
    # Score processes
    wl = Whitelist.from_config(cfg)
    ports_watch = {int(p) for p in cfg.get("ports", "").split(",") if p.isdigit()}
    hscorer = HeuristicScorer(ports_watch, cpu_high=cfg["cpu_high"], weights=cfg.get("weights"))
    ml_weight = float(cfg.get("ml_weight", 2.0))
    
    # Load ML model
    model = None
    if MODEL_PATH.exists():
        try:
            try:
                model = IsolationForestModel.load(MODEL_PATH)
            except Exception:
                model = ZScoreModel.load(MODEL_PATH)
        except Exception:
            pass
    
    findings: List[dict] = []
    for pid, proc in all_procs.items():
        # Heuristics
        reasons = hscorer.score_proc(proc, all_procs)
        
        # Whitelist dampening
        if wl.is_allowed(proc):
            reasons = [
                Suspicion(max(0, r.score - WHITELIST_SCORE_REDUCTION), r.reason + " (whitelisted)") 
                if r.score < WHITELIST_HIGH_SEVERITY_THRESHOLD else r 
                for r in reasons
            ]
        
        proc.heuristic_reasons = [r for r in reasons if r.score > 0]
        proc.heuristic_score = sum(r.score for r in reasons)
        
        # ML scoring
        if model is not None:
            x = extract_features(proc)
            proc.ml_score = model.anomaly_score(x)
        else:
            proc.ml_score = 0.0
        
        proc.total_score = proc.heuristic_score + ml_weight * proc.ml_score
        
        if proc.total_score >= min_score:
            parent_name = all_procs.get(proc.ppid, ProcInfo(0, "")).name if proc.ppid in all_procs else "N/A"
            
            findings.append({
                'pid': proc.pid,
                'ppid': proc.ppid,
                'name': proc.name,
                'user': proc.user,
                'parent_name': parent_name,
                'total_score': round(proc.total_score, 2),
                'heuristic_score': round(proc.heuristic_score, 2),
                'ml_score': round(proc.ml_score, 2),
                'cpu_percent': round(proc.cpu_percent, 1),
                'mem_mb': round(proc.mem_mb, 1),
                'reasons': [{'score': r.score, 'reason': r.reason} for r in proc.heuristic_reasons],
                'cmdline': ' '.join(proc.cmdline[:5]),
                'status': 'critical' if proc.total_score >= 8 else 'warning' if proc.total_score >= 5 else 'normal'
            })
    
    findings.sort(key=lambda p: p['total_score'], reverse=True)
    cached_procs = all_procs
    
    return jsonify({
        'processes': findings,
        'total': len(all_procs),
        'suspicious': len(findings),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/stats', methods=['GET'])
# @token_required  # Temporarily disabled for testing
def get_stats():
    """Get system statistics"""
    # current_user = 'admin'  # Temporary for testing
    cfg = load_config(CONFIG_PATH)
    min_score = cfg.get('min_score', 3.0)
    
    total_procs = len(cached_procs)
    critical = sum(1 for p in cached_procs.values() if hasattr(p, 'total_score') and p.total_score >= 8)
    warning = sum(1 for p in cached_procs.values() if hasattr(p, 'total_score') and 5 <= p.total_score < 8)
    normal = total_procs - critical - warning
    
    return jsonify({
        'total_processes': total_procs,
        'critical': critical,
        'warning': warning,
        'normal': normal,
        'model_loaded': MODEL_PATH.exists(),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/process/<int:pid>', methods=['GET'])
# @token_required  # Temporarily disabled for testing
def get_process_detail(pid):
    """Get detailed information about a specific process"""
    # current_user = 'admin'  # Temporary for testing
    if pid not in cached_procs:
        return jsonify({'message': 'Process not found'}), 404
    
    proc = cached_procs[pid]
    parent = cached_procs.get(proc.ppid)
    
    return jsonify({
        'pid': proc.pid,
        'ppid': proc.ppid,
        'name': proc.name,
        'user': proc.user,
        'parent_name': parent.name if parent else 'N/A',
        'cmdline': proc.cmdline,
        'exe': proc.exe,
        'cpu_percent': proc.cpu_percent,
        'mem_mb': proc.mem_mb,
        'num_fds': proc.num_fds,
        'num_threads': proc.num_threads,
        'listening_ports': proc.listening_ports,
        'connections': proc.connections,
        'environ': proc.environ,
        'total_score': getattr(proc, 'total_score', 0),
        'heuristic_score': getattr(proc, 'heuristic_score', 0),
        'ml_score': getattr(proc, 'ml_score', 0),
        'reasons': [{'score': r.score, 'reason': r.reason} for r in getattr(proc, 'heuristic_reasons', [])]
    })


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'service': 'procsentinel-api'})


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        CONFIG_PATH = sys.argv[1]
    
    print("Starting ProcSentinel API Server...")
    print("Default credentials: admin / admin123")
    print("API running on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
