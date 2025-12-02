import os
import hashlib
from pathlib import Path
from typing import List, Optional

class C:
    RESET = '\033[0m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    GRAY = '\033[90m'

def readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""

def read_text(path: Path, limit: int = 1_000_000) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(limit)
    except (IOError, OSError):
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
    except (IOError, OSError):
        return []

def listdir(path: Path, max_items: int = 10000) -> List[str]:
    try:
        return os.listdir(path)[:max_items]
    except (IOError, OSError):
        return []

def sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError):
        return None
