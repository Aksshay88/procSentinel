from pathlib import Path
import re
from typing import Dict, List, Tuple

from .utils import read_lines, readlink, listdir

def get_connections_by_inode() -> Dict[str, Dict]:
    inode_map: Dict[str, Dict] = {}
    hex_pattern = re.compile(r"([0-9A-F]{8}):([0-9A-F]{4})\s+([0-9A-F]{8}):([0-9A-F]{4})")

    def parse_net_file(file_path: Path):
        for line in read_lines(file_path):
            parts = line.split()
            if len(parts) < 10 or not parts[9].isdigit():
                continue
            inode = parts[9]
            match = hex_pattern.search(line)
            if not match:
                continue
            remote_ip_hex, remote_port_hex = match.group(3), match.group(4)
            if remote_ip_hex != "00000000":
                try:
                    r_port = int(remote_port_hex, 16)
                    inode_map[inode] = {"rport": r_port}
                except ValueError:
                    continue

    parse_net_file(Path("/proc/net/tcp"))
    parse_net_file(Path("/proc/net/tcp6"))
    return inode_map

def get_process_connections(pid: int, inode_map: Dict[str, Dict]) -> Tuple[int, List[int]]:
    remote_ports: List[int] = []
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        for fd in listdir(fd_dir):
            link = readlink(fd_dir / fd)
            if link.startswith("socket:[") and link.endswith("]"):
                inode = link[8:-1]
                if inode in inode_map:
                    remote_ports.append(inode_map[inode]["rport"])
    except Exception:
        pass
    return len(remote_ports), remote_ports
