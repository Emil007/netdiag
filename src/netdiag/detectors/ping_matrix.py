from __future__ import annotations

import re
import subprocess
from typing import Any


_LINE = re.compile(
    r"^(\S+)\s*:\s*xmt/rcv/%loss\s*=\s*(\d+)/(\d+)/(\d+)%"
    r"(?:,\s*min/avg/max\s*=\s*([\d.]+)/([\d.]+)/([\d.]+))?"
)


def ping_round(
    hosts: list[str],
    *,
    iface: str | None = None,
    count: int = 3,
    timeout_ms: int = 800,
) -> dict[str, dict[str, Any]]:
    res: dict[str, dict[str, Any]] = {}
    if not hosts:
        return res
    cmd = ["fping", "-c", str(count), "-p", "200", "-t", str(timeout_ms), "-q"]
    if iface:
        cmd.extend(["-I", iface])
    cmd.extend(hosts)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(60, count * 2 * len(hosts)),
        )
        text = (proc.stderr or "") + (proc.stdout or "")
    except Exception as exc:
        return {h: {"sent": count, "recv": 0, "loss": 100, "error": str(exc)} for h in hosts}

    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        entry: dict[str, Any] = {
            "sent": int(m.group(2)),
            "recv": int(m.group(3)),
            "loss": int(m.group(4)),
        }
        if m.group(5):
            entry["rtt_min"] = float(m.group(5))
            entry["rtt_avg"] = float(m.group(6))
            entry["rtt_max"] = float(m.group(7))
        res[m.group(1)] = entry

    for h in hosts:
        if h not in res:
            res[h] = {"sent": count, "recv": 0, "loss": 100}
    return res


def tcp_probe(host: str, port: int = 443, timeout_s: float = 2.0) -> bool:
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False
