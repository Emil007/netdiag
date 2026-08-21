from __future__ import annotations

import re
import subprocess
from typing import Any


_LINE = re.compile(
    r"^(\S+)\s*:\s*xmt/rcv/%loss\s*=\s*(\d+)/(\d+)/(\d+)%"
    r"(?:,\s*min/avg/max\s*=\s*([\d.]+)/([\d.]+)/([\d.]+))?"
)


def ping_round(hosts: list[str], count: int = 3, timeout_ms: int = 800) -> dict[str, dict[str, Any]]:
    """Run fping once; return per-host sent/recv/loss[/rtt]."""
    res: dict[str, dict[str, Any]] = {}
    if not hosts:
        return res
    try:
        proc = subprocess.run(
            ["fping", "-c", str(count), "-p", "200", "-t", str(timeout_ms), "-q", *hosts],
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
        host = m.group(1)
        entry: dict[str, Any] = {
            "sent": int(m.group(2)),
            "recv": int(m.group(3)),
            "loss": int(m.group(4)),
        }
        if m.group(5):
            entry["rtt_min"] = float(m.group(5))
            entry["rtt_avg"] = float(m.group(6))
            entry["rtt_max"] = float(m.group(7))
        res[host] = entry

    for h in hosts:
        if h not in res:
            res[h] = {"sent": count, "recv": 0, "loss": 100}
    return res
