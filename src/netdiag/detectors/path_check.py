from __future__ import annotations

import subprocess
from typing import Any


def traceroute_path(target: str, max_hops: int = 8) -> dict[str, Any]:
    hops: list[str] = []
    try:
        proc = subprocess.run(
            ["traceroute", "-n", "-w", "1", "-q", "1", "-m", str(max_hops), target],
            capture_output=True,
            text=True,
            timeout=30,
        )
        text = proc.stdout or ""
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                hops.append(parts[1])
    except Exception as exc:
        return {"target": target, "hops": hops, "error": str(exc)}
    return {"target": target, "hops": hops, "error": ""}
