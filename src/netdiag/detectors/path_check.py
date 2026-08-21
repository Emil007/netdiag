from __future__ import annotations

import subprocess
import threading
from typing import Any, Callable


def traceroute_path(target: str, max_hops: int = 8, iface: str | None = None) -> dict[str, Any]:
    hops: list[str] = []
    cmd = ["traceroute", "-n", "-w", "1", "-q", "1", "-m", str(max_hops)]
    if iface:
        cmd.extend(["-i", iface])
    cmd.append(target)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                hop = parts[1]
                if hop not in ("*", ""):
                    hops.append(hop)
    except Exception as exc:
        return {"target": target, "hops": hops, "error": str(exc)}
    return {"target": target, "hops": hops, "error": ""}


def run_path_checks_async(
    targets: list[str],
    iface: str | None,
    on_done: Callable[[list[dict[str, Any]]], None],
) -> None:
    def worker() -> None:
        results = [traceroute_path(t, iface=iface) for t in targets]
        on_done(results)

    threading.Thread(target=worker, name="pathcheck", daemon=True).start()
