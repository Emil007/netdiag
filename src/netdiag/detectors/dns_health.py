from __future__ import annotations

import subprocess
import time
from typing import Any


def dns_check(
    resolvers: list[str],
    names: list[str],
    timeout_ms: int = 1500,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    timeout_s = max(0.5, timeout_ms / 1000.0)
    for resolver in resolvers or ["127.0.0.1"]:
        for name in names or ["example.com"]:
            t0 = time.time()
            ok = False
            err = ""
            answer = ""
            try:
                proc = subprocess.run(
                    ["dig", f"@{resolver}", name, "+short", "+time=1", "+tries=1"],
                    capture_output=True,
                    text=True,
                    timeout=timeout_s + 1,
                )
                out = (proc.stdout or "").strip()
                err = (proc.stderr or "").strip()
                ok = proc.returncode == 0 and bool(out)
                answer = out.splitlines()[0] if out else ""
            except Exception as exc:
                err = str(exc)
            results.append(
                {
                    "resolver": resolver,
                    "name": name,
                    "ok": ok,
                    "answer": answer,
                    "error": err,
                    "latency_ms": int((time.time() - t0) * 1000),
                }
            )
    return results
