from __future__ import annotations

from pathlib import Path
from typing import Any


COUNTERS = [
    "rx_packets",
    "tx_packets",
    "multicast",
    "rx_errors",
    "rx_crc_errors",
    "rx_dropped",
    "tx_errors",
    "tx_dropped",
]


def read_counters(iface: str) -> dict[str, int]:
    base = Path("/sys/class/net") / iface / "statistics"
    vals: dict[str, int] = {}
    for name in COUNTERS:
        try:
            vals[name] = int((base / name).read_text().strip())
        except Exception:
            vals[name] = 0
    return vals


def read_carrier(iface: str) -> dict[str, Any]:
    base = Path("/sys/class/net") / iface
    out: dict[str, Any] = {"iface": iface, "operstate": "unknown", "carrier": None, "speed": None}
    try:
        out["operstate"] = (base / "operstate").read_text().strip()
    except Exception:
        pass
    try:
        out["carrier"] = int((base / "carrier").read_text().strip())
    except Exception:
        pass
    try:
        out["speed"] = int((base / "speed").read_text().strip())
    except Exception:
        pass
    return out


def delta(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    return {k: int(b.get(k, 0)) - int(a.get(k, 0)) for k in COUNTERS}
