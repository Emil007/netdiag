from __future__ import annotations

import re
import subprocess
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

_ETHTOOL_CRC = re.compile(
    r"(rx[_ ]?crc[_ ]?errors?|rx[_ ]?fcs[_ ]?errors?|crc[_ ]?error)\s*:\s*(\d+)",
    re.I,
)


def read_counters(iface: str) -> dict[str, int]:
    """Sysfs counters only — do not mix absolute ethtool into this series."""
    base = Path("/sys/class/net") / iface / "statistics"
    vals: dict[str, int] = {}
    for name in COUNTERS:
        try:
            vals[name] = int((base / name).read_text().strip())
        except Exception:
            vals[name] = 0
    return vals


def ethtool_crc_errors(iface: str) -> int | None:
    try:
        out = subprocess.check_output(
            ["ethtool", "-S", iface],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
        )
    except Exception:
        return None
    total = 0
    found = False
    for line in out.splitlines():
        m = _ETHTOOL_CRC.search(line)
        if m:
            found = True
            total += int(m.group(2))
    return total if found else None


class EthtoolCrcTracker:
    """Delta-only ethtool CRC series; ignore negatives; never merge into sysfs absolute."""

    def __init__(self) -> None:
        self._last: int | None = None

    def delta(self, iface: str) -> int:
        cur = ethtool_crc_errors(iface)
        if cur is None:
            return 0
        prev = self._last
        self._last = cur
        if prev is None:
            return 0
        d = cur - prev
        return d if d > 0 else 0


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
    out = {k: int(b.get(k, 0)) - int(a.get(k, 0)) for k in COUNTERS}
    for k, v in list(out.items()):
        if v < 0:
            out[k] = 0
    return out
