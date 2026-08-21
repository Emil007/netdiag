from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field


# STP config BPDUs / RSTP often show as STP with root/bridge ids
_STP = re.compile(
    r"STP.*?root[\s-]?id\s+[0-9a-f.:]+\.?([0-9a-f.]{14,17}|[0-9a-f:]{17}).*?"
    r"bridge[\s-]?id\s+[0-9a-f.:]+\.?([0-9a-f.]{14,17}|[0-9a-f:]{17})",
    re.I,
)
_STP_SIMPLE = re.compile(r"\bSTP\b", re.I)
_MAC = re.compile(r"((?:[0-9a-f]{2}[:.-]){5}[0-9a-f]{2})", re.I)
_LLDP = re.compile(r"\bLLDP\b", re.I)


def normalize_mac(raw: str) -> str:
    hex_only = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(hex_only) >= 12:
        hex_only = hex_only[-12:]
        return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2)).lower()
    return raw.lower()


@dataclass
class L2BridgeWatch:
    """One tcpdump for broadcast/multicast + STP/LLDP (merged bcast+bridge observer)."""

    iface: str
    packets: int = 0
    window_start: float = field(default_factory=time.time)
    samples: list = field(default_factory=list)
    baseline: float = 0.0
    bridges: dict[str, dict] = field(default_factory=dict)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="l2watch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def tick(self) -> dict:
        now = time.time()
        dt = max(0.001, now - self.window_start)
        pps = self.packets / dt
        self.packets = 0
        self.window_start = now
        self.samples.append(pps)
        if len(self.samples) > 60:
            self.samples = self.samples[-60:]
        if len(self.samples) >= 10:
            ordered = sorted(self.samples)
            self.baseline = ordered[len(ordered) // 2]
        storm = False
        if self.baseline > 0 and pps > max(self.baseline * 5, self.baseline + 100) and pps > 50:
            storm = True
        elif self.baseline == 0 and len(self.samples) >= 10 and pps > 500:
            storm = True
        return {
            "pps": pps,
            "baseline": self.baseline,
            "storm": float(storm),
            "bridges": list(self.bridges.values()),
        }

    def _run(self) -> None:
        # Single consumer: bcast/mcast counts + STP/LLDP hints (avoids an extra forever-tcpdump).
        cmd = [
            "tcpdump",
            "-i",
            self.iface,
            "-nnel",
            "-l",
            "broadcast",
            "or",
            "multicast",
            "or",
            "ether",
            "dst",
            "01:80:c2:00:00:00",
            "or",
            "ether",
            "proto",
            "0x88cc",
        ]
        while not self._stop.is_set():
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
            except Exception:
                time.sleep(5)
                continue
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    if self._stop.is_set():
                        break
                    self.packets += 1
                    self._parse_bridge(line)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
            time.sleep(1)

    def _parse_bridge(self, line: str) -> None:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if _LLDP.search(line):
            macs = _MAC.findall(line)
            src = normalize_mac(macs[0]) if macs else "unknown"
            # Keep chassis/port-ish tokens without marketing fluff
            detail = " ".join(line.split()[:24])
            key = f"lldp:{src}"
            self.bridges[key] = {
                "kind": "lldp",
                "id": src,
                "detail": detail[:160],
                "last_seen": now,
            }
            return
        if _STP_SIMPLE.search(line) or "01:80:c2:00:00:00" in line.lower():
            m = _STP.search(line)
            macs = _MAC.findall(line)
            bridge = normalize_mac(m.group(2)) if m else (normalize_mac(macs[0]) if macs else "unknown")
            root = normalize_mac(m.group(1)) if m else ""
            key = f"stp:{bridge}"
            self.bridges[key] = {
                "kind": "stp",
                "id": bridge,
                "root": root,
                "detail": f"STP bridge {bridge}" + (f" root {root}" if root else ""),
                "last_seen": now,
            }


def parse_l2_line(line: str) -> dict | None:
    """Unit-testable parser for a single tcpdump -e line."""
    watch = L2BridgeWatch("x")
    before = dict(watch.bridges)
    watch._parse_bridge(line)
    if watch.bridges == before:
        return None
    return next(iter(watch.bridges.values()))
