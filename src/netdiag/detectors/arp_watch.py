from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable


_IS_AT = re.compile(
    r"((?:[0-9a-f]{2}:){5}[0-9a-f]{2}).*?is-at.*?(\d+\.\d+\.\d+\.\d+)|"
    r"(\d+\.\d+\.\d+\.\d+).*?is-at.*?((?:[0-9a-f]{2}:){5}[0-9a-f]{2})",
    re.I,
)


@dataclass
class ArpWatch:
    iface: str
    on_conflict: Callable[[str, str, str], None] | None = None
    ip_to_mac: dict[str, str] = field(default_factory=dict)
    conflicts: list[str] = field(default_factory=list)
    packets: int = 0
    window_start: float = field(default_factory=time.time)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="arpwatch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def pps(self) -> float:
        dt = max(0.001, time.time() - self.window_start)
        rate = self.packets / dt
        self.packets = 0
        self.window_start = time.time()
        return rate

    def _run(self) -> None:
        cmd = ["tcpdump", "-i", self.iface, "-nnel", "-l", "arp"]
        while not self._stop.is_set():
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
            except Exception as exc:
                self.conflicts.append(f"arpwatch start failed: {exc}")
                time.sleep(5)
                continue
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    if self._stop.is_set():
                        break
                    self.packets += 1
                    self._handle(line)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
            time.sleep(1)

    def _handle(self, line: str) -> None:
        ip = mac = None
        m = _IS_AT.search(line)
        if m:
            if m.group(1) and m.group(2):
                mac, ip = m.group(1).lower(), m.group(2)
            elif m.group(3) and m.group(4):
                ip, mac = m.group(3), m.group(4).lower()
        if not ip or not mac:
            return
        prev = self.ip_to_mac.get(ip)
        if prev and prev != mac:
            msg = f"IP conflict / ARP flip: {ip} was {prev}, now {mac}"
            self.conflicts.append(msg)
            if self.on_conflict:
                self.on_conflict(ip, prev, mac)
        self.ip_to_mac[ip] = mac
