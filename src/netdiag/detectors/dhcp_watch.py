from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable


_MAC = re.compile(r"((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", re.I)


@dataclass
class DhcpWatch:
    iface: str
    expected_mac: str = ""
    on_alarm: Callable[[str, str], None] | None = None
    learned_mac: str = ""
    alarms: list[str] = field(default_factory=list)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="dhcpwatch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        # tcpdump DHCP replies (boot reply / offer/ack roughly via udp 67/68)
        cmd = [
            "tcpdump",
            "-i",
            self.iface,
            "-nnel",
            "-l",
            "udp",
            "port",
            "67",
            "or",
            "udp",
            "port",
            "68",
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
            except Exception as exc:
                self.alarms.append(f"dhcpwatch start failed: {exc}")
                time.sleep(5)
                continue

            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    if self._stop.is_set():
                        break
                    self._handle_line(line)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
            time.sleep(1)

    def _handle_line(self, line: str) -> None:
        # Prefer source MAC of frames that look like server replies toward clients
        if "67 >" not in line and "bootps" not in line.lower() and ".67:" not in line:
            # still inspect offers
            if "Offer" not in line and "ACK" not in line and "ack" not in line:
                return
        macs = _MAC.findall(line.lower())
        if not macs:
            return
        # First MAC in -e output is typically source
        src = macs[0]
        expected = (self.expected_mac or self.learned_mac).lower()
        if not expected:
            self.learned_mac = src
            return
        if src != expected and src not in ("ff:ff:ff:ff:ff:ff",):
            msg = f"Unexpected DHCP server MAC {src} (expected {expected})"
            self.alarms.append(msg)
            if self.on_alarm:
                self.on_alarm(src, msg)
