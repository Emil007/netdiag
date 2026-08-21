from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable


# Server replies: BOOTP/DHCP from udp/67 toward client
_SERVERISH = re.compile(
    r"(?:\.\d+\.67\s*>|Offer|ACK|ack|Boot Reply|boot reply)",
    re.I,
)
_CLIENTISH = re.compile(
    r"(?:Discover|Request|Inform|\.68\s*>)",
    re.I,
)
_MAC = re.compile(r"((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", re.I)
_SIP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.67\s*>")


@dataclass
class DhcpWatch:
    iface: str
    expected_mac: str = ""
    on_alarm: Callable[[str, str], None] | None = None
    on_learned: Callable[[str], None] | None = None
    learned_mac: str = ""
    alarms: list[str] = field(default_factory=list)
    _seen_bad: set[str] = field(default_factory=set)
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
        cmd = [
            "tcpdump",
            "-i",
            self.iface,
            "-nnel",
            "-l",
            "udp",
            "src",
            "port",
            "67",
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
        if _CLIENTISH.search(line) and not _SERVERISH.search(line):
            return
        if not _SERVERISH.search(line) and ".67 >" not in line and "67 >" not in line:
            # src port 67 filter should already limit; still require reply-ish
            if "Offer" not in line and "ACK" not in line and "ack" not in line:
                return
        macs = _MAC.findall(line.lower())
        if not macs:
            return
        # With -e, first MAC is typically source (server on replies from port 67)
        src = macs[0]
        if src == "ff:ff:ff:ff:ff:ff":
            return
        expected = (self.expected_mac or self.learned_mac).lower()
        if not expected:
            self.learned_mac = src
            if self.on_learned:
                self.on_learned(src)
            return
        if src != expected:
            if src in self._seen_bad:
                return
            self._seen_bad.add(src)
            msg = f"Unexpected DHCP server MAC {src} (expected {expected})"
            self.alarms.append(msg)
            if self.on_alarm:
                self.on_alarm(src, msg)
