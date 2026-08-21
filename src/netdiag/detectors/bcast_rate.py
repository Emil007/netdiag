from __future__ import annotations

import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class BcastRateWatch:
    """Count broadcast/multicast frames via tcpdump for a real pps baseline."""

    iface: str
    packets: int = 0
    window_start: float = field(default_factory=time.time)
    samples: deque = field(default_factory=lambda: deque(maxlen=60))
    baseline: float = 0.0
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="bcastwatch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def tick(self) -> dict[str, float]:
        now = time.time()
        dt = max(0.001, now - self.window_start)
        pps = self.packets / dt
        self.packets = 0
        self.window_start = now
        self.samples.append(pps)
        if len(self.samples) >= 10:
            ordered = sorted(self.samples)
            self.baseline = ordered[len(ordered) // 2]  # median
        storm = False
        # Need baseline; require pps >> baseline and absolute floor
        if self.baseline > 0 and pps > max(self.baseline * 5, self.baseline + 100) and pps > 50:
            storm = True
        elif self.baseline == 0 and len(self.samples) >= 10 and pps > 500:
            storm = True
        return {"pps": pps, "baseline": self.baseline, "storm": float(storm)}

    def _run(self) -> None:
        cmd = [
            "tcpdump",
            "-i",
            self.iface,
            "-n",
            "-l",
            "broadcast",
            "or",
            "multicast",
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
                for _line in proc.stdout:
                    if self._stop.is_set():
                        break
                    self.packets += 1
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
            time.sleep(1)
