from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LanCensus:
    """Passive ARP/DHCP speaker counts — not an inventory / nmap product."""

    baseline_s: float = 1800.0
    recent_s: float = 120.0
    # ip or mac -> last_seen
    speakers: dict[str, float] = field(default_factory=dict)
    last_note_at: float = 0.0

    def observe(self, key: str, now: float | None = None) -> None:
        if not key or key in ("0.0.0.0", "ff:ff:ff:ff:ff:ff"):
            return
        self.speakers[key.lower()] = now if now is not None else time.time()
        self._prune()

    def _prune(self) -> None:
        now = time.time()
        cutoff = now - self.baseline_s
        dead = [k for k, t in self.speakers.items() if t < cutoff]
        for k in dead:
            del self.speakers[k]

    def snapshot(self, now: float | None = None) -> dict[str, Any]:
        now = now if now is not None else time.time()
        self._prune()
        recent = sum(1 for t in self.speakers.values() if now - t <= self.recent_s)
        baseline = len(self.speakers)
        drop = baseline - recent
        # Mass disappear: had a meaningful LAN population, recent speakers collapsed
        mass = baseline >= 8 and recent <= max(2, int(baseline * 0.35)) and drop >= 5
        return {
            "recent": recent,
            "baseline": baseline,
            "text": f"census: {baseline}→{recent}",
            "mass_disappear": mass,
        }
