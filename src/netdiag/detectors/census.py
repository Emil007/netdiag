from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LanCensus:
    """Passive ARP/DHCP speaker counts — not an inventory / nmap product.

    One key per host (prefer IP). Mass-disappear uses a short active window so
    overnight quiet does not look like a sudden fault.
    """

    baseline_s: float = 1800.0
    # Speakers heard in this window count as "active LAN" for mass detection
    active_s: float = 900.0
    recent_s: float = 120.0
    # key (ip preferred) -> last_seen
    speakers: dict[str, float] = field(default_factory=dict)
    last_note_at: float = 0.0

    def observe(self, key: str, now: float | None = None) -> None:
        """Legacy single-key observe (tests / DHCP MAC-only)."""
        self.observe_host(ip=None, mac=key, now=now)

    def observe_host(
        self,
        *,
        ip: str | None = None,
        mac: str | None = None,
        now: float | None = None,
    ) -> None:
        """Count one host per ARP/DHCP event — prefer IP over MAC."""
        key = self._host_key(ip, mac)
        if not key:
            return
        self.speakers[key] = now if now is not None else time.time()
        self._prune()

    @staticmethod
    def _host_key(ip: str | None, mac: str | None) -> str | None:
        if ip:
            ip = ip.strip().lower()
            if ip and ip not in ("0.0.0.0", "255.255.255.255"):
                return f"ip:{ip}"
        if mac:
            mac = mac.strip().lower()
            if mac and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                return f"mac:{mac}"
        return None

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
        active = sum(1 for t in self.speakers.values() if now - t <= self.active_s)
        baseline = len(self.speakers)
        drop = active - recent
        # Mass only on a sharp collapse within the active window (not overnight fade).
        # Overnight: after active_s of silence, active≈0 → no mass.
        mass = (
            active >= 8
            and recent <= max(2, int(active * 0.35))
            and drop >= 5
        )
        return {
            "recent": recent,
            "active": active,
            "baseline": baseline,
            "text": f"{active}→{recent} speakers (last {int(self.recent_s / 60) or 1} min)"
            if self.recent_s >= 60
            else f"{active}→{recent} speakers (last {int(self.recent_s)}s)",
            "mass_disappear": mass,
        }
