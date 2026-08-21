from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import Config


@dataclass
class ClassResult:
    kind: str
    verdict: str


def classify_loss(
    cfg: Config,
    lost: set[str],
    *,
    same_segment_down: bool | None = None,
    carrier_down: bool = False,
    link_errors_delta: int = 0,
    bcast_delta: int = 0,
    wifi_vantages_bad: bool = False,
    ethernet_vantages_ok: bool = False,
) -> ClassResult | None:
    """Classify based on which canary hosts are currently failing."""
    if carrier_down and (not lost or same_segment_down):
        return ClassResult(
            "PROBE_ISOLATED",
            "Probe host NIC carrier is down. Suspect local cable, NIC, or the switch port this host uses.",
        )

    if link_errors_delta > 0 and lost:
        # Annotate later; still classify topology first
        pass

    if wifi_vantages_bad and ethernet_vantages_ok and not (lost & cfg.hosts_by_role("gateway")):
        return ClassResult(
            "WIFI_PATH",
            "Wi-Fi vantage(s) are unhealthy or silent while ethernet vantages still look healthy. "
            "Suspect mesh/Wi-Fi path, not the wired switch.",
        )

    if not lost:
        if wifi_vantages_bad and ethernet_vantages_ok:
            return ClassResult(
                "WIFI_PATH",
                "Wi-Fi vantage(s) are unhealthy or silent while local wired canaries are fine. "
                "Suspect mesh/Wi-Fi.",
            )
        return None

    roles = cfg.roles()
    external = roles.get("external", set())
    gateway = roles.get("gateway", set())
    same_seg = roles.get("same_segment", set())
    all_hosts = set(cfg.hosts())
    internal = all_hosts - external

    if lost and lost <= external:
        return ClassResult(
            "INTERNET",
            "Only external targets were unreachable. The LAN path to the router looks fine — "
            "this is likely the ISP/WAN side.",
        )

    inner = lost & internal

    if same_seg and same_segment_down is None:
        same_segment_down = bool(same_seg) and same_seg <= lost

    # Uplink: local same-segment still up, but gateway/mesh/external down
    if same_seg and not (lost & same_seg):
        remote = (gateway | roles.get("mesh", set()) | external) & all_hosts
        if remote and remote <= lost:
            return ClassResult(
                "UPLINK_DOWN",
                "Devices on the same switch/segment as the probe still answer, but the router "
                "(and usually mesh/internet) do not. Suspect the uplink cable from this switch "
                "to the router, or the router LAN port.",
            )

    if same_segment_down and gateway and gateway <= lost:
        return ClassResult(
            "PROBE_ISOLATED",
            "Same-segment canaries and the router are unreachable from this probe. "
            "Suspect the local switch, its power, or this host's NIC/cable.",
        )

    if internal and inner == internal:
        return ClassResult(
            "TOTAL_OUTAGE",
            "All configured internal canaries were unreachable, including the gateway. "
            "Suspect router restart, broadcast storm/loop, or a wide L2 failure.",
        )

    # Single group containment
    for g in cfg.groups:
        gset = set(g.hosts)
        if not gset or g.role == "external":
            continue
        if inner and inner <= gset:
            if len(inner) == 1:
                h = next(iter(inner))
                return ClassResult(
                    "SINGLE_HOST",
                    f"Only {h} (group '{g.id}', role {g.role}) was unreachable. "
                    "Suspect that device, its cable, or its switch port.",
                )
            return ClassResult(
                "BRANCH",
                f"Only canaries in group '{g.id}' (role {g.role}) were unreachable. "
                "Suspect that branch: AP/mesh node, switch spur, or uplink for that segment.",
            )

    extra = ""
    if link_errors_delta > 0:
        extra = f" NIC also counted +{link_errors_delta} receive errors during the window."
    if bcast_delta > 5000:
        extra += f" High multicast/broadcast delta (+{bcast_delta})."

    return ClassResult(
        "MIXED",
        "Loss spread across multiple groups without a clean single-branch pattern. "
        "Suspect DHCP issues, IP conflict, short storm, or overlapping faults." + extra,
    )


def classify_detector_event(kind: str, detail: str) -> ClassResult:
    return ClassResult(kind, detail)


def vantage_flags(
    cfg: Config,
    satellite_rows: list[dict[str, Any]],
    local_ping: dict[str, dict[str, Any]],
    now_ts: float,
) -> dict[str, bool]:
    """Derive wifi_vantages_bad / ethernet_vantages_ok from satellite freshness + loss."""
    stale_s = cfg.satellite_stale_s
    wifi_bad = False
    eth_ok = True

    # Local vantage
    local_loss = any(
        (local_ping.get(h) or {}).get("loss", 0) >= 100 for h in cfg.hosts() if h
    )
    if cfg.vantage.link == "wifi" and local_loss:
        wifi_bad = True
    if cfg.vantage.link == "ethernet" and local_loss:
        # ethernet local loss doesn't mean eth_ok for triangulation of wifi
        pass

    expected = {s.id: s.link for s in cfg.satellites}
    seen = {r["vantage_id"]: r for r in satellite_rows}

    for vid, link in expected.items():
        row = seen.get(vid)
        if row is None:
            if link == "wifi":
                wifi_bad = True
            continue
        # parse received_at roughly via payload age if present
        age = _age_seconds(row.get("received_at"), now_ts)
        payload = row.get("payload") or {}
        ping = payload.get("ping") or {}
        lossy = any((ping.get(h) or {}).get("loss", 0) >= 100 for h in ping)
        if age is not None and age > stale_s:
            if link == "wifi":
                wifi_bad = True
            elif link == "ethernet":
                eth_ok = False
        elif lossy:
            if link == "wifi":
                wifi_bad = True
            elif link == "ethernet":
                eth_ok = False
        else:
            if link == "ethernet":
                eth_ok = eth_ok and True

    # Also consider unexpected samples
    for row in satellite_rows:
        link = row.get("link") or "ethernet"
        age = _age_seconds(row.get("received_at"), now_ts)
        payload = row.get("payload") or {}
        ping = payload.get("ping") or {}
        lossy = any((ping.get(h) or {}).get("loss", 0) >= 100 for h in ping)
        silent = age is not None and age > stale_s
        if link == "wifi" and (silent or lossy):
            wifi_bad = True
        if link == "ethernet" and not silent and not lossy:
            eth_ok = True

    # If coordinator is ethernet and can reach gateway, eth vantage ok
    gw = cfg.hosts_by_role("gateway")
    if cfg.vantage.link == "ethernet" and gw:
        if all((local_ping.get(h) or {}).get("loss", 100) < 100 for h in gw):
            eth_ok = True

    return {"wifi_vantages_bad": wifi_bad, "ethernet_vantages_ok": eth_ok}


def _age_seconds(received_at: str | None, now_ts: float) -> float | None:
    if not received_at:
        return None
    from datetime import datetime, timezone

    try:
        dt = datetime.strptime(received_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return now_ts - dt.timestamp()
    except Exception:
        return None
