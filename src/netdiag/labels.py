from __future__ import annotations

# Plain-language labels next to incident codes (keep the code in UI).
KIND_LABELS: dict[str, str] = {
    "BRANCH": "Room/spur problem",
    "SINGLE_HOST": "One device unreachable",
    "PROBE_ISOLATED": "This probe cut off",
    "UPLINK_DOWN": "Path toward router",
    "TOTAL_OUTAGE": "Wide LAN outage",
    "WIFI_PATH": "Wi-Fi / mesh air path",
    "INTERNET": "Outside the home (ISP/WAN)",
    "MIXED": "Unclear pattern",
    "ROGUE_DHCP": "Unexpected DHCP server",
    "IP_CONFLICT": "IP address conflict",
    "DNS_FAILURE": "DNS lookup failure",
    "PATH_CHANGE": "Route path changed",
    "LINK_ERRORS": "Probe NIC errors",
    "BCAST_STORM": "Broadcast storm hint",
    "NIC_SPEED": "NIC speed drop",
}


def kind_label(kind: str | None) -> str:
    if not kind:
        return ""
    return KIND_LABELS.get(str(kind), "")


def format_kind(kind: str | None) -> str:
    """e.g. BRANCH — Room/spur problem"""
    if not kind:
        return ""
    label = kind_label(kind)
    return f"{kind} — {label}" if label else str(kind)
