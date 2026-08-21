from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import Config, SatelliteExpect


@dataclass
class ClassResult:
    kind: str
    verdict: str
    where_text: str = ""
    confidence: str = "single_vantage"  # single_vantage | confirmed
    matrix: list[dict[str, Any]] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)


def parse_ts(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def host_down(ping: dict[str, Any] | None, loss_threshold_pct: int = 50) -> bool:
    if not ping:
        return True
    loss = int(ping.get("loss", 100))
    recv = int(ping.get("recv", 0))
    return recv == 0 or loss >= loss_threshold_pct


def group_reachability(
    cfg: Config,
    ping: dict[str, dict[str, Any]],
    loss_threshold_pct: int = 50,
) -> dict[str, str]:
    """Per group id: ok | loss | mixed | empty."""
    out: dict[str, str] = {}
    for g in cfg.groups:
        if not g.hosts:
            out[g.id] = "empty"
            continue
        downs = [host_down(ping.get(h), loss_threshold_pct) for h in g.hosts]
        if all(downs):
            out[g.id] = "loss"
        elif not any(downs):
            out[g.id] = "ok"
        else:
            out[g.id] = "mixed"
    return out


def resolve_satellite_states(
    cfg: Config,
    rows: list[dict[str, Any]],
    now_ts: float,
) -> list[dict[str, Any]]:
    """Return enriched satellite rows with presence state."""
    by_id = {r["vantage_id"]: r for r in rows}
    out: list[dict[str, Any]] = []

    for expect in cfg.satellites:
        row = dict(by_id.get(expect.id) or {})
        row["vantage_id"] = expect.id
        row["link"] = row.get("link") or expect.link
        row["availability"] = expect.resolved_availability()
        row["placement"] = expect.placement if expect.placement in ("router", "other") else "other"
        state = _compute_state(cfg, row, now_ts, expect)
        row["state"] = state
        row["expected"] = True
        out.append(row)

    for row in rows:
        if cfg.satellite_by_id(row["vantage_id"]):
            continue
        r = dict(row)
        link = (r.get("link") or "ethernet").lower()
        avail = r.get("availability") or ("intermittent" if link == "wifi" else "always")
        r["availability"] = avail
        r["placement"] = "other"
        fake = SatelliteExpect(id=r["vantage_id"], link=link, availability=avail)
        r["state"] = _compute_state(cfg, r, now_ts, fake)
        r["expected"] = False  # store/show only — excluded from classify
        out.append(r)

    return out


def _compute_state(
    cfg: Config,
    row: dict[str, Any],
    now_ts: float,
    expect: SatelliteExpect,
) -> str:
    if row.get("last_event") == "offline" or (row.get("payload") or {}).get("event") == "offline":
        return "offline"

    if not row.get("received_at") and not row.get("last_seen"):
        return "never_seen"

    age = _age(row.get("received_at") or row.get("last_seen"), now_ts)
    if age is None:
        return "never_seen"

    if age <= cfg.satellite_stale_s:
        return "online"
    if age <= cfg.satellite_offline_after_s:
        return "stale"
    return "offline"


def _age(iso: str | None, now_ts: float) -> float | None:
    ts = parse_ts(iso)
    if ts is None:
        return None
    return now_ts - ts


def build_vantage_matrix(
    cfg: Config,
    local_ping: dict[str, dict[str, Any]],
    sat_states: list[dict[str, Any]],
    loss_threshold_pct: int = 50,
) -> list[dict[str, Any]]:
    """Rows = vantages, columns summarized per group."""
    rows: list[dict[str, Any]] = []
    local_groups = group_reachability(cfg, local_ping, loss_threshold_pct)
    rows.append(
        {
            "vantage_id": cfg.vantage.id,
            "link": cfg.vantage.link,
            "state": "online",
            "groups": local_groups,
            "ping": local_ping,
        }
    )
    for sat in sat_states:
        state = sat.get("state", "never_seen")
        payload = sat.get("payload") or {}
        ping = payload.get("ping") or {}
        if state == "online":
            groups = group_reachability(cfg, ping, loss_threshold_pct)
        else:
            groups = {g.id: state for g in cfg.groups}
        rows.append(
            {
                "vantage_id": sat["vantage_id"],
                "link": sat.get("link"),
                "state": state,
                "availability": sat.get("availability"),
                "placement": sat.get("placement") or "other",
                "groups": groups,
                "ping": ping if state == "online" else {},
            }
        )
    return rows


def classify_loss(
    cfg: Config,
    lost: set[str],
    *,
    local_ping: dict[str, dict[str, Any]] | None = None,
    sat_states: list[dict[str, Any]] | None = None,
    same_segment_down: bool | None = None,
    carrier_down: bool = False,
    warmup: bool = False,
    loss_threshold_pct: int = 50,
) -> ClassResult | None:
    local_ping = local_ping or {}
    # Unexpected (unlisted) satellites: STATUS only — never triangulation / WIFI_PATH
    all_sats = sat_states or []
    sat_states = [s for s in all_sats if s.get("expected", True)]
    matrix = build_vantage_matrix(cfg, local_ping, sat_states, loss_threshold_pct)

    eth_online = [
        r
        for r in matrix
        if r.get("link") == "ethernet" and r.get("state") == "online"
    ]
    wifi_fault = _wifi_path_candidate(
        cfg, sat_states, eth_online, warmup, lost=lost, local_ping=local_ping
    )

    if carrier_down:
        return ClassResult(
            "PROBE_ISOLATED",
            "Probe host NIC carrier is down. Suspect local cable, NIC, or the switch port this host uses.",
            where_text=_where_probe_isolated(eth_online, cfg, confirmed=_router_side_ok(eth_online, cfg)),
            confidence="confirmed" if _router_side_ok(eth_online, cfg) else "single_vantage",
            matrix=matrix,
        )

    roles = cfg.roles()
    external = roles.get("external", set())
    gateway = roles.get("gateway", set())
    same_seg = roles.get("same_segment", set())
    all_hosts = set(cfg.hosts())
    internal = all_hosts - external

    if same_seg and same_segment_down is None:
        same_segment_down = bool(same_seg) and same_seg <= lost

    # WIFI_PATH only from real stale+corroboration path, never never_seen/offline
    if wifi_fault and not (lost & gateway):
        return ClassResult(
            "WIFI_PATH",
            wifi_fault,
            where_text="The break looks like the Wi-Fi / mesh air path. Wired ethernet vantages still look healthy.",
            confidence="confirmed",
            matrix=matrix,
        )

    if not lost:
        return None

    if lost and lost <= external:
        return ClassResult(
            "INTERNET",
            "Only external targets were unreachable from this probe. The path to the router looks fine — "
            "likely ISP/WAN, or ICMP blocked toward those targets (see TCP fallback notes).",
            where_text="Outside the home LAN (ISP/WAN), not an unmanaged switch.",
            matrix=matrix,
        )

    router_side = _router_side_vantage(eth_online, cfg)
    router_side_ok = _vantage_reaches(router_side, cfg, ("gateway", "external"))
    coord_row = next((r for r in matrix if r["vantage_id"] == cfg.vantage.id), None)

    # Both coordinator and router-side lose gateway → router/ISP, not local switch
    if gateway and gateway <= lost:
        if router_side and not router_side_ok:
            return ClassResult(
                "TOTAL_OUTAGE",
                "Coordinator and a wired vantage nearer the router both lose the gateway. "
                "Suspect the router or ISP, not a single unmanaged switch next to the probe.",
                where_text="Router / ISP side — not the unmanaged switch next to the coordinator alone.",
                confidence="confirmed",
                matrix=matrix,
            )

    # Confirmed PROBE_ISOLATED: local same_segment down, router-side sat still OK
    if same_segment_down and gateway and (gateway <= lost):
        confirmed = bool(router_side_ok)
        return ClassResult(
            "PROBE_ISOLATED",
            "Same-segment canaries and the router are unreachable from this probe. "
            "Suspect the unmanaged switch this host plugs into, its power, or this host's NIC/cable.",
            where_text=_where_probe_isolated(eth_online, cfg, confirmed=confirmed),
            confidence="confirmed" if confirmed else "single_vantage",
            matrix=matrix,
        )

    # UPLINK_DOWN: same_segment up, gateway down; router-side confirms when present
    if same_seg and not (lost & same_seg):
        remote = (gateway | roles.get("mesh", set()) | external) & all_hosts
        if remote and remote <= lost:
            confirmed = bool(router_side_ok)
            return ClassResult(
                "UPLINK_DOWN",
                "Devices on the same switch/segment as the probe still answer, but the router "
                "(and usually mesh/internet) do not from this probe.",
                where_text=_where_uplink(confirmed=confirmed),
                confidence="confirmed" if confirmed else "single_vantage",
                matrix=matrix,
            )

    if not same_seg and gateway and gateway <= lost and internal and (lost & internal) == (internal & lost):
        # No same_segment configured — do not pretend uplink vs isolated
        if internal <= lost:
            return ClassResult(
                "TOTAL_OUTAGE",
                "All internal canaries unreachable, but no same_segment canary is configured, "
                "so this probe cannot tell local-switch failure from uplink-to-router failure.",
                where_text="Ambiguous without a same_segment canary (and ideally a wired satellite on the router side).",
                confidence="single_vantage",
                matrix=matrix,
            )

    if internal and lost >= internal and internal <= lost:
        return ClassResult(
            "TOTAL_OUTAGE",
            "All configured internal canaries were unreachable, including the gateway.",
            where_text="Wide outage — router restart, storm/loop, or shared path failure.",
            matrix=matrix,
        )

    # BRANCH / SINGLE_HOST with optional sat confirmation
    for g in cfg.groups:
        gset = set(g.hosts)
        if not gset or g.role in ("external",):
            continue
        inner = lost & internal
        if inner and inner <= gset:
            sat_sees_g = _group_status_from_sats(eth_online, g.id, cfg.vantage.id)
            if len(inner) == 1:
                h = next(iter(inner))
                where = _where_branch(g.id, sat_sees_g, single=True)
                return ClassResult(
                    "SINGLE_HOST",
                    f"Only {h} (group '{g.id}', role {g.role}) was unreachable from this probe.",
                    where_text=where,
                    confidence="confirmed" if sat_sees_g in ("loss", "ok") else "single_vantage",
                    matrix=matrix,
                )
            where = _where_branch(g.id, sat_sees_g, single=False)
            return ClassResult(
                "BRANCH",
                f"Only canaries in group '{g.id}' (role {g.role}) were unreachable from this probe. "
                "Suspect that room/spur: unmanaged switch, cable, or AP for that segment.",
                where_text=where,
                confidence="confirmed" if sat_sees_g in ("loss", "ok") else "single_vantage",
                matrix=matrix,
            )

    # Satellite isolated while coordinator OK
    for sat in eth_online:
        if sat["vantage_id"] == cfg.vantage.id:
            continue
        if _vantage_isolated(sat, cfg) and coord_row and not _vantage_isolated(coord_row, cfg):
            return ClassResult(
                "BRANCH",
                f"Wired satellite '{sat['vantage_id']}' looks isolated while the coordinator still reaches the gateway.",
                where_text=(
                    f"The unmanaged switch or cable on satellite '{sat['vantage_id']}'s side, "
                    "not the coordinator's switch."
                ),
                confidence="confirmed",
                matrix=matrix,
            )

    return ClassResult(
        "MIXED",
        "Loss spread across multiple groups without a clean single-spur pattern. "
        "Suspect DHCP issues, IP conflict, short storm, or overlapping faults.",
        where_text="Unclear single location — check the vantage × group table.",
        matrix=matrix,
    )


def _wifi_path_candidate(
    cfg: Config,
    sat_states: list[dict[str, Any]],
    eth_online: list[dict[str, Any]],
    warmup: bool,
    *,
    lost: set[str] | None = None,
    local_ping: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    if warmup:
        return None
    lost = lost or set()
    local_ping = local_ping or {}
    eth_healthy = False
    for r in eth_online:
        if _vantage_reaches(r, cfg, ("gateway",)):
            eth_healthy = True
            break
    if cfg.vantage.link == "ethernet":
        for r in eth_online:
            if r["vantage_id"] == cfg.vantage.id and _vantage_reaches(r, cfg, ("gateway",)):
                eth_healthy = True

    if not eth_healthy:
        return None

    mesh_wifi_hosts = cfg.hosts_by_role("mesh") | cfg.hosts_by_role("wifi")
    mesh_wifi_lossy = bool(lost & mesh_wifi_hosts) or any(
        host_down(local_ping.get(h)) for h in mesh_wifi_hosts
    )

    for sat in sat_states:
        if not sat.get("expected", True):
            continue
        if sat.get("link") != "wifi":
            continue
        state = sat.get("state")
        avail = sat.get("availability") or "intermittent"
        if state in ("never_seen", "offline"):
            continue
        if state == "online":
            ping = (sat.get("payload") or {}).get("ping") or {}
            if ping and any(host_down(ping.get(h)) for h in ping):
                gw = cfg.hosts_by_role("gateway")
                if gw and any(host_down(ping.get(h)) for h in gw):
                    return (
                        f"Wi-Fi satellite '{sat['vantage_id']}' is checking in but cannot reach "
                        "the router while ethernet vantages can."
                    )
            continue
        if state == "stale":
            if avail == "intermittent":
                if mesh_wifi_lossy:
                    return (
                        f"Intermittent Wi-Fi satellite '{sat['vantage_id']}' went silent, and "
                        "mesh/Wi-Fi canaries are also lossy while ethernet still reaches the router."
                    )
                continue
            return (
                f"Always-on Wi-Fi satellite '{sat['vantage_id']}' went silent after being online, "
                "while ethernet vantages still reach the router."
            )
    return None


def _vantage_reaches(row: dict[str, Any] | None, cfg: Config, roles: tuple[str, ...]) -> bool:
    if not row or row.get("state") != "online":
        return False
    groups = row.get("groups") or {}
    for g in cfg.groups:
        if g.role in roles:
            st = groups.get(g.id)
            if st == "ok":
                return True
            if st == "loss":
                return False
    return False


def _router_side_vantage(eth_online: list[dict[str, Any]], cfg: Config) -> dict[str, Any] | None:
    others = [r for r in eth_online if r["vantage_id"] != cfg.vantage.id]
    if not others:
        return None
    for r in others:
        if r.get("placement") == "router":
            return r
    for r in others:
        if _vantage_reaches(r, cfg, ("gateway",)):
            return r
    return others[0]


def _router_side_ok(eth_online: list[dict[str, Any]], cfg: Config) -> bool:
    return _vantage_reaches(_router_side_vantage(eth_online, cfg), cfg, ("gateway", "external"))


def _vantage_isolated(row: dict[str, Any], cfg: Config) -> bool:
    groups = row.get("groups") or {}
    gw = [g.id for g in cfg.groups if g.role == "gateway"]
    if not gw:
        return False
    return all(groups.get(gid) == "loss" for gid in gw)


def _group_status_from_sats(
    eth_online: list[dict[str, Any]], group_id: str, coord_id: str
) -> str | None:
    """Status of group_id from other ethernet vantages only (never the coordinator)."""
    for r in eth_online:
        if r.get("vantage_id") == coord_id:
            continue
        st = (r.get("groups") or {}).get(group_id)
        if st in ("ok", "loss"):
            return st
    return None


def _where_probe_isolated(eth_online: list[dict[str, Any]], cfg: Config, confirmed: bool) -> str:
    if confirmed:
        return (
            "The unmanaged switch the coordinator plugs into, or this host's NIC/cable. "
            "A wired vantage on the other side still reached the gateway (confirmed)."
        )
    return (
        "Likely the unmanaged switch this host plugs into, or this host's NIC/cable "
        "(single vantage — add a wired satellite on the router side to confirm)."
    )


def _where_uplink(confirmed: bool) -> str:
    if confirmed:
        return (
            "The break is between the coordinator and the router: the unmanaged switch that host uses, "
            "or that switch's cable/path to the router. A wired vantage on the router side still reached "
            "the gateway (confirmed)."
        )
    return (
        "Likely the uplink from this switch toward the router, or the router LAN port it uses "
        "(inferred from canaries only — confidence: single vantage)."
    )


def _where_branch(group_id: str, sat_sees: str | None, single: bool) -> str:
    noun = "device/port" if single else "room/spur"
    if sat_sees == "loss":
        return (
            f"Named spur '{group_id}' — the unmanaged switch or cable those canaries sit on "
            f"(seen from multiple ethernet vantages)."
        )
    if sat_sees == "ok":
        return (
            f"Path between the coordinator and spur '{group_id}' (coordinator's switch or a shared "
            "uplink), not the far device alone — another ethernet vantage still reached that group."
        )
    return f"Named {noun} '{group_id}' (single vantage)."


def classify_detector_event(kind: str, detail: str) -> ClassResult:
    return ClassResult(kind, detail)
