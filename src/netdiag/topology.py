from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .config import Config, data_dir


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def show_local_switch(cfg: Config) -> bool:
    """Only when same_segment is configured or vantage.behind_switch is true."""
    if cfg.hosts_by_role("same_segment"):
        return True
    return bool(getattr(cfg.vantage, "behind_switch", False))


def branch_parent(cfg: Config, group_id: str, has_local: bool) -> str:
    for g in cfg.groups:
        if g.id != group_id:
            continue
        attach = getattr(g, "attach", "gateway") or "gateway"
        if attach == "local_switch" and has_local:
            return "local_switch"
        return "gateway"
    return "gateway"


def build_topology(
    cfg: Config,
    *,
    matrix: list[dict[str, Any]] | None = None,
    incident: dict[str, Any] | None = None,
    l2_bridges: list[dict[str, Any]] | None = None,
    link_fault: bool = False,
    shared_upstream_hint: str | None = None,
    census: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build topology graph for HTML/JSON. Inferred — not a cable tracer."""
    matrix = matrix or []
    l2_bridges = l2_bridges or []
    kind = (incident or {}).get("kind") or ""
    where = (incident or {}).get("where_text") or ""
    confidence = ((incident or {}).get("meta") or {}).get("confidence") or (
        (incident or {}).get("confidence") or ""
    )
    if not confidence:
        confidence = "n/a" if not kind else "single_vantage"

    coord_groups = {}
    for row in matrix:
        if row.get("vantage_id") == cfg.vantage.id:
            coord_groups = row.get("groups") or {}
            break

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def add_node(nid: str, label: str, ntype: str, **extra: Any) -> None:
        nodes.append({"id": nid, "label": label, "type": ntype, **extra})

    def add_edge(src: str, dst: str, status: str = "unknown", fault: bool = False, label: str = "") -> None:
        edges.append({"from": src, "to": dst, "status": status, "fault": fault, "label": label})

    add_node("internet", "Internet / ISP", "internet")
    add_node("gateway", "Router (gateway)", "gateway")

    for g in cfg.groups:
        if g.role == "mesh":
            st = coord_groups.get(g.id, "unknown")
            add_node(f"mesh:{g.id}", f"Mesh/AP {g.id}", "mesh", group=g.id, status=st)

    has_local = show_local_switch(cfg)
    if has_local:
        add_node("local_switch", "Local unmanaged switch (inferred)", "switch", inferred=True)

    add_node(
        "coordinator",
        f"Coordinator ({cfg.vantage.id})",
        "coordinator",
        link=cfg.vantage.link,
    )

    for g in cfg.groups:
        if g.role == "same_segment":
            st = coord_groups.get(g.id, "unknown")
            add_node(f"group:{g.id}", f"same_segment {g.id}", "same_segment", group=g.id, status=st)
        elif g.role == "branch":
            st = coord_groups.get(g.id, "unknown")
            add_node(f"group:{g.id}", f"Spur {g.id}", "branch", group=g.id, status=st)
        elif g.role == "wifi":
            st = coord_groups.get(g.id, "unknown")
            add_node(f"group:{g.id}", f"Wi-Fi {g.id}", "wifi", group=g.id, status=st)

    for s in cfg.satellites:
        add_node(
            f"sat:{s.id}",
            f"Satellite {s.id}",
            "satellite",
            link=s.link,
            placement=s.placement,
        )

    for i, b in enumerate(l2_bridges):
        add_node(
            f"l2:{b.get('kind')}:{b.get('id') or i}",
            f"{b.get('kind', 'l2').upper()} {b.get('id', '')}",
            "l2_bridge",
            detail=b.get("detail", ""),
        )

    if shared_upstream_hint:
        add_node("shared_upstream", shared_upstream_hint, "inferred_upstream", inferred=True)

    if census and census.get("baseline", 0) > 0:
        label = f"other LAN clients ({census.get('recent', 0)})"
        add_node(
            "lan_clients",
            label,
            "census",
            recent=census.get("recent"),
            baseline=census.get("baseline"),
            mass=bool(census.get("mass_disappear")),
        )

    ext_st = coord_groups.get(next((g.id for g in cfg.groups if g.role == "external"), ""), "unknown")
    gw_st = coord_groups.get(next((g.id for g in cfg.groups if g.role == "gateway"), ""), "unknown")

    fault_uplink = kind == "UPLINK_DOWN"
    fault_isolated = kind == "PROBE_ISOLATED"
    fault_internet = kind == "INTERNET"
    fault_wifi = kind == "WIFI_PATH"
    fault_total = kind == "TOTAL_OUTAGE"
    fault_branch = kind in ("BRANCH", "SINGLE_HOST")

    add_edge(
        "internet",
        "gateway",
        status="loss" if fault_internet or (ext_st == "loss" and gw_st == "ok") else ("ok" if ext_st == "ok" else ext_st),
        fault=fault_internet or fault_total,
        label="WAN",
    )

    if has_local:
        add_edge(
            "gateway",
            "local_switch",
            status="loss" if fault_uplink or fault_total else ("ok" if gw_st == "ok" else gw_st),
            fault=fault_uplink or fault_total,
            label="uplink",
        )
        add_edge(
            "local_switch",
            "coordinator",
            status="loss" if fault_isolated or link_fault else "ok",
            fault=fault_isolated or link_fault,
            label="NIC/cable" if link_fault else "local",
        )
        for g in cfg.groups:
            if g.role == "same_segment":
                st = coord_groups.get(g.id, "unknown")
                add_edge(
                    "local_switch",
                    f"group:{g.id}",
                    status=st,
                    fault=fault_isolated and st == "loss",
                )
    else:
        add_edge(
            "gateway",
            "coordinator",
            status="loss" if fault_uplink or fault_isolated or fault_total else ("ok" if gw_st == "ok" else gw_st),
            fault=fault_uplink or fault_isolated or fault_total or link_fault,
            label="NIC/cable" if link_fault else "",
        )

    for g in cfg.groups:
        if g.role == "branch":
            st = coord_groups.get(g.id, "unknown")
            hosts = (incident or {}).get("hosts") or {}
            blamed = fault_branch and (
                any(h in g.hosts for h in hosts)
                or g.id in where
                or g.id in ((incident or {}).get("verdict") or "")
            )
            parent = branch_parent(cfg, g.id, has_local)
            add_edge(parent, f"group:{g.id}", status=st, fault=blamed, label=g.id)
        if g.role == "mesh":
            st = coord_groups.get(g.id, "unknown")
            add_edge(
                "gateway",
                f"mesh:{g.id}",
                status=st,
                fault=fault_wifi and st == "loss",
            )
        if g.role == "wifi":
            st = coord_groups.get(g.id, "unknown")
            add_edge("gateway", f"group:{g.id}", status=st, fault=fault_wifi)

    for s in cfg.satellites:
        sid = f"sat:{s.id}"
        if s.placement == "router":
            parent = "gateway"
        elif has_local:
            parent = "local_switch"
        else:
            parent = "gateway"
        add_edge(parent, sid, status="unknown", fault=False, label=s.placement)

    if shared_upstream_hint and any(n["id"] == "shared_upstream" for n in nodes):
        add_edge("gateway", "shared_upstream", status="loss", fault=True, label="shared?")

    for b in l2_bridges:
        nid = f"l2:{b.get('kind')}:{b.get('id')}"
        if any(n["id"] == nid for n in nodes):
            parent = "local_switch" if has_local else "gateway"
            add_edge(parent, nid, status="ok", fault=False, label="STP/LLDP")

    if census and any(n["id"] == "lan_clients" for n in nodes):
        add_edge(
            "gateway",
            "lan_clients",
            status="loss" if census.get("mass_disappear") else "ok",
            fault=bool(census.get("mass_disappear") and kind),
            label=census.get("text") or "",
        )

    fault_node_ids = set()
    for e in edges:
        if e.get("fault"):
            fault_node_ids.add(e["from"])
            fault_node_ids.add(e["to"])
    for n in nodes:
        n["fault"] = n["id"] in fault_node_ids

    return {
        "caption": (
            "Inferred topology from canaries, optional satellites, and STP/LLDP hints — "
            "not a cable tracer. Silent unmanaged switches appear only if same_segment / "
            "behind_switch, co-inferred, or advertising STP/LLDP."
        ),
        "where": where,
        "confidence": confidence,
        "incident_kind": kind or None,
        "nodes": nodes,
        "edges": edges,
        "link_fault": link_fault,
        "shared_upstream_hint": shared_upstream_hint,
        "census": census,
    }


def topology_svg(topo: dict[str, Any]) -> str:
    """Simple layered SVG map."""
    nodes = topo.get("nodes") or []
    edges = topo.get("edges") or []
    columns = {
        "internet": 0,
        "gateway": 1,
        "mesh": 2,
        "switch": 2,
        "inferred_upstream": 2,
        "l2_bridge": 2,
        "census": 2,
        "coordinator": 3,
        "same_segment": 3,
        "branch": 4,
        "wifi": 4,
        "satellite": 3,
    }
    by_col: dict[int, list] = {}
    for n in nodes:
        col = columns.get(n.get("type"), 3)
        by_col.setdefault(col, []).append(n)

    positions: dict[str, tuple[float, float]] = {}
    width = 920
    height = 420
    for col, lst in by_col.items():
        x = 80 + col * 180
        for i, n in enumerate(lst):
            y = 60 + i * (320 / max(1, len(lst)))
            positions[n["id"]] = (x, y)

    status_color = {
        "ok": "#2a7",
        "loss": "#c33",
        "mixed": "#c80",
        "unknown": "#99a",
        "empty": "#ccd",
    }

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" style="max-width:{width}px;background:#f7f8fa;border-radius:8px">'
    ]
    for e in edges:
        a = positions.get(e["from"])
        b = positions.get(e["to"])
        if not a or not b:
            continue
        color = "#c33" if e.get("fault") else status_color.get(e.get("status"), "#99a")
        width_e = 3.5 if e.get("fault") else 1.5
        parts.append(
            f'<line x1="{a[0]}" y1="{a[1]}" x2="{b[0]}" y2="{b[1]}" '
            f'stroke="{color}" stroke-width="{width_e}" />'
        )
        if e.get("label"):
            mx, my = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2
            parts.append(
                f'<text x="{mx}" y="{my - 4}" font-size="10" fill="#456" text-anchor="middle">'
                f'{_esc(e["label"])}</text>'
            )

    for n in nodes:
        pos = positions.get(n["id"])
        if not pos:
            continue
        fill = "#fee" if n.get("fault") else "#fff"
        stroke = "#c33" if n.get("fault") else "#889"
        parts.append(
            f'<rect x="{pos[0] - 55}" y="{pos[1] - 18}" width="110" height="36" '
            f'rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
        )
        parts.append(
            f'<text x="{pos[0]}" y="{pos[1] + 4}" font-size="11" text-anchor="middle" fill="#122">'
            f'{_esc(n.get("label", n["id"])[:22])}</text>'
        )

    parts.append("</svg>")
    return "".join(parts)


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_topology_files(topo: dict[str, Any], where: str = "", confidence: str = "") -> None:
    from .labels import format_kind

    reports = data_dir() / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    _atomic_write(reports / "topology.json", json.dumps(topo, indent=2))
    svg = topology_svg(topo)
    kind = topo.get("incident_kind")
    kind_disp = topo.get("incident_kind_display") or (format_kind(kind) if kind else "")
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>netdiag topology</title>
<style>
 body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 1.5rem; color: #122; background: #f7f8fa; }}
 .card {{ background: #fff; border: 1px solid #dde; border-radius: 8px; padding: 1rem; max-width: 960px; }}
 .where {{ font-size: 1.05rem; margin: 0.8rem 0; }}
 .muted {{ color: #567; font-size: 0.9rem; }}
 a {{ color: #06c; }}
 svg {{ max-width: 100%; height: auto; }}
</style></head><body>
<p><a href="report.html">&larr; Report</a></p>
<div class="card">
<h1>Topology map</h1>
<p class="muted">{_esc(topo.get("caption", ""))}</p>
<p class="where"><strong>Where:</strong> {_esc(where or topo.get("where") or "n/a")}<br/>
<strong>Confidence:</strong> {_esc(confidence or topo.get("confidence") or "n/a")}
{" · <strong>" + _esc(kind_disp) + "</strong>" if kind_disp else ""}</p>
{svg}
</div></body></html>
"""
    _atomic_write(reports / "topology.html", html)


def embed_topology_fragment(topo: dict[str, Any]) -> str:
    from .labels import format_kind

    svg = topology_svg(topo)
    where = _esc(topo.get("where") or "n/a")
    conf = _esc(topo.get("confidence") or "n/a")
    kind = topo.get("incident_kind")
    kind_disp = _esc(topo.get("incident_kind_display") or (format_kind(kind) if kind else ""))
    return (
        f'<div class="topo-embed">'
        f'<p><strong>Where:</strong> {where}<br/><strong>Confidence:</strong> {conf}'
        f'{(" · <strong>" + kind_disp + "</strong>") if kind_disp else ""}'
        f' · <a href="topology.html">Full map</a></p>'
        f"{svg}"
        f'<p class="muted">{_esc(topo.get("caption", ""))}</p>'
        f"</div>"
    )


def infer_shared_upstream(cfg: Config, lost: set[str]) -> str | None:
    """If multiple branch groups fail together while gateway ok, suggest shared upstream."""
    if not lost:
        return None
    roles = cfg.roles()
    if lost & roles.get("gateway", set()):
        return None
    failed_branches = []
    for g in cfg.groups:
        if g.role != "branch":
            continue
        if set(g.hosts) and set(g.hosts) <= lost:
            failed_branches.append(g.id)
    if len(failed_branches) >= 2:
        return f"Possible shared upstream of: {', '.join(failed_branches)}"
    return None
