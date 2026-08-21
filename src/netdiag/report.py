from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template

from .config import Config, data_dir
from .timeutil import display_ts


AGG_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>netdiag — {{ site_name }}</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 1000px; color: #122; background: #f7f8fa; }
  h1 { font-size: 1.6rem; margin-bottom: 0.2rem; }
  .meta { color: #456; margin-bottom: 1.5rem; }
  .card { background: #fff; border: 1px solid #dde; border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.35rem 0.45rem; border-bottom: 1px solid #eee; }
  th { color: #456; font-weight: 600; }
  .kind { font-weight: 700; }
  .warn { color: #a30; }
  .muted { color: #789; }
  a { color: #06c; }
  pre { white-space: pre-wrap; font-size: 0.85rem; }
  .topo-embed svg { display: block; margin-top: 0.5rem; }
</style>
</head>
<body>
  <h1>netdiag report — {{ site_name }}</h1>
  <p class="meta">Generated {{ generated }} · Running since {{ started }} · Vantage <strong>{{ vantage_id }}</strong> ({{ vantage_link }})
     · <a href="topology.html">Topology map</a></p>

  <div class="card">
    <h2>Summary</h2>
    <p>{{ summary_text }}</p>
    <table>
      <tr><th>Class</th><th>Weighted score</th></tr>
      {% for kind, n in by_kind %}
      <tr><td class="kind">{{ kind }}</td><td>{{ '%.0f'|format(n) }}</td></tr>
      {% else %}
      <tr><td colspan="2">No incidents yet.</td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Topology (fault path)</h2>
    {{ topology_html | safe }}
  </div>

  <div class="card">
    <h2>Vantage × group</h2>
    <table>
      <tr>
        <th>Vantage</th><th>Link</th><th>State</th>
        {% for gid in group_ids %}<th>{{ gid }}</th>{% endfor %}
      </tr>
      {% for row in matrix %}
      <tr>
        <td>{{ row.vantage_id }}</td>
        <td>{{ row.link }}</td>
        <td class="{{ 'warn' if row.state == 'stale' else ('muted' if row.state in ['never_seen','offline'] else '') }}">{{ row.state }}</td>
        {% for gid in group_ids %}
        <td>{{ row.groups.get(gid, '—') }}</td>
        {% endfor %}
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Canary loss</h2>
    <table>
      <tr><th>Host</th><th>Group</th><th>Rounds</th><th>Bad</th><th>Loss %</th><th>RTT avg</th><th>RTT max</th></tr>
      {% for row in host_stats %}
      <tr>
        <td>{{ row.host }}</td>
        <td>{{ row.group }}</td>
        <td>{{ row.rounds }}</td>
        <td>{{ row.bad }}</td>
        <td class="{{ 'warn' if row.loss_pct > 1 else '' }}">{{ '%.2f'|format(row.loss_pct) }}</td>
        <td>{% if row.rtt_avg is not none %}{{ '%.1f'|format(row.rtt_avg) }}{% else %}—{% endif %}</td>
        <td>{% if row.rtt_max %}{{ '%.1f'|format(row.rtt_max) }}{% else %}—{% endif %}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Satellites</h2>
    <table>
      <tr><th>ID</th><th>Link</th><th>Availability</th><th>Last seen</th><th>State</th></tr>
      {% for s in satellites %}
      <tr>
        <td>{{ s.id }}</td>
        <td>{{ s.link }}</td>
        <td>{{ s.availability }}</td>
        <td>{{ s.last_seen }}</td>
        <td class="{{ 'warn' if s.warn else ('muted' if s.status in ['never_seen','offline'] else '') }}">{{ s.status }}</td>
      </tr>
      {% else %}
      <tr><td colspan="5">None configured (single-probe mode).</td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>L2 bridges observed</h2>
    <p class="meta">Passive STP/LLDP hints on this segment. Many cheap unmanaged switches send nothing — absence does not mean no switch.</p>
    <ul>
      {% for b in l2_bridges %}
      <li><strong>{{ b.kind }}</strong> {{ b.detail }}{% if b.extra %} — {{ b.extra }}{% endif %}</li>
      {% else %}
      <li>none</li>
      {% endfor %}
    </ul>
  </div>

  <div class="card">
    <h2>Incidents</h2>
    <table>
      <tr><th>When</th><th>Class</th><th>Duration</th><th>Where / detail</th></tr>
      {% for inc in incidents %}
      <tr>
        <td>{{ inc.start_disp }}</td>
        <td class="kind">{{ inc.kind }}</td>
        <td>{{ inc.duration }}</td>
        <td><a href="incidents/{{ inc.file }}">#{{ inc.id }}</a> — {{ inc.where_short or inc.verdict_short }}</td>
      </tr>
      {% else %}
      <tr><td colspan="4">None yet.</td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Probe NIC / health</h2>
    <pre>{{ iface_text }}</pre>
  </div>
</body>
</html>
"""

INC_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Incident {{ id }} — {{ kind }}</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 900px; color: #122; background: #f7f8fa; }
  .card { background: #fff; border: 1px solid #dde; border-radius: 8px; padding: 1rem 1.2rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.35rem 0.45rem; border-bottom: 1px solid #eee; }
  a { color: #06c; }
  pre { white-space: pre-wrap; }
  .topo-embed svg { display: block; margin-top: 0.5rem; }
</style>
</head>
<body>
  <p><a href="../report.html">&larr; Aggregate report</a> · <a href="../topology.html">Topology</a></p>
  <div class="card">
    <h1>{{ kind }}</h1>
    <p><strong>Start:</strong> {{ start }}<br/>
       <strong>End:</strong> {{ end or 'ongoing' }}<br/>
       <strong>Duration:</strong> {{ duration }}<br/>
       <strong>Confidence:</strong> {{ confidence }}</p>
    <h2>Where</h2>
    <p>{{ where_text or 'n/a' }}</p>
    <h2>Fault path on map</h2>
    {{ topology_html | safe }}
    <h2>Verdict</h2>
    <p>{{ verdict }}</p>
    <h2>Vantage × group</h2>
    <table>
      <tr><th>Vantage</th><th>Link</th><th>State</th>{% for gid in group_ids %}<th>{{ gid }}</th>{% endfor %}</tr>
      {% for row in matrix %}
      <tr>
        <td>{{ row.vantage_id }}</td><td>{{ row.link }}</td><td>{{ row.state }}</td>
        {% for gid in group_ids %}<td>{{ row.groups.get(gid, '—') }}</td>{% endfor %}
      </tr>
      {% else %}
      <tr><td colspan="3">n/a</td></tr>
      {% endfor %}
    </table>
    <h2>Affected hosts</h2>
    <pre>{{ hosts_text }}</pre>
    <h2>Vantages</h2>
    <pre>{{ vantage_summary or 'n/a' }}</pre>
    <h2>Linked capture</h2>
    <p>{{ pcap or '(none)' }}</p>
    <h2>Extra</h2>
    <pre>{{ meta_text }}</pre>
  </div>
</body>
</html>
"""


def matching_pcap(
    caps: Path,
    when: datetime | None = None,
    timezone_name: str = "UTC",
) -> str:
    if when is None:
        when = datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    try:
        from zoneinfo import ZoneInfo

        local_tz = ZoneInfo(timezone_name)
    except Exception:
        local_tz = timezone.utc
    best = None
    try:
        for f in caps.iterdir():
            m = re.match(r"bcast-(\d{8})-(\d{4})", f.name)
            if not m:
                continue
            # Filename is written in container TZ
            naive = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M")
            t_local = naive.replace(tzinfo=local_tz)
            t_utc = t_local.astimezone(timezone.utc)
            if t_utc <= when.astimezone(timezone.utc) and (best is None or t_utc > best[0]):
                best = (t_utc, f.name)
    except Exception:
        pass
    return best[1] if best else ""


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def write_incident_html(
    inc: dict[str, Any],
    out_dir: Path,
    cfg: Config,
    topology_html: str = "",
) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    start = inc.get("start") or ""
    safe = re.sub(r"[^0-9A-Za-z_-]+", "", start.replace(":", "").replace("T", "-"))
    fname = f"{safe}-{inc.get('id')}.html"
    hosts = inc.get("hosts") or {}
    hosts_text = "\n".join(
        f"{h}: {n} bad rounds" for h, n in sorted(hosts.items(), key=lambda x: -x[1])
    )
    meta = dict(inc.get("meta") or {})
    matrix = meta.get("matrix") or []
    group_ids = [g.id for g in cfg.groups]
    if not topology_html:
        from .topology import build_topology, embed_topology_fragment

        topo = build_topology(
            cfg,
            matrix=matrix,
            incident={
                "kind": inc.get("kind"),
                "where_text": inc.get("where_text") or "",
                "hosts": hosts,
                "meta": meta,
                "confidence": meta.get("confidence"),
                "verdict": inc.get("verdict"),
            },
            l2_bridges=meta.get("l2_bridges") or [],
            link_fault=bool(meta.get("link_fault")),
            shared_upstream_hint=meta.get("shared_upstream_hint"),
            census=meta.get("census"),
        )
        # Fix relative link for incident pages
        topology_html = embed_topology_fragment(topo).replace(
            'href="topology.html"', 'href="../topology.html"'
        )
    html = Template(INC_TEMPLATE).render(
        id=inc.get("id"),
        kind=inc.get("kind"),
        start=display_ts(start, cfg.timezone),
        end=display_ts(inc.get("end"), cfg.timezone) if inc.get("end") else None,
        duration=_duration(inc),
        verdict=inc.get("verdict"),
        where_text=inc.get("where_text") or meta.get("where_text") or "",
        confidence=meta.get("confidence", "single_vantage"),
        hosts_text=hosts_text or "(none)",
        vantage_summary=inc.get("vantage_summary"),
        pcap=inc.get("pcap"),
        meta_text=json.dumps(meta, indent=2, default=str),
        matrix=matrix,
        group_ids=group_ids,
        topology_html=topology_html,
    )
    _atomic_write(out_dir / fname, html)
    return fname


def write_reports(
    cfg: Config,
    *,
    started: str,
    host_stats: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    satellites: list[dict[str, Any]],
    iface_text: str,
    summary_text: str,
    by_kind_weighted: list[tuple[str, float]] | None = None,
    matrix: list[dict[str, Any]] | None = None,
    l2_bridges: list[dict[str, Any]] | None = None,
    topology: dict[str, Any] | None = None,
) -> None:
    root = data_dir()
    reports = root / "reports"
    incidents_dir = reports / "incidents"
    reports.mkdir(parents=True, exist_ok=True)

    from .topology import embed_topology_fragment, write_topology_files

    if topology is None:
        from .topology import build_topology

        open_inc = next((i for i in incidents if not i.get("end")), None)
        topology = build_topology(
            cfg,
            matrix=matrix,
            incident=open_inc,
            l2_bridges=l2_bridges,
        )
    write_topology_files(topology)
    topo_frag = embed_topology_fragment(topology)

    by_kind = by_kind_weighted or []
    inc_rows = []
    for inc in incidents:
        # Per-incident map with that incident's blame frozen
        from .topology import build_topology

        meta = dict(inc.get("meta") or {})
        inc_topo = build_topology(
            cfg,
            matrix=meta.get("matrix") or matrix or [],
            incident=inc,
            l2_bridges=meta.get("l2_bridges") or l2_bridges or [],
            link_fault=bool(meta.get("link_fault")),
            shared_upstream_hint=meta.get("shared_upstream_hint"),
            census=meta.get("census") or (topology or {}).get("census"),
        )
        fname = write_incident_html(
            inc,
            incidents_dir,
            cfg,
            topology_html=embed_topology_fragment(inc_topo).replace(
                'href="topology.html"', 'href="../topology.html"'
            ),
        )
        verdict = inc.get("verdict") or ""
        where = inc.get("where_text") or ""
        inc_rows.append(
            {
                "id": inc.get("id"),
                "start": inc.get("start"),
                "start_disp": display_ts(inc.get("start"), cfg.timezone),
                "kind": inc.get("kind"),
                "duration": _duration(inc),
                "file": fname,
                "verdict_short": (verdict[:120] + "…") if len(verdict) > 120 else verdict,
                "where_short": (where[:140] + "…") if len(where) > 140 else where,
            }
        )

    generated = display_ts(
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), cfg.timezone
    )
    group_ids = [g.id for g in cfg.groups]
    html = Template(AGG_TEMPLATE).render(
        site_name=cfg.site_name,
        generated=generated,
        started=started,
        vantage_id=cfg.vantage.id,
        vantage_link=cfg.vantage.link,
        summary_text=summary_text,
        by_kind=by_kind,
        host_stats=host_stats,
        satellites=satellites,
        incidents=inc_rows,
        iface_text=iface_text,
        matrix=matrix or [],
        group_ids=group_ids,
        l2_bridges=l2_bridges or [],
        topology_html=topo_frag,
    )
    _atomic_write(reports / "report.html", html)
    payload = {
        "site": cfg.site_name,
        "generated": generated,
        "started": started,
        "vantage": {"id": cfg.vantage.id, "link": cfg.vantage.link},
        "summary": summary_text,
        "by_kind_weighted": dict(by_kind),
        "host_stats": host_stats,
        "satellites": satellites,
        "incidents": incidents,
        "matrix": matrix,
        "l2_bridges": l2_bridges or [],
        "topology": topology,
    }
    _atomic_write(reports / "report.json", json.dumps(payload, indent=2, default=str))


def append_event(text: str) -> None:
    path = data_dir() / "logs" / "EVENTS.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def write_status(text: str) -> None:
    path = data_dir() / "logs" / "STATUS.txt"
    _atomic_write(path, text)


def rotate_events_log(logs: Path, max_bytes: int = 5_000_000) -> None:
    path = logs / "EVENTS.log"
    if not path.exists() or path.stat().st_size < max_bytes:
        return
    rotated = logs / "EVENTS.log.1"
    if rotated.exists():
        rotated.unlink()
    path.rename(rotated)


def _duration(inc: dict[str, Any]) -> str:
    start = inc.get("start")
    end = inc.get("end")
    if not start:
        return "?"
    try:
        s = datetime.strptime(start.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
        e = (
            datetime.strptime(end.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
            if end
            else datetime.utcnow()
        )
        secs = int((e - s).total_seconds())
        if secs < 60:
            return f"{secs}s"
        return f"{secs // 60}m {secs % 60}s"
    except Exception:
        return "?"
