from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

from .config import Config, data_dir


AGG_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>netdiag — {{ site_name }}</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 960px; color: #122; background: #f7f8fa; }
  h1 { font-size: 1.6rem; margin-bottom: 0.2rem; }
  .meta { color: #456; margin-bottom: 1.5rem; }
  .card { background: #fff; border: 1px solid #dde; border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
  th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid #eee; }
  th { color: #456; font-weight: 600; }
  .kind { font-weight: 700; }
  .warn { color: #a30; }
  a { color: #06c; }
</style>
</head>
<body>
  <h1>netdiag report — {{ site_name }}</h1>
  <p class="meta">Generated {{ generated }} · Running since {{ started }} · Vantage <strong>{{ vantage_id }}</strong> ({{ vantage_link }})</p>

  <div class="card">
    <h2>Summary</h2>
    <p>{{ summary_text }}</p>
    <table>
      <tr><th>Class</th><th>Count</th></tr>
      {% for kind, n in by_kind %}
      <tr><td class="kind">{{ kind }}</td><td>{{ n }}</td></tr>
      {% else %}
      <tr><td colspan="2">No incidents yet.</td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Canary loss (this vantage)</h2>
    <table>
      <tr><th>Host</th><th>Group</th><th>Rounds</th><th>Bad</th><th>Loss %</th></tr>
      {% for row in host_stats %}
      <tr>
        <td>{{ row.host }}</td>
        <td>{{ row.group }}</td>
        <td>{{ row.rounds }}</td>
        <td>{{ row.bad }}</td>
        <td class="{{ 'warn' if row.loss_pct > 1 else '' }}">{{ '%.2f'|format(row.loss_pct) }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Satellites</h2>
    <table>
      <tr><th>ID</th><th>Link</th><th>Last seen</th><th>Status</th></tr>
      {% for s in satellites %}
      <tr>
        <td>{{ s.id }}</td>
        <td>{{ s.link }}</td>
        <td>{{ s.last_seen }}</td>
        <td class="{{ 'warn' if s.status != 'ok' else '' }}">{{ s.status }}</td>
      </tr>
      {% else %}
      <tr><td colspan="4">No satellites reporting (single-probe mode is fine).</td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Incidents</h2>
    <table>
      <tr><th>When</th><th>Class</th><th>Duration</th><th>Detail</th></tr>
      {% for inc in incidents %}
      <tr>
        <td>{{ inc.start }}</td>
        <td class="kind">{{ inc.kind }}</td>
        <td>{{ inc.duration }}</td>
        <td><a href="incidents/{{ inc.file }}">{{ inc.kind }} #{{ inc.id }}</a> — {{ inc.verdict_short }}</td>
      </tr>
      {% else %}
      <tr><td colspan="4">None yet.</td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Probe NIC</h2>
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
  body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 800px; color: #122; background: #f7f8fa; }
  .card { background: #fff; border: 1px solid #dde; border-radius: 8px; padding: 1rem 1.2rem; }
  a { color: #06c; }
  pre { white-space: pre-wrap; }
</style>
</head>
<body>
  <p><a href="../report.html">&larr; Aggregate report</a></p>
  <div class="card">
    <h1>{{ kind }}</h1>
    <p><strong>Start:</strong> {{ start }}<br/>
       <strong>End:</strong> {{ end or 'ongoing' }}<br/>
       <strong>Duration:</strong> {{ duration }}</p>
    <h2>Verdict</h2>
    <p>{{ verdict }}</p>
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


def matching_pcap(caps: Path, ts: datetime) -> str:
    best = None
    try:
        for f in caps.iterdir():
            m = re.match(r"bcast-(\d{8})-(\d{4})", f.name)
            if not m:
                continue
            t = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M")
            if t <= ts and (best is None or t > best[0]):
                best = (t, f.name)
    except Exception:
        pass
    return best[1] if best else ""


def write_incident_html(inc: dict[str, Any], out_dir: Path) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    start = inc.get("start") or ""
    safe = re.sub(r"[^0-9A-Za-z_-]+", "", start.replace(":", "").replace("T", "-"))
    fname = f"{safe}-{inc.get('id')}.html"
    hosts = inc.get("hosts") or {}
    hosts_text = "\n".join(f"{h}: {n} bad rounds" for h, n in sorted(hosts.items(), key=lambda x: -x[1]))
    meta = inc.get("meta") or {}
    html = Template(INC_TEMPLATE).render(
        id=inc.get("id"),
        kind=inc.get("kind"),
        start=start,
        end=inc.get("end"),
        duration=_duration(inc),
        verdict=inc.get("verdict"),
        hosts_text=hosts_text or "(none)",
        vantage_summary=inc.get("vantage_summary"),
        pcap=inc.get("pcap"),
        meta_text=json.dumps(meta, indent=2),
    )
    (out_dir / fname).write_text(html, encoding="utf-8")
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
) -> None:
    root = data_dir()
    reports = root / "reports"
    incidents_dir = reports / "incidents"
    reports.mkdir(parents=True, exist_ok=True)

    by_kind_map: dict[str, int] = {}
    inc_rows = []
    for inc in incidents:
        by_kind_map[inc["kind"]] = by_kind_map.get(inc["kind"], 0) + 1
        fname = write_incident_html(inc, incidents_dir)
        verdict = inc.get("verdict") or ""
        inc_rows.append(
            {
                "id": inc.get("id"),
                "start": inc.get("start"),
                "kind": inc.get("kind"),
                "duration": _duration(inc),
                "file": fname,
                "verdict_short": (verdict[:120] + "…") if len(verdict) > 120 else verdict,
            }
        )

    by_kind = sorted(by_kind_map.items(), key=lambda x: -x[1])
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
    )
    (reports / "report.html").write_text(html, encoding="utf-8")

    payload = {
        "site": cfg.site_name,
        "generated": generated,
        "started": started,
        "vantage": {"id": cfg.vantage.id, "link": cfg.vantage.link},
        "summary": summary_text,
        "by_kind": dict(by_kind),
        "host_stats": host_stats,
        "satellites": satellites,
        "incidents": incidents,
    }
    (reports / "report.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def append_event(text: str) -> None:
    path = data_dir() / "logs" / "EVENTS.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def write_status(text: str) -> None:
    path = data_dir() / "logs" / "STATUS.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _duration(inc: dict[str, Any]) -> str:
    start = inc.get("start")
    end = inc.get("end")
    if not start:
        return "?"
    try:
        s = datetime.strptime(start.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
        e = datetime.strptime(end.replace("Z", ""), "%Y-%m-%dT%H:%M:%S") if end else datetime.utcnow()
        secs = int((e - s).total_seconds())
        if secs < 60:
            return f"{secs}s"
        return f"{secs // 60}m {secs % 60}s"
    except Exception:
        return "?"
