from __future__ import annotations

from pathlib import Path

from .config import Config, data_dir
from .report import _atomic_write


def write_waiting_stubs(cfg: Config) -> None:
    """Placeholder report/topology/STATUS until the first real report tick."""
    root = data_dir()
    reports = root / "reports"
    logs = root / "logs"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "incidents").mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    n = int(cfg.report_interval_s)
    msg = (
        f"Waiting for first data… Warming up — first real report in about {n} seconds "
        f"(probe {cfg.vantage.id} on {cfg.iface})."
    )
    stub_html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta http-equiv="refresh" content="10"/>
<title>netdiag — waiting</title>
<style>
 body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #122; background: #f7f8fa; }}
 .card {{ background: #fff; border: 1px solid #dde; border-radius: 8px; padding: 1.2rem; max-width: 36rem; }}
 .muted {{ color: #567; }}
</style></head><body>
<div class="card">
<h1>netdiag</h1>
<p><strong>Waiting for first data…</strong></p>
<p class="muted">{msg}</p>
<p class="muted">This page refreshes automatically. Live status: <a href="/">/</a></p>
</div></body></html>
"""
    _atomic_write(reports / "report.html", stub_html)
    _atomic_write(reports / "topology.html", stub_html.replace("<h1>netdiag</h1>", "<h1>netdiag topology</h1>"))
    _atomic_write(
        reports / "topology.json",
        '{\n  "ready": false,\n  "caption": "Waiting for first data…"\n}\n',
    )
    _atomic_write(
        logs / "STATUS.txt",
        "NETDIAG STATUS\n"
        f"generated: Waiting for first data…\n"
        f"vantage: {cfg.vantage.id} ({cfg.vantage.link})\n"
        f"iface: {cfg.iface}\n"
        f"note: {msg}\n",
    )


def seed_status_hub(hub, cfg: Config) -> None:
    """Initial StatusHub values so GET / does not look broken."""
    token = (cfg.ingest_token or "").strip()
    locked = (not token or token == "change-me") and not cfg.allow_insecure_ingest
    hub.update(
        {
            "ready": False,
            "site": cfg.site_name,
            "generated": "Waiting for first data…",
            "vantage_id": cfg.vantage.id,
            "vantage_link": cfg.vantage.link,
            "open_incident": None,
            "census_text": "Waiting for first data…",
            "census": {},
            "satellites": [],
            "health_notes": [],
            "ingest_locked": locked,
            "waiting_message": (
                f"Warming up — first measurements in about {int(cfg.report_interval_s)} seconds."
            ),
        }
    )
