from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path


def reap_old_captures(caps: Path, keep_hours: float) -> int:
    """Delete bcast-*.pcap older than keep_hours."""
    if keep_hours <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=keep_hours)
    removed = 0
    if not caps.is_dir():
        return 0
    for f in caps.glob("bcast-*.pcap"):
        try:
            mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                f.unlink(missing_ok=True)
                removed += 1
        except OSError:
            continue
    return removed


def reap_old_csvs(logs: Path, keep_days: float = 14.0) -> int:
    """Delete ping-YYYY-MM-DD.csv and iface-YYYY-MM-DD.csv older than keep_days."""
    if keep_days <= 0 or not logs.is_dir():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    removed = 0
    pat = re.compile(r"^(ping|iface)-(\d{4}-\d{2}-\d{2})\.csv$")
    for f in logs.iterdir():
        if not f.is_file():
            continue
        m = pat.match(f.name)
        if not m:
            continue
        try:
            day = datetime.strptime(m.group(2), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if day < cutoff:
                f.unlink(missing_ok=True)
                removed += 1
        except (OSError, ValueError):
            continue
    return removed


def reap_old_incident_html(
    incidents_dir: Path,
    *,
    keep_days: float = 30.0,
    keep_names: set[str] | None = None,
) -> int:
    """Delete incident HTML older than keep_days, unless listed in keep_names (e.g. last 200)."""
    if keep_days <= 0 or not incidents_dir.is_dir():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    keep_names = keep_names or set()
    removed = 0
    for f in incidents_dir.glob("*.html"):
        if f.name in keep_names:
            continue
        try:
            mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                f.unlink(missing_ok=True)
                removed += 1
        except OSError:
            continue
    return removed
