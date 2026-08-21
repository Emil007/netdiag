from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def display_ts(iso_or_dt: str | datetime | None, tz_name: str) -> str:
    if iso_or_dt is None:
        return ""
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc
    if isinstance(iso_or_dt, datetime):
        dt = iso_or_dt
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    else:
        text = str(iso_or_dt).replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except Exception:
            return str(iso_or_dt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %Z")
