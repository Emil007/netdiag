from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Store:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start TEXT NOT NULL,
                    end TEXT,
                    kind TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    hosts_json TEXT NOT NULL,
                    meta_json TEXT NOT NULL DEFAULT '{}',
                    pcap TEXT NOT NULL DEFAULT '',
                    vantage_summary TEXT NOT NULL DEFAULT '',
                    where_text TEXT NOT NULL DEFAULT '',
                    identity_key TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS satellite_samples (
                    vantage_id TEXT NOT NULL PRIMARY KEY,
                    link TEXT NOT NULL,
                    availability TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT 'never_seen',
                    last_seen TEXT,
                    last_event TEXT NOT NULL DEFAULT '',
                    received_at TEXT,
                    payload_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS satellite_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vantage_id TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    event TEXT NOT NULL DEFAULT 'sample',
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            # migrate older DBs
            cols = {r[1] for r in c.execute("PRAGMA table_info(incidents)").fetchall()}
            if "where_text" not in cols:
                c.execute("ALTER TABLE incidents ADD COLUMN where_text TEXT NOT NULL DEFAULT ''")
            if "identity_key" not in cols:
                c.execute("ALTER TABLE incidents ADD COLUMN identity_key TEXT NOT NULL DEFAULT ''")

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def set_kv(self, key: str, value: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_kv(self, key: str, default: str = "") -> str:
        with self._conn() as c:
            row = c.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def open_incident(
        self,
        kind: str,
        verdict: str,
        hosts: dict[str, int],
        meta: dict[str, Any] | None = None,
        pcap: str = "",
        vantage_summary: str = "",
        where_text: str = "",
        identity_key: str = "",
        start: str | None = None,
    ) -> int:
        start = start or utcnow_iso()
        with self._conn() as c:
            cur = c.execute(
                """INSERT INTO incidents(start,end,kind,verdict,hosts_json,meta_json,pcap,
                   vantage_summary,where_text,identity_key)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    start,
                    None,
                    kind,
                    verdict,
                    json.dumps(hosts),
                    json.dumps(meta or {}),
                    pcap,
                    vantage_summary,
                    where_text,
                    identity_key,
                ),
            )
            return int(cur.lastrowid)

    def find_open_by_identity(self, kind: str, identity_key: str) -> int | None:
        with self._conn() as c:
            row = c.execute(
                """SELECT id FROM incidents WHERE end IS NULL AND kind=? AND identity_key=?
                   ORDER BY id DESC LIMIT 1""",
                (kind, identity_key),
            ).fetchone()
            return int(row["id"]) if row else None

    def recently_closed(self, kind: str, identity_key: str, within_s: float) -> bool:
        with self._conn() as c:
            row = c.execute(
                """SELECT end FROM incidents WHERE end IS NOT NULL AND kind=? AND identity_key=?
                   ORDER BY id DESC LIMIT 1""",
                (kind, identity_key),
            ).fetchone()
        if not row or not row["end"]:
            return False
        try:
            end = datetime.strptime(row["end"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - end).total_seconds() < within_s
        except Exception:
            return False

    def update_incident(
        self,
        incident_id: int,
        *,
        kind: str | None = None,
        verdict: str | None = None,
        hosts: dict[str, int] | None = None,
        meta: dict[str, Any] | None = None,
        pcap: str | None = None,
        vantage_summary: str | None = None,
        where_text: str | None = None,
        end: str | None = None,
    ) -> None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not row:
                return
            data = dict(row)
            if kind is not None:
                data["kind"] = kind
            if verdict is not None:
                data["verdict"] = verdict
            if hosts is not None:
                data["hosts_json"] = json.dumps(hosts)
            if meta is not None:
                data["meta_json"] = json.dumps(meta)
            if pcap is not None:
                data["pcap"] = pcap
            if vantage_summary is not None:
                data["vantage_summary"] = vantage_summary
            if where_text is not None:
                data["where_text"] = where_text
            if end is not None:
                data["end"] = end
            c.execute(
                """UPDATE incidents SET start=?, end=?, kind=?, verdict=?, hosts_json=?,
                   meta_json=?, pcap=?, vantage_summary=?, where_text=?, identity_key=? WHERE id=?""",
                (
                    data["start"],
                    data["end"],
                    data["kind"],
                    data["verdict"],
                    data["hosts_json"],
                    data["meta_json"],
                    data["pcap"],
                    data["vantage_summary"],
                    data.get("where_text", ""),
                    data.get("identity_key", ""),
                    incident_id,
                ),
            )

    def close_incident(self, incident_id: int, end: str | None = None) -> None:
        self.update_incident(incident_id, end=end or utcnow_iso())

    def list_incidents(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["hosts"] = json.loads(d.pop("hosts_json") or "{}")
            d["meta"] = json.loads(d.pop("meta_json") or "{}")
            out.append(d)
        return out

    def ensure_satellite_row(self, vantage_id: str, link: str, availability: str = "") -> None:
        with self._conn() as c:
            row = c.execute(
                "SELECT vantage_id FROM satellite_samples WHERE vantage_id=?", (vantage_id,)
            ).fetchone()
            if row:
                return
            c.execute(
                """INSERT INTO satellite_samples(vantage_id, link, availability, state, last_seen,
                   last_event, received_at, payload_json)
                   VALUES(?,?,?,'never_seen',NULL,'',NULL,'{}')""",
                (vantage_id, link, availability),
            )

    def upsert_satellite(
        self,
        vantage_id: str,
        link: str,
        payload: dict[str, Any],
        *,
        state: str | None = None,
        availability: str = "",
        event: str = "sample",
    ) -> None:
        now = utcnow_iso()
        with self._conn() as c:
            c.execute(
                """INSERT INTO satellite_samples(vantage_id, link, availability, state, last_seen,
                   last_event, received_at, payload_json)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(vantage_id) DO UPDATE SET
                     link=excluded.link,
                     availability=COALESCE(NULLIF(excluded.availability,''), satellite_samples.availability),
                     state=COALESCE(excluded.state, satellite_samples.state),
                     last_seen=excluded.last_seen,
                     last_event=excluded.last_event,
                     received_at=excluded.received_at,
                     payload_json=excluded.payload_json""",
                (
                    vantage_id,
                    link,
                    availability,
                    state or "online",
                    now,
                    event,
                    now,
                    json.dumps(payload),
                ),
            )
            c.execute(
                """INSERT INTO satellite_history(vantage_id, ts, event, payload_json)
                   VALUES(?,?,?,?)""",
                (vantage_id, now, event, json.dumps(payload)),
            )
            # keep last ~200 history rows per vantage
            c.execute(
                """DELETE FROM satellite_history WHERE id NOT IN (
                     SELECT id FROM satellite_history WHERE vantage_id=? ORDER BY id DESC LIMIT 200
                   ) AND vantage_id=?""",
                (vantage_id, vantage_id),
            )

    def set_satellite_state(self, vantage_id: str, state: str, event: str = "") -> None:
        with self._conn() as c:
            c.execute(
                """UPDATE satellite_samples SET state=?, last_event=COALESCE(NULLIF(?,''), last_event)
                   WHERE vantage_id=?""",
                (state, event, vantage_id),
            )

    def list_satellites(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM satellite_samples").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d.pop("payload_json") or "{}")
            out.append(d)
        return out

    def satellite_history(self, vantage_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                """SELECT * FROM satellite_history WHERE vantage_id=? ORDER BY id DESC LIMIT ?""",
                (vantage_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]
