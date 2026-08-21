from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Incident:
    id: int | None
    start: str
    end: str | None
    kind: str
    verdict: str
    hosts_json: str
    meta_json: str
    pcap: str
    vantage_summary: str


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
                    vantage_summary TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS satellite_samples (
                    vantage_id TEXT NOT NULL,
                    link TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (vantage_id)
                );
                CREATE TABLE IF NOT EXISTS kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

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
        start: str | None = None,
    ) -> int:
        start = start or _utcnow()
        with self._conn() as c:
            cur = c.execute(
                """INSERT INTO incidents(start,end,kind,verdict,hosts_json,meta_json,pcap,vantage_summary)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (
                    start,
                    None,
                    kind,
                    verdict,
                    json.dumps(hosts),
                    json.dumps(meta or {}),
                    pcap,
                    vantage_summary,
                ),
            )
            return int(cur.lastrowid)

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
            if end is not None:
                data["end"] = end
            c.execute(
                """UPDATE incidents SET start=?, end=?, kind=?, verdict=?, hosts_json=?,
                   meta_json=?, pcap=?, vantage_summary=? WHERE id=?""",
                (
                    data["start"],
                    data["end"],
                    data["kind"],
                    data["verdict"],
                    data["hosts_json"],
                    data["meta_json"],
                    data["pcap"],
                    data["vantage_summary"],
                    incident_id,
                ),
            )

    def close_incident(self, incident_id: int, end: str | None = None) -> None:
        self.update_incident(incident_id, end=end or _utcnow())

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

    def upsert_satellite(self, vantage_id: str, link: str, payload: dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute(
                """INSERT INTO satellite_samples(vantage_id, link, received_at, payload_json)
                   VALUES(?,?,?,?)
                   ON CONFLICT(vantage_id) DO UPDATE SET
                     link=excluded.link,
                     received_at=excluded.received_at,
                     payload_json=excluded.payload_json""",
                (vantage_id, link, _utcnow(), json.dumps(payload)),
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
