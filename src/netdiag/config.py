from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Group:
    id: str
    role: str
    hosts: list[str]


@dataclass
class Vantage:
    id: str
    link: str  # ethernet | wifi
    note: str = ""


@dataclass
class SatelliteExpect:
    id: str
    link: str


@dataclass
class Config:
    site_name: str
    timezone: str
    vantage: Vantage
    iface: str
    snaplen: int
    rotate_hours: int
    keep_hours: int
    groups: list[Group]
    expected_dhcp_mac: str
    dns_resolvers: list[str]
    dns_names: list[str]
    ping_interval_s: float
    incident_clear_s: float
    dns_interval_s: float
    dns_timeout_ms: int
    path_interval_s: float
    bcast_pps_warn: float
    satellite_stale_s: float
    report_interval_s: float
    ingest_enabled: bool
    ingest_host: str
    ingest_port: int
    ingest_token: str
    satellites: list[SatelliteExpect]
    coordinator_url: str
    coordinator_token: str
    raw: dict[str, Any] = field(default_factory=dict)

    def hosts(self) -> list[str]:
        seen: list[str] = []
        for g in self.groups:
            for h in g.hosts:
                if h not in seen:
                    seen.append(h)
        return seen

    def group_for_host(self, host: str) -> Group | None:
        for g in self.groups:
            if host in g.hosts:
                return g
        return None

    def hosts_by_role(self, role: str) -> set[str]:
        out: set[str] = set()
        for g in self.groups:
            if g.role == role:
                out.update(g.hosts)
        return out

    def roles(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for g in self.groups:
            out.setdefault(g.role, set()).update(g.hosts)
        return out


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    return val


def _env_bool(name: str, default: bool) -> bool:
    val = _env(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    val = _env(name)
    if val is None:
        return default
    return int(val)


def _env_float(name: str, default: float) -> float:
    val = _env(name)
    if val is None:
        return default
    return float(val)


def _parse_list(val: str | list | None) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x) for x in val]
    text = str(val).strip()
    if not text:
        return []
    if text.startswith("["):
        data = json.loads(text)
        return [str(x) for x in data]
    return [p.strip() for p in text.replace(";", ",").split(",") if p.strip()]


def _parse_groups(val: str | list | None) -> list[Group] | None:
    if val is None or val == "":
        return None
    if isinstance(val, list):
        data = val
    else:
        text = str(val).strip()
        data = json.loads(text) if text.startswith("[") else yaml.safe_load(text)
    if not data:
        return []
    out: list[Group] = []
    for g in data:
        hosts = g.get("hosts") or []
        if isinstance(hosts, str):
            hosts = _parse_list(hosts)
        out.append(
            Group(
                id=str(g.get("id", "unnamed")),
                role=str(g.get("role", "other")).lower(),
                hosts=[str(h) for h in hosts],
            )
        )
    return out


def _parse_satellites(val: str | list | None) -> list[SatelliteExpect] | None:
    if val is None or val == "":
        return None
    if isinstance(val, list):
        data = val
    else:
        text = str(val).strip()
        data = json.loads(text) if text.startswith("[") else yaml.safe_load(text)
    if not data:
        return []
    return [
        SatelliteExpect(id=str(s.get("id")), link=str(s.get("link", "ethernet")).lower())
        for s in data
        if s.get("id")
    ]


def _default_raw() -> dict[str, Any]:
    return {
        "site": {"name": "Home LAN", "timezone": "Europe/Berlin"},
        "vantage": {"id": "coordinator", "link": "ethernet", "note": ""},
        "capture": {"iface": "eth0", "snaplen": 128, "rotate_hours": 1, "keep_hours": 48},
        "groups": [
            {"id": "router", "role": "gateway", "hosts": ["192.168.1.1"]},
            {"id": "internet", "role": "external", "hosts": ["1.1.1.1", "8.8.8.8"]},
        ],
        "dhcp": {"expected_server_mac": ""},
        "dns": {
            "resolvers": ["192.168.1.1"],
            "names": ["example.com", "cloudflare.com", "google.com"],
        },
        "thresholds": {},
        "ingest": {"enabled": True, "host": "0.0.0.0", "port": 8787, "token": "change-me"},
        "satellites": [],
        "coordinator": {},
    }


def load_config(path: str | Path | None = None) -> Config:
    """Load config from optional file, then overlay docker-compose environment variables."""
    raw = _default_raw()

    # Full YAML from env wins as base (Portainer-friendly single blob)
    inline = _env("NETDIAG_CONFIG_YAML")
    if inline:
        loaded = yaml.safe_load(inline) or {}
        raw.update(loaded)

    path = Path(path or os.environ.get("NETDIAG_CONFIG", "/app/config.yaml"))
    if path.is_file():
        with path.open(encoding="utf-8") as fh:
            file_raw = yaml.safe_load(fh) or {}
        # deep-ish merge top-level keys
        for key, value in file_raw.items():
            if isinstance(value, dict) and isinstance(raw.get(key), dict):
                merged = dict(raw[key])
                merged.update(value)
                raw[key] = merged
            else:
                raw[key] = value

    site = dict(raw.get("site") or {})
    vantage_raw = dict(raw.get("vantage") or {})
    capture = dict(raw.get("capture") or {})
    dhcp = dict(raw.get("dhcp") or {})
    dns = dict(raw.get("dns") or {})
    thr = dict(raw.get("thresholds") or {})
    ingest = dict(raw.get("ingest") or {})
    coord = dict(raw.get("coordinator") or {})

    # Environment overlays (docker-compose / Portainer)
    if _env("NETDIAG_SITE_NAME"):
        site["name"] = _env("NETDIAG_SITE_NAME")
    if _env("TZ") or _env("NETDIAG_TIMEZONE"):
        site["timezone"] = _env("NETDIAG_TIMEZONE") or _env("TZ") or site.get("timezone")

    if _env("NETDIAG_VANTAGE_ID"):
        vantage_raw["id"] = _env("NETDIAG_VANTAGE_ID")
    if _env("NETDIAG_VANTAGE_LINK"):
        vantage_raw["link"] = _env("NETDIAG_VANTAGE_LINK")
    if _env("NETDIAG_VANTAGE_NOTE") is not None and "NETDIAG_VANTAGE_NOTE" in os.environ:
        vantage_raw["note"] = _env("NETDIAG_VANTAGE_NOTE") or ""

    if _env("IFACE") or _env("NETDIAG_IFACE"):
        capture["iface"] = _env("IFACE") or _env("NETDIAG_IFACE")
    if _env("NETDIAG_SNAPLEN"):
        capture["snaplen"] = _env_int("NETDIAG_SNAPLEN", 128)
    if _env("NETDIAG_ROTATE_HOURS"):
        capture["rotate_hours"] = _env_int("NETDIAG_ROTATE_HOURS", 1)
    if _env("NETDIAG_KEEP_HOURS"):
        capture["keep_hours"] = _env_int("NETDIAG_KEEP_HOURS", 48)

    if "NETDIAG_DHCP_MAC" in os.environ:
        dhcp["expected_server_mac"] = _env("NETDIAG_DHCP_MAC") or ""

    if _env("NETDIAG_DNS_RESOLVERS"):
        dns["resolvers"] = _parse_list(_env("NETDIAG_DNS_RESOLVERS"))
    if _env("NETDIAG_DNS_NAMES"):
        dns["names"] = _parse_list(_env("NETDIAG_DNS_NAMES"))

    for key, env_name, caster, default in (
        ("ping_interval_s", "NETDIAG_PING_INTERVAL_S", _env_float, 5.0),
        ("incident_clear_s", "NETDIAG_INCIDENT_CLEAR_S", _env_float, 60.0),
        ("dns_interval_s", "NETDIAG_DNS_INTERVAL_S", _env_float, 30.0),
        ("dns_timeout_ms", "NETDIAG_DNS_TIMEOUT_MS", _env_int, 1500),
        ("path_interval_s", "NETDIAG_PATH_INTERVAL_S", _env_float, 300.0),
        ("bcast_pps_warn", "NETDIAG_BCAST_PPS_WARN", _env_float, 200.0),
        ("satellite_stale_s", "NETDIAG_SATELLITE_STALE_S", _env_float, 45.0),
        ("report_interval_s", "NETDIAG_REPORT_INTERVAL_S", _env_float, 60.0),
    ):
        if env_name in os.environ and os.environ.get(env_name) != "":
            thr[key] = caster(env_name, default)

    if "NETDIAG_INGEST_ENABLED" in os.environ:
        ingest["enabled"] = _env_bool("NETDIAG_INGEST_ENABLED", True)
    if _env("NETDIAG_INGEST_HOST"):
        ingest["host"] = _env("NETDIAG_INGEST_HOST")
    if _env("NETDIAG_INGEST_PORT"):
        ingest["port"] = _env_int("NETDIAG_INGEST_PORT", 8787)
    if "NETDIAG_INGEST_TOKEN" in os.environ:
        ingest["token"] = _env("NETDIAG_INGEST_TOKEN") or ""

    if _env("NETDIAG_COORDINATOR_URL"):
        coord["url"] = _env("NETDIAG_COORDINATOR_URL")
    if "NETDIAG_COORDINATOR_TOKEN" in os.environ:
        coord["token"] = _env("NETDIAG_COORDINATOR_TOKEN") or ""

    groups = _parse_groups(_env("NETDIAG_GROUPS"))
    if groups is None:
        groups = []
        for g in raw.get("groups") or []:
            hosts = g.get("hosts") or []
            if isinstance(hosts, str):
                hosts = _parse_list(hosts)
            groups.append(
                Group(
                    id=str(g.get("id", "unnamed")),
                    role=str(g.get("role", "other")).lower(),
                    hosts=[str(h) for h in hosts],
                )
            )

    sats = _parse_satellites(_env("NETDIAG_SATELLITES"))
    if sats is None:
        sats = [
            SatelliteExpect(id=str(s.get("id")), link=str(s.get("link", "ethernet")).lower())
            for s in (raw.get("satellites") or [])
            if s.get("id")
        ]

    link = str(vantage_raw.get("link", "ethernet")).lower()
    if link not in ("ethernet", "wifi"):
        link = "ethernet"

    iface = str(
        _env("IFACE")
        or _env("NETDIAG_IFACE")
        or capture.get("iface")
        or "eth0"
    )

    return Config(
        site_name=str(site.get("name", "Home LAN")),
        timezone=str(site.get("timezone") or _env("TZ") or "UTC"),
        vantage=Vantage(
            id=str(vantage_raw.get("id", "local")),
            link=link,
            note=str(vantage_raw.get("note", "")),
        ),
        iface=iface,
        snaplen=int(capture.get("snaplen", 128)),
        rotate_hours=int(capture.get("rotate_hours", 1)),
        keep_hours=int(capture.get("keep_hours", 48)),
        groups=groups,
        expected_dhcp_mac=str(dhcp.get("expected_server_mac") or "").lower().replace("-", ":"),
        dns_resolvers=[str(x) for x in (dns.get("resolvers") or [])],
        dns_names=[str(x) for x in (dns.get("names") or [])],
        ping_interval_s=float(thr.get("ping_interval_s", 5)),
        incident_clear_s=float(thr.get("incident_clear_s", 60)),
        dns_interval_s=float(thr.get("dns_interval_s", 30)),
        dns_timeout_ms=int(thr.get("dns_timeout_ms", 1500)),
        path_interval_s=float(thr.get("path_interval_s", 300)),
        bcast_pps_warn=float(thr.get("bcast_pps_warn", 200)),
        satellite_stale_s=float(thr.get("satellite_stale_s", 45)),
        report_interval_s=float(thr.get("report_interval_s", 60)),
        ingest_enabled=bool(ingest.get("enabled", True)),
        ingest_host=str(ingest.get("host", "0.0.0.0")),
        ingest_port=int(ingest.get("port", 8787)),
        ingest_token=str(ingest.get("token") or coord.get("token") or ""),
        satellites=sats,
        coordinator_url=str(coord.get("url") or ""),
        coordinator_token=str(coord.get("token") or ""),
        raw=raw,
    )


def data_dir() -> Path:
    return Path(os.environ.get("NETDIAG_DATA", "/data"))
