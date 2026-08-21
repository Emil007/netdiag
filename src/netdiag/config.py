from __future__ import annotations

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


def load_config(path: str | Path | None = None) -> Config:
    path = Path(path or os.environ.get("NETDIAG_CONFIG", "/app/config.yaml"))
    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    site = raw.get("site") or {}
    vantage_raw = raw.get("vantage") or {}
    capture = raw.get("capture") or {}
    dhcp = raw.get("dhcp") or {}
    dns = raw.get("dns") or {}
    thr = raw.get("thresholds") or {}
    ingest = raw.get("ingest") or {}
    coord = raw.get("coordinator") or {}

    iface = os.environ.get("IFACE") or capture.get("iface") or "eth0"
    link = str(vantage_raw.get("link", "ethernet")).lower()
    if link not in ("ethernet", "wifi"):
        link = "ethernet"

    groups = []
    for g in raw.get("groups") or []:
        hosts = g.get("hosts") or []
        if isinstance(hosts, str):
            hosts = hosts.replace(",", " ").split()
        groups.append(
            Group(
                id=str(g.get("id", "unnamed")),
                role=str(g.get("role", "other")).lower(),
                hosts=[str(h) for h in hosts],
            )
        )

    sats = [
        SatelliteExpect(id=str(s.get("id")), link=str(s.get("link", "ethernet")).lower())
        for s in (raw.get("satellites") or [])
        if s.get("id")
    ]

    return Config(
        site_name=str(site.get("name", "Home LAN")),
        timezone=str(site.get("timezone", "UTC")),
        vantage=Vantage(
            id=str(vantage_raw.get("id", "local")),
            link=link,
            note=str(vantage_raw.get("note", "")),
        ),
        iface=str(iface),
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
