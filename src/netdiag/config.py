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
    availability: str = "always"  # always | intermittent


@dataclass
class SatelliteExpect:
    id: str
    link: str
    availability: str = ""  # empty = default from link
    note: str = ""
    placement: str = "other"  # router | other

    def resolved_availability(self) -> str:
        if self.availability in ("always", "intermittent"):
            return self.availability
        return "intermittent" if self.link == "wifi" else "always"


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
    satellite_offline_after_s: float
    report_interval_s: float
    warmup_s: float
    loss_threshold_pct: int
    fail_rounds: int
    confirm_rounds: int
    ingest_enabled: bool
    ingest_host: str
    ingest_port: int
    ingest_token: str
    allow_insecure_ingest: bool
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

    def satellite_by_id(self, vid: str) -> SatelliteExpect | None:
        for s in self.satellites:
            if s.id == vid:
                return s
        return None


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


def _parse_hosts(hosts: Any) -> list[str]:
    if hosts is None:
        return []
    if isinstance(hosts, str):
        return [p for p in hosts.replace(",", " ").split() if p]
    return [str(h) for h in hosts]


def load_config(path: str | Path | None = None) -> Config:
    """Load canaries/satellites from config.yaml; short host overrides from environment."""
    path = Path(path or os.environ.get("NETDIAG_CONFIG", "/app/config.yaml"))
    raw: dict[str, Any] = {}
    if path.is_file():
        with path.open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

    site = dict(raw.get("site") or {})
    vantage_raw = dict(raw.get("vantage") or {})
    capture = dict(raw.get("capture") or {})
    dhcp = dict(raw.get("dhcp") or {})
    dns = dict(raw.get("dns") or {})
    thr = dict(raw.get("thresholds") or {})
    ingest = dict(raw.get("ingest") or {})
    coord = dict(raw.get("coordinator") or {})

    # Short host-specific env overlays only (compose), never JSON blobs
    if _env("TZ"):
        site["timezone"] = _env("TZ")
    if _env("IFACE") or _env("NETDIAG_IFACE"):
        capture["iface"] = _env("IFACE") or _env("NETDIAG_IFACE")
    if "NETDIAG_INGEST_TOKEN" in os.environ:
        ingest["token"] = _env("NETDIAG_INGEST_TOKEN") or ""
    if _env("NETDIAG_INGEST_PORT"):
        ingest["port"] = int(_env("NETDIAG_INGEST_PORT") or "8787")
    if _env("NETDIAG_INGEST_HOST"):
        ingest["host"] = _env("NETDIAG_INGEST_HOST")
    if _env("NETDIAG_COORDINATOR_URL"):
        coord["url"] = _env("NETDIAG_COORDINATOR_URL")
    if "NETDIAG_COORDINATOR_TOKEN" in os.environ:
        coord["token"] = _env("NETDIAG_COORDINATOR_TOKEN") or ""

    link = str(vantage_raw.get("link", "ethernet")).lower()
    if link not in ("ethernet", "wifi"):
        link = "ethernet"
    avail = str(vantage_raw.get("availability") or "").lower()
    if avail not in ("always", "intermittent"):
        avail = "intermittent" if link == "wifi" else "always"

    groups = [
        Group(
            id=str(g.get("id", "unnamed")),
            role=str(g.get("role", "other")).lower(),
            hosts=_parse_hosts(g.get("hosts")),
        )
        for g in (raw.get("groups") or [])
    ]

    sats: list[SatelliteExpect] = []
    for s in raw.get("satellites") or []:
        if not s.get("id"):
            continue
        slink = str(s.get("link", "ethernet")).lower()
        savail = str(s.get("availability") or "").lower()
        sats.append(
            SatelliteExpect(
                id=str(s["id"]),
                link=slink if slink in ("ethernet", "wifi") else "ethernet",
                availability=savail if savail in ("always", "intermittent") else "",
                note=str(s.get("note") or ""),
                placement=str(s.get("placement") or "other").lower(),
            )
        )

    iface = str(capture.get("iface") or "eth0")
    token = str(ingest.get("token") or coord.get("token") or "")

    return Config(
        site_name=str(site.get("name", "Home LAN")),
        timezone=str(site.get("timezone") or _env("TZ") or "UTC"),
        vantage=Vantage(
            id=str(vantage_raw.get("id", "coordinator")),
            link=link,
            note=str(vantage_raw.get("note", "")),
            availability=avail,
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
        satellite_offline_after_s=float(thr.get("satellite_offline_after_s", 1200)),
        report_interval_s=float(thr.get("report_interval_s", 60)),
        warmup_s=float(thr.get("warmup_s", 150)),
        loss_threshold_pct=int(thr.get("loss_threshold_pct", 50)),
        fail_rounds=int(thr.get("fail_rounds", 2)),
        confirm_rounds=int(thr.get("confirm_rounds", 2)),
        ingest_enabled=bool(ingest.get("enabled", True)),
        ingest_host=str(ingest.get("host", "0.0.0.0")),
        ingest_port=int(ingest.get("port", 8787)),
        ingest_token=token,
        allow_insecure_ingest=_env_bool("NETDIAG_ALLOW_INSECURE_INGEST", False),
        satellites=sats,
        coordinator_url=str(coord.get("url") or ""),
        coordinator_token=str(coord.get("token") or ""),
        raw=raw,
    )


def data_dir() -> Path:
    return Path(os.environ.get("NETDIAG_DATA", "/data"))
