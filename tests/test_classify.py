from __future__ import annotations

from netdiag.classify import classify_loss
from netdiag.config import Config, Group, Vantage


def _cfg() -> Config:
    return Config(
        site_name="t",
        timezone="UTC",
        vantage=Vantage("c", "ethernet"),
        iface="eth0",
        snaplen=128,
        rotate_hours=1,
        keep_hours=48,
        groups=[
            Group("router", "gateway", ["192.168.1.1"]),
            Group("mesh_a", "mesh", ["192.168.1.2"]),
            Group("same", "same_segment", ["192.168.1.12"]),
            Group("net", "external", ["1.1.1.1"]),
        ],
        expected_dhcp_mac="",
        dns_resolvers=[],
        dns_names=[],
        ping_interval_s=5,
        incident_clear_s=60,
        dns_interval_s=30,
        dns_timeout_ms=1500,
        path_interval_s=300,
        bcast_pps_warn=200,
        satellite_stale_s=45,
        report_interval_s=60,
        ingest_enabled=True,
        ingest_host="0.0.0.0",
        ingest_port=8787,
        ingest_token="x",
        satellites=[],
        coordinator_url="",
        coordinator_token="",
    )


def test_internet_only():
    r = classify_loss(_cfg(), {"1.1.1.1"})
    assert r and r.kind == "INTERNET"


def test_uplink():
    r = classify_loss(_cfg(), {"192.168.1.1", "192.168.1.2", "1.1.1.1"})
    assert r and r.kind == "UPLINK_DOWN"


def test_wifi_path():
    r = classify_loss(
        _cfg(),
        set(),
        wifi_vantages_bad=True,
        ethernet_vantages_ok=True,
    )
    assert r and r.kind == "WIFI_PATH"


def test_single_host():
    r = classify_loss(_cfg(), {"192.168.1.2"})
    assert r and r.kind == "SINGLE_HOST"


if __name__ == "__main__":
    test_internet_only()
    test_uplink()
    test_wifi_path()
    test_single_host()
    print("ok")
