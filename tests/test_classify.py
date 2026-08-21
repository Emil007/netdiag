from __future__ import annotations

import time
from pathlib import Path

from netdiag.capture import reap_old_captures
from netdiag.classify import classify_loss, resolve_satellite_states
from netdiag.config import Config, Group, SatelliteExpect, Vantage


def _cfg(**kwargs) -> Config:
    base = dict(
        site_name="t",
        timezone="UTC",
        vantage=Vantage("coordinator", "ethernet", availability="always"),
        iface="eth0",
        snaplen=128,
        rotate_hours=1,
        keep_hours=48,
        groups=[
            Group("router", "gateway", ["192.168.1.1"]),
            Group("mesh_a", "mesh", ["192.168.1.2"]),
            Group("same", "same_segment", ["192.168.1.12"]),
            Group("living_room", "branch", ["192.168.1.10"]),
            Group("net", "external", ["1.1.1.1"]),
        ],
        expected_dhcp_mac="",
        dns_resolvers=["192.168.1.1"],
        dns_names=["example.com"],
        ping_interval_s=5,
        incident_clear_s=60,
        dns_interval_s=30,
        dns_timeout_ms=1500,
        path_interval_s=300,
        bcast_pps_warn=200,
        satellite_stale_s=45,
        satellite_offline_after_s=1200,
        report_interval_s=60,
        warmup_s=150,
        loss_threshold_pct=50,
        fail_rounds=2,
        confirm_rounds=2,
        ingest_enabled=True,
        ingest_host="0.0.0.0",
        ingest_port=8787,
        ingest_token="secret",
        allow_insecure_ingest=False,
        satellites=[],
        coordinator_url="",
        coordinator_token="",
    )
    base.update(kwargs)
    return Config(**base)


def _ping(loss_map: dict[str, int]) -> dict:
    out = {}
    for h, loss in loss_map.items():
        recv = 0 if loss >= 100 else (1 if loss >= 50 else 3)
        out[h] = {"sent": 3, "recv": recv, "loss": loss}
    return out


def test_internet_only():
    r = classify_loss(_cfg(), {"1.1.1.1"}, local_ping=_ping({"1.1.1.1": 100, "192.168.1.1": 0, "192.168.1.12": 0}))
    assert r and r.kind == "INTERNET"


def test_uplink_single_vantage():
    lost = {"192.168.1.1", "192.168.1.2", "1.1.1.1"}
    ping = _ping({h: (100 if h in lost else 0) for h in ["192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"]})
    r = classify_loss(_cfg(), lost, local_ping=ping)
    assert r and r.kind == "UPLINK_DOWN"
    assert r.confidence == "single_vantage"


def test_uplink_confirmed_by_router_side_sat():
    cfg = _cfg(
        satellites=[SatelliteExpect("sat-wired-1", "ethernet", "always")],
    )
    lost = {"192.168.1.1", "192.168.1.2", "1.1.1.1"}
    local = _ping({h: (100 if h in lost else 0) for h in ["192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"]})
    sat_ping = _ping({h: 0 for h in ["192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"]})
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wired-1",
            "link": "ethernet",
            "availability": "always",
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "last_event": "sample",
            "payload": {"ping": sat_ping},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    r = classify_loss(cfg, lost, local_ping=local, sat_states=states)
    assert r and r.kind == "UPLINK_DOWN"
    assert r.confidence == "confirmed"
    assert "confirmed" in r.where_text.lower() or "router side" in r.where_text.lower() or "wired vantage" in r.where_text.lower()


def test_probe_isolated_confirmed():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wired-1", "ethernet", "always")])
    lost = {"192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"}
    local = _ping({h: 100 for h in lost})
    sat_ping = _ping({h: 0 for h in lost})
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wired-1",
            "link": "ethernet",
            "availability": "always",
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "last_event": "sample",
            "payload": {"ping": sat_ping},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    r = classify_loss(
        cfg, lost, local_ping=local, sat_states=states, same_segment_down=True
    )
    assert r and r.kind == "PROBE_ISOLATED"
    assert r.confidence == "confirmed"


def test_both_lose_gateway_not_local_switch():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wired-1", "ethernet", "always")])
    lost = {"192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"}
    local = _ping({h: 100 for h in lost})
    sat_ping = _ping({h: 100 for h in lost})
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wired-1",
            "link": "ethernet",
            "availability": "always",
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "last_event": "sample",
            "payload": {"ping": sat_ping},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    r = classify_loss(cfg, lost, local_ping=local, sat_states=states, same_segment_down=True)
    assert r and r.kind == "TOTAL_OUTAGE"
    assert "router" in r.where_text.lower() or "isp" in r.where_text.lower()


def test_never_seen_wifi_sat_no_wifi_path():
    cfg = _cfg(
        satellites=[SatelliteExpect("sat-wifi-1", "wifi", "intermittent")],
    )
    now = time.time()
    states = resolve_satellite_states(cfg, [], now)
    assert states[0]["state"] == "never_seen"
    local = _ping({"192.168.1.1": 0, "192.168.1.12": 0, "1.1.1.1": 0, "192.168.1.2": 0, "192.168.1.10": 0})
    r = classify_loss(cfg, set(), local_ping=local, sat_states=states)
    assert r is None


def test_offline_intermittent_sat_no_wifi_path():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wifi-1", "wifi", "intermittent")])
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wifi-1",
            "link": "wifi",
            "availability": "intermittent",
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 10000)),
            "last_event": "offline",
            "payload": {"event": "offline"},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    assert states[0]["state"] == "offline"
    local = _ping({"192.168.1.1": 0, "192.168.1.12": 0, "1.1.1.1": 0, "192.168.1.2": 0, "192.168.1.10": 0})
    r = classify_loss(cfg, set(), local_ping=local, sat_states=states)
    assert r is None


def test_stale_always_wifi_sat_wifi_path():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wifi-1", "wifi", "always")])
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wifi-1",
            "link": "wifi",
            "availability": "always",
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 90)),
            "last_event": "sample",
            "payload": {"ping": {}},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    assert states[0]["state"] == "stale"
    local = _ping({"192.168.1.1": 0, "192.168.1.12": 0, "1.1.1.1": 0, "192.168.1.2": 0, "192.168.1.10": 0})
    r = classify_loss(cfg, set(), local_ping=local, sat_states=states)
    assert r and r.kind == "WIFI_PATH"


def test_capture_reaper(tmp_path: Path):
    old = tmp_path / "bcast-20000101-0000.pcap"
    old.write_bytes(b"x")
    # force old mtime
    import os

    os.utime(old, (0, 0))
    new = tmp_path / "bcast-20990101-0000.pcap"
    new.write_bytes(b"y")
    n = reap_old_captures(tmp_path, keep_hours=1)
    assert n >= 1
    assert not old.exists()
    assert new.exists()


def test_dhcp_ignores_client_frames():
    from netdiag.detectors.dhcp_watch import DhcpWatch

    alarms = []
    w = DhcpWatch("eth0", expected_mac="aa:bb:cc:dd:ee:ff", on_alarm=lambda m, msg: alarms.append(msg))
    # client-looking line should be ignored
    w._handle_line("12:34:56:78:9a:bc > ff:ff:ff:ff:ff:ff, ethertype IPv4, 192.168.1.50.68 > 255.255.255.255.67: BOOTP/DHCP, Request")
    assert alarms == []
    # server offer
    w._handle_line(
        "aa:bb:cc:dd:ee:00 > 12:34:56:78:9a:bc, ethertype IPv4, 192.168.1.1.67 > 192.168.1.50.68: BOOTP/DHCP, Offer"
    )
    assert len(alarms) == 1
