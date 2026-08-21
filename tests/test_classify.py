from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from unittest import mock

from netdiag.capture import reap_old_captures
from netdiag.classify import classify_loss, resolve_satellite_states
from netdiag.config import Config, Group, SatelliteExpect, Vantage
from netdiag.detectors.l2_bridge import parse_l2_line
from netdiag.detectors.retention import reap_old_csvs, reap_old_incident_html


def _cfg(**kwargs) -> Config:
    base = dict(
        site_name="t",
        timezone="UTC",
        vantage=Vantage("coordinator", "ethernet", availability="always"),
        iface="eth0",
        snaplen=128,
        rotate_hours=1,
        keep_hours=48,
        csv_keep_days=14,
        incident_html_keep_days=30,
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


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def test_internet_only():
    r = classify_loss(
        _cfg(),
        {"1.1.1.1"},
        local_ping=_ping({"1.1.1.1": 100, "192.168.1.1": 0, "192.168.1.12": 0}),
    )
    assert r and r.kind == "INTERNET"


def test_uplink_single_vantage():
    lost = {"192.168.1.1", "192.168.1.2", "1.1.1.1"}
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"]
    ping = _ping({h: (100 if h in lost else 0) for h in hosts})
    r = classify_loss(_cfg(), lost, local_ping=ping)
    assert r and r.kind == "UPLINK_DOWN"
    assert r.confidence == "single_vantage"


def test_warmup_still_classifies_local_uplink():
    lost = {"192.168.1.1", "192.168.1.2", "1.1.1.1"}
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"]
    ping = _ping({h: (100 if h in lost else 0) for h in hosts})
    r = classify_loss(_cfg(), lost, local_ping=ping, warmup=True)
    assert r and r.kind == "UPLINK_DOWN"


def test_warmup_suppresses_wifi_path():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wifi-1", "wifi", "always")])
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wifi-1",
            "link": "wifi",
            "availability": "always",
            "received_at": _iso(now - 90),
            "last_event": "sample",
            "payload": {"ping": {}},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    local = _ping(
        {h: 0 for h in ["192.168.1.1", "192.168.1.12", "1.1.1.1", "192.168.1.2", "192.168.1.10"]}
    )
    r = classify_loss(cfg, set(), local_ping=local, sat_states=states, warmup=True)
    assert r is None


def test_branch_no_sat_is_single_vantage():
    lost = {"192.168.1.10"}
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"]
    ping = _ping({h: (100 if h in lost else 0) for h in hosts})
    r = classify_loss(_cfg(), lost, local_ping=ping)
    assert r and r.kind == "SINGLE_HOST"
    assert r.confidence == "single_vantage"
    assert "single vantage" in r.where_text.lower() or "named" in r.where_text.lower()


def test_branch_sat_also_loss_confirmed():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wired-1", "ethernet", "always", placement="router")])
    lost = {"192.168.1.10"}
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"]
    local = _ping({h: (100 if h in lost else 0) for h in hosts})
    sat_ping = _ping({h: (100 if h in lost else 0) for h in hosts})
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wired-1",
            "link": "ethernet",
            "availability": "always",
            "placement": "router",
            "received_at": _iso(now),
            "last_event": "sample",
            "payload": {"ping": sat_ping},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    r = classify_loss(cfg, lost, local_ping=local, sat_states=states)
    assert r and r.kind == "SINGLE_HOST"
    assert r.confidence == "confirmed"
    assert "multiple" in r.where_text.lower() or "spur" in r.where_text.lower()


def test_branch_sat_ok_path_between():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wired-1", "ethernet", "always", placement="router")])
    lost = {"192.168.1.10"}
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"]
    local = _ping({h: (100 if h in lost else 0) for h in hosts})
    sat_ping = _ping({h: 0 for h in hosts})
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wired-1",
            "link": "ethernet",
            "availability": "always",
            "placement": "router",
            "received_at": _iso(now),
            "last_event": "sample",
            "payload": {"ping": sat_ping},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    r = classify_loss(cfg, lost, local_ping=local, sat_states=states)
    assert r and r.confidence == "confirmed"
    assert "between" in r.where_text.lower()


def test_never_seen_wifi_sat_no_wifi_path():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wifi-1", "wifi", "intermittent")])
    now = time.time()
    states = resolve_satellite_states(cfg, [], now)
    assert states[0]["state"] == "never_seen"
    local = _ping(
        {h: 0 for h in ["192.168.1.1", "192.168.1.12", "1.1.1.1", "192.168.1.2", "192.168.1.10"]}
    )
    assert classify_loss(cfg, set(), local_ping=local, sat_states=states) is None


def test_offline_intermittent_sat_no_wifi_path():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wifi-1", "wifi", "intermittent")])
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wifi-1",
            "link": "wifi",
            "availability": "intermittent",
            "received_at": _iso(now - 10000),
            "last_event": "offline",
            "payload": {"event": "offline"},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    local = _ping(
        {h: 0 for h in ["192.168.1.1", "192.168.1.12", "1.1.1.1", "192.168.1.2", "192.168.1.10"]}
    )
    assert classify_loss(cfg, set(), local_ping=local, sat_states=states) is None


def test_stale_always_wifi_sat_wifi_path():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wifi-1", "wifi", "always")])
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wifi-1",
            "link": "wifi",
            "availability": "always",
            "received_at": _iso(now - 90),
            "last_event": "sample",
            "payload": {"ping": {}},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    local = _ping(
        {h: 0 for h in ["192.168.1.1", "192.168.1.12", "1.1.1.1", "192.168.1.2", "192.168.1.10"]}
    )
    r = classify_loss(cfg, set(), local_ping=local, sat_states=states)
    assert r and r.kind == "WIFI_PATH"


def test_intermittent_stale_with_mesh_loss_wifi_path():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wifi-1", "wifi", "intermittent")])
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wifi-1",
            "link": "wifi",
            "availability": "intermittent",
            "received_at": _iso(now - 90),
            "last_event": "sample",
            "payload": {"ping": {}},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    lost = {"192.168.1.2"}
    local = _ping(
        {
            "192.168.1.1": 0,
            "192.168.1.12": 0,
            "1.1.1.1": 0,
            "192.168.1.2": 100,
            "192.168.1.10": 0,
        }
    )
    r = classify_loss(cfg, lost, local_ping=local, sat_states=states)
    assert r and r.kind == "WIFI_PATH"


def test_intermittent_stale_mesh_ok_quiet():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wifi-1", "wifi", "intermittent")])
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wifi-1",
            "link": "wifi",
            "availability": "intermittent",
            "received_at": _iso(now - 90),
            "last_event": "sample",
            "payload": {"ping": {}},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    local = _ping(
        {h: 0 for h in ["192.168.1.1", "192.168.1.12", "1.1.1.1", "192.168.1.2", "192.168.1.10"]}
    )
    assert classify_loss(cfg, set(), local_ping=local, sat_states=states) is None


def test_unlisted_wifi_sat_ignored():
    cfg = _cfg(satellites=[])  # none listed
    now = time.time()
    rows = [
        {
            "vantage_id": "rogue-wifi",
            "link": "wifi",
            "availability": "always",
            "received_at": _iso(now - 90),
            "last_event": "sample",
            "payload": {"ping": {}},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    assert states[0]["expected"] is False
    local = _ping(
        {h: 0 for h in ["192.168.1.1", "192.168.1.12", "1.1.1.1", "192.168.1.2", "192.168.1.10"]}
    )
    assert classify_loss(cfg, set(), local_ping=local, sat_states=states) is None


def test_capture_reaper(tmp_path: Path):
    old = tmp_path / "bcast-20000101-0000.pcap"
    old.write_bytes(b"x")
    os.utime(old, (0, 0))
    new = tmp_path / "bcast-20990101-0000.pcap"
    new.write_bytes(b"y")
    n = reap_old_captures(tmp_path, keep_hours=1)
    assert n >= 1
    assert not old.exists()
    assert new.exists()


def test_reaper_runs_while_fake_tcpdump_alive(tmp_path: Path):
    """Reaper must not depend on tcpdump exiting."""
    old = tmp_path / "bcast-20000101-1200.pcap"
    old.write_bytes(b"old")
    os.utime(old, (0, 0))
    stop = threading.Event()

    def fake_wait():
        stop.wait(2)

    # Simulate: reap while a long-running process would be blocking
    t = threading.Thread(target=fake_wait)
    t.start()
    n = reap_old_captures(tmp_path, keep_hours=1)
    stop.set()
    t.join(timeout=3)
    assert n >= 1
    assert not old.exists()


def test_dhcp_ignores_client_frames():
    from netdiag.detectors.dhcp_watch import DhcpWatch

    alarms = []
    w = DhcpWatch(
        "eth0",
        expected_mac="aa:bb:cc:dd:ee:ff",
        on_alarm=lambda m, msg: alarms.append(msg),
    )
    w._handle_line(
        "12:34:56:78:9a:bc > ff:ff:ff:ff:ff:ff, ethertype IPv4, "
        "192.168.1.50.68 > 255.255.255.255.67: BOOTP/DHCP, Request"
    )
    assert alarms == []
    w._handle_line(
        "aa:bb:cc:dd:ee:00 > 12:34:56:78:9a:bc, ethertype IPv4, "
        "192.168.1.1.67 > 192.168.1.50.68: BOOTP/DHCP, Offer"
    )
    assert len(alarms) == 1


def test_stp_parser():
    line = (
        "11:22:33:44:55:66 > 01:80:c2:00:00:00, ethertype 802.1Q, "
        "STP 802.1d, Config, Flags [none], bridge-id 8000.11:22:33:44:55:66.8002, "
        "length 35, root-id 8000.aa:bb:cc:dd:ee:ff"
    )
    parsed = parse_l2_line(line)
    assert parsed is not None
    assert parsed["kind"] == "stp"


def test_uplink_confirmed_by_router_side_sat():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wired-1", "ethernet", "always", placement="router")])
    lost = {"192.168.1.1", "192.168.1.2", "1.1.1.1"}
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"]
    local = _ping({h: (100 if h in lost else 0) for h in hosts})
    sat_ping = _ping({h: 0 for h in hosts})
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wired-1",
            "link": "ethernet",
            "availability": "always",
            "placement": "router",
            "received_at": _iso(now),
            "last_event": "sample",
            "payload": {"ping": sat_ping},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    r = classify_loss(cfg, lost, local_ping=local, sat_states=states)
    assert r and r.kind == "UPLINK_DOWN" and r.confidence == "confirmed"


def test_probe_isolated_confirmed():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wired-1", "ethernet", "always", placement="router")])
    lost = {"192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"}
    local = _ping({h: 100 for h in lost})
    sat_ping = _ping({h: 0 for h in lost})
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wired-1",
            "link": "ethernet",
            "availability": "always",
            "placement": "router",
            "received_at": _iso(now),
            "last_event": "sample",
            "payload": {"ping": sat_ping},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    r = classify_loss(
        cfg, lost, local_ping=local, sat_states=states, same_segment_down=True
    )
    assert r and r.kind == "PROBE_ISOLATED" and r.confidence == "confirmed"


def test_both_lose_gateway_not_local_switch():
    cfg = _cfg(satellites=[SatelliteExpect("sat-wired-1", "ethernet", "always", placement="router")])
    lost = {"192.168.1.1", "192.168.1.2", "192.168.1.12", "192.168.1.10", "1.1.1.1"}
    local = _ping({h: 100 for h in lost})
    sat_ping = _ping({h: 100 for h in lost})
    now = time.time()
    rows = [
        {
            "vantage_id": "sat-wired-1",
            "link": "ethernet",
            "availability": "always",
            "placement": "router",
            "received_at": _iso(now),
            "last_event": "sample",
            "payload": {"ping": sat_ping},
        }
    ]
    states = resolve_satellite_states(cfg, rows, now)
    r = classify_loss(cfg, lost, local_ping=local, sat_states=states, same_segment_down=True)
    assert r and r.kind == "TOTAL_OUTAGE"


def test_config_yaml_env_primary(monkeypatch):
    yaml_text = """
site:
  name: Env Site
vantage:
  id: coord-env
  link: ethernet
groups:
  - id: router
    role: gateway
    hosts: ["10.0.0.1"]
  - id: internet
    role: external
    hosts: ["1.1.1.1"]
ingest:
  token: secret-token
"""
    monkeypatch.setenv("NETDIAG_CONFIG_YAML", yaml_text)
    monkeypatch.setenv("IFACE", "enp3s0")
    monkeypatch.setenv("NETDIAG_INGEST_TOKEN", "from-env")
    from netdiag.config import load_config

    cfg = load_config()
    assert cfg.site_name == "Env Site"
    assert cfg.vantage.id == "coord-env"
    assert cfg.iface == "enp3s0"
    assert cfg.ingest_token == "from-env"
    assert "10.0.0.1" in cfg.hosts()


def test_topology_has_gateway_and_coordinator():
    from netdiag.topology import build_topology

    topo = build_topology(_cfg())
    ids = {n["id"] for n in topo["nodes"]}
    assert "gateway" in ids
    assert "coordinator" in ids
    assert "internet" in ids
    assert "local_switch" in ids  # same_segment present in _cfg


def test_topology_no_local_switch_without_same_segment():
    from netdiag.topology import build_topology

    cfg = _cfg(
        groups=[
            Group("router", "gateway", ["192.168.1.1"]),
            Group("living_room", "branch", ["192.168.1.10"]),
            Group("net", "external", ["1.1.1.1"]),
        ]
    )
    topo = build_topology(cfg)
    ids = {n["id"] for n in topo["nodes"]}
    assert "local_switch" not in ids
    # branch attaches to gateway
    assert any(e["from"] == "gateway" and e["to"] == "group:living_room" for e in topo["edges"])


def test_topology_behind_switch_flag():
    from netdiag.topology import build_topology

    cfg = _cfg(
        vantage=Vantage("coordinator", "ethernet", availability="always", behind_switch=True),
        groups=[
            Group("router", "gateway", ["192.168.1.1"]),
            Group("net", "external", ["1.1.1.1"]),
        ],
    )
    topo = build_topology(cfg)
    assert any(n["id"] == "local_switch" for n in topo["nodes"])


def test_topology_uplink_down_fault_edge():
    from netdiag.topology import build_topology

    cfg = _cfg()
    matrix = [
        {
            "vantage_id": "coordinator",
            "link": "ethernet",
            "state": "online",
            "groups": {
                "router": "loss",
                "same": "ok",
                "living_room": "loss",
                "mesh_a": "loss",
                "net": "loss",
            },
        }
    ]
    topo = build_topology(
        cfg,
        matrix=matrix,
        incident={
            "kind": "UPLINK_DOWN",
            "where_text": "Uplink toward router from local switch",
            "hosts": {"192.168.1.1": 1},
            "confidence": "single_vantage",
        },
    )
    assert topo["confidence"] == "single_vantage"
    fault_edges = [e for e in topo["edges"] if e.get("fault")]
    assert fault_edges
    assert any(
        e.get("label") == "uplink" or (e["from"] == "gateway" and e["to"] == "local_switch")
        for e in fault_edges
    )


def test_live_map_confidence_from_classifier_not_sat_list():
    from netdiag.topology import build_topology

    cfg = _cfg(
        satellites=[SatelliteExpect("sat-wired-1", "ethernet", "always", placement="router")]
    )
    topo = build_topology(
        cfg,
        incident={
            "kind": "UPLINK_DOWN",
            "where_text": "uplink",
            "confidence": "single_vantage",
            "meta": {"confidence": "single_vantage"},
        },
    )
    assert topo["confidence"] == "single_vantage"


def test_link_fault_clears_after_quiet(monkeypatch):
    """After CRC then quiet past incident_clear_s, sticky clears; map fault only via open_inc."""
    from netdiag.engine import Analyzer

    cfg = _cfg(incident_clear_s=1)
    a = object.__new__(Analyzer)
    a.cfg = cfg
    a.open_inc = None
    a.link_fault_last_at = time.time() - 5
    a.link_fault_note = "old"
    assert a._link_fault_sticky() is False
    a.link_fault_last_at = time.time()
    assert a._link_fault_sticky() is True
    assert a._map_link_fault() is False  # no open incident
    a.open_inc = {"link_fault": True}
    assert a._map_link_fault() is True
    a.open_inc = {"link_fault": False}
    assert a._map_link_fault() is False


def test_census_one_key_per_arp_host():
    from netdiag.detectors.census import LanCensus

    c = LanCensus()
    now = time.time()
    c.observe_host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01", now=now)
    c.observe_host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01", now=now)
    assert len(c.speakers) == 1
    c.observe_host(ip="192.168.1.11", mac="aa:bb:cc:dd:ee:02", now=now)
    assert len(c.speakers) == 2


def test_census_mass_disappear_sharp_collapse():
    from netdiag.detectors.census import LanCensus

    c = LanCensus(baseline_s=3600, active_s=900, recent_s=120)
    now = time.time()
    for i in range(20):
        # Seen within active window (e.g. 5 min ago) then mostly go quiet
        c.speakers[f"ip:192.168.1.{i}"] = now - 300
    c.speakers["ip:192.168.1.1"] = now
    c.speakers["ip:192.168.1.2"] = now
    snap = c.snapshot(now)
    assert snap["mass_disappear"]
    assert snap["active"] >= 8
    assert "census:" in snap["text"]


def test_census_overnight_quiet_not_mass():
    from netdiag.detectors.census import LanCensus

    c = LanCensus(baseline_s=3600, active_s=900, recent_s=120)
    now = time.time()
    # Daytime speakers aged past active window (overnight fade)
    for i in range(20):
        c.speakers[f"ip:192.168.1.{i}"] = now - 2000
    snap = c.snapshot(now)
    assert snap["active"] == 0
    assert snap["mass_disappear"] is False


def test_reap_old_csvs(tmp_path: Path):
    old = tmp_path / "ping-2000-01-01.csv"
    old.write_text("x", encoding="utf-8")
    os.utime(old, (0, 0))
    recent = tmp_path / f"ping-{time.strftime('%Y-%m-%d')}.csv"
    recent.write_text("y", encoding="utf-8")
    n = reap_old_csvs(tmp_path, keep_days=14)
    assert n >= 1
    assert not old.exists()
    assert recent.exists()


def test_reap_old_incident_html(tmp_path: Path):
    old = tmp_path / "20000101-000000-1.html"
    old.write_text("<html/>", encoding="utf-8")
    os.utime(old, (0, 0))
    keep = tmp_path / "keep-me-99.html"
    keep.write_text("<html/>", encoding="utf-8")
    os.utime(keep, (0, 0))
    n = reap_old_incident_html(tmp_path, keep_days=1, keep_names={"keep-me-99.html"})
    assert n >= 1
    assert not old.exists()
    assert keep.exists()


def test_stp_verbose_alpine_line():
    # Typical Alpine tcpdump -v STP line shape
    line = (
        "12:00:00.000000 00:11:22:33:44:55 > 01:80:c2:00:00:00, "
        "802.1d config BPDU: STP flags [none], root-id 8000.00:aa:bb:cc:dd:ee.8001, "
        "bridge-id 8000.00:11:22:33:44:55.8002, port-id 8002, "
        "message-age 0.00s, max-age 20.00s, hello-time 2.00s, forward-delay 15.00s"
    )
    # Fallback path uses root/bridge regexes when combined _STP misses
    parsed = parse_l2_line(line)
    assert parsed is not None
    assert parsed["kind"] == "stp"
    assert "11:22:33:44:55" in parsed["id"] or parsed["id"] != "unknown"


def test_lldp_line():
    line = (
        "12:00:01.000000 aa:bb:cc:dd:ee:ff > 01:80:c2:00:00:0e, ethertype LLDP (0x88cc), "
        "length 100: LLDP, length 86 Chassis ID TLV"
    )
    parsed = parse_l2_line(line)
    assert parsed is not None
    assert parsed["kind"] == "lldp"


def test_shared_upstream_hint():
    from netdiag.topology import infer_shared_upstream

    cfg = _cfg(
        groups=[
            Group("router", "gateway", ["192.168.1.1"]),
            Group("a", "branch", ["192.168.1.10"]),
            Group("b", "branch", ["192.168.1.20"]),
            Group("net", "external", ["1.1.1.1"]),
        ]
    )
    hint = infer_shared_upstream(cfg, {"192.168.1.10", "192.168.1.20"})
    assert hint and "shared upstream" in hint.lower()
