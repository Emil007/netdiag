from __future__ import annotations

import json
import signal
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .config import Config, data_dir, load_config
from .detectors.dns_health import dns_check
from .detectors.iface_counters import read_carrier, read_counters
from .detectors.ping_matrix import ping_round


def run_satellite(config_path: str | None = None) -> None:
    cfg = load_config(config_path)
    if not cfg.coordinator_url:
        raise SystemExit("satellite config missing coordinator.url")

    data_dir().mkdir(parents=True, exist_ok=True)
    print(
        f"satellite {cfg.vantage.id} ({cfg.vantage.link}/{cfg.vantage.availability}) "
        f"-> {cfg.coordinator_url}",
        flush=True,
    )

    stopping = {"flag": False}

    def _stop(signum, frame) -> None:  # noqa: ANN001
        stopping["flag"] = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    _post(
        cfg,
        {
            "vantage_id": cfg.vantage.id,
            "link": cfg.vantage.link,
            "availability": cfg.vantage.availability,
            "note": cfg.vantage.note,
            "event": "online",
            "ts": _utc(),
            "iface": cfg.iface,
            "ping": {},
            "counters": {},
            "carrier": {},
            "dns": [],
        },
    )

    last_dns = 0.0
    dns_results: list = []

    try:
        while not stopping["flag"]:
            t0 = time.time()
            ping = ping_round(cfg.hosts(), iface=cfg.iface)
            counters = read_counters(cfg.iface)
            carrier = read_carrier(cfg.iface)
            if time.time() - last_dns >= cfg.dns_interval_s:
                dns_results = dns_check(
                    cfg.dns_resolvers, cfg.dns_names, cfg.dns_timeout_ms
                )
                last_dns = time.time()

            payload = {
                "vantage_id": cfg.vantage.id,
                "link": cfg.vantage.link,
                "availability": cfg.vantage.availability,
                "note": cfg.vantage.note,
                "event": "sample",
                "ts": _utc(),
                "iface": cfg.iface,
                "ping": ping,
                "counters": counters,
                "carrier": carrier,
                "dns": dns_results,
            }
            _post(cfg, payload)
            path = data_dir() / "logs" / "satellite-last.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            sleep = max(0.5, cfg.ping_interval_s - (time.time() - t0))
            # wake early on stop
            end = time.time() + sleep
            while time.time() < end and not stopping["flag"]:
                time.sleep(0.2)
    finally:
        _post(
            cfg,
            {
                "vantage_id": cfg.vantage.id,
                "link": cfg.vantage.link,
                "availability": cfg.vantage.availability,
                "event": "offline",
                "reason": "shutdown",
                "ts": _utc(),
                "ping": {},
            },
        )
        print("satellite goodbye sent", flush=True)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _post(cfg: Config, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        cfg.coordinator_url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Netdiag-Token": cfg.coordinator_token,
            "Authorization": f"Bearer {cfg.coordinator_token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.URLError as exc:
        print(f"push failed: {exc}", flush=True)
