from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime

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
        f"satellite {cfg.vantage.id} ({cfg.vantage.link}) -> {cfg.coordinator_url}",
        flush=True,
    )

    last_dns = 0.0
    dns_results = []

    while True:
        t0 = time.time()
        ping = ping_round(cfg.hosts())
        counters = read_counters(cfg.iface)
        carrier = read_carrier(cfg.iface)
        if time.time() - last_dns >= cfg.dns_interval_s:
            dns_results = dns_check(cfg.dns_resolvers, cfg.dns_names, cfg.dns_timeout_ms)
            last_dns = time.time()

        payload = {
            "vantage_id": cfg.vantage.id,
            "link": cfg.vantage.link,
            "note": cfg.vantage.note,
            "ts": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "iface": cfg.iface,
            "ping": ping,
            "counters": counters,
            "carrier": carrier,
            "dns": dns_results,
        }
        _post(cfg.coordinator_url, cfg.coordinator_token, payload)

        # local breadcrumbs
        path = data_dir() / "logs" / "satellite-last.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        sleep = max(0.5, cfg.ping_interval_s - (time.time() - t0))
        time.sleep(sleep)


def _post(url: str, token: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Netdiag-Token": token,
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.URLError as exc:
        print(f"push failed: {exc}", flush=True)
