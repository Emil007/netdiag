from __future__ import annotations

import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from .config import data_dir, load_config


def reap_old_captures(caps: Path, keep_hours: float) -> int:
    """Delete bcast-*.pcap older than keep_hours. Returns number removed."""
    if keep_hours <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=keep_hours)
    removed = 0
    if not caps.is_dir():
        return 0
    for f in caps.glob("bcast-*.pcap"):
        try:
            # Prefer mtime; also parse filename if possible
            mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                f.unlink(missing_ok=True)
                removed += 1
        except OSError:
            continue
    return removed


def run_capture(config_path: str | None = None) -> None:
    cfg = load_config(config_path)
    caps = data_dir() / "captures"
    caps.mkdir(parents=True, exist_ok=True)

    rotate_s = max(60, int(cfg.rotate_hours * 3600))
    out = str(caps / "bcast-%Y%m%d-%H%M.pcap")
    bpf = (
        "broadcast or multicast or arp or "
        "(udp port 67 or udp port 68) or "
        "(udp port 53) or (tcp port 53)"
    )
    cmd = [
        "tcpdump",
        "-i",
        cfg.iface,
        "-s",
        str(cfg.snaplen),
        "-w",
        out,
        "-G",
        str(rotate_s),
        "-U",
        bpf,
    ]
    print("capture:", " ".join(cmd), flush=True)
    last_reap = 0.0

    while True:
        # Reap on a timer regardless of tcpdump lifetime
        now = time.time()
        if now - last_reap > 300:
            n = reap_old_captures(caps, cfg.keep_hours)
            if n:
                print(f"reaped {n} old pcap(s)", flush=True)
            last_reap = now

        proc = subprocess.Popen(cmd)
        code = proc.wait()
        # -G rotates forever without -W; unexpected exit → restart
        if code == 0:
            # unusual; brief pause
            time.sleep(1)
            continue
        print(f"tcpdump exited code={code}, restarting in 3s", flush=True)
        time.sleep(3)
