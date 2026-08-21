from __future__ import annotations

import signal
import subprocess
import time
from pathlib import Path

from .config import Config, data_dir, load_config


def run_capture(config_path: str | None = None) -> None:
    cfg = load_config(config_path)
    caps = data_dir() / "captures"
    caps.mkdir(parents=True, exist_ok=True)

    # tcpdump rotating files: bcast-YYYYMMDD-HHMM.pcap via -w + strftime + -G
    # keep_hours files roughly = keep_hours / rotate_hours
    rotate_s = max(60, cfg.rotate_hours * 3600)
    filecount = max(2, int(cfg.keep_hours / max(cfg.rotate_hours, 1)))
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
        "-W",
        str(filecount),
        "-U",
        bpf,
    ]
    print("capture:", " ".join(cmd), flush=True)

    while True:
        proc = subprocess.Popen(cmd)
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            raise
        print("tcpdump exited, restarting in 3s", flush=True)
        time.sleep(3)


def nearest_pcap(when=None) -> str:
    caps = data_dir() / "captures"
    from .report import matching_pcap
    from datetime import datetime

    return matching_pcap(caps, when or datetime.now())
