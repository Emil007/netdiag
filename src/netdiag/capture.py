from __future__ import annotations

import shutil
import subprocess
import threading
import time
from pathlib import Path

from .config import data_dir, load_config
from .detectors.retention import reap_old_captures


def free_bytes(path: Path) -> int | None:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def run_capture(config_path: str | None = None) -> None:
    cfg = load_config(config_path)
    caps = data_dir() / "captures"
    caps.mkdir(parents=True, exist_ok=True)

    rotate_s = max(60, int(cfg.rotate_hours * 3600))
    out = str(caps / "bcast-%Y%m%d-%H%M.pcap")
    # Include STP/LLDP multicast in the ring for forensics; live L2 parse is separate/merged in analyzer.
    bpf = (
        "broadcast or multicast or arp or "
        "(udp port 67 or udp port 68) or "
        "(udp port 53) or (tcp port 53) or "
        "ether dst 01:80:c2:00:00:00 or ether proto 0x88cc"
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

    stop = threading.Event()

    def reaper_loop() -> None:
        # Independent of tcpdump lifetime — must run while capture is healthy for days.
        while not stop.is_set():
            n = reap_old_captures(caps, cfg.keep_hours)
            if n:
                print(f"reaped {n} old pcap(s)", flush=True)
            free = free_bytes(data_dir())
            if free is not None and free < 500 * 1024 * 1024:
                print(
                    f"WARNING: free space on data volume under 500MB ({free} bytes)",
                    flush=True,
                )
            stop.wait(300)

    reaper = threading.Thread(target=reaper_loop, name="pcap-reaper", daemon=True)
    reaper.start()

    try:
        while True:
            proc = subprocess.Popen(cmd)
            # Poll so we can notice exit without blocking reaper (reaper is threaded anyway)
            while proc.poll() is None:
                time.sleep(5)
            code = proc.returncode
            if code == 0:
                time.sleep(1)
                continue
            print(f"tcpdump exited code={code}, restarting in 3s", flush=True)
            time.sleep(3)
    finally:
        stop.set()
