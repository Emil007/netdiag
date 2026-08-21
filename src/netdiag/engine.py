from __future__ import annotations

import csv
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .classify import classify_detector_event, classify_loss, vantage_flags
from .config import Config, data_dir, load_config
from .detectors.arp_watch import ArpWatch
from .detectors.dhcp_watch import DhcpWatch
from .detectors.dns_health import dns_check
from .detectors.iface_counters import delta, read_carrier, read_counters
from .detectors.path_check import traceroute_path
from .detectors.ping_matrix import ping_round
from .ingest import start_ingest
from .report import append_event, matching_pcap, write_reports, write_status
from .store import Store


class Analyzer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.root = data_dir()
        self.logs = self.root / "logs"
        self.caps = self.root / "captures"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.caps.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.logs / "netdiag.db")
        self.started = datetime.now()
        self.started_s = self.started.strftime("%Y-%m-%d %H:%M:%S")
        self.stats: dict[str, dict[str, int]] = {
            h: {"rounds": 0, "bad": 0, "lost": 0, "sent": 0} for h in cfg.hosts()
        }
        self.open_inc: dict[str, Any] | None = None
        self.clear_since: float | None = None
        self.base_counters = read_counters(cfg.iface)
        self.round_counters = dict(self.base_counters)
        self.last_dns = 0.0
        self.last_path = 0.0
        self.last_report = 0.0
        self.last_dns_results: list[dict[str, Any]] = []
        self.last_paths: list[dict[str, Any]] = []
        self.dhcp_alarms: list[str] = []
        self.arp_alarms: list[str] = []
        self.dhcp = DhcpWatch(cfg.iface, cfg.expected_dhcp_mac, on_alarm=self._on_dhcp)
        self.arp = ArpWatch(cfg.iface, on_conflict=self._on_arp)

    def _on_dhcp(self, mac: str, msg: str) -> None:
        self.dhcp_alarms.append(msg)
        path = self.logs / "ALARM-dhcp.log"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now().isoformat()} {msg}\n")
        self._detector_incident("ROGUE_DHCP", msg, meta={"mac": mac})

    def _on_arp(self, ip: str, old: str, new: str) -> None:
        msg = f"IP conflict / ARP flip: {ip} was {old}, now {new}"
        self.arp_alarms.append(msg)
        self._detector_incident("IP_CONFLICT", msg, meta={"ip": ip, "old": old, "new": new})

    def _detector_incident(self, kind: str, verdict: str, meta: dict | None = None) -> None:
        cr = classify_detector_event(kind, verdict)
        pcap = matching_pcap(self.caps, datetime.now())
        iid = self.store.open_incident(
            cr.kind, cr.verdict, {}, meta=meta, pcap=pcap, vantage_summary=self._vantage_summary_text()
        )
        self.store.close_incident(iid)
        block = (
            f"\n=== {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  [{cr.kind}]\n"
            f"  Verdacht:  {cr.verdict}\n"
            f"  pcap:      {pcap or '(none)'}\n"
        )
        append_event(block)
        print(block, flush=True)

    def run(self) -> None:
        print(
            f"analyzer {self.cfg.vantage.id} on {self.cfg.iface} "
            f"({len(self.cfg.hosts())} canaries)",
            flush=True,
        )
        start_ingest(self.cfg, self.store)
        self.dhcp.start()
        self.arp.start()
        try:
            while True:
                t0 = time.time()
                self._tick()
                sleep = max(0.2, self.cfg.ping_interval_s - (time.time() - t0))
                time.sleep(sleep)
        finally:
            self.dhcp.stop()
            self.arp.stop()

    def _tick(self) -> None:
        ping = ping_round(self.cfg.hosts())
        counters = read_counters(self.cfg.iface)
        carrier = read_carrier(self.cfg.iface)
        dlt = delta(self.round_counters, counters)
        self.round_counters = counters

        lost_now = set()
        for host, st in self.stats.items():
            st["rounds"] += 1
            p = ping.get(host) or {"sent": 0, "recv": 0, "loss": 100}
            st["sent"] += int(p.get("sent", 0))
            st["lost"] += int(p.get("sent", 0)) - int(p.get("recv", 0))
            if int(p.get("loss", 100)) >= 100 or int(p.get("recv", 0)) == 0:
                st["bad"] += 1
                lost_now.add(host)

        self._append_csv("ping", ping)
        self._append_iface_csv(counters, carrier)

        now = time.time()
        if now - self.last_dns >= self.cfg.dns_interval_s:
            self.last_dns_results = dns_check(
                self.cfg.dns_resolvers, self.cfg.dns_names, self.cfg.dns_timeout_ms
            )
            self.last_dns = now
            fails = [r for r in self.last_dns_results if not r.get("ok")]
            if fails and len(fails) == len(self.last_dns_results):
                self._detector_incident(
                    "DNS_FAILURE",
                    "All configured DNS checks failed. Suspect router DNS/resolver or upstream DNS.",
                    meta={"results": fails[:6]},
                )

        if now - self.last_path >= self.cfg.path_interval_s:
            self.last_paths = []
            for role in ("gateway", "external"):
                for h in list(self.cfg.hosts_by_role(role))[:1]:
                    self.last_paths.append(traceroute_path(h))
            self.last_path = now

        bcast_pps = 0.0
        # approximate from multicast counter delta / interval
        if self.cfg.ping_interval_s > 0:
            bcast_pps = dlt.get("multicast", 0) / self.cfg.ping_interval_s
        if bcast_pps >= self.cfg.bcast_pps_warn and lost_now:
            # annotate open incident via meta; also standalone if severe
            pass

        sat_rows = self.store.list_satellites()
        flags = vantage_flags(self.cfg, sat_rows, ping, now)
        same_seg = self.cfg.hosts_by_role("same_segment")
        same_down = bool(same_seg) and same_seg <= lost_now
        carrier_down = carrier.get("carrier") == 0 or carrier.get("operstate") in ("down", "lowerlayerdown")
        link_err = dlt.get("rx_errors", 0) + dlt.get("rx_crc_errors", 0)

        result = classify_loss(
            self.cfg,
            lost_now,
            same_segment_down=same_down,
            carrier_down=carrier_down,
            link_errors_delta=link_err,
            bcast_delta=dlt.get("multicast", 0),
            wifi_vantages_bad=flags["wifi_vantages_bad"],
            ethernet_vantages_ok=flags["ethernet_vantages_ok"],
        )

        if link_err > 0 and not self.open_inc:
            # soft note via status; hard incident if sustained with loss
            if lost_now:
                result = result or classify_detector_event(
                    "LINK_ERRORS",
                    f"Probe NIC saw +{link_err} receive/CRC errors with concurrent canary loss. "
                    "Suspect cable, port, or duplex issue on this host's link.",
                )

        if bcast_pps >= self.cfg.bcast_pps_warn * 5 and lost_now:
            result = classify_detector_event(
                "BCAST_STORM",
                f"Very high multicast/broadcast rate (~{bcast_pps:.0f}/s) with canary loss. "
                "Suspect loop or storm.",
            )

        self._update_incident(result, lost_now, dlt, flags)

        if now - self.last_report >= self.cfg.report_interval_s:
            self._write_outputs(ping, counters, carrier, sat_rows, flags)
            self.last_report = now

    def _update_incident(
        self,
        result,
        lost_now: set[str],
        dlt: dict[str, int],
        flags: dict[str, bool],
    ) -> None:
        if result:
            self.clear_since = None
            if not self.open_inc:
                pcap = matching_pcap(self.caps, datetime.now())
                hosts = {h: 1 for h in lost_now}
                iid = self.store.open_incident(
                    result.kind,
                    result.verdict,
                    hosts,
                    meta={"delta": dlt, "flags": flags},
                    pcap=pcap,
                    vantage_summary=self._vantage_summary_text(),
                )
                self.open_inc = {
                    "id": iid,
                    "kind": result.kind,
                    "verdict": result.verdict,
                    "hosts": hosts,
                    "start": datetime.now(),
                    "delta0": dict(self.base_counters),
                    "counters0": read_counters(self.cfg.iface),
                }
                print(f"incident open [{result.kind}] id={iid}", flush=True)
            else:
                for h in lost_now:
                    self.open_inc["hosts"][h] = self.open_inc["hosts"].get(h, 0) + 1
                self.open_inc["kind"] = result.kind
                self.open_inc["verdict"] = result.verdict
                self.store.update_incident(
                    self.open_inc["id"],
                    kind=result.kind,
                    verdict=result.verdict,
                    hosts=self.open_inc["hosts"],
                    meta={"delta": dlt, "flags": flags},
                    vantage_summary=self._vantage_summary_text(),
                )
        else:
            if self.open_inc:
                if self.clear_since is None:
                    self.clear_since = time.time()
                elif time.time() - self.clear_since >= self.cfg.incident_clear_s:
                    self._close_incident()

    def _close_incident(self) -> None:
        assert self.open_inc
        iid = self.open_inc["id"]
        counters1 = read_counters(self.cfg.iface)
        dlt = delta(self.open_inc["counters0"], counters1)
        crc = dlt.get("rx_crc_errors", 0) + dlt.get("rx_errors", 0)
        extra = ""
        if crc > 0:
            extra += (
                f" During the incident +{crc} receive/CRC errors on {self.cfg.iface} "
                "(physical/link hint)."
            )
        if dlt.get("multicast", 0) > 5000:
            extra += f" +{dlt['multicast']} multicast frames during the window (storm hint)."
        verdict = self.open_inc["verdict"] + extra
        pcap = matching_pcap(self.caps, self.open_inc["start"])
        self.store.update_incident(
            iid,
            verdict=verdict,
            hosts=self.open_inc["hosts"],
            meta={"delta": dlt},
            pcap=pcap,
            vantage_summary=self._vantage_summary_text(),
        )
        self.store.close_incident(iid)
        hosts = ", ".join(
            f"{h} [{self._group_label(h)}, {n}x]"
            for h, n in sorted(self.open_inc["hosts"].items(), key=lambda x: -x[1])
        )
        block = (
            f"\n=== {self.open_inc['start'].strftime('%Y-%m-%d %H:%M:%S')}  "
            f"[{self.open_inc['kind']}]  closed\n"
            f"  Affected: {hosts or '(detector only)'}\n"
            f"  Verdict:  {verdict}\n"
            f"  pcap:      {pcap or '(none)'}\n"
        )
        append_event(block)
        print(block, flush=True)
        self.open_inc = None
        self.clear_since = None

    def _group_label(self, host: str) -> str:
        g = self.cfg.group_for_host(host)
        return g.id if g else "?"

    def _vantage_summary_text(self) -> str:
        lines = [f"local={self.cfg.vantage.id}/{self.cfg.vantage.link}"]
        for row in self.store.list_satellites():
            lines.append(f"{row['vantage_id']}/{row.get('link')} last={row.get('received_at')}")
        return "; ".join(lines)

    def _append_csv(self, kind: str, ping: dict[str, dict[str, Any]]) -> None:
        day = datetime.now().strftime("%Y-%m-%d")
        path = self.logs / f"ping-{day}.csv"
        new = not path.exists()
        with path.open("a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(["ts", "host", "sent", "recv", "loss", "rtt_avg"])
            ts = datetime.now().isoformat(timespec="seconds")
            for host, p in ping.items():
                w.writerow(
                    [
                        ts,
                        host,
                        p.get("sent"),
                        p.get("recv"),
                        p.get("loss"),
                        p.get("rtt_avg", ""),
                    ]
                )

    def _append_iface_csv(self, counters: dict[str, int], carrier: dict[str, Any]) -> None:
        day = datetime.now().strftime("%Y-%m-%d")
        path = self.logs / f"iface-{day}.csv"
        new = not path.exists()
        with path.open("a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            keys = list(counters.keys())
            if new:
                w.writerow(["ts", "operstate", "carrier", "speed", *keys])
            w.writerow(
                [
                    datetime.now().isoformat(timespec="seconds"),
                    carrier.get("operstate"),
                    carrier.get("carrier"),
                    carrier.get("speed"),
                    *[counters.get(k, 0) for k in keys],
                ]
            )

    def _write_outputs(
        self,
        ping: dict[str, dict[str, Any]],
        counters: dict[str, int],
        carrier: dict[str, Any],
        sat_rows: list[dict[str, Any]],
        flags: dict[str, bool],
    ) -> None:
        host_stats = []
        for h, st in self.stats.items():
            g = self.cfg.group_for_host(h)
            loss_pct = (100.0 * st["lost"] / st["sent"]) if st["sent"] else 0.0
            host_stats.append(
                {
                    "host": h,
                    "group": g.id if g else "?",
                    "rounds": st["rounds"],
                    "bad": st["bad"],
                    "loss_pct": loss_pct,
                }
            )
        host_stats.sort(key=lambda r: -r["loss_pct"])

        sats = []
        now = time.time()
        expected = {s.id: s.link for s in self.cfg.satellites}
        seen = {r["vantage_id"]: r for r in sat_rows}
        for vid, link in expected.items():
            row = seen.get(vid)
            if not row:
                sats.append({"id": vid, "link": link, "last_seen": "never", "status": "missing"})
                continue
            age = _age(row.get("received_at"), now)
            status = "ok"
            if age is None or age > self.cfg.satellite_stale_s:
                status = "silent"
            sats.append(
                {
                    "id": vid,
                    "link": row.get("link") or link,
                    "last_seen": row.get("received_at"),
                    "status": status,
                }
            )
        for row in sat_rows:
            if row["vantage_id"] in expected:
                continue
            age = _age(row.get("received_at"), now)
            sats.append(
                {
                    "id": row["vantage_id"],
                    "link": row.get("link"),
                    "last_seen": row.get("received_at"),
                    "status": "ok" if age is not None and age <= self.cfg.satellite_stale_s else "silent",
                }
            )

        incidents = self.store.list_incidents(200)
        by_kind: dict[str, int] = {}
        for inc in incidents:
            by_kind[inc["kind"]] = by_kind.get(inc["kind"], 0) + 1
        if by_kind:
            top = max(by_kind.items(), key=lambda x: x[1])
            summary = f"Hottest class so far: {top[0]} ({top[1]}x). See incidents below."
        else:
            summary = "No incidents yet. Either the network is quiet, or canaries do not cover the failing path."
        if flags.get("wifi_vantages_bad") and flags.get("ethernet_vantages_ok"):
            summary += " Wi-Fi vantage trouble with healthy ethernet — watch for WIFI_PATH."

        dlt = delta(self.base_counters, counters)
        iface_text = (
            f"iface={self.cfg.iface} operstate={carrier.get('operstate')} "
            f"carrier={carrier.get('carrier')} speed={carrier.get('speed')}\n"
            f"deltas since start: {dlt}\n"
            f"flags: {flags}\n"
        )

        write_reports(
            self.cfg,
            started=self.started_s,
            host_stats=host_stats,
            incidents=incidents,
            satellites=sats,
            iface_text=iface_text,
            summary_text=summary,
        )

        # STATUS.txt
        lines = [
            "NETDIAG STATUS",
            f"generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"running since: {self.started_s}",
            f"vantage: {self.cfg.vantage.id} ({self.cfg.vantage.link})",
            "",
            "--- INCIDENTS ---",
        ]
        if not by_kind:
            lines.append("  none yet")
        else:
            for k, n in sorted(by_kind.items(), key=lambda x: -x[1]):
                lines.append(f"  {k:16} {n:3}x")
        lines.append("")
        lines.append("--- CANARY LOSS % ---")
        for row in host_stats[:20]:
            lines.append(
                f"  {row['host']:18} {row['group']:16} {row['loss_pct']:6.2f}%"
            )
        lines.append("")
        lines.append("--- SATELLITES ---")
        if not sats:
            lines.append("  (none)")
        for s in sats:
            lines.append(f"  {s['id']:16} {s['link']:10} {s['status']:8} {s['last_seen']}")
        lines.append("")
        lines.append("--- NIC ---")
        lines.append(f"  {iface_text.strip()}")
        if self.open_inc:
            lines.append("")
            lines.append(f"OPEN INCIDENT: {self.open_inc['kind']} id={self.open_inc['id']}")
        write_status("\n".join(lines) + "\n")


def _age(received_at: str | None, now_ts: float) -> float | None:
    if not received_at:
        return None
    try:
        from datetime import timezone

        dt = datetime.strptime(received_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return now_ts - dt.timestamp()
    except Exception:
        return None


def run_analyzer(config_path: str | None = None) -> None:
    cfg = load_config(config_path)
    Analyzer(cfg).run()
