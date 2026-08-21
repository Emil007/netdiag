from __future__ import annotations

import csv
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .classify import (
    ClassResult,
    classify_detector_event,
    classify_loss,
    host_down,
    resolve_satellite_states,
)
from .config import Config, data_dir, load_config
from .detectors.arp_watch import ArpWatch
from .detectors.bcast_rate import BcastRateWatch
from .detectors.dhcp_watch import DhcpWatch
from .detectors.dns_health import dns_check
from .detectors.iface_counters import delta, read_carrier, read_counters
from .detectors.path_check import run_path_checks_async
from .detectors.ping_matrix import ping_round, tcp_probe
from .ingest import start_ingest
from .report import append_event, matching_pcap, rotate_events_log, write_reports, write_status
from .store import Store
from .timeutil import display_ts, utcnow, utcnow_iso


class Analyzer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.root = data_dir()
        self.logs = self.root / "logs"
        self.caps = self.root / "captures"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.caps.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.logs / "netdiag.db")
        self.started = utcnow()
        self.started_s = display_ts(self.started, cfg.timezone)
        self.stats: dict[str, dict[str, Any]] = {
            h: {
                "rounds": 0,
                "bad": 0,
                "lost": 0,
                "sent": 0,
                "fail_streak": 0,
                "rtt_sum": 0.0,
                "rtt_n": 0,
                "rtt_max": 0.0,
            }
            for h in cfg.hosts()
        }
        self.open_inc: dict[str, Any] | None = None
        self.clear_since: float | None = None
        self.pending_kind: str | None = None
        self.pending_rounds = 0
        self.base_counters = read_counters(cfg.iface)
        self.round_counters = dict(self.base_counters)
        self.last_dns = 0.0
        self.last_path = 0.0
        self.last_report = 0.0
        self.last_dns_results: list[dict[str, Any]] = []
        self.last_paths: list[dict[str, Any]] = []
        self.path_baselines: dict[str, list[str]] = {}
        self.last_speed: int | None = None
        self.iface_ok = (Path("/sys/class/net") / cfg.iface).exists()
        self.health_notes: list[str] = []
        self.open_detectors: dict[str, int] = {}  # identity -> incident id

        learned = self.store.get_kv("dhcp_expected_mac", cfg.expected_dhcp_mac)
        self.dhcp = DhcpWatch(
            cfg.iface,
            learned or cfg.expected_dhcp_mac,
            on_alarm=self._on_dhcp,
            on_learned=self._on_dhcp_learned,
        )
        self.arp = ArpWatch(cfg.iface, on_conflict=self._on_arp)
        self.bcast = BcastRateWatch(cfg.iface)

        for s in cfg.satellites:
            self.store.ensure_satellite_row(
                s.id, s.link, s.resolved_availability()
            )

        if not self.iface_ok:
            self.health_notes.append(
                f"ERROR: interface '{cfg.iface}' not found under /sys/class/net — "
                "counters/capture/DHCP/ARP will be dead; fix IFACE."
            )
        if cfg.vantage.link == "ethernet" and not cfg.hosts_by_role("same_segment"):
            self.health_notes.append(
                "WARNING: no same_segment canary — cannot tell local-switch failure from "
                "uplink-to-router failure on this ethernet probe."
            )

    def _on_dhcp_learned(self, mac: str) -> None:
        self.store.set_kv("dhcp_expected_mac", mac)
        print(f"learned DHCP server MAC {mac}", flush=True)

    def _on_dhcp(self, mac: str, msg: str) -> None:
        self._coalesced_detector("ROGUE_DHCP", mac, msg, meta={"mac": mac})

    def _on_arp(self, ip: str, a: str, b: str) -> None:
        msg = f"IP conflict: {ip} claimed by {a} and {b} within a short window"
        self._coalesced_detector("IP_CONFLICT", ip, msg, meta={"ip": ip, "macs": [a, b]})

    def _coalesced_detector(
        self, kind: str, identity: str, verdict: str, meta: dict | None = None
    ) -> None:
        key = f"{kind}:{identity}"
        if key in self.open_detectors:
            self.store.update_incident(
                self.open_detectors[key],
                verdict=verdict,
                meta=meta or {},
            )
            return
        if self.store.recently_closed(kind, key, self.cfg.incident_clear_s):
            return
        existing = self.store.find_open_by_identity(kind, key)
        if existing:
            self.open_detectors[key] = existing
            return
        pcap = matching_pcap(self.caps, utcnow())
        iid = self.store.open_incident(
            kind,
            verdict,
            {},
            meta=meta,
            pcap=pcap,
            vantage_summary=self._vantage_summary_text(),
            identity_key=key,
        )
        self.open_detectors[key] = iid
        block = (
            f"\n=== {display_ts(utcnow_iso(), self.cfg.timezone)}  [{kind}]\n"
            f"  Verdict:  {verdict}\n"
            f"  pcap:      {pcap or '(none)'}\n"
        )
        append_event(block)
        print(block, flush=True)

    def _clear_detector_if_ok(self, kind: str, identity: str) -> None:
        key = f"{kind}:{identity}"
        iid = self.open_detectors.pop(key, None)
        if iid:
            self.store.close_incident(iid)

    def run(self) -> None:
        print(
            f"analyzer {self.cfg.vantage.id} on {self.cfg.iface} "
            f"({len(self.cfg.hosts())} canaries)",
            flush=True,
        )
        for note in self.health_notes:
            print(note, flush=True)
        start_ingest(self.cfg, self.store)
        if self.iface_ok:
            self.dhcp.start()
            self.arp.start()
            self.bcast.start()
        try:
            while True:
                t0 = time.time()
                self._tick()
                sleep = max(0.2, self.cfg.ping_interval_s - (time.time() - t0))
                time.sleep(sleep)
        finally:
            self.dhcp.stop()
            self.arp.stop()
            self.bcast.stop()

    def _tick(self) -> None:
        ping = ping_round(self.cfg.hosts(), iface=self.cfg.iface)
        # ICMP fallback for external canaries
        for h in self.cfg.hosts_by_role("external"):
            p = ping.get(h) or {}
            if host_down(p, 100):
                gw_ok = any(
                    not host_down(ping.get(g), self.cfg.loss_threshold_pct)
                    for g in self.cfg.hosts_by_role("gateway")
                )
                if gw_ok and tcp_probe(h, 443):
                    ping[h] = {
                        "sent": 3,
                        "recv": 3,
                        "loss": 0,
                        "note": "icmp_lost_tcp443_ok",
                    }

        counters = read_counters(self.cfg.iface)
        carrier = read_carrier(self.cfg.iface)
        dlt = delta(self.round_counters, counters)
        self.round_counters = counters
        bcast = self.bcast.tick() if self.iface_ok else {"pps": 0, "baseline": 0, "storm": 0}

        speed = carrier.get("speed")
        if isinstance(speed, int) and speed > 0:
            if self.last_speed and speed < self.last_speed:
                note = f"NIC speed dropped {self.last_speed} → {speed} Mb/s on {self.cfg.iface}"
                self.health_notes.append(note)
                append_event(f"\n=== {display_ts(utcnow_iso(), self.cfg.timezone)}  [NIC_SPEED]\n  Verdict:  {note}\n")
            self.last_speed = speed

        lost_now: set[str] = set()
        for host, st in self.stats.items():
            st["rounds"] += 1
            p = ping.get(host) or {"sent": 0, "recv": 0, "loss": 100}
            st["sent"] += int(p.get("sent", 0))
            st["lost"] += int(p.get("sent", 0)) - int(p.get("recv", 0))
            rtt = p.get("rtt_avg")
            if isinstance(rtt, (int, float)):
                st["rtt_sum"] += float(rtt)
                st["rtt_n"] += 1
                st["rtt_max"] = max(float(st["rtt_max"]), float(p.get("rtt_max") or rtt))
            down = host_down(p, self.cfg.loss_threshold_pct)
            if down:
                st["fail_streak"] += 1
                st["bad"] += 1
            else:
                st["fail_streak"] = 0
            if st["fail_streak"] >= self.cfg.fail_rounds:
                lost_now.add(host)

        self._append_csv(ping)
        self._append_iface_csv(counters, carrier)

        now = time.time()
        warmup = (now - self.started.timestamp()) < self.cfg.warmup_s

        if now - self.last_dns >= self.cfg.dns_interval_s:
            self.last_dns_results = dns_check(
                self.cfg.dns_resolvers, self.cfg.dns_names, self.cfg.dns_timeout_ms
            )
            self.last_dns = now
            self._eval_dns(ping)

        if now - self.last_path >= self.cfg.path_interval_s:
            targets = []
            for role in ("gateway", "external"):
                targets.extend(list(self.cfg.hosts_by_role(role))[:1])
            run_path_checks_async(targets, self.cfg.iface, self._on_paths)
            self.last_path = now

        sat_rows = self.store.list_satellites()
        sat_states = resolve_satellite_states(self.cfg, sat_rows, now)
        # Persist computed states for always-listed never_seen rows
        for s in self.cfg.satellites:
            self.store.ensure_satellite_row(s.id, s.link, s.resolved_availability())

        same_seg = self.cfg.hosts_by_role("same_segment")
        same_down = bool(same_seg) and same_seg <= lost_now
        carrier_down = carrier.get("carrier") == 0 or carrier.get("operstate") in (
            "down",
            "lowerlayerdown",
        )
        link_err = dlt.get("rx_errors", 0) + dlt.get("rx_crc_errors", 0)

        result = None
        if not warmup:
            result = classify_loss(
                self.cfg,
                lost_now,
                local_ping=ping,
                sat_states=sat_states,
                same_segment_down=same_down,
                carrier_down=carrier_down,
                warmup=warmup,
                loss_threshold_pct=self.cfg.loss_threshold_pct,
            )

        annotations: list[str] = []
        if link_err > 0:
            annotations.append(f"+{link_err} NIC receive/CRC errors this interval")
        if bcast.get("storm"):
            annotations.append(
                f"broadcast/multicast pps={bcast['pps']:.0f} (baseline≈{bcast['baseline']:.0f})"
            )
        if result and annotations:
            result.annotations.extend(annotations)
            result.verdict = result.verdict + " " + "; ".join(annotations) + "."
        elif not result and annotations and link_err > 0 and not lost_now:
            # standalone LINK_ERRORS only with no topology pattern
            result = classify_detector_event(
                "LINK_ERRORS",
                f"Probe NIC saw +{link_err} receive/CRC errors without a clear topology loss pattern.",
            )
        elif not result and bcast.get("storm") and not lost_now:
            result = classify_detector_event(
                "BCAST_STORM",
                f"Broadcast/multicast rate elevated (pps={bcast['pps']:.0f}, baseline≈{bcast['baseline']:.0f}) "
                "without canary loss.",
            )

        self._update_incident(result, lost_now, dlt, sat_states)

        if now - self.last_report >= self.cfg.report_interval_s:
            self._write_outputs(ping, counters, carrier, sat_states, bcast)
            rotate_events_log(self.logs)
            self.last_report = now

    def _eval_dns(self, ping: dict[str, dict[str, Any]]) -> None:
        fails = [r for r in self.last_dns_results if not r.get("ok")]
        if not fails or len(fails) < max(1, len(self.last_dns_results) // 2):
            for r in self.cfg.dns_resolvers:
                self._clear_detector_if_ok("DNS_FAILURE", r)
            return
        # If resolver IP itself is unreachable, that is uplink/router — not DNS
        for r in fails:
            resolver = r["resolver"]
            if host_down(ping.get(resolver), self.cfg.loss_threshold_pct):
                continue
            self._coalesced_detector(
                "DNS_FAILURE",
                resolver,
                f"DNS resolver {resolver} failing lookups while the resolver IP is still reachable.",
                meta={"results": [r]},
            )

    def _on_paths(self, results: list[dict[str, Any]]) -> None:
        self.last_paths = results
        for r in results:
            target = r.get("target")
            hops = [h for h in (r.get("hops") or []) if h and h != "*"]
            if not target or len(hops) < 1:
                continue
            prev = self.path_baselines.get(target)
            if prev is None:
                self.path_baselines[target] = hops
                continue
            if hops != prev:
                msg = f"Path to {target} changed: {' → '.join(prev)}  =>  {' → '.join(hops)}"
                self._coalesced_detector("PATH_CHANGE", target, msg, meta={"old": prev, "new": hops})
                self.path_baselines[target] = hops

    def _update_incident(
        self,
        result: ClassResult | None,
        lost_now: set[str],
        dlt: dict[str, int],
        sat_states: list[dict[str, Any]],
    ) -> None:
        if result:
            # confirmation hysteresis for ping classes
            if result.kind not in (
                "ROGUE_DHCP",
                "IP_CONFLICT",
                "DNS_FAILURE",
                "LINK_ERRORS",
                "BCAST_STORM",
                "PATH_CHANGE",
            ):
                if self.pending_kind == result.kind:
                    self.pending_rounds += 1
                else:
                    self.pending_kind = result.kind
                    self.pending_rounds = 1
                if self.pending_rounds < self.cfg.confirm_rounds and not self.open_inc:
                    return

            self.clear_since = None
            if not self.open_inc:
                pcap = matching_pcap(self.caps, utcnow())
                hosts = {h: 1 for h in lost_now}
                meta = {
                    "delta": dlt,
                    "matrix": result.matrix,
                    "confidence": result.confidence,
                    "annotations": result.annotations,
                }
                iid = self.store.open_incident(
                    result.kind,
                    result.verdict,
                    hosts,
                    meta=meta,
                    pcap=pcap,
                    vantage_summary=self._vantage_summary_text(),
                    where_text=result.where_text,
                    identity_key=f"ping:{result.kind}",
                )
                self.open_inc = {
                    "id": iid,
                    "kind": result.kind,
                    "verdict": result.verdict,
                    "where_text": result.where_text,
                    "hosts": hosts,
                    "start": utcnow(),
                    "counters0": read_counters(self.cfg.iface),
                    "matrix": result.matrix,
                }
                print(f"incident open [{result.kind}] id={iid}", flush=True)
            else:
                for h in lost_now:
                    self.open_inc["hosts"][h] = self.open_inc["hosts"].get(h, 0) + 1
                self.open_inc["kind"] = result.kind
                self.open_inc["verdict"] = result.verdict
                self.open_inc["where_text"] = result.where_text
                self.open_inc["matrix"] = result.matrix
                self.store.update_incident(
                    self.open_inc["id"],
                    kind=result.kind,
                    verdict=result.verdict,
                    hosts=self.open_inc["hosts"],
                    meta={"delta": dlt, "matrix": result.matrix, "confidence": result.confidence},
                    vantage_summary=self._vantage_summary_text(),
                    where_text=result.where_text,
                )
        else:
            self.pending_kind = None
            self.pending_rounds = 0
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
            extra += f" During the incident +{crc} receive/CRC errors on {self.cfg.iface}."
        if dlt.get("multicast", 0) > 5000:
            extra += f" +{dlt['multicast']} multicast counter delta during the window."
        verdict = self.open_inc["verdict"] + extra
        pcap = matching_pcap(self.caps, self.open_inc["start"])
        self.store.update_incident(
            iid,
            verdict=verdict,
            hosts=self.open_inc["hosts"],
            meta={"delta": dlt, "matrix": self.open_inc.get("matrix")},
            pcap=pcap,
            vantage_summary=self._vantage_summary_text(),
            where_text=self.open_inc.get("where_text") or "",
        )
        self.store.close_incident(iid)
        hosts = ", ".join(
            f"{h} [{self._group_label(h)}, {n}x]"
            for h, n in sorted(self.open_inc["hosts"].items(), key=lambda x: -x[1])
        )
        block = (
            f"\n=== {display_ts(self.open_inc['start'], self.cfg.timezone)}  "
            f"[{self.open_inc['kind']}]  closed\n"
            f"  Affected: {hosts or '(detector)'}\n"
            f"  Verdict:  {verdict}\n"
            f"  Where:    {self.open_inc.get('where_text') or 'n/a'}\n"
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
        now = time.time()
        states = resolve_satellite_states(self.cfg, self.store.list_satellites(), now)
        parts = [f"local={self.cfg.vantage.id}/{self.cfg.vantage.link}/online"]
        for s in states:
            parts.append(
                f"{s['vantage_id']}/{s.get('link')}/{s.get('state')}"
                f"(avail={s.get('availability')}, last={s.get('received_at') or 'never'})"
            )
        return "; ".join(parts)

    def _append_csv(self, ping: dict[str, dict[str, Any]]) -> None:
        day = utcnow().strftime("%Y-%m-%d")
        path = self.logs / f"ping-{day}.csv"
        new = not path.exists()
        with path.open("a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(["ts", "host", "sent", "recv", "loss", "rtt_avg", "note"])
            ts = utcnow_iso()
            for host, p in ping.items():
                w.writerow(
                    [
                        ts,
                        host,
                        p.get("sent"),
                        p.get("recv"),
                        p.get("loss"),
                        p.get("rtt_avg", ""),
                        p.get("note", ""),
                    ]
                )

    def _append_iface_csv(self, counters: dict[str, int], carrier: dict[str, Any]) -> None:
        day = utcnow().strftime("%Y-%m-%d")
        path = self.logs / f"iface-{day}.csv"
        new = not path.exists()
        with path.open("a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            keys = list(counters.keys())
            if new:
                w.writerow(["ts", "operstate", "carrier", "speed", *keys])
            w.writerow(
                [
                    utcnow_iso(),
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
        sat_states: list[dict[str, Any]],
        bcast: dict[str, float],
    ) -> None:
        host_stats = []
        for h, st in self.stats.items():
            g = self.cfg.group_for_host(h)
            loss_pct = (100.0 * st["lost"] / st["sent"]) if st["sent"] else 0.0
            rtt_avg = (st["rtt_sum"] / st["rtt_n"]) if st["rtt_n"] else None
            host_stats.append(
                {
                    "host": h,
                    "group": g.id if g else "?",
                    "rounds": st["rounds"],
                    "bad": st["bad"],
                    "loss_pct": loss_pct,
                    "rtt_avg": rtt_avg,
                    "rtt_max": st["rtt_max"] or None,
                }
            )
        host_stats.sort(key=lambda r: -r["loss_pct"])

        sats = []
        for s in sat_states:
            state = s.get("state", "never_seen")
            sats.append(
                {
                    "id": s["vantage_id"],
                    "link": s.get("link"),
                    "availability": s.get("availability"),
                    "last_seen": display_ts(s.get("received_at"), self.cfg.timezone)
                    if s.get("received_at")
                    else "never",
                    "status": state,
                    "warn": state in ("stale", "fault"),
                }
            )

        incidents = self.store.list_incidents(200)
        # hottest by duration * recency weight, not raw count
        scores: dict[str, float] = {}
        now = utcnow().timestamp()
        for inc in incidents:
            kind = inc["kind"]
            try:
                start = datetime.strptime(inc["start"], "%Y-%m-%dT%H:%M:%SZ").timestamp()
            except Exception:
                start = now
            end = now
            if inc.get("end"):
                try:
                    end = datetime.strptime(inc["end"], "%Y-%m-%dT%H:%M:%SZ").timestamp()
                except Exception:
                    pass
            dur = max(1.0, end - start)
            age_h = max(0.1, (now - end) / 3600.0)
            scores[kind] = scores.get(kind, 0.0) + dur / age_h
        by_kind = sorted(scores.items(), key=lambda x: -x[1])

        if by_kind:
            summary = f"Hottest suspect (duration×recency): {by_kind[0][0]}."
        else:
            summary = "No incidents yet."
        if self.health_notes:
            summary += " " + self.health_notes[-1]

        from .classify import build_vantage_matrix

        matrix = build_vantage_matrix(
            self.cfg, ping, sat_states, self.cfg.loss_threshold_pct
        )

        dlt = delta(self.base_counters, counters)
        iface_text = (
            f"iface={self.cfg.iface} exists={self.iface_ok} "
            f"operstate={carrier.get('operstate')} carrier={carrier.get('carrier')} "
            f"speed={carrier.get('speed')}\n"
            f"deltas since start: {dlt}\n"
            f"bcast pps={bcast.get('pps'):.1f} baseline≈{bcast.get('baseline'):.1f}\n"
            f"canaries={len(self.cfg.hosts())} satellites={len(sat_states)}\n"
        )
        for n in self.health_notes[-5:]:
            iface_text += n + "\n"

        write_reports(
            self.cfg,
            started=self.started_s,
            host_stats=host_stats,
            incidents=incidents,
            satellites=sats,
            iface_text=iface_text,
            summary_text=summary,
            by_kind_weighted=by_kind,
            matrix=matrix,
        )

        lines = [
            "NETDIAG STATUS",
            f"generated: {display_ts(utcnow_iso(), self.cfg.timezone)}",
            f"running since: {self.started_s}",
            f"vantage: {self.cfg.vantage.id} ({self.cfg.vantage.link})",
            f"iface: {self.cfg.iface} ok={self.iface_ok}",
            "",
            "--- HEALTH ---",
        ]
        lines.extend(f"  {n}" for n in (self.health_notes or ["  ok"]))
        lines += ["", "--- INCIDENTS (weighted) ---"]
        if not by_kind:
            lines.append("  none yet")
        else:
            for k, score in by_kind[:10]:
                lines.append(f"  {k:16} score={score:.0f}")
        lines += ["", "--- CANARY LOSS % ---"]
        for row in host_stats[:20]:
            rtt = f" rtt≈{row['rtt_avg']:.1f}ms" if row.get("rtt_avg") is not None else ""
            lines.append(
                f"  {row['host']:18} {row['group']:16} {row['loss_pct']:6.2f}%{rtt}"
            )
        lines += ["", "--- SATELLITES ---"]
        if not sats:
            lines.append("  (none configured)")
        for s in sats:
            lines.append(
                f"  {s['id']:16} {s['link']:10} {s['status']:12} "
                f"avail={s.get('availability')} last={s['last_seen']}"
            )
        lines += ["", "--- NIC ---", f"  {iface_text.strip()}"]
        if self.open_inc:
            lines += ["", f"OPEN INCIDENT: {self.open_inc['kind']} id={self.open_inc['id']}"]
            lines.append(f"  Where: {self.open_inc.get('where_text')}")
        write_status("\n".join(lines) + "\n")


def run_analyzer(config_path: str | None = None) -> None:
    cfg = load_config(config_path)
    Analyzer(cfg).run()
