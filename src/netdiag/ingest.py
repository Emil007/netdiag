from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from .config import Config
    from .store import Store

MAX_BODY = 256 * 1024


def start_ingest(cfg: "Config", store: "Store") -> ThreadingHTTPServer | None:
    if not cfg.ingest_enabled:
        print("ingest disabled", flush=True)
        return None

    token = (cfg.ingest_token or "").strip()
    if not token or token == "change-me":
        if not cfg.allow_insecure_ingest:
            print(
                "ERROR: ingest token empty or placeholder 'change-me'. "
                "Set ingest.token in config.yaml (and matching satellite token). "
                "Or set NETDIAG_ALLOW_INSECURE_INGEST=1 for a lab only.",
                flush=True,
            )
            return None
        print("WARNING: insecure ingest allowed", flush=True)

    expected_ids = {s.id for s in cfg.satellites}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            return

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path.rstrip("/") != "/ingest":
                self.send_error(404)
                return
            auth = self.headers.get("Authorization", "")
            hdr_token = self.headers.get("X-Netdiag-Token", "")
            provided = hdr_token
            if auth.lower().startswith("bearer "):
                provided = auth.split(" ", 1)[1].strip()
            if token and provided != token:
                self.send_error(401, "bad token")
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY:
                self.send_error(413, "body too large")
                return
            body = self.rfile.read(length)
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                self.send_error(400, "invalid json")
                return
            if not isinstance(payload, dict):
                self.send_error(400, "invalid payload")
                return
            vid = str(payload.get("vantage_id") or "")
            link = str(payload.get("link") or "ethernet").lower()
            avail = str(payload.get("availability") or "")
            event = str(payload.get("event") or "sample")
            if not vid or len(vid) > 64:
                self.send_error(400, "missing vantage_id")
                return
            # Unknown ids are stored but mark expected=false; classification skips
            # unknown for triangulation until listed in config (still record presence)
            state = "offline" if event == "offline" else "online"
            store.upsert_satellite(
                vid,
                link,
                payload,
                state=state,
                availability=avail,
                event=event,
            )
            self.send_response(204)
            self.end_headers()

    # Bind as configured; comment in compose recommends LAN IP
    server = ThreadingHTTPServer((cfg.ingest_host, cfg.ingest_port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="ingest", daemon=True)
    thread.start()
    print(
        f"ingest listening on {cfg.ingest_host}:{cfg.ingest_port}/ingest "
        f"(expected satellites: {sorted(expected_ids) or 'none yet'})",
        flush=True,
    )
    return server
