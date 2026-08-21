from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from .config import Config
    from .store import Store


def start_ingest(cfg: "Config", store: "Store") -> ThreadingHTTPServer | None:
    if not cfg.ingest_enabled:
        return None

    token = cfg.ingest_token

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
            body = self.rfile.read(length)
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                self.send_error(400, "invalid json")
                return
            vid = str(payload.get("vantage_id") or payload.get("vantage", {}).get("id") or "")
            link = str(payload.get("link") or payload.get("vantage", {}).get("link") or "ethernet")
            if not vid:
                self.send_error(400, "missing vantage_id")
                return
            store.upsert_satellite(vid, link.lower(), payload)
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer((cfg.ingest_host, cfg.ingest_port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="ingest", daemon=True)
    thread.start()
    print(f"ingest listening on {cfg.ingest_host}:{cfg.ingest_port}/ingest", flush=True)
    return server
