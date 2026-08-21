from __future__ import annotations

import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlparse

if TYPE_CHECKING:
    from .config import Config
    from .store import Store

MAX_BODY = 256 * 1024

STATUS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>netdiag status</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 1.5rem; max-width: 42rem;
         color: #122; background: #f4f6f8; }
  h1 { font-size: 1.35rem; margin: 0 0 0.35rem; }
  .meta { color: #567; font-size: 0.9rem; margin-bottom: 1rem; }
  .card { background: #fff; border: 1px solid #dde3ea; border-radius: 8px;
          padding: 1rem 1.1rem; margin-bottom: 0.85rem; }
  .kind { font-weight: 700; font-size: 1.1rem; }
  .warn { color: #a33; }
  .ok { color: #2a6; }
  .muted { color: #678; }
  a { color: #06c; }
  ul { margin: 0.4rem 0 0; padding-left: 1.2rem; }
  .banner { background: #fff6e8; border: 1px solid #e6c98a; color: #6a4a10;
            padding: 0.65rem 0.8rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.9rem; }
  .links a { margin-right: 0.85rem; }
</style>
</head>
<body>
  <h1>netdiag</h1>
  <p class="meta" id="meta">Loading…</p>
  <div id="banner" class="banner" hidden></div>
  <div class="card" id="incident">
    <div class="muted">Open incident</div>
    <div id="incBody">…</div>
  </div>
  <div class="card">
    <div class="muted">Census</div>
    <div id="census">…</div>
  </div>
  <div class="card">
    <div class="muted">Satellites</div>
    <ul id="sats"></ul>
  </div>
  <div class="card links">
    <a href="/reports/report.html">Report</a>
    <a href="/reports/topology.html">Topology</a>
    <a href="/logs/STATUS.txt">STATUS.txt</a>
  </div>
  <p class="meta">LAN only — do not expose this port to the internet. Auto-refresh ~5s.</p>
<script>
async function tick() {
  try {
    const r = await fetch('/api/status.json', {cache:'no-store'});
    const d = await r.json();
    document.getElementById('meta').textContent =
      (d.site || 'netdiag') + ' · ' + (d.generated || '') +
      ' · ' + (d.vantage_id || '') + ' (' + (d.vantage_link || '') + ')';
    const ban = document.getElementById('banner');
    if (d.ingest_locked) {
      ban.hidden = false;
      ban.textContent = 'Ingest locked: set a real NETDIAG_INGEST_TOKEN (not change-me). Status UI still works.';
    } else { ban.hidden = true; }
    const inc = d.open_incident;
    const body = document.getElementById('incBody');
    if (inc && inc.kind) {
      body.innerHTML = '<div class="kind warn">' + esc(inc.kind) + '</div>' +
        '<div>Confidence: ' + esc(inc.confidence || 'n/a') + '</div>' +
        '<div>Where: ' + esc(inc.where_text || 'n/a') + '</div>' +
        (inc.href ? '<div><a href="' + esc(inc.href) + '">Incident page</a></div>' : '');
    } else {
      body.innerHTML = '<div class="ok">None open</div>';
    }
    document.getElementById('census').textContent = d.census_text || 'census: n/a';
    const ul = document.getElementById('sats');
    ul.innerHTML = '';
    const sats = d.satellites || [];
    if (!sats.length) {
      ul.innerHTML = '<li class="muted">None configured</li>';
    } else {
      sats.forEach(s => {
        const li = document.createElement('li');
        li.textContent = (s.id || '?') + ' · ' + (s.status || '') +
          ' · ' + (s.link || '') + ' · last ' + (s.last_seen || 'never');
        if (s.warn) li.className = 'warn';
        ul.appendChild(li);
      });
    }
  } catch (e) {
    document.getElementById('meta').textContent = 'Status unavailable';
  }
}
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
tick();
setInterval(tick, 5000);
</script>
</body>
</html>
"""


class StatusHub:
    """Thread-safe live snapshot for the status UI / JSON API."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snap: dict[str, Any] = {
            "site": "",
            "generated": "",
            "vantage_id": "",
            "vantage_link": "",
            "open_incident": None,
            "census_text": "census: n/a",
            "satellites": [],
            "health_notes": [],
            "ingest_locked": False,
        }

    def update(self, snap: dict[str, Any]) -> None:
        with self._lock:
            self._snap = dict(snap)

    def get(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._snap)


def start_ingest(
    cfg: "Config",
    store: "Store",
    status_hub: StatusHub | None = None,
    data_root: Path | None = None,
) -> ThreadingHTTPServer | None:
    """Start HTTP on ingest port. UI can run even when ingest token is locked."""
    from .config import data_dir

    status_ui = bool(getattr(cfg, "status_ui", True))
    if not cfg.ingest_enabled and not status_ui:
        print("ingest/status HTTP disabled", flush=True)
        return None

    token = (cfg.ingest_token or "").strip()
    ingest_locked = (not token or token == "change-me") and not cfg.allow_insecure_ingest
    if ingest_locked:
        print(
            "WARNING: ingest POST locked — token empty or 'change-me'. "
            "Status UI still serves on this port. Set NETDIAG_INGEST_TOKEN to enable satellites.",
            flush=True,
        )
    elif cfg.allow_insecure_ingest and (not token or token == "change-me"):
        print("WARNING: insecure ingest allowed", flush=True)

    hub = status_hub or StatusHub()
    # Seed ingest_locked so UI banner works before first report tick
    seed = hub.get()
    seed["ingest_locked"] = ingest_locked
    seed["site"] = cfg.site_name
    seed["vantage_id"] = cfg.vantage.id
    seed["vantage_link"] = cfg.vantage.link
    hub.update(seed)

    root = Path(data_root or data_dir()).resolve()
    reports_root = (root / "reports").resolve()
    logs_root = (root / "logs").resolve()
    expected_ids = {s.id for s in cfg.satellites}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            return

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = unquote(parsed.path)

            if not status_ui and path not in ("/healthz",):
                self.send_error(404, "status UI disabled")
                return

            if path in ("/", "/status"):
                self._send_bytes(200, "text/html; charset=utf-8", STATUS_HTML.encode("utf-8"))
                return

            if path == "/api/status.json":
                payload = hub.get()
                payload["ingest_locked"] = ingest_locked
                body = json.dumps(payload, indent=2, default=str).encode("utf-8")
                self._send_bytes(200, "application/json; charset=utf-8", body)
                return

            if path.startswith("/reports/"):
                rel = path[len("/reports/") :]
                self._send_file(reports_root, rel)
                return

            if path in ("/logs/STATUS.txt", "/STATUS.txt"):
                self._send_file(logs_root, "STATUS.txt")
                return

            if path == "/healthz":
                self._send_bytes(200, "text/plain", b"ok\n")
                return

            self.send_error(404)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path.rstrip("/") != "/ingest":
                self.send_error(404)
                return
            if not cfg.ingest_enabled:
                self.send_error(503, "ingest disabled")
                return
            if ingest_locked:
                self.send_error(
                    503,
                    "ingest locked: set a real token (not change-me)",
                )
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

        def _send_bytes(self, code: int, ctype: str, data: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send_file(self, base: Path, rel: str) -> None:
            if not rel or ".." in rel.replace("\\", "/").split("/"):
                self.send_error(400, "bad path")
                return
            target = (base / rel).resolve()
            try:
                target.relative_to(base)
            except ValueError:
                self.send_error(403, "forbidden")
                return
            if not target.is_file():
                self.send_error(404)
                return
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            if target.suffix in (".html", ".txt", ".json", ".csv"):
                if target.suffix == ".html":
                    ctype = "text/html; charset=utf-8"
                elif target.suffix == ".txt":
                    ctype = "text/plain; charset=utf-8"
                elif target.suffix == ".json":
                    ctype = "application/json; charset=utf-8"
            data = target.read_bytes()
            self._send_bytes(200, ctype, data)

    server = ThreadingHTTPServer((cfg.ingest_host, cfg.ingest_port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="ingest-http", daemon=True)
    thread.start()
    print(
        f"HTTP on {cfg.ingest_host}:{cfg.ingest_port}/ "
        f"(status UI={'on' if status_ui else 'off'}; "
        f"ingest={'locked' if ingest_locked else 'open'}; "
        f"expected satellites: {sorted(expected_ids) or 'none'})",
        flush=True,
    )
    return server
