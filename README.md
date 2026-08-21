# netdiag

Home-LAN diagnostics as a **Docker Compose** stack. Run for a few days on a Linux host with Docker Engine, then open the HTML report (and topology map).

Image (multi-arch amd64 / arm64 / **arm/v7**): `ghcr.io/emil007/netdiag:latest` — built on GitHub Actions. Pull it; do not `build:` on the Docker host unless you are developing. Arm/v7 covers Raspberry Pi 2 and other 32-bit Pis.

## Compose builder (GitHub Pages)

Prefer a form over hand-editing YAML? Use the **[compose builder](https://emil007.github.io/netdiag/)** — client-side only; it downloads a ready `docker-compose.yml` (and optional satellite compose). Nothing is uploaded.

Repo settings: **Pages → Source → GitHub Actions** (one-time) so the workflow can publish `docs/composer/`.

You can still hand-edit `docker-compose.yml` as below.

## Quick start

Edit **only** `docker-compose.yml` (canaries, satellites, thresholds live in `NETDIAG_CONFIG_YAML`), then:

```bash
docker compose up -d
```

Short overlays in the same file: `IFACE`, `TZ`, `NETDIAG_INGEST_TOKEN`. No separate `config.yaml` mount is required.

**Live status (same port as ingest):** open `http://<coordinator-lan-ip>:8787/` — open incident, census, satellites; links into report/topology HTML. Satellites still `POST` to `http://<ip>:8787/ingest`. LAN only — do not expose this port to the internet. The status page works even while the token is still `change-me`; ingest stays locked until you set a real token.

Reports on disk: `data/reports/report.html`, `data/reports/topology.html`. Also `data/logs/STATUS.txt` and `EVENTS.log`.

Daily `ping-` / `iface-` CSVs are deleted after `csv_keep_days` (default 14). Old incident HTML is pruned after `incident_html_keep_days` (default 30), keeping the last ~200 report links.

If `docker pull` fails: `docker login ghcr.io`, or set the GHCR package visibility to public.

Ingest will **not** accept satellites until the token is something other than `change-me` (unless `NETDIAG_ALLOW_INSECURE_INGEST=1` for a lab).

**Portainer (optional):** paste the same `docker-compose.yml` into a stack. Some UIs need an absolute path for `./data`.

## Satellites (optional)

Edit `docker-compose.satellite.yml` (`NETDIAG_CONFIG_YAML` + token), then:

```bash
docker compose -f docker-compose.satellite.yml up -d
```

List the satellite under `satellites:` in the coordinator compose `NETDIAG_CONFIG_YAML` (default list is empty).

### Bare Raspberry Pi (headless)

Flash Raspberry Pi OS Lite (32-bit for Pi 2). You can **copy bootfs files by
hand** or use `prepare-boot.ps1` — see
[`scripts/pi-satellite/README.md`](scripts/pi-satellite/README.md).
**Env + groups alone do not install Docker**; zero-touch needs `user-data` (or
SSH bootstrap). Image includes **linux/arm/v7** for Pi 2.

## Docs

- [docs/MAPPING.md](docs/MAPPING.md) — canaries, dumb switches, placement
- [docs/FINDINGS.md](docs/FINDINGS.md) — how to read classes / Where sentences
- `config.example.yaml` — optional docs-only mirror of the compose YAML block

## Requirements

- Linux + Docker Compose v2
- `network_mode: host`
- `NET_RAW` + `NET_ADMIN`

## License

MIT — only on networks you own or are authorized to monitor.
