#!/usr/bin/env bash
# netdiag — install satellite on a Raspberry Pi (wired or wifi).
# Safe to re-run. Reads /boot/firmware/netdiag.env or /boot/netdiag.env when present.
set -euo pipefail

REPO_RAW="${NETDIAG_REPO_RAW:-https://raw.githubusercontent.com/Emil007/netdiag/main}"
IMAGE="${NETDIAG_IMAGE:-ghcr.io/emil007/netdiag:latest}"
INSTALL_DIR="${NETDIAG_INSTALL_DIR:-/opt/netdiag}"

die() { echo "netdiag-bootstrap: $*" >&2; exit 1; }
log() { echo "netdiag-bootstrap: $*"; }

find_env_file() {
  local f
  for f in \
    "${NETDIAG_ENV_FILE:-}" \
    /boot/firmware/netdiag.env \
    /boot/netdiag.env \
    /etc/netdiag.env \
    "${INSTALL_DIR}/netdiag.env"
  do
    [[ -n "$f" && -f "$f" ]] && { echo "$f"; return 0; }
  done
  return 1
}

find_groups_file() {
  local f
  for f in \
    "${NETDIAG_GROUPS_FILE:-}" \
    /boot/firmware/netdiag.groups.yaml \
    /boot/netdiag.groups.yaml \
    /etc/netdiag.groups.yaml \
    "${INSTALL_DIR}/netdiag.groups.yaml"
  do
    [[ -n "$f" && -f "$f" ]] && { echo "$f"; return 0; }
  done
  return 1
}

# --- args / env ---
MODE=""
COORDINATOR_URL=""
TOKEN=""
VANTAGE_ID=""
IFACE=""
LINK=""
AVAILABILITY=""
NOTE=""
TZ_VALUE="${TZ:-Europe/Berlin}"
SITE_NAME="${SITE_NAME:-Home LAN}"
DNS_RESOLVER=""
DNS_NAMES="${DNS_NAMES:-example.com,cloudflare.com}"

usage() {
  cat <<'EOF'
Usage: bootstrap.sh [--mode wired|wifi] [--coordinator URL] [--token TOKEN] ...

  --mode          wired (ethernet to router) or wifi
  --coordinator   ingest URL, e.g. http://192.168.1.222:8787/ingest
  --token         same as coordinator NETDIAG_INGEST_TOKEN
  --vantage-id    must match coordinator satellites[].id
  --iface         eth0 / wlan0 / ...
  --env-file      path to netdiag.env
  --groups-file   YAML list under groups: (mirror coordinator)

Prefer dropping netdiag.env (+ optional netdiag.groups.yaml) and
netdiag-bootstrap.sh on the boot partition; cloud-init (-Unattended) runs
this script on first boot. Curl from GitHub is only a fallback.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --coordinator|--url) COORDINATOR_URL="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --vantage-id) VANTAGE_ID="${2:-}"; shift 2 ;;
    --iface) IFACE="${2:-}"; shift 2 ;;
    --env-file) NETDIAG_ENV_FILE="${2:-}"; shift 2 ;;
    --groups-file) NETDIAG_GROUPS_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

ENV_LOADED=""
if env_path="$(find_env_file)"; then
  log "loading $env_path"
  ENV_LOADED="$env_path"
  tmp_env="$(mktemp)"
  # Strip CRLF; quote unquoted values that contain spaces so `source` is safe
  # (e.g. SITE_NAME=Home LAN → SITE_NAME="Home LAN")
  sed 's/\r$//' "$env_path" \
    | sed -E 's/^([A-Za-z_][A-Za-z0-9_]*)=([^"'\''].*[[:space:]].*)$/\1="\2"/' \
    >"$tmp_env"
  set -a
  # shellcheck disable=SC1090
  source "$tmp_env"
  set +a
  rm -f "$tmp_env"
fi

MODE="${MODE:-${NETDIAG_MODE:-}}"
COORDINATOR_URL="${COORDINATOR_URL:-${NETDIAG_COORDINATOR_URL:-}}"
TOKEN="${TOKEN:-${NETDIAG_TOKEN:-${NETDIAG_COORDINATOR_TOKEN:-}}}"
VANTAGE_ID="${VANTAGE_ID:-${NETDIAG_VANTAGE_ID:-}}"
IFACE="${IFACE:-${NETDIAG_IFACE:-}}"
TZ_VALUE="${TZ:-$TZ_VALUE}"
SITE_NAME="${SITE_NAME:-Home LAN}"
DNS_RESOLVER="${DNS_RESOLVER:-${NETDIAG_DNS_RESOLVER:-}}"

[[ -n "$MODE" ]] || die "MODE missing (wired|wifi) — set in netdiag.env or --mode"
[[ -n "$COORDINATOR_URL" ]] || die "COORDINATOR_URL missing"
[[ -n "$TOKEN" && "$TOKEN" != "change-me" ]] || die "TOKEN missing or still change-me"

case "$MODE" in
  wired|ethernet)
    LINK="${LINK:-ethernet}"
    AVAILABILITY="${AVAILABILITY:-always}"
    IFACE="${IFACE:-eth0}"
    VANTAGE_ID="${VANTAGE_ID:-sat-fritz-wired}"
    NOTE="${NOTE:-Pi wired satellite}"
    ;;
  wifi|wlan)
    LINK="${LINK:-wifi}"
    AVAILABILITY="${AVAILABILITY:-intermittent}"
    IFACE="${IFACE:-wlan0}"
    VANTAGE_ID="${VANTAGE_ID:-sat-wifi}"
    NOTE="${NOTE:-Pi Wi-Fi satellite}"
    ;;
  *) die "MODE must be wired or wifi (got: $MODE)" ;;
esac

if [[ -z "$DNS_RESOLVER" ]]; then
  # best-effort: first nameserver, else empty (omit dns block hosts later)
  DNS_RESOLVER="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
fi

DNS_NAMES_YAML=""
IFS=',' read -ra _dns_names <<<"$DNS_NAMES"
for n in "${_dns_names[@]}"; do
  n="$(echo "$n" | xargs)"
  [[ -n "$n" ]] || continue
  DNS_NAMES_YAML+="\"$n\", "
done
DNS_NAMES_YAML="${DNS_NAMES_YAML%, }"

GROUPS_YAML=""
if groups_path="$(find_groups_file)"; then
  log "using groups from $groups_path"
  GROUPS_YAML="$(sed 's/\r$//' "$groups_path")"
else
  log "no netdiag.groups.yaml — using minimal router + internet (edit and re-run to match coordinator)"
  GROUPS_YAML="$(cat <<'YAML'
- id: router
  role: gateway
  hosts: ["192.168.1.1"]
- id: internet
  role: external
  hosts: ["1.1.1.1", "8.8.8.8"]
YAML
)"
fi

# indent groups 2 spaces under groups:
GROUPS_INDENTED="$(printf '%s\n' "$GROUPS_YAML" | sed 's/^/          /')"

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo)"

export DEBIAN_FRONTEND=noninteractive
if ! command -v docker >/dev/null 2>&1; then
  log "installing Docker"
  apt-get update -y
  apt-get install -y ca-certificates curl
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
else
  log "Docker already installed"
fi

# compose plugin
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y docker-compose-plugin || true
fi
docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"

mkdir -p "$INSTALL_DIR/data"
if [[ -n "${ENV_LOADED:-}" && -f "$ENV_LOADED" ]]; then
  sed 's/\r$//' "$ENV_LOADED" >"$INSTALL_DIR/netdiag.env"
fi
if groups_path="$(find_groups_file)"; then
  sed 's/\r$//' "$groups_path" >"$INSTALL_DIR/netdiag.groups.yaml"
fi

DNS_BLOCK=""
if [[ -n "$DNS_RESOLVER" ]]; then
  DNS_BLOCK="$(cat <<EOF
        dns:
          resolvers: ["${DNS_RESOLVER}"]
          names: [${DNS_NAMES_YAML}]
EOF
)"
fi

cat >"$INSTALL_DIR/docker-compose.yml" <<EOF
# Generated by netdiag pi-satellite bootstrap — $(date -u +%Y-%m-%dT%H:%MZ)
services:
  satellite:
    image: ${IMAGE}
    container_name: netdiag-satellite
    command: ["satellite"]
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      TZ: ${TZ_VALUE}
      IFACE: ${IFACE}
      NETDIAG_COORDINATOR_TOKEN: ${TOKEN}
      NETDIAG_DATA: /data
      NETDIAG_CONFIG_YAML: |
        site:
          name: "${SITE_NAME}"
          timezone: ${TZ_VALUE}

        vantage:
          id: ${VANTAGE_ID}
          link: ${LINK}
          availability: ${AVAILABILITY}
          note: "${NOTE}"

        capture:
          iface: ${IFACE}

        coordinator:
          url: "${COORDINATOR_URL}"
          token: "${TOKEN}"

        groups:
${GROUPS_INDENTED}
${DNS_BLOCK}

        thresholds:
          ping_interval_s: 5
          dns_interval_s: 30
          dns_timeout_ms: 1500

    volumes:
      - ${INSTALL_DIR}/data:/data
    restart: unless-stopped
EOF

log "pulling ${IMAGE} (arm/v7 on Pi 2 — first pull can take several minutes)"
docker pull "$IMAGE"

log "starting satellite (${VANTAGE_ID}, iface=${IFACE})"
cd "$INSTALL_DIR"
docker compose up -d

cat >/etc/systemd/system/netdiag-satellite.service <<EOF
[Unit]
Description=netdiag satellite
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose stop
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable netdiag-satellite.service

log "done. Check coordinator status UI; vantage id must be listed under satellites: (${VANTAGE_ID})"
docker compose -f "$INSTALL_DIR/docker-compose.yml" ps
