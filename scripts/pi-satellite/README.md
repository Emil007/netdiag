# netdiag — headless Raspberry Pi satellite

Bare Pi (empty microSD): flash once with Imager, drop `netdiag.env` + canary
YAML on the boot partition, boot, then one SSH (or a PowerShell wait script)
installs Docker and the satellite.

## Recommended flow (keeps Imager SSH / Wi‑Fi)

### 1. Flash

[Raspberry Pi Imager](https://www.raspberrypi.com/software/):

| Board | OS |
|-------|-----|
| **Pi 2 Model B** | Raspberry Pi OS **Lite (32-bit)** |
| Pi 3 / 4 / 5 / Zero 2 | Lite 64-bit is fine |

Gear (OS customisation):

- Enable **SSH**
- Username + password
- Hostname e.g. `netdiag-fritz` / `netdiag-wifi`
- **Wi‑Fi** only for the wifi satellite  
  **Pi 2 has no onboard Wi‑Fi** — use a USB dongle and configure Wi‑Fi in Imager
- Wired sat: Ethernet into the **main router** (Fritzbox), not behind a suspect switch

### 2. Drop config on `bootfs` (Windows)

After write, the FAT volume is usually **bootfs**. From the repo:

```powershell
.\scripts\pi-satellite\prepare-boot.ps1 -BootDrive E: -Mode wired `
  -CoordinatorUrl http://192.168.1.222:8787/ingest -Token 'YOUR_TOKEN' `
  -GroupsSource '.\personal\pi-satellite\netdiag.groups.yaml'
```

Use `-Mode wifi` for the Wi‑Fi Pi. That writes:

- `netdiag.env` — mode, coordinator URL, token  
- `netdiag.groups.yaml` — must mirror coordinator canaries  

Do **not** overwrite Imager’s `user-data` unless you know you need
`-IncludeCloudInitUserData` (it replaces SSH/Wi‑Fi settings from Imager).

### 3. Boot, then install

Eject, power on, wait until the Pi is on the LAN, then either:

```powershell
.\scripts\pi-satellite\prepare-boot.ps1 -WaitAndBootstrap `
  -SshHost netdiag-fritz.local -SshUser YOUR_USER
```

or SSH yourself:

```bash
curl -fsSL https://raw.githubusercontent.com/Emil007/netdiag/main/scripts/pi-satellite/bootstrap.sh | sudo bash
```

(`netdiag.env` on the boot partition supplies MODE / URL / TOKEN.)

Bootstrap installs Docker, pulls `ghcr.io/emil007/netdiag:latest` (**arm/v7**
on Pi 2), writes `/opt/netdiag/docker-compose.yml`, and enables a systemd unit.
First image pull on Pi 2 can take several minutes.

### 4. Verify

Coordinator status UI: `http://<coordinator>:8787/` — vantage should leave
`never_seen`. On the Pi: `sudo docker ps`.

## Coordinator `satellites:` ids

Defaults from `NETDIAG_MODE`:

| Mode | vantage id | placement (on coordinator) |
|------|------------|------------------------------|
| wired | `sat-fritz-wired` | `router` |
| wifi | `sat-wifi` | `other` (intermittent) |

## Optional fully unattended cloud-init

Only if you did **not** use Imager OS customisation: copy
`cloud-init.user-data` → bootfs `user-data` (edit SSH password in that file
first), plus `netdiag.env` / groups. See comments in `cloud-init.user-data`.

## Re-run

```bash
sudo bash -c 'curl -fsSL https://raw.githubusercontent.com/Emil007/netdiag/main/scripts/pi-satellite/bootstrap.sh | bash'
```

Update `/boot/firmware/netdiag.env` or `netdiag.groups.yaml` (Bookworm) or
`/boot/...` on older images, then re-run.
