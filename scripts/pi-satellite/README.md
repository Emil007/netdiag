# netdiag — Raspberry Pi satellite (headless)

You can **copy files onto the SD `bootfs` by hand**. `prepare-boot.ps1` is optional
convenience (UTF-8/LF, generates cloud-init, copies bootstrap). It is **not** required.

Flash [Raspberry Pi OS Lite](https://www.raspberrypi.com/software/) first
(**32-bit** for Pi 2; 64-bit OK on Pi 3+). The FAT volume after Imager is usually **`bootfs`**.

---

## What each bootfs file does

| Bootfs file | Role |
|-------------|------|
| `netdiag.env` | Mode, coordinator URL, token, vantage id, iface |
| `netdiag.groups.yaml` | Canaries (must mirror coordinator `groups:`) |
| `netdiag-bootstrap.sh` | Installer script (Docker + compose + satellite) |
| `user-data` + `meta-data` | cloud-init: user/SSH + **runs bootstrap on first boot** |
| `network-config` | Optional Wi‑Fi (only if you use wifi mode) |

**Important:** `netdiag.env` + `netdiag.groups.yaml` alone are **config only**. They do
**not** install Docker or start the satellite. Something must still run bootstrap
(zero-touch `user-data`, or SSH / `-WaitAndBootstrap`).

| Goal | Files on bootfs |
|------|-----------------|
| Config only (finish later over SSH) | `netdiag.env` + `netdiag.groups.yaml` |
| Ready for SSH bootstrap | above + `netdiag-bootstrap.sh` |
| **Zero-touch** (no SSH for install) | above + `user-data` + `meta-data` (+ `network-config` if Wi‑Fi) |

Repo sources (examples): `netdiag.env.example`, `netdiag.groups.yaml.example`,
`bootstrap.sh`. Personal stacks may use private env files (gitignored).

---

## Path A — manual copy

1. Flash Lite. For zero-touch: **skip Imager OS customisation** (you will supply
   `user-data`). For SSH-later: you may enable SSH/Wi‑Fi in Imager instead.
2. Copy onto `bootfs` (rename as shown):

| Source in repo | Name on bootfs |
|----------------|----------------|
| your env file (e.g. `netdiag.env.example`) | `netdiag.env` |
| `netdiag.groups.yaml.example` (or your mirror) | `netdiag.groups.yaml` |
| `bootstrap.sh` | `netdiag-bootstrap.sh` |

3. **Zero-touch:** also add `user-data` + `meta-data` generated for your
   hostname/user/password (easiest via Path B), or write equivalent cloud-init
   yourself that runs `/boot/firmware/netdiag-bootstrap.sh` (or `/boot/...`).
4. Eject, boot. If you skipped `user-data`, SSH in and run:
   `sudo bash /boot/firmware/netdiag-bootstrap.sh` (or `/boot/netdiag-bootstrap.sh`).

---

## Path B — `prepare-boot.ps1` (optional)

### B1 — Zero-touch (recommended)

Imager = **flash Lite only**, no OS customisation. Then one command writes the
full set (including generated `user-data` — **requires** `-SshPassword` and/or
`-SshPubkey`):

```powershell
.\scripts\pi-satellite\prepare-boot.ps1 -Unattended -BootDrive E: `
  -Hostname netdiag-wired -SshUser netdiag -SshPassword 'choose-a-real-password' `
  -EnvSource '.\scripts\pi-satellite\netdiag.env.example' `
  -GroupsSource '.\scripts\pi-satellite\netdiag.groups.yaml.example'
```

`-BootDrive` is required with `-Unattended`.  
`-Token` / `-CoordinatorUrl` / `-Mode` only rewrite the env when you **pass those
params**; otherwise `EnvSource` values are kept.

Optional Wi‑Fi: add `-Mode wifi -WifiSsid '…' -WifiPassword '…'` (writes
`network-config`). Pi 2 needs a USB Wi‑Fi dongle. Prefer editing a dedicated
env file rather than inventing missing filenames.

Power on — first boot installs Docker, pulls `ghcr.io/emil007/netdiag:latest`
(**linux/arm/v7** on Pi 2), starts the satellite. Needs network to GHCR (package
public or `docker login`).

### B2 — Config + bootstrap on card, install over SSH later

Imager may enable SSH. This does **not** finish setup by itself:

```powershell
.\scripts\pi-satellite\prepare-boot.ps1 -BootDrive E: `
  -EnvSource '.\scripts\pi-satellite\netdiag.env.example' `
  -GroupsSource '.\scripts\pi-satellite\netdiag.groups.yaml.example'
```

Writes `netdiag.env`, `netdiag.groups.yaml`, `netdiag-bootstrap.sh` — **no**
`user-data`, so **Docker is not installed until** you run bootstrap:

```powershell
.\scripts\pi-satellite\prepare-boot.ps1 -WaitAndBootstrap `
  -SshHost netdiag-wired.local -SshUser YOUR_USER
```

Or SSH: `sudo bash /boot/firmware/netdiag-bootstrap.sh`

Do **not** mix Imager OS customisation with `-Unattended`.

---

## After install

Coordinator status: `http://<coordinator>:8787/` — vantage leaves `never_seen`.  
List matching ids under coordinator `satellites:` (defaults if unset in env:
wired → `sat-fritz-wired`, wifi → `sat-wifi`; override with `NETDIAG_VANTAGE_ID`).

Re-run: `sudo bash /boot/firmware/netdiag-bootstrap.sh` (update env/groups on
boot partition first if needed).
