# Copy netdiag.env (+ groups) onto Raspberry Pi bootfs after Imager write.
# Optionally SSH in once the Pi is online and run bootstrap automatically.
#
#   # After Imager — only drop config (keeps Imager SSH/Wi-Fi user-data):
#   .\scripts\pi-satellite\prepare-boot.ps1 -BootDrive E: -Mode wired `
#     -CoordinatorUrl http://192.168.1.222:8787/ingest -Token '…' `
#     -GroupsSource '.\personal\pi-satellite\netdiag.groups.yaml'
#
#   # After the Pi boots on the LAN:
#   .\scripts\pi-satellite\prepare-boot.ps1 -WaitAndBootstrap `
#     -SshHost netdiag-fritz.local -SshUser pi

param(
    [string] $BootDrive = "",

    [ValidateSet("wired", "wifi")]
    [string] $Mode = "wired",

    [string] $CoordinatorUrl = "http://192.168.1.10:8787/ingest",
    [string] $Token = "change-me",

    [string] $EnvSource = "",
    [string] $GroupsSource = "",

    # Dangerous: overwrites Imager user-data (SSH/Wi-Fi). Off by default.
    [switch] $IncludeCloudInitUserData,
    [string] $UserDataSource = "",

    [switch] $WaitAndBootstrap,
    [string] $SshHost = "",
    [string] $SshUser = "pi",
    [int] $WaitTimeoutSec = 300
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($BootDrive) {
    $boot = $BootDrive.TrimEnd("\")
    if (-not (Test-Path $boot)) { throw "Boot drive not found: $boot" }

    if (-not $EnvSource) { $EnvSource = Join-Path $here "netdiag.env.example" }
    if (-not $GroupsSource) { $GroupsSource = Join-Path $here "netdiag.groups.yaml.example" }

    $envText = Get-Content -Raw $EnvSource
    $envText = $envText -replace "(?m)^NETDIAG_MODE=.*$", "NETDIAG_MODE=$Mode"
    $envText = $envText -replace "(?m)^NETDIAG_COORDINATOR_URL=.*$", "NETDIAG_COORDINATOR_URL=$CoordinatorUrl"
    $envText = $envText -replace "(?m)^NETDIAG_TOKEN=.*$", "NETDIAG_TOKEN=$Token"
    [System.IO.File]::WriteAllText("$boot\netdiag.env", ($envText -replace "`r`n", "`n"))

    Copy-Item -Force $GroupsSource "$boot\netdiag.groups.yaml"

    if ($IncludeCloudInitUserData) {
        if (-not $UserDataSource) { $UserDataSource = Join-Path $here "cloud-init.user-data" }
        Copy-Item -Force $UserDataSource "$boot\user-data"
        Write-Host "WARNING: wrote user-data (may replace Imager SSH/Wi-Fi settings)"
    }

    Write-Host "Wrote netdiag.env + netdiag.groups.yaml -> $boot"
    Write-Host "Eject the card, boot the Pi, then run with -WaitAndBootstrap when it is on the LAN."
}

if ($WaitAndBootstrap) {
    if (-not $SshHost) { throw "-SshHost required with -WaitAndBootstrap (hostname or IP)" }
    $deadline = (Get-Date).AddSeconds($WaitTimeoutSec)
    Write-Host "Waiting for $SshHost ..."
    do {
        try {
            $r = Test-Connection -ComputerName $SshHost -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($r) { break }
        } catch {}
        Start-Sleep -Seconds 3
        if ((Get-Date) -gt $deadline) { throw "Timed out waiting for $SshHost" }
    } while ($true)

    Write-Host "Running bootstrap over SSH (you may be prompted for the password)..."
    $cmd = 'curl -fsSL https://raw.githubusercontent.com/Emil007/netdiag/main/scripts/pi-satellite/bootstrap.sh | sudo bash'
    ssh -o StrictHostKeyChecking=accept-new "${SshUser}@${SshHost}" $cmd
}
