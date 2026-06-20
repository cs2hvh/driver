# install_wdk.ps1 — fetches the WDK installer and runs it silently with
# ALL features enabled (including the kernel-mode headers/libs that the
# GUI install missed). Run as Administrator in the VM.
#
# Usage:
#   PowerShell -ExecutionPolicy Bypass -File install_wdk.ps1

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
          [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "ERROR: must run elevated. Right-click PowerShell → Run as Administrator." -ForegroundColor Red
    exit 1
}

# Microsoft's stable WDK 10.0.26100 download URL (Windows 11 24H2 WDK).
# This pairs with Windows 11 SDK 10.0.26100 which you already have.
$wdkUrl  = "https://go.microsoft.com/fwlink/?linkid=2272234"
$wdkOut  = "$env:TEMP\wdksetup.exe"

Write-Host "[*] Downloading WDK 10.0.26100 installer..."
Invoke-WebRequest -Uri $wdkUrl -OutFile $wdkOut -UseBasicParsing
Write-Host "[+] Downloaded to $wdkOut"

Write-Host "[*] Running WDK installer silently (all features)..."
# /features + = install every optional feature (km headers, libs, tools, samples)
# /quiet     = no GUI
# /norestart = don't reboot
$proc = Start-Process -FilePath $wdkOut `
                      -ArgumentList "/features", "+", "/quiet", "/norestart" `
                      -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Host "[-] WDK installer exited $($proc.ExitCode)" -ForegroundColor Yellow
} else {
    Write-Host "[+] WDK install reported success" -ForegroundColor Green
}

Write-Host ""
Write-Host "[*] Verifying km/ headers..."
$kmDirs = @(
    "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km",
    "C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0\km"
)
$foundAny = $false
foreach ($d in $kmDirs) {
    if (Test-Path "$d\ntddk.h") {
        Write-Host "  [OK] ntddk.h found at $d" -ForegroundColor Green
        $foundAny = $true
    }
}
if (-not $foundAny) {
    Write-Host "[-] km/ headers STILL missing after install" -ForegroundColor Red
    Write-Host "    Try installing the matching Windows 11 SDK first (Visual Studio Installer → Modify → Individual Components → search '10.0.26100' or '10.0.28000')."
    exit 1
}

Write-Host ""
Write-Host "[+] Done. Try Build → Rebuild Solution in VS now." -ForegroundColor Green
