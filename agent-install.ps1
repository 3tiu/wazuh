<#
.SYNOPSIS
    Installs two Cloudflare Access TCP proxies (WinSW-wrapped services) and the Wazuh agent on a
    Windows endpoint, wiring the agent through a Cloudflare Tunnel to a remote Wazuh manager.

.DESCRIPTION
    Architecture:
      Wazuh agent (127.0.0.1) -> CFAccess-WazuhEnroll service (127.0.0.1:1515) -> Cloudflare Access -> manager:authd
      Wazuh agent (127.0.0.1) -> CFAccess-WazuhAgent  service (127.0.0.1:1514) -> Cloudflare Access -> manager:remoted

.NOTES
    - Run as Administrator.
    - cloudflared is PINNED to 2026.5.1. Do NOT point this at /latest/ -- 2026.6.0 has an
      unresolved regression where 'access tcp' ignores service-token auth and falls back to
      interactive browser auth on every connection (cloudflare/cloudflared#1673). Check that
      issue before bumping the version.
    - Uses WinSW (github.com/winsw/winsw) to wrap 'cloudflared access tcp' as a Windows
      service. NSSM was considered but nssm.cc is a single unmirrored host that 503s under
      load -- not something you want as a dependency across a 20+ machine rollout. WinSW
      ships off GitHub Releases instead.
    - Designed to be pushed via GPO startup script, Intune Win32 app, or PsExec for fleet rollout.
    - Test on ONE machine before mass deployment.

.EXAMPLE
    $env:CF_SERVICE_TOKEN_ID = "xxxxxxxx.access"
    $env:CF_SERVICE_TOKEN_SECRET = "xxxxxxxxxxxxxxxx"
    $env:WAZUH_REGISTRATION_PASSWORD = "yyyyyyyy"
    .\Deploy-WazuhAgent-CloudflareTunnel.ps1
#>

param(
    [string]$EnrollHostname        = "",
    [string]$AgentHostname         = "",
    [string]$ServiceTokenId        = $env:CF_SERVICE_TOKEN_ID,
    [string]$ServiceTokenSecret    = $env:CF_SERVICE_TOKEN_SECRET,
    [string]$RegistrationPassword  = $env:WAZUH_REGISTRATION_PASSWORD,
    [string]$WazuhVersion          = "4.14.5-1",
    [string]$WazuhMsiUrl           = "",
    [string]$AgentGroup            = "default",
    [string]$InstallRoot           = "C:\Program Files\cloudflared",
    # PINNED version -- see NOTES above before changing this
    [string]$CloudflaredVersion    = "2026.5.1",
    # WinSW 2.x stable line; v2.12.0 is current latest stable as of writing
    [string]$WinSwVersion          = "v2.12.0"
)

if (-not $WazuhMsiUrl) {
    $WazuhMsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi"
}

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script as Administrator."
    }
}
Assert-Admin

if (-not $ServiceTokenId -or -not $ServiceTokenSecret) {
    throw "Cloudflare Access service token missing. Set CF_SERVICE_TOKEN_ID / CF_SERVICE_TOKEN_SECRET or pass -ServiceTokenId / -ServiceTokenSecret."
}
if (-not $RegistrationPassword) {
    throw "Wazuh registration password missing. Set WAZUH_REGISTRATION_PASSWORD or pass -RegistrationPassword."
}

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null

# --- 1. Get the pinned cloudflared build ---
$cloudflaredExe = Join-Path $InstallRoot "cloudflared.exe"
if (-not (Test-Path $cloudflaredExe)) {
    $url = "https://github.com/cloudflare/cloudflared/releases/download/$CloudflaredVersion/cloudflared-windows-amd64.exe"
    Write-Host "Downloading cloudflared $CloudflaredVersion ..."
    Invoke-WebRequest -Uri $url -OutFile $cloudflaredExe
}
$ver = & $cloudflaredExe --version
Write-Host "cloudflared reports: $ver"

# --- 2. Get the WinSW template exe (used to wrap each 'cloudflared access tcp' as a service) ---
$winswTemplate = Join-Path $InstallRoot "WinSW-template.exe"
if (-not (Test-Path $winswTemplate)) {
    $winswUrl = "https://github.com/winsw/winsw/releases/download/$WinSwVersion/WinSW-x64.exe"
    Write-Host "Downloading WinSW $WinSwVersion ..."
    Invoke-WebRequest -Uri $winswUrl -OutFile $winswTemplate
}

function Install-ProxyService {
    param([string]$Name, [string]$Hostname, [int]$LocalPort)

    $svcExe = Join-Path $InstallRoot "$Name.exe"
    $svcXml = Join-Path $InstallRoot "$Name.xml"
    $logDir = Join-Path $InstallRoot "logs"
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null

    # Stop/remove a prior install so this script is safely re-runnable
    if (Test-Path $svcExe) {
        & $svcExe stop 2>$null | Out-Null
        & $svcExe uninstall 2>$null | Out-Null
    }
    Copy-Item $winswTemplate -Destination $svcExe -Force

    $xml = @"
<service>
  <id>$Name</id>
  <name>$Name</name>
  <description>Cloudflare Access TCP proxy for Wazuh ($Name)</description>
  <executable>$cloudflaredExe</executable>
  <arguments>access tcp --hostname $Hostname --url 127.0.0.1:$LocalPort --service-token-id $ServiceTokenId --service-token-secret $ServiceTokenSecret</arguments>
  <startmode>Automatic</startmode>
  <onfailure action="restart" delay="3 sec"/>
  <logpath>$logDir</logpath>
  <log mode="roll"></log>
</service>
"@
    Set-Content -Path $svcXml -Value $xml -Encoding UTF8

    & $svcExe install
    & $svcExe start
}

Write-Host "Installing Cloudflare Access proxy services..."
Install-ProxyService -Name "CFAccess-WazuhEnroll" -Hostname $EnrollHostname -LocalPort 1515
Install-ProxyService -Name "CFAccess-WazuhAgent"  -Hostname $AgentHostname  -LocalPort 1514

Start-Sleep -Seconds 5

foreach ($port in 1515, 1514) {
    $test = Test-NetConnection -ComputerName 127.0.0.1 -Port $port -WarningAction SilentlyContinue
    if (-not $test.TcpTestSucceeded) {
        throw "Local proxy on port $port did not come up. Check $InstallRoot\logs\*.log -- if you see repeated browser-auth attempts in the log, you are likely hitting cloudflared#1673; confirm you're on $CloudflaredVersion."
    }
}
Write-Host "Tunnel proxies are up on 127.0.0.1:1514 and 127.0.0.1:1515."

# --- 3. Download and install the Wazuh agent against the local proxies ---
$wazuhMsiPath = Join-Path $env:TEMP "wazuh-agent-$WazuhVersion.msi"
Write-Host "Downloading Wazuh agent $WazuhVersion from $WazuhMsiUrl ..."
Invoke-WebRequest -Uri $WazuhMsiUrl -OutFile $wazuhMsiPath

$msiArgs = @(
    "/i", "`"$wazuhMsiPath`"",
    "/q",
    "WAZUH_MANAGER=127.0.0.1",
    "WAZUH_REGISTRATION_SERVER=127.0.0.1",
    "WAZUH_REGISTRATION_PASSWORD=$RegistrationPassword",
    "WAZUH_AGENT_GROUP=$AgentGroup",
    "WAZUH_AGENT_NAME=$($env:COMPUTERNAME.ToLower())"
)

Write-Host "Installing Wazuh agent..."
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -NoNewWindow

Start-Sleep -Seconds 3
$svc = Get-Service | Where-Object { $_.DisplayName -like "*Wazuh*" } | Select-Object -First 1
if (-not $svc) { throw "Wazuh service not found after install -- check the MSI log." }
Set-Service -Name $svc.Name -StartupType Automatic
Start-Service -Name $svc.Name

Write-Host "Done. On the manager, verify enrollment with: /var/ossec/bin/agent_control -l"
