<#
.SYNOPSIS
    Automates deployment of Wazuh agent active-response extensions, YARA, Sysmon,
    Sysinternals tools, and PowerShell logging hardening.

.DESCRIPTION
    - Restarts the Wazuh agent service
    - Downloads active-response scripts/binaries into ossec-agent\active-response\bin
    - Sets up YARA (engine + rules)
    - Runs the Sysmon installer
    - Deploys sigcheck.ps1 / otx.ps1 to Sysinternals folder
    - Enables PowerShell Module Logging via registry
    - Updates ar.conf and local_internal_options.conf
    - Forces a group policy update
    - Restarts the Wazuh agent service again

.NOTES
    Must be run as Administrator.
    Source files are pulled from a third-party GitHub repo (3tiu/wazuh-files).
    Review/verify that repo's contents before running this in production.
#>

[CmdletBinding()]
param(
    [string]$OssecPath = "C:\Program Files (x86)\ossec-agent",
    [switch]$SkipSysmon
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"  # speeds up Invoke-WebRequest a lot

# ------------------------------------------------------------------
# 0. Pre-flight checks
# ------------------------------------------------------------------
function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "This script must be run from an elevated (Administrator) PowerShell session."
    }
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Download-File {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination
    )
    $destDir = Split-Path -Path $Destination -Parent
    if (-not (Test-Path $destDir)) {
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
    }
    Write-Host "Downloading: $Url"
    Write-Host "        ->  $Destination"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    } catch {
        Write-Warning "Failed to download $Url : $($_.Exception.Message)"
        throw
    }
}

Assert-Admin

if (-not (Test-Path $OssecPath)) {
    throw "Wazuh agent install path not found at '$OssecPath'. Pass -OssecPath if it's installed elsewhere."
}

$arBin      = Join-Path $OssecPath "active-response\bin"
$yaraDir    = Join-Path $arBin "yara"
$yaraRules  = Join-Path $yaraDir "rules"
$sysinternalsDir = "C:\Program Files\sysinternals"
$repoBase   = "https://github.com/3tiu/wazuh-files/raw/refs/heads/main"

# ------------------------------------------------------------------
# 1. Start the Wazuh service (in case it isn't running yet)
# ------------------------------------------------------------------
Write-Step "Starting WazuhSvc"
try {
    Start-Service -Name "WazuhSvc" -ErrorAction Stop
    Write-Host "WazuhSvc started."
} catch {
    Write-Warning "Could not start WazuhSvc (it may already be running): $($_.Exception.Message)"
}

# ------------------------------------------------------------------
# 2. Active-response scripts/binaries
# ------------------------------------------------------------------
Write-Step "Deploying active-response files to $arBin"

$activeResponseFiles = @(
    @{ File = "remove-threat.exe";        Url = "$repoBase/active-response/remove-threat.exe" },
    @{ File = "disableuseraccount.cmd";   Url = "$repoBase/active-response/disableuseraccount.cmd" },
    @{ File = "disableuseraccount.ps1";   Url = "$repoBase/active-response/disableuseraccount.ps1" },
    @{ File = "domainsinkhole.cmd";       Url = "$repoBase/active-response/domainsinkhole.cmd" },
    @{ File = "domainsinkhole.ps1";       Url = "$repoBase/active-response/domainsinkhole.ps1" },
    @{ File = "otx.cmd";                  Url = "$repoBase/active-response/otx.cmd" },
    @{ File = "windowsfirewall.cmd";      Url = "$repoBase/active-response/windowsfirewall.cmd" },
    @{ File = "windowsfirewall.ps1";      Url = "$repoBase/active-response/windowsfirewall.ps1" },
    @{ File = "yara.bat";                 Url = "$repoBase/active-response/yara.bat" }
)

foreach ($item in $activeResponseFiles) {
    Download-File -Url $item.Url -Destination (Join-Path $arBin $item.File)
}

# ------------------------------------------------------------------
# 3. YARA engine + rules
# ------------------------------------------------------------------
Write-Step "Setting up YARA"

New-Item -Path $yaraDir   -ItemType Directory -Force | Out-Null
New-Item -Path $yaraRules -ItemType Directory -Force | Out-Null

Download-File -Url "$repoBase/active-response/yara/yara64.exe" -Destination (Join-Path $yaraDir "yara64.exe")
Download-File -Url "$repoBase/active-response/yara/rules/yara_rules.yar" -Destination (Join-Path $yaraRules "yara_rules.yar")

# ------------------------------------------------------------------
# 4. Sysmon install
# ------------------------------------------------------------------
if (-not $SkipSysmon) {
    Write-Step "Installing Sysmon"
    $sysmonScript = Join-Path $env:TEMP "sysmon_install.ps1"
    Download-File -Url "https://raw.githubusercontent.com/3tiu/wazuh/refs/heads/main/sysmon_install.ps1" -Destination $sysmonScript
    try {
        & powershell.exe -ExecutionPolicy Bypass -File $sysmonScript
    } catch {
        Write-Warning "Sysmon install script failed: $($_.Exception.Message)"
    }
} else {
    Write-Host "Skipping Sysmon install (-SkipSysmon specified)."
}

# ------------------------------------------------------------------
# 5. Sysinternals helper scripts
# ------------------------------------------------------------------
Write-Step "Deploying Sysinternals helper scripts to $sysinternalsDir"

Download-File -Url "$repoBase/sysinternals/sigcheck.ps1" -Destination (Join-Path $sysinternalsDir "sigcheck.ps1")
Download-File -Url "$repoBase/sysinternals/otx.ps1"       -Destination (Join-Path $sysinternalsDir "otx.ps1")

# ------------------------------------------------------------------
# 6. Enable PowerShell Module Logging
# ------------------------------------------------------------------
Write-Step "Enabling PowerShell Module Logging"

$RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}
Set-ItemProperty -Path $RegistryPath -Name "EnableModuleLogging" -Value 1 -Type DWord

# Only create ModuleNames if it doesn't already exist (New-ItemProperty errors if it does)
if (-not (Get-ItemProperty -Path $RegistryPath -Name "ModuleNames" -ErrorAction SilentlyContinue)) {
    New-ItemProperty -Path $RegistryPath -Name "ModuleNames" -PropertyType MultiString -Value "*" | Out-Null
} else {
    Set-ItemProperty -Path $RegistryPath -Name "ModuleNames" -Value "*"
}

# ------------------------------------------------------------------
# 7. ar.conf  (active response definitions)
# ------------------------------------------------------------------
Write-Step "Updating shared\ar.conf"

$arConfPath = Join-Path $OssecPath "shared\ar.conf"
$arConfDir  = Split-Path -Path $arConfPath -Parent
if (-not (Test-Path $arConfDir)) {
    New-Item -Path $arConfDir -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path $arConfPath)) {
    New-Item -Path $arConfPath -ItemType File -Force | Out-Null
}

$arConfLines = @(
    "windowsfirewall - windowsfirewall.cmd - 0",
    "domainsinkhole - domainsinkhole.cmd - 0",
    "disableuseraccount - disableuseraccount.cmd - 0"
)

$existingArConf = Get-Content -Path $arConfPath -ErrorAction SilentlyContinue
foreach ($line in $arConfLines) {
    if ($existingArConf -notcontains $line) {
        Add-Content -Path $arConfPath -Value $line
        Write-Host "Added: $line"
    } else {
        Write-Host "Already present, skipping: $line"
    }
}

# ------------------------------------------------------------------
# 8. local_internal_options.conf
# ------------------------------------------------------------------
Write-Step "Updating local_internal_options.conf"

$localInternalPath = Join-Path $OssecPath "local_internal_options.conf"
if (-not (Test-Path $localInternalPath)) {
    New-Item -Path $localInternalPath -ItemType File -Force | Out-Null
}

$internalOptionLines = @(
    "wazuh_command.remote_commands=1",
    "logcollector.remote_commands=1"
)

$existingInternal = Get-Content -Path $localInternalPath -ErrorAction SilentlyContinue
foreach ($line in $internalOptionLines) {
    if ($existingInternal -notcontains $line) {
        Add-Content -Path $localInternalPath -Value $line
        Write-Host "Added: $line"
    } else {
        Write-Host "Already present, skipping: $line"
    }
}

# ------------------------------------------------------------------
# 9. Group policy update
# ------------------------------------------------------------------
Write-Step "Running gpupdate /force"
try {
    gpupdate /force | Out-Host
} catch {
    Write-Warning "gpupdate failed: $($_.Exception.Message)"
}

# ------------------------------------------------------------------
# 10. Restart Wazuh service to apply changes
# ------------------------------------------------------------------
Write-Step "Restarting WazuhSvc"
try {
    Restart-Service -Name "WazuhSvc" -Force -ErrorAction Stop
    Write-Host "WazuhSvc restarted."
} catch {
    Write-Warning "Could not restart WazuhSvc: $($_.Exception.Message)"
}

Write-Host "`nDeployment complete." -ForegroundColor Green
Write-Host "Files placed under: $arBin"
Write-Host "ar.conf:                    $arConfPath"
Write-Host "local_internal_options.conf: $localInternalPath"
