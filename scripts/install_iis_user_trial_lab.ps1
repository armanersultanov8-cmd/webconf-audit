Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repoRoot ".lab\user_trial\iis"
$logPath = Join-Path $logDir "install-log.txt"

if (-not (Test-Path $logDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
}
Start-Transcript -Path $logPath -Force | Out-Null

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "== $Message =="
}

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell window."
    }
}

function Ensure-WindowsFeature {
    param([string]$Name)

    $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name
    if ($feature.State -eq "Enabled") {
        Write-Host "Already enabled: $Name"
        return $false
    }

    Write-Host "Enabling: $Name"
    $result = Enable-WindowsOptionalFeature -Online -FeatureName $Name -All -NoRestart
    return $result.RestartNeeded
}

try {
    Assert-Admin

    $labRoot = Join-Path $repoRoot ".lab\user_trial\iis"
    $siteRoot = Join-Path $labRoot "site"
    $machineConfigPath = Join-Path $labRoot "machine.config"
    $appHostFixturePath = Join-Path $labRoot "applicationHost.config"

    if (-not (Test-Path $siteRoot -PathType Container)) {
        throw "Site root not found: $siteRoot"
    }
    if (-not (Test-Path $machineConfigPath -PathType Leaf)) {
        throw "machine.config fixture not found: $machineConfigPath"
    }
    if (-not (Test-Path $appHostFixturePath -PathType Leaf)) {
        throw "applicationHost.config fixture not found: $appHostFixturePath"
    }

    $siteName = "webconf-audit-user-trial"
    $appPoolName = "webconf-audit-user-trial"
    $httpPort = 18094
    $httpsPort = 18446
    $certFriendlyName = "webconf-audit user trial iis"
    $certDnsNames = @("user-trial.local", "localhost", $env:COMPUTERNAME)

    $features = @(
        "IIS-WebServerRole",
        "IIS-WebServer",
        "IIS-CommonHttpFeatures",
        "IIS-StaticContent",
        "IIS-DefaultDocument",
        "IIS-DirectoryBrowsing",
        "IIS-HttpErrors",
        "IIS-HttpRedirect",
        "IIS-HealthAndDiagnostics",
        "IIS-HttpLogging",
        "IIS-Security",
        "IIS-RequestFiltering",
        "IIS-BasicAuthentication",
        "IIS-ApplicationDevelopment",
        "IIS-NetFxExtensibility45",
        "IIS-ASPNET45",
        "IIS-ISAPIExtensions",
        "IIS-ISAPIFilter",
        "IIS-CGI",
        "IIS-WebDAV",
        "IIS-ManagementConsole"
    )

    $restartNeeded = $false

    Write-Step "Installing IIS Components"
    foreach ($feature in $features) {
        if (Ensure-WindowsFeature -Name $feature) {
            $restartNeeded = $true
        }
    }

    Write-Step "Loading IIS Management Module"
    Import-Module WebAdministration

    Write-Step "Checking Port Conflicts"
    $conflicts = Get-WebBinding | Where-Object {
        $_.bindingInformation -like "*:${httpPort}:*" -or
        $_.bindingInformation -like "*:${httpsPort}:*"
    } | Where-Object {
        $_.ItemXPath -notlike "*site[@name='$siteName']*"
    }

    if ($conflicts) {
        $summary = $conflicts | ForEach-Object {
            "$($_.protocol) $($_.bindingInformation)"
        }
        throw "Port conflicts detected: $($summary -join ', ')"
    }

    Write-Step "Preparing Application Pool"
    if (-not (Test-Path "IIS:\AppPools\$appPoolName")) {
        New-WebAppPool -Name $appPoolName | Out-Null
    }
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name managedRuntimeVersion -Value "v4.0"
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name managedPipelineMode -Value "Integrated"
    Set-ItemProperty "IIS:\AppPools\$appPoolName" -Name autoStart -Value $true

    Write-Step "Granting IIS Read Access To Lab Content"
    $grantTargets = @(
        "IIS_IUSRS",
        "IUSR",
        "IIS AppPool\$appPoolName"
    )
    foreach ($target in $grantTargets) {
        Write-Host "Granting RX to $target"
        & icacls $siteRoot /grant "${target}:(OI)(CI)RX" /T /C | Out-Null
    }

    Write-Step "Recreating Site"
    if (Get-Website -Name $siteName -ErrorAction SilentlyContinue) {
        Stop-Website -Name $siteName -ErrorAction SilentlyContinue
        Remove-Website -Name $siteName
    }

    New-Website `
        -Name $siteName `
        -PhysicalPath $siteRoot `
        -ApplicationPool $appPoolName `
        -Port $httpPort `
        -IPAddress "*" `
        | Out-Null

    Write-Step "Creating HTTPS Binding"
    if (-not (Get-WebBinding -Name $siteName -Protocol https -Port $httpsPort -ErrorAction SilentlyContinue)) {
        New-WebBinding -Name $siteName -Protocol https -Port $httpsPort -IPAddress "*" | Out-Null
    }

    Write-Step "Provisioning Self-Signed Certificate"
    $cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.FriendlyName -eq $certFriendlyName } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $cert) {
        $cert = New-SelfSignedCertificate `
            -DnsName $certDnsNames `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -FriendlyName $certFriendlyName `
            -NotAfter (Get-Date).AddYears(2)
    }

    $sslBindingPath = "IIS:\SslBindings\0.0.0.0!$httpsPort"
    if (Test-Path $sslBindingPath) {
        Remove-Item $sslBindingPath -Force
    }
    Get-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)" | New-Item $sslBindingPath | Out-Null

    Write-Step "Starting IIS Services And Site"
    foreach ($serviceName in "WAS", "W3SVC") {
        Set-Service -Name $serviceName -StartupType Automatic
        if ((Get-Service $serviceName).Status -ne "Running") {
            Start-Service -Name $serviceName
        }
    }
    Start-WebAppPool -Name $appPoolName
    Start-Website -Name $siteName

    Write-Step "Current Site State"
    $site = Get-Website -Name $siteName
    $bindings = Get-WebBinding -Name $siteName | Select-Object protocol, bindingInformation
    $site | Select-Object name, id, state, physicalPath, applicationPool | Format-List
    $bindings | Format-Table -AutoSize

    Write-Step "How To Verify"
    Write-Host "Local IIS analyzer against the real IIS config store:"
    Write-Host "  .\.venv\Scripts\webconf-audit.exe analyze-iis C:\Windows\System32\inetsrv\config\applicationHost.config --machine-config C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"
    Write-Host ""
    Write-Host "External HTTP:"
    Write-Host "  .\.venv\Scripts\webconf-audit.exe analyze-external http://127.0.0.1:$httpPort"
    Write-Host ""
    Write-Host "External HTTPS:"
    Write-Host "  .\.venv\Scripts\webconf-audit.exe analyze-external https://127.0.0.1:$httpsPort"
    Write-Host ""
    Write-Host "Lab fixtures used by the site:"
    Write-Host "  $siteRoot"
    Write-Host "  $appHostFixturePath"
    Write-Host "  $machineConfigPath"

    if ($restartNeeded) {
        Write-Host ""
        Write-Warning "One or more IIS components requested a restart. If the site misbehaves, reboot Windows once and rerun this script."
    }
}
finally {
    Stop-Transcript | Out-Null
}
