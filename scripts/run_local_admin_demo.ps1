Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$repoSrc = Join-Path $repoRoot "src"
$demoRoot = Join-Path $repoRoot "demo\local_admin"
$reportsDir = Join-Path $demoRoot "reports"
$composeFile = Join-Path $demoRoot "docker-compose.yml"

function Resolve-PythonExecutable {
    $candidates = @()

    if ($env:WEBCONF_AUDIT_PYTHON) {
        $configured = $env:WEBCONF_AUDIT_PYTHON.Trim()
        if ([string]::IsNullOrWhiteSpace($configured)) {
            Write-Error "WEBCONF_AUDIT_PYTHON is set but empty."
            exit 1
        }

        $configuredCommand = Get-Command $configured -ErrorAction SilentlyContinue
        if ($configuredCommand) {
            return $configuredCommand.Source
        }

        if (Test-Path $configured -PathType Leaf) {
            return (Resolve-Path $configured).Path
        }

        if (Test-Path $configured -PathType Container) {
            Write-Error "WEBCONF_AUDIT_PYTHON must point to a Python executable, not a directory: $configured"
            exit 1
        }

        Write-Error "WEBCONF_AUDIT_PYTHON is set but cannot be resolved: $configured"
        exit 1
    }

    if ($env:VIRTUAL_ENV) {
        $candidates += @(
            (Join-Path $env:VIRTUAL_ENV "Scripts\python.exe")
            (Join-Path $env:VIRTUAL_ENV "bin/python")
        )
    }

    $candidates += @(
        (Join-Path $repoRoot ".venv\Scripts\python.exe")
        (Join-Path $repoRoot ".venv/bin/python")
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate -PathType Leaf)) {
            return (Resolve-Path $candidate).Path
        }
    }

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        return $pythonCommand.Source
    }

    throw (
        "Python interpreter not found. Set WEBCONF_AUDIT_PYTHON, activate a " +
        "virtual environment, or create .venv in the repository root."
    )
}

$pythonExe = Resolve-PythonExecutable

if (Test-Path $repoSrc) {
    if ([string]::IsNullOrEmpty($env:PYTHONPATH)) {
        $env:PYTHONPATH = $repoSrc
    }
    elseif (-not (($env:PYTHONPATH -split [IO.Path]::PathSeparator) -contains $repoSrc)) {
        $env:PYTHONPATH = "$repoSrc$([IO.Path]::PathSeparator)$env:PYTHONPATH"
    }
}

New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "== $Title =="
}

function Save-Output {
    param(
        [string]$Name,
        [string]$Content
    )

    $targetPath = Join-Path $reportsDir $Name
    [System.IO.File]::WriteAllText($targetPath, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

function ConvertTo-ProcessArgument {
    param([string]$Argument)

    if ($null -eq $Argument) {
        return '""'
    }

    if ($Argument.Length -eq 0) {
        return '""'
    }

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $escaped = $Argument -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Invoke-CheckedCommand {
    param(
        [string]$Label,
        [string[]]$Command
    )

    Write-Host $Label
    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    try {
        $argumentList = @()
        if ($Command.Length -gt 1) {
            $argumentList = $Command[1..($Command.Length - 1)] | ForEach-Object {
                ConvertTo-ProcessArgument $_
            }
        }

        $process = Start-Process `
            -FilePath $Command[0] `
            -ArgumentList ($argumentList -join ' ') `
            -WorkingDirectory $repoRoot `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath

        $stdout = [System.IO.File]::ReadAllText($stdoutPath)
        $stderr = [System.IO.File]::ReadAllText($stderrPath)
        $output = $stdout + $stderr
        $exitCode = $process.ExitCode
    }
    finally {
        if (Test-Path $stdoutPath) {
            Remove-Item $stdoutPath -Force
        }
        if (Test-Path $stderrPath) {
            Remove-Item $stderrPath -Force
        }
    }

    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode.`n$output"
    }

    return $output.TrimEnd()
}

function Invoke-BestEffortCommand {
    param([string[]]$Command)

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Command[0] $Command[1..($Command.Length - 1)] *> $null
        $null = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Invoke-AnalyzerPair {
    param(
        [string]$Label,
        [string]$ServerName,
        [string]$ConfigPath
    )

    $textReport = Invoke-CheckedCommand "$Label (text)" @(
        $pythonExe,
        "-m",
        "webconf_audit.cli",
        "analyze-$ServerName",
        $ConfigPath
    )
    $jsonReport = Invoke-CheckedCommand "$Label (json)" @(
        $pythonExe,
        "-m",
        "webconf_audit.cli",
        "analyze-$ServerName",
        $ConfigPath,
        "--format",
        "json"
    )

    return @{
        Text = $textReport
        Json = $jsonReport
    }
}

$nginxMainConfig = Join-Path $demoRoot "nginx\nginx.conf"
$apacheMainConfig = Join-Path $demoRoot "apache\conf\httpd.conf"
$lighttpdMainConfig = Join-Path $demoRoot "lighttpd\lighttpd.conf"
$iisMainConfig = Join-Path $demoRoot "iis\web.config"
$iisMachineConfig = Join-Path $demoRoot "iis\machine.config"

$compose = @("docker", "compose", "-f", $composeFile)
$stackStarted = $false
$runCompleted = $false

Write-Section "Preparing Images"
Invoke-CheckedCommand "Pull nginx image" ($compose + @("pull", "nginx")) | Out-Null
Invoke-CheckedCommand "Pull apache image" ($compose + @("pull", "apache")) | Out-Null
Invoke-CheckedCommand "Build lighttpd image" ($compose + @("build", "lighttpd")) | Out-Null

Write-Section "Native Config Validation"
$nginxValidate = Invoke-CheckedCommand "Validate nginx config" ($compose + @(
    "run",
    "--rm",
    "nginx",
    "nginx",
    "-t",
    "-c",
    "/etc/nginx/nginx.conf"
))
$apacheValidate = Invoke-CheckedCommand "Validate apache config" ($compose + @(
    "run",
    "--rm",
    "apache",
    "httpd",
    "-t",
    "-f",
    "/usr/local/apache2/conf/httpd.conf"
))
$lighttpdValidate = Invoke-CheckedCommand "Validate lighttpd config" ($compose + @(
    "run",
    "--rm",
    "lighttpd",
    "lighttpd",
    "-tt",
    "-f",
    "/etc/lighttpd/lighttpd.conf"
))

Save-Output "nginx-native-validation.txt" $nginxValidate
Save-Output "apache-native-validation.txt" $apacheValidate
Save-Output "lighttpd-native-validation.txt" $lighttpdValidate

Write-Section "Starting Containers"
try {
    Invoke-CheckedCommand "Start docker compose stack" ($compose + @("up", "-d")) | Out-Null
    $stackStarted = $true
    $composePs = Invoke-CheckedCommand "List running validation containers" ($compose + @("ps"))
    Save-Output "running-containers.txt" $composePs

    Write-Section "Analyzer Runs"
    $nginxReports = Invoke-AnalyzerPair "Analyze nginx config" "nginx" $nginxMainConfig
    $apacheReports = Invoke-AnalyzerPair "Analyze apache config" "apache" $apacheMainConfig
    $lighttpdReports = Invoke-AnalyzerPair "Analyze lighttpd config" "lighttpd" $lighttpdMainConfig
    $iisTextReport = Invoke-CheckedCommand "Analyze IIS config (text)" @(
        $pythonExe,
        "-m",
        "webconf_audit.cli",
        "analyze-iis",
        $iisMainConfig,
        "--machine-config",
        $iisMachineConfig
    )
    $iisJsonReport = Invoke-CheckedCommand "Analyze IIS config (json)" @(
        $pythonExe,
        "-m",
        "webconf_audit.cli",
        "analyze-iis",
        $iisMainConfig,
        "--machine-config",
        $iisMachineConfig,
        "--format",
        "json"
    )
    $iisReports = @{
        Text = $iisTextReport
        Json = $iisJsonReport
    }

    Save-Output "nginx-analysis.txt" $nginxReports.Text
    Save-Output "nginx-analysis.json" $nginxReports.Json
    Save-Output "apache-analysis.txt" $apacheReports.Text
    Save-Output "apache-analysis.json" $apacheReports.Json
    Save-Output "lighttpd-analysis.txt" $lighttpdReports.Text
    Save-Output "lighttpd-analysis.json" $lighttpdReports.Json
    Save-Output "iis-analysis.txt" $iisReports.Text
    Save-Output "iis-analysis.json" $iisReports.Json

    Write-Section "Summary"
    $runCompleted = $true
    Write-Host "Reports saved under: $reportsDir"
    Write-Host "Text and JSON reports were generated for all four analyzers."
    Write-Host "Docker compose services remain running for manual inspection."
    Write-Host "Stop them with: docker compose -f `"$composeFile`" down --remove-orphans"
    Write-Host ""
    Write-Host "Nginx analysis (text):"
    Write-Host $nginxReports.Text
    Write-Host ""
    Write-Host "Apache analysis (text):"
    Write-Host $apacheReports.Text
    Write-Host ""
    Write-Host "Lighttpd analysis (text):"
    Write-Host $lighttpdReports.Text
    Write-Host ""
    Write-Host "IIS analysis (text):"
    Write-Host $iisReports.Text
}
finally {
    if ($stackStarted -and -not $runCompleted) {
        Invoke-BestEffortCommand ($compose + @("down", "--remove-orphans"))
    }
}
