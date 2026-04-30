Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$demoRoot = Join-Path $repoRoot "demo\local_admin"
$reportsDir = Join-Path $demoRoot "reports"
$composeFile = Join-Path $demoRoot "docker-compose.yml"
$pythonExe = Join-Path $repoRoot ".venv\Scripts\python.exe"

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
    if ($null -eq $Argument -or $Argument.Length -eq 0) { return '""' }
    if ($Argument -notmatch '[\s"]') { return $Argument }
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
            -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath
        $stdout = [System.IO.File]::ReadAllText($stdoutPath)
        $stderr = [System.IO.File]::ReadAllText($stderrPath)
        $output = $stdout + $stderr
        $exitCode = $process.ExitCode
    }
    finally {
        if (Test-Path $stdoutPath) { Remove-Item $stdoutPath -Force }
        if (Test-Path $stderrPath) { Remove-Item $stderrPath -Force }
    }
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode.`n$output"
    }
    return $output.TrimEnd()
}

function Test-TcpPortReachable {
    # NOTE: the host parameter is named ``$TcpHost`` on purpose - ``$Host``
    # is a PowerShell automatic variable (the hosting application's host
    # object), so ``param([string]$Host)`` would shadow it and break
    # parameter binding at runtime.
    param(
        [string]$TcpHost,
        [int]$Port,
        [int]$TimeoutMs = 2000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $asyncResult = $client.BeginConnect($TcpHost, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }

        $client.EndConnect($asyncResult)
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

if (-not (Test-Path $pythonExe)) {
    throw "Python virtual environment not found at $pythonExe"
}

$compose = @("docker", "compose", "-f", $composeFile)

Write-Section "Checking Containers"
$composePs = Invoke-CheckedCommand "List running containers" ($compose + @("ps", "--format", "table"))
Write-Host $composePs
if ($composePs -notmatch "webconf-audit-validation") {
    Write-Host ""
    Write-Host "No running demo containers found."
    Write-Host "Start them first: .\scripts\run_local_admin_demo.ps1"
    Write-Host "Or: docker compose -f $composeFile up -d"
    exit 1
}

# Port mapping: nginx=18080, apache=18081, lighttpd=18082
$targets = @(
    @{ Name = "nginx";    Host = "127.0.0.1"; Port = 18080; Target = "localhost:18080" },
    @{ Name = "apache";   Host = "127.0.0.1"; Port = 18081; Target = "localhost:18081" },
    @{ Name = "lighttpd"; Host = "127.0.0.1"; Port = 18082; Target = "localhost:18082" }
)

Write-Section "Checking Port Mappings"
$unreachableTargets = @()
foreach ($t in $targets) {
    $reachable = Test-TcpPortReachable -TcpHost $t.Host -Port $t.Port
    Write-Host ("{0,-8} {1,-15} {2}" -f $t.Name, $t.Target, $(if ($reachable) { "ok" } else { "unreachable" }))
    if (-not $reachable) {
        $unreachableTargets += $t
    }
}

if ($unreachableTargets.Count -gt 0) {
    Write-Host ""
    Write-Host "Expected demo endpoints are not reachable on localhost:"
    foreach ($t in $unreachableTargets) {
        Write-Host " - $($t.Name): $($t.Target)"
    }
    Write-Host "Start the demo first: .\scripts\run_local_admin_demo.ps1"
    Write-Host "Or: docker compose -f $composeFile up -d"
    exit 1
}

Write-Section "External Analysis (text)"
foreach ($t in $targets) {
    $report = Invoke-CheckedCommand "Analyze $($t.Name) externally" @(
        $pythonExe, "-m", "webconf_audit.cli",
        "analyze-external", $t.Target, "--no-scan-ports"
    )
    Save-Output "$($t.Name)-external.txt" $report
    Write-Host $report
    Write-Host ""
}

Write-Section "External Analysis (JSON)"
foreach ($t in $targets) {
    $report = Invoke-CheckedCommand "Analyze $($t.Name) externally (JSON)" @(
        $pythonExe, "-m", "webconf_audit.cli",
        "analyze-external", $t.Target, "--no-scan-ports", "--format", "json"
    )
    Save-Output "$($t.Name)-external.json" $report
}

Write-Section "Done"
Write-Host "External reports saved under: $reportsDir"
Write-Host "Note: containers run on localhost without TLS, so TLS-specific"
Write-Host "findings will not appear. This is expected for a local demo."
