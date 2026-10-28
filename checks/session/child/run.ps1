param(
    [Parameter(Mandatory = $true)]
    [string] $ResultsDirectory,
    [switch] $AllowEnableChildSessions,
    [ValidateRange(15, 300)]
    [int] $TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$project = Join-Path $PSScriptRoot 'SessionContractExperiment.csproj'
$buildDirectory = Join-Path $PSScriptRoot 'bin\experiment'
$results = [System.IO.Path]::GetFullPath($ResultsDirectory)
[System.IO.Directory]::CreateDirectory($results) | Out-Null
$evidencePath = Join-Path $results 'session-contract.json'
if (Test-Path -LiteralPath $evidencePath) {
    throw 'Use a fresh results directory; an existing report will not be overwritten.'
}

# The caller chooses the installed/pinned SDK and architecture. This script
# neither downloads software nor changes machine authentication/driver settings.
& dotnet build $project --configuration Release --output $buildDirectory --nologo -p:ContinuousIntegrationBuild=true
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$program = Join-Path $buildDirectory 'SessionContractExperiment.exe'
$programArgs = @('--output', $evidencePath, '--timeout-seconds', $TimeoutSeconds.ToString())
if ($AllowEnableChildSessions) { $programArgs += '--allow-enable-child-sessions' }
$start = [System.Diagnostics.ProcessStartInfo]::new()
$start.FileName = $program
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
foreach ($argument in $programArgs) { $start.ArgumentList.Add($argument) }
$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $start
if (-not $process.Start()) { throw 'Could not start the experiment process.' }
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
$timedOut = -not $process.WaitForExit(($TimeoutSeconds + 45) * 1000)
if ($timedOut) {
    # Stop only the process tree that this wrapper started. A forced termination
    # does not establish cleanup of an OS-owned session or global enablement.
    $process.Kill($true)
    $null = $process.WaitForExit(10000)
    $result = 1
    'runner_status=external_timeout; cleanup_verified=false'
} else {
    $result = $process.ExitCode
}
if ($stdout.Wait(10000)) { Write-Output $stdout.Result }
if ($stderr.Wait(10000) -and $stderr.Result) { Write-Output $stderr.Result }
$process.Dispose()
if (Test-Path -LiteralPath $evidencePath) {
    Get-Content -LiteralPath $evidencePath -Raw
} elseif ($timedOut) {
    [ordered]@{
        schema = 'session-contract-runner/v1'
        status = 'external_timeout'
        cleanup_verified = $false
        functional_pass = $false
    } | ConvertTo-Json | Set-Content -LiteralPath $evidencePath -Encoding utf8
    Get-Content -LiteralPath $evidencePath -Raw
}
exit $result
