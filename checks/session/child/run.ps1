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
& $program @programArgs
$result = $LASTEXITCODE
if (Test-Path -LiteralPath $evidencePath) {
    Get-Content -LiteralPath $evidencePath -Raw
}
exit $result
