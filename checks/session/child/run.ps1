param(
    [Parameter(Mandatory = $true)]
    [string] $ResultsDirectory,
    [switch] $AllowEnableChildSessions,
    [switch] $AlternateTestAccount,
    [switch] $TestDirectInput,
    [switch] $TestWindowInput,
    [switch] $NativeOleHost,
    [string] $ChildSearchHelper,
    [ValidateRange(15, 300)]
    [int] $TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($TestDirectInput -and $TestWindowInput) {
    throw 'TestDirectInput and TestWindowInput are mutually exclusive.'
}

if ($NativeOleHost -and -not $TestWindowInput) {
    throw 'NativeOleHost requires the complete TestWindowInput acceptance path.'
}

function Test-ExactBoolean {
    param([object] $Report, [string] $Name, [bool] $Expected)
    $property = $Report.PSObject.Properties[$Name]
    return $null -ne $property -and $property.Value -is [bool] -and $property.Value -eq $Expected
}

function Test-ChildRenderEligibility {
    param([object] $Report, [bool] $Requested)
    if ($null -eq $Report -or $Report -isnot [pscustomobject] -or
        -not (Test-ExactBoolean $Report 'child_search_preparation_requested' $Requested)) { return $false }
    if (-not $Requested) { return $true }
    foreach ($name in @('child_search_render_probe_eligible', 'child_search_preparation_cleanup_verified')) {
        if (-not (Test-ExactBoolean $Report $name $true)) { return $false }
    }
    # Exactly one preparation outcome is eligible: actual preparation success,
    # or the narrowly revalidated, input-clean unresolved foreground observation.
    $prepared = (Test-ExactBoolean $Report 'child_search_preparation_verified' $true) -and
        (Test-ExactBoolean $Report 'child_search_foreground_unresolved' $false)
    $observed = (Test-ExactBoolean $Report 'child_search_preparation_verified' $false) -and
        (Test-ExactBoolean $Report 'child_search_foreground_unresolved' $true)
    return $prepared -or $observed
}

function Test-WindowInputReport {
    param([string] $Json, [bool] $ChildPreparationRequested, [bool] $NativeHostRequested = $false)
    try { $report = ConvertFrom-Json -InputObject $Json -NoEnumerate }
    catch { return $false }
    if ($null -eq $report -or $report -isnot [pscustomobject]) { return $false }
    $schema = $report.PSObject.Properties['schema']
    $status = $report.PSObject.Properties['status']
    if ($null -eq $schema -or $schema.Value -isnot [string] -or
        $schema.Value -cne 'session-contract-experiment/v1' -or
        $null -eq $status -or $status.Value -isnot [string] -or
        $status.Value -cne 'different_account_child_frame_and_window_input_verified') { return $false }
    $required = @('window_input_requested', 'window_input_verified', 'window_input_cleanup_verified',
        'window_child_received_expected_text', 'window_child_received_expected_button_sequence',
        'frame_challenge_verified', 'different_account_verified', 'child_matches_created_account_sid',
        'witness_in_expected_session', 'witness_identity_matches', 'child_removed', 'enable_state_restored',
        'task_removed', 'task_instances_stopped', 'test_account_removed', 'witness_sandbox_removed',
        'parent_still_active_after_cleanup')
    foreach ($name in $required) {
        if (-not (Test-ExactBoolean $report $name $true)) { return $false }
    }
    foreach ($name in @('direct_input_requested', 'direct_input_channel_verified',
        'physical_input_isolation_verified', 'native_multiseat_verified', 'same_user_sid')) {
        if (-not (Test-ExactBoolean $report $name $false)) { return $false }
    }
    if (-not (Test-ChildRenderEligibility $report $ChildPreparationRequested)) { return $false }
    if ($NativeHostRequested) {
        foreach ($name in @('native_ole_host_requested', 'native_host_component_verified', 'native_host_cleanup_verified')) {
            if (-not (Test-ExactBoolean $report $name $true)) { return $false }
        }
        foreach ($name in @('full_native_viewer_executed', 'full_native_binding_executed')) {
            if (-not (Test-ExactBoolean $report $name $false)) { return $false }
        }
    }
    return $true
}

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
if ($NativeOleHost) {
    & (Join-Path $PSScriptRoot '..\native-host\build.ps1') -HarnessExecutable $program
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
$programArgs = @('--output', $evidencePath, '--timeout-seconds', $TimeoutSeconds.ToString())
if ($AllowEnableChildSessions) { $programArgs += '--allow-enable-child-sessions' }
if ($AlternateTestAccount) { $programArgs += '--alternate-test-account' }
if ($TestDirectInput) { $programArgs += '--test-direct-input' }
if ($TestWindowInput) { $programArgs += '--test-window-input' }
if ($NativeOleHost) { $programArgs += '--native-ole-host' }
if ($ChildSearchHelper) {
    if (-not $AlternateTestAccount) { throw 'Child Search preparation requires the owned alternate account.' }
    $programArgs += @('--child-search-helper', [System.IO.Path]::GetFullPath($ChildSearchHelper))
}
. (Join-Path $PSScriptRoot 'environment-snapshot.ps1')
'environment_snapshot_phase=before'
Write-SessionEnvironmentSnapshot
$start = [System.Diagnostics.ProcessStartInfo]::new()
$start.FileName = $program
$start.UseShellExecute = $false
# Suppress console allocation for this owned harness with redirected output.
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
foreach ($argument in $programArgs) { $start.ArgumentList.Add($argument) }
$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $start
$authWindowStart = [datetime]::UtcNow
if (-not $process.Start()) { throw 'Could not start the experiment process.' }
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
$timedOut = -not $process.WaitForExit(($TimeoutSeconds + 75) * 1000)
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
Write-RecentAuthFailures -StartTime $authWindowStart
Write-RecentRdpEvents -StartTime $authWindowStart
'environment_snapshot_phase=after'
Write-SessionEnvironmentSnapshot
if (Test-Path -LiteralPath $evidencePath) {
    $evidenceText = Get-Content -LiteralPath $evidencePath -Raw
    Write-Output $evidenceText
    if ($ChildSearchHelper) {
        try {
            $reported = ConvertFrom-Json -InputObject $evidenceText -NoEnumerate
            if (-not (Test-ChildRenderEligibility $reported $true)) {
                $result = 1
                'runner_child_render_eligibility_gate=not_verified'
            }
        } catch {
            $result = 1
            'runner_child_render_eligibility_gate=invalid_evidence'
        }
    }
    if ($TestWindowInput) {
        $windowContractVerified = $result -eq 0 -and
            (Test-WindowInputReport -Json $evidenceText -ChildPreparationRequested ([bool]$ChildSearchHelper) -NativeHostRequested ([bool]$NativeOleHost))
        'window_input_runner_contract_verified=' + $windowContractVerified.ToString().ToLowerInvariant()
        # A report cannot override a nonzero process result. A zero exit alone
        # cannot replace typed frame/input/account/cleanup evidence.
        if ($result -eq 0 -and -not $windowContractVerified) { $result = 1 }
    }
} elseif ($timedOut) {
    [ordered]@{
        schema = 'session-contract-runner/v1'
        status = 'external_timeout'
        cleanup_verified = $false
        functional_pass = $false
    } | ConvertTo-Json | Set-Content -LiteralPath $evidencePath -Encoding utf8
    Get-Content -LiteralPath $evidencePath -Raw
} elseif ($ChildSearchHelper) {
    $result = 1
    'runner_child_render_eligibility_gate=missing_evidence'
} elseif ($TestWindowInput -and $result -eq 0) {
    $result = 1
    'window_input_runner_contract_verified=false; evidence_missing=true'
}
exit $result
