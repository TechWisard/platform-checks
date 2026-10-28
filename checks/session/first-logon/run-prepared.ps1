param(
    [Parameter(Mandatory = $true)][string] $PreparationProgram,
    [Parameter(Mandatory = $true)][string] $CalibrationProgram,
    [Parameter(Mandatory = $true)][string] $ResultsDirectory,
    [switch] $AllowDisposablePrivacyPreparation,
    [ValidateRange(15, 300)][int] $TimeoutSeconds = 120
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-PolicySnapshot {
    param([Microsoft.Win32.RegistryKey] $Base, [object] $Specification)
    $key = $Base.OpenSubKey($Specification.Path, $false)
    try {
        $exists = $null -ne $key -and @($key.GetValueNames()) -contains $Specification.Name
        $kind = $null
        $value = $null
        if ($exists) {
            $kind = $key.GetValueKind($Specification.Name)
            $allowed = @([Microsoft.Win32.RegistryValueKind]::DWord, [Microsoft.Win32.RegistryValueKind]::QWord,
                [Microsoft.Win32.RegistryValueKind]::String, [Microsoft.Win32.RegistryValueKind]::ExpandString,
                [Microsoft.Win32.RegistryValueKind]::MultiString, [Microsoft.Win32.RegistryValueKind]::Binary,
                [Microsoft.Win32.RegistryValueKind]::None)
            if ($kind -notin $allowed) { throw 'Unsupported prior registry kind.' }
            $value = $key.GetValue($Specification.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -eq $value) { throw 'Prior registry value unavailable.' }
            if ($value -is [System.Array]) { $value = $value.Clone() }
        }
        [pscustomobject]@{
            Specification = $Specification; KeyExisted = ($null -ne $key)
            ValueExisted = $exists; Kind = $kind; Value = $value
            MutationAttempted = $false; Applied = $false; Restored = $false
        }
    } finally { if ($null -ne $key) { $key.Dispose() } }
}

function Test-PolicyValueEqual {
    param([object] $Left, [object] $Right)
    if ($Left.ValueExisted -ne $Right.ValueExisted) { return $false }
    if (-not $Left.ValueExisted) { return $true }
    return $Left.Kind -eq $Right.Kind -and
        [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($Left.Value, $Right.Value)
}

function Set-OwnedPolicy {
    param([Microsoft.Win32.RegistryKey] $Base, [object] $Snapshot)
    $spec = $Snapshot.Specification
    $fresh = Read-PolicySnapshot -Base $Base -Specification $spec
    if ($fresh.KeyExisted -ne $Snapshot.KeyExisted -or -not (Test-PolicyValueEqual $Snapshot $fresh)) {
        throw 'Policy changed before our mutation.'
    }
    $slash = $spec.Path.LastIndexOf('\')
    $parent = $Base.OpenSubKey($spec.Path.Substring(0, $slash), $true)
    if ($null -eq $parent) { throw 'Expected policy parent does not exist.' }
    $key = $null
    try {
        # Record the attempt before CreateSubKey/SetValue, so partial failures
        # are included in finally. Only this fixed leaf and named value change.
        $Snapshot.MutationAttempted = $true
        $key = $parent.CreateSubKey($spec.Path.Substring($slash + 1), $true)
        if ($null -eq $key) { throw 'Could not open fixed policy leaf.' }
        $key.SetValue($spec.Name, [int]$spec.Desired, [Microsoft.Win32.RegistryValueKind]::DWord)
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $parent.Dispose()
    }
    $readback = Read-PolicySnapshot -Base $Base -Specification $spec
    if (-not $readback.ValueExisted -or $readback.Kind -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
        $readback.Value -ne [int]$spec.Desired) { throw 'Policy readback failed.' }
    $Snapshot.Applied = $true
}

function Restore-OwnedPolicy {
    param([Microsoft.Win32.RegistryKey] $Base, [object] $Snapshot)
    if (-not $Snapshot.MutationAttempted) { $Snapshot.Restored = $true; return }
    $spec = $Snapshot.Specification
    $key = $Base.OpenSubKey($spec.Path, $true)
    try {
        if ($null -eq $key) {
            if ($Snapshot.ValueExisted) { throw 'Prior policy leaf unavailable during restore.' }
        } elseif ($Snapshot.ValueExisted) {
            $key.SetValue($spec.Name, $Snapshot.Value, $Snapshot.Kind)
        } else {
            $key.DeleteValue($spec.Name, $false)
        }
    } finally { if ($null -ne $key) { $key.Dispose() } }
    $readback = Read-PolicySnapshot -Base $Base -Specification $spec
    if (-not (Test-PolicyValueEqual $Snapshot $readback)) { throw 'Exact prior policy value or kind not restored.' }
    # This intentionally restores values, not entire registry trees. A leaf
    # created by this script may remain empty; other values/keys are not deleted.
    $Snapshot.Restored = $true
}

function Invoke-OwnedProcess {
    param([string] $Executable, [string[]] $Arguments, [int] $WaitMilliseconds, [int] $MaximumOutput)
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [System.IO.Path]::GetFullPath($Executable)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    $started = $false
    $stopped = $false
    $stopAttempted = $false
    try {
        $started = $process.Start()
        if (-not $started) { throw 'Owned process did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $stopped = $process.WaitForExit($WaitMilliseconds)
        if (-not $stopped) {
            $stopAttempted = $true
            $process.Kill($true)
            $stopped = $process.WaitForExit(3000)
            if (-not $stopped) { throw 'Owned process stop unverified.' }
            throw 'Owned process external timeout; native cleanup unverified.'
        }
        if (-not $stdout.Wait(1000) -or -not $stderr.Wait(1000)) { throw 'Owned output completion timeout.' }
        if ($stdout.Result.Length -gt $MaximumOutput -or $stderr.Result.Length -gt $MaximumOutput) {
            throw 'Owned output limit exceeded.'
        }
        [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $stdout.Result; ErrorOutput = $stderr.Result }
    } finally {
        if ($started -and -not $stopped -and -not $stopAttempted) {
            $stopAttempted = $true
            try {
                if (-not $process.HasExited) {
                    $process.Kill($true)
                }
                $stopped = $process.WaitForExit(3000)
            } catch { $stopped = $false }
        }
        if ($started -and -not $stopped) {
            [Console]::WriteLine('{"schema":"first-logon-process-cleanup/v1","own_process_stopped":false,"native_cleanup_verified":false}')
        }
        $process.Dispose()
    }
}

$specifications = @(
    [pscustomobject]@{ Id = 'disable_privacy_experience'; Path = 'SOFTWARE\Policies\Microsoft\Windows\OOBE'; Name = 'DisablePrivacyExperience'; Desired = 1 },
    [pscustomobject]@{ Id = 'first_logon_animation'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableFirstLogonAnimation'; Desired = 0 }
)
$snapshots = [System.Collections.Generic.List[object]]::new()
$restoreErrors = [System.Collections.Generic.List[object]]::new()
$base = $null
$phase = 'preflight'
$outcome = 1
$failureHresult = 0L
$failureType = $null
$preparationExit = $null
$calibrationExit = $null
$experimentExit = $null
$preparationVerified = $false
$policiesApplied = $false
try {
    if (-not $AllowDisposablePrivacyPreparation -or -not [System.OperatingSystem]::IsWindows() -or
        -not [System.Environment]::Is64BitProcess -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows') {
        throw 'Explicit disposable hosted Windows opt-in is required.'
    }
    $calibrationRunner = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\window\run.ps1'))
    $childRunner = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\child\run.ps1'))
    $powershell = Join-Path $PSHOME 'pwsh.exe'
    $phase = 'snapshot_presentation_policies'
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    foreach ($specification in $specifications) { $snapshots.Add((Read-PolicySnapshot -Base $base -Specification $specification)) }
    $phase = 'apply_presentation_policies'
    foreach ($snapshot in $snapshots) { Set-OwnedPolicy -Base $base -Snapshot $snapshot }
    $policiesApplied = $true
    $phase = 'prepare_parent_first_logon'
    # 40s wait + <=3s stop + <=2s output completion stays within 45s. The
    # helper may Invoke once; an external timeout never proves native cleanup.
    $prepared = Invoke-OwnedProcess -Executable $PreparationProgram -WaitMilliseconds 40000 -MaximumOutput 16384 `
        -Arguments @('--allow-disposable-privacy-preparation')
    $preparationExit = $prepared.ExitCode
    if ($prepared.ErrorOutput.Length) { throw 'Unexpected helper stderr.' }
    $report = $prepared.Output.Trim() | ConvertFrom-Json -Depth 8
    if ($report.schema -ne 'first-logon-prepare/v1') { throw 'Unexpected preparation schema.' }
    Write-Output $prepared.Output.Trim()
    if ($preparationExit -ne 0 -or $report.status -notin @('completed', 'not_needed') -or
        $report.ordinary_desktop_verified -ne $true -or $report.cleanup_verified -ne $true -or
        $report.session_functionality_verified -ne $false) { throw 'Parent desktop preparation not verified.' }
    $preparationVerified = $true
    $phase = 'native_window_calibration'
    $calibration = Invoke-OwnedProcess -Executable $powershell -WaitMilliseconds 65000 -MaximumOutput 1048576 `
        -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive',
        '-File', $calibrationRunner, '-Program', [System.IO.Path]::GetFullPath($CalibrationProgram))
    $calibrationExit = $calibration.ExitCode
    Write-Output $calibration.Output
    if ($calibration.ErrorOutput.Length) { throw 'Unexpected calibration stderr.' }
    if ($calibrationExit -ne 0) { throw 'Independent native window calibration failed.' }
    $phase = 'verify_policies_before_new_account'
    foreach ($snapshot in $snapshots) {
        $readback = Read-PolicySnapshot -Base $base -Specification $snapshot.Specification
        if (-not $readback.ValueExisted -or $readback.Kind -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
            $readback.Value -ne [int]$snapshot.Specification.Desired) { throw 'Presentation policy changed before fresh account.' }
    }
    $phase = 'child_session_frame_and_input'
    $experiment = Invoke-OwnedProcess -Executable $powershell -WaitMilliseconds (($TimeoutSeconds + 210) * 1000) -MaximumOutput 1048576 `
        -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive',
        '-File', $childRunner, '-ResultsDirectory', [System.IO.Path]::GetFullPath($ResultsDirectory),
        '-AllowEnableChildSessions', '-AlternateTestAccount', '-TestDirectInput', '-TimeoutSeconds', $TimeoutSeconds.ToString())
    $experimentExit = $experiment.ExitCode
    Write-Output $experiment.Output
    if ($experiment.ErrorOutput.Length) { throw 'Unexpected experiment stderr.' }
    if ($experimentExit -ne 0) { throw 'Child session frame/input contract did not pass.' }
    $phase = 'completed'
    $outcome = 0
} catch {
    $failureHresult = ([long]$_.Exception.HResult -band 4294967295L)
    $failureType = $_.Exception.GetType().Name
    $outcome = 1
} finally {
    # Each snapshot restores independently, even after another restoration
    # error. No exit statement or arbitrary child script runs in this scope.
    foreach ($snapshot in $snapshots) {
        try { Restore-OwnedPolicy -Base $base -Snapshot $snapshot }
        catch {
            $restoreErrors.Add([ordered]@{ id = $snapshot.Specification.Id; hresult = ([long]$_.Exception.HResult -band 4294967295L) })
            $outcome = 1
        }
    }
    if ($null -ne $base) { $base.Dispose() }
}
$restored = $restoreErrors.Count -eq 0 -and @($snapshots | Where-Object { -not $_.Restored }).Count -eq 0
if (-not $restored) { $outcome = 1 }
[ordered]@{
    schema = 'prepared-session-contract/v1'
    status = $(if ($outcome -eq 0) { 'verified' } else { 'failed' })
    stage = $phase
    error_hresult = $failureHresult
    error_type = $failureType
    presentation_policies_applied = $policiesApplied
    parent_preparation_verified = $preparationVerified
    preparation_exit = $preparationExit
    native_calibration_exit = $calibrationExit
    child_experiment_exit = $experimentExit
    policy_values_restored = $restored
    policy_values = @($snapshots | ForEach-Object {
        [ordered]@{ id = $_.Specification.Id; existed_before = $_.ValueExisted;
            prior_kind = $(if ($null -eq $_.Kind) { $null } else { [int]$_.Kind });
            policy_leaf_existed_before = $_.KeyExisted; mutation_attempted = $_.MutationAttempted; restored = $_.Restored }
    })
    restore_errors = $restoreErrors.ToArray()
    preparation_alone_proves_frame_or_input = $false
    physical_isolation_verified = $false
} | ConvertTo-Json -Depth 6 -Compress
exit $outcome
