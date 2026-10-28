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

function Test-SearchEscape {
    param([object] $Report)
    $property = $Report.PSObject.Properties['search_escape']
    if ($null -eq $property -or $null -eq $property.Value) { return $false }
    $action = $property.Value
    $numbers = @('hresult', 'initial_search_count', 'recheck_search_count', 'async_down_mask', 'queue_down_mask',
        'send_call_count', 'requested_input_count', 'inserted_input_count', 'send_last_error', 'cleanup_call_count',
        'cleanup_inserted_count', 'cleanup_last_error', 'release_observations', 'virtual_key', 'after_second_ms', 'elapsed_ms')
    foreach ($name in $numbers) {
        $field = $action.PSObject.Properties[$name]
        if ($null -eq $field -or ($field.Value -isnot [int] -and $field.Value -isnot [long]) -or
            $field.Value -lt 0 -or $field.Value -gt 4294967295L) { return $false }
    }
    $flags = @('checked', 'first_snapshot_verified', 'original_target_destroyed', 'owner_verified', 'owner_reverified',
        'first_page_verified', 'recheck_page_verified', 'same_root_reverified', 'key_state_checked',
        'keyboard_state_query_succeeded', 'async_highbits_up', 'queue_highbits_up', 'send_attempted', 'pair_inserted',
        'release_cleanup_attempted', 'release_event_inserted', 'escape_up_observed', 'key_cleanup_verified',
        'physical_key_state_proven', 'delivery_to_target_proven')
    foreach ($name in $flags) {
        $field = $action.PSObject.Properties[$name]
        if ($null -eq $field -or $field.Value -isnot [bool]) { return $false }
    }
    if ($action.virtual_key -ne 27 -or $action.physical_key_state_proven -ne $false -or
        $action.delivery_to_target_proven -ne $false -or $action.hresult -ne 0 -or
        $action.key_cleanup_verified -ne $true) { return $false }
    if (-not $action.checked) {
        if ($action.stage -ne 'not_attempted') { return $false }
        foreach ($name in $numbers) {
            if ($name -ne 'virtual_key' -and $action.$name -ne 0) { return $false }
        }
        foreach ($name in $flags) {
            if ($name -ne 'key_cleanup_verified' -and $action.$name -ne $false) { return $false }
        }
        return $true
    }
    # One guarded pair only. A partial insertion fails eligibility even if its
    # sole permitted key-up cleanup succeeds. No API count claims UI delivery.
    $fresh = @($Report.fresh_foreground)
    if ($fresh.Count -ne 2) { return $false }
    $observed = $fresh[0]
    return $Report.invoke_count -eq 2 -and $Report.second_action.invoke_succeeded -eq $true -and
        $action.stage -eq 'pair_inserted' -and $action.after_second_ms -ge 5000 -and
        $action.send_attempted -eq $true -and $action.send_call_count -eq 1 -and
        $action.requested_input_count -eq 2 -and $action.inserted_input_count -eq 2 -and $action.pair_inserted -eq $true -and
        $action.cleanup_call_count -eq 0 -and $action.cleanup_inserted_count -eq 0 -and $action.cleanup_last_error -eq 0 -and
        $action.release_cleanup_attempted -eq $false -and $action.release_event_inserted -eq $true -and
        $action.escape_up_observed -eq $true -and $action.release_observations -ge 1 -and
        $action.first_snapshot_verified -eq $true -and $action.original_target_destroyed -eq $true -and
        $action.owner_verified -eq $true -and $action.owner_reverified -eq $true -and
        $action.first_page_verified -eq $true -and $action.recheck_page_verified -eq $true -and
        $action.same_root_reverified -eq $true -and $action.initial_search_count -eq 1 -and $action.recheck_search_count -eq 1 -and
        $action.key_state_checked -eq $true -and $action.keyboard_state_query_succeeded -eq $true -and
        $action.async_highbits_up -eq $true -and $action.queue_highbits_up -eq $true -and
        $action.async_down_mask -eq 0 -and $action.queue_down_mask -eq 0 -and
        $observed.attempted -eq $true -and $observed.exact_search_identity -eq $true -and $observed.hresult -eq 0 -and
        $observed.active_desktop_verified -eq $true -and $observed.original_target_destroyed -eq $true -and
        $observed.owner_verified -eq $true -and $observed.owner_stable -eq $true -and
        $observed.search_page.completed -eq $true -and $observed.search_page.hresult -eq 0 -and
        $observed.search_page.owner_verified -eq $true -and $observed.search_page.owner_stable -eq $true -and
        $observed.search_page.root_verified -eq $true -and $observed.search_page.root_control_type -eq 50032 -and
        @($observed.search_page.fixed_name_counts).Count -eq 8 -and $observed.search_page.fixed_name_counts[0] -eq 1
}

function Test-PreparationEligibility {
    param([object] $Report, [int] $ExitCode)
    if ($Report.schema -ne 'first-logon-prepare/v1' -or $Report.opted_in -ne $true -or
        $Report.disposable_environment_verified -ne $true -or $Report.session_id -le 0 -or
        $Report.input_default_desktop_verified -ne $true -or $Report.final_active_input_desktop_verified -ne $true -or
        $Report.cleanup_verified -ne $true -or $Report.cleanup_hresult -ne 0 -or
        $Report.session_functionality_verified -ne $false -or $Report.other_ui_invoked -ne $false -or
        $Report.force_closed_window -ne $false -or $Report.credential_fields_read -ne $false -or
        $Report.search_values_read -ne $false -or $Report.other_keys_sent -ne $false -or $Report.focus_changed_by_helper -ne $false -or
        $Report.privacy_toggle_values_changed_by_helper -ne $false) { return $false }
    if (-not (Test-SearchEscape -Report $Report)) { return $false }
    $second = $Report.second_action
    $firstKnownAccept = $Report.button_label_before.category -eq 3 -or
        $Report.button_label_before.safe_ascii -ceq 'Accept these privacy settings'
    if ($Report.first_label_is_known_accept -ne $firstKnownAccept) { return $false }
    $noAction = $Report.target_initially_foreground -eq $false -and $Report.invoke_count -eq 0 -and
        $Report.invoke_attempted -eq $false -and $Report.invoke_succeeded -eq $false -and
        $second.checked -eq $false -and $second.invoke_attempted -eq $false -and $second.invoke_succeeded -eq $false
    $firstOwnedAction = $Report.target_initially_foreground -eq $true -and
        $Report.invoke_attempted -eq $true -and $Report.invoke_succeeded -eq $true -and $Report.invoke_hresult -eq 0 -and
        $Report.target_owner_verified -eq $true -and $Report.target_owner_reverified -eq $true -and
        $Report.root_handle_verified -eq $true -and $Report.same_button_reverified -eq $true -and
        $Report.initial_heading_count -ge 1 -and $Report.initial_heading_count -le 8 -and
        $Report.recheck_heading_count -ge 1 -and $Report.recheck_heading_count -le 8 -and
        $Report.initial_button_count -eq 1 -and $Report.recheck_button_count -eq 1 -and $Report.com_uninitialized -eq $true
    $oneAction = $firstOwnedAction -and $Report.invoke_count -eq 1 -and
        $second.invoke_attempted -eq $false -and $second.invoke_succeeded -eq $false
    $twoActions = $firstOwnedAction -and $Report.invoke_count -eq 2 -and -not $firstKnownAccept -and
        $second.checked -eq $true -and $second.stage -eq 'invoked' -and
        $second.invoke_attempted -eq $true -and $second.invoke_succeeded -eq $true -and $second.invoke_hresult -eq 0 -and
        $second.delay_ms -ge 1000 -and $second.delay_ms -lt 6000 -and
        $second.first_page_verified -eq $true -and $second.recheck_page_verified -eq $true -and
        $second.owner_verified -eq $true -and $second.owner_reverified -eq $true -and $second.same_button_reverified -eq $true -and
        $second.initial_heading_count -ge 1 -and $second.initial_heading_count -le 8 -and
        $second.recheck_heading_count -ge 1 -and $second.recheck_heading_count -le 8 -and
        $second.initial_button_count -eq 1 -and $second.recheck_button_count -eq 1 -and
        $second.first_label.hresult -eq 0 -and $second.recheck_label.hresult -eq 0 -and
        $second.first_label.safe_ascii -ceq 'Accept these privacy settings' -and
        $second.recheck_label.safe_ascii -ceq 'Accept these privacy settings'
    if (-not ($noAction -or $oneAction -or $twoActions)) { return $false }
    $ordinary = $ExitCode -eq 0 -and $Report.status -in @('completed', 'not_needed') -and
        $Report.hresult -eq 0 -and $Report.ordinary_desktop_verified -eq $true
    # Only the observed foreground-category timeout is eligible. API, ownership,
    # cleanup, session, desktop and other errors remain failures. This is not a
    # setup-completion claim; independent pixel/ownership calibration must pass.
    $foregroundTimeout = $ExitCode -eq 1 -and $Report.status -eq 'failed' -and
        $Report.stage -eq 'ordinary_desktop_timeout' -and $Report.hresult -eq 2147942658L -and
        $Report.wait_guard -eq 3 -and $Report.explorer_shell_verified -eq $true
    return $ordinary -or $foregroundTimeout
}

function Test-NativeCalibration {
    param([object] $Report, [int] $ExitCode, [long] $SessionId)
    return $ExitCode -eq 0 -and $Report.schema -eq 'native-window-calibration/v1' -and
        $Report.status -eq 'passed' -and $Report.exit_code -eq 0 -and $Report.session_query_ok -eq $true -and
        $Report.session_id -eq $SessionId -and $SessionId -gt 0 -and $Report.observed_challenge_and_grid -eq $true -and
        $Report.own_root_mask_before -eq 511 -and $Report.own_root_mask_after -eq 511 -and
        $Report.window_visible -eq $true -and $Report.inside_virtual_screen -eq $true -and
        $Report.paint_count -gt 0 -and $Report.capture_count -gt 0 -and $Report.capture_ok -eq $true -and
        @($Report.counts_within3).Count -eq 8 -and @($Report.counts_within3 | Where-Object { $_ -lt 80 }).Count -eq 0 -and
        $Report.own_window_cleanup -eq $true -and $Report.class_cleanup -eq $true -and $Report.gdi_cleanup -eq $true
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
$preparationEligible = $false
$nativeCalibrationVerified = $false
$parentDisplayVerified = $false
$foregroundTimeoutAccepted = $false
$calibrationDiagnosticOnly = $false
$calibrationErrorHresult = $null
$calibrationErrorType = $null
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
    # The helper has at most two privacy Invokes and one guarded Escape pair;
    # an external timeout never proves native cleanup.
    $prepared = Invoke-OwnedProcess -Executable $PreparationProgram -WaitMilliseconds 40000 -MaximumOutput 16384 `
        -Arguments @('--allow-disposable-privacy-preparation')
    $preparationExit = $prepared.ExitCode
    if ($prepared.ErrorOutput.Length) { throw 'Unexpected helper stderr.' }
    $report = $prepared.Output.Trim() | ConvertFrom-Json -Depth 8
    if ($report.schema -ne 'first-logon-prepare/v1') { throw 'Unexpected preparation schema.' }
    Write-Output $prepared.Output.Trim()
    $preparationVerified = $preparationExit -eq 0 -and $report.status -in @('completed', 'not_needed') -and
        $report.ordinary_desktop_verified -eq $true -and $report.cleanup_verified -eq $true -and
        $report.session_functionality_verified -eq $false
    $preparationEligible = Test-PreparationEligibility -Report $report -ExitCode $preparationExit
    $calibrationDiagnosticOnly = -not $preparationEligible
    $phase = 'native_window_calibration'
    # A completed helper result always receives an independent pixel/ownership
    # calibration. The helper report/status is preserved. Only the explicitly
    # recognized foreground timeout may use actual display proof instead of
    # the ordinary-foreground heuristic; every other helper failure blocks.
    try {
        $calibration = Invoke-OwnedProcess -Executable $powershell -WaitMilliseconds 65000 -MaximumOutput 1048576 `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive',
            '-File', $calibrationRunner, '-Program', [System.IO.Path]::GetFullPath($CalibrationProgram))
        $calibrationExit = $calibration.ExitCode
        Write-Output $calibration.Output
        if ($calibration.ErrorOutput.Length) { throw 'Unexpected calibration stderr.' }
        $calibrationLines = @($calibration.Output -split '\r?\n' | Where-Object {
            $_.StartsWith('{"schema":"native-window-calibration/v1",', [System.StringComparison]::Ordinal)
        })
        if ($calibrationLines.Count -ne 1) { throw 'Expected one actual native calibration report.' }
        $calibrationReport = $calibrationLines[0] | ConvertFrom-Json -Depth 8
        $nativeCalibrationVerified = Test-NativeCalibration -Report $calibrationReport -ExitCode $calibrationExit -SessionId $report.session_id
    } catch {
        $calibrationErrorHresult = ([long]$_.Exception.HResult -band 4294967295L)
        $calibrationErrorType = $_.Exception.GetType().Name
    }
    if (-not $preparationEligible) {
        $phase = 'prepare_parent_first_logon'
        throw 'Helper action ownership, cleanup or active desktop not verified; calibration is diagnostic only.'
    }
    if ($null -ne $calibrationErrorHresult) { throw 'Independent native calibration did not complete.' }
    if (-not $nativeCalibrationVerified) { throw 'Independent native window calibration failed.' }
    $parentDisplayVerified = $true
    $foregroundTimeoutAccepted = -not $preparationVerified
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
    helper_outcome_eligible = $preparationEligible
    parent_display_verified = $parentDisplayVerified
    readiness_basis = $(if ($parentDisplayVerified) { 'independent_native_calibration' } else { 'unverified' })
    foreground_heuristic_timeout_accepted = $foregroundTimeoutAccepted
    setup_completion_verified = $false
    preparation_exit = $preparationExit
    native_calibration_exit = $calibrationExit
    native_calibration_verified = $nativeCalibrationVerified
    calibration_diagnostic_only = $calibrationDiagnosticOnly
    calibration_error_hresult = $calibrationErrorHresult
    calibration_error_type = $calibrationErrorType
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
