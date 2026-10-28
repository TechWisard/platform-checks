param([Parameter(Mandatory = $true)][string] $Executable)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Integer {
    param([object] $Value)
    if ($Value -isnot [int] -and $Value -isnot [long] -and $Value -isnot [uint32] -and $Value -isnot [uint64]) {
        throw 'integer_field_required'
    }
}

function Assert-FalseScope {
    param([object] $Report)
    foreach ($name in @('synthetic_invoke_called', 'listener_recv_called', 'listener_send_called',
            'server_protocol_reply_sent', 'credentials_provided', 'password_methods_called',
            'child_feature_changed', 'accounts_created', 'session_creation_verified',
            'remote_frame_verified', 'input_channel_verified', 'physical_multiseat_verified')) {
        if ($Report.$name -isnot [bool] -or $Report.$name -ne $false) { throw 'scope_flag_invalid' }
    }
}

function Assert-NativePass {
    param([object] $Report)
    if ($Report.schema -cne 'native-event-delivery/v1' -or $Report.status -cne 'verified' -or
        $Report.stage -cne 'completed' -or $Report.operation -cne '') { throw 'native_result_contradiction' }
    Assert-FalseScope -Report $Report
    foreach ($name in @('environment_verified', 'non_system_verified', 'sta_verified', 'system_control_verified',
            'host_verified', 'parent_hidden', 'child_mode_disabled', 'credential_prompt_disabled', 'gateway_direct',
            'reconnect_disabled', 'listener_bound', 'listener_exclusive', 'listener_address_verified', 'listener_started',
            'socket_accepted', 'peer_loopback', 'accepted_socket_closed', 'advised', 'advise_cookie_nonzero',
            'connect_called', 'connect_returned', 'callbacks_on_owner_thread', 'connecting_seen', 'disconnected_seen',
            'native_event_delivery_verified', 'request_close_called', 'request_close_verified', 'disconnected_for_cleanup',
            'sink_detached', 'unadvised', 'advise_cookie_cleared', 'references_released', 'host_closed', 'parent_destroyed',
            'class_unregistered', 'listener_thread_joined', 'listener_socket_closed', 'winsock_cleaned', 'ole_uninitialized',
            'watchdog_stopped', 'watchdog_handles_closed', 'cleanup_verified')) {
        if ($Report.$name -isnot [bool] -or $Report.$name -ne $true) { throw 'required_gate_missing' }
    }
    foreach ($name in @('event_overflow', 'event_contract_failed', 'login_seen', 'authentication_warning_seen', 'fatal_seen')) {
        if ($Report.$name -isnot [bool] -or $Report.$name -ne $false) { throw 'unexpected_event_state' }
    }
    foreach ($name in @('error_hresult', 'cleanup_hresult', 'advise_hresult', 'connect_hresult', 'request_close_hresult',
            'unadvise_hresult', 'host_close_hresult', 'connected_before', 'connected_after', 'close_status', 'socket_error', 'shutdown_error')) {
        Assert-Integer -Value $Report.$name
        if ($Report.$name -ne 0) { throw 'required_zero_field_nonzero' }
    }
    foreach ($name in @('architecture', 'pointer_bits', 'event_count', 'connecting_sequence', 'disconnected_sequence', 'elapsed_ms')) {
        Assert-Integer -Value $Report.$name
    }
    if ($Report.architecture -notin @(9, 12) -or $Report.pointer_bits -ne 64 -or $Report.elapsed_ms -lt 0 -or
        $Report.event_count -lt 2 -or $Report.event_count -gt 64 -or $Report.events -isnot [array] -or
        $Report.events.Count -ne $Report.event_count -or $Report.connecting_sequence -lt 1 -or
        $Report.disconnected_sequence -le $Report.connecting_sequence -or $Report.disconnected_sequence -gt $Report.event_count) {
        throw 'event_count_or_order_invalid'
    }
    for ($index = 0; $index -lt $Report.events.Count; ++$index) {
        $row = $Report.events[$index]
        foreach ($name in @('sequence', 'kind', 'code')) { Assert-Integer -Value $row.$name }
        if ($row.sequence -ne ($index + 1) -or $row.kind -lt 0 -or $row.kind -gt 10 -or
            $row.code -lt -2147483648L -or $row.code -gt 2147483647L -or $row.kind -in @(2, 4, 7, 10)) {
            throw 'event_record_invalid'
        }
    }
    if ($Report.events[[int]$Report.connecting_sequence - 1].kind -ne 0 -or
        $Report.events[[int]$Report.disconnected_sequence - 1].kind -ne 3) { throw 'event_sequence_kind_mismatch' }
}

$process = $null
$ownedDirectory = $null
$outcome = 1
try {
    if (-not [System.OperatingSystem]::IsWindows()) { throw 'windows_required' }
    $resolved = (Resolve-Path -LiteralPath $Executable).ProviderPath
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw 'executable_missing' }
    $candidate = Join-Path ([IO.Path]::GetTempPath()) ('native-events-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $candidate -ErrorAction Stop | Out-Null
    $ownedDirectory = $candidate
    $stdout = Join-Path $ownedDirectory 'stdout.json'
    $stderr = Join-Path $ownedDirectory 'stderr.txt'
    $process = Start-Process -FilePath $resolved -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null = $process.Handle
    if (-not $process.WaitForExit(50000)) {
        [ordered]@{ schema = 'native-event-delivery-launch/v1'; status = 'timeout'; cleanup_verified = $false } | ConvertTo-Json -Compress
    } else {
        $process.Refresh()
        $nativeExit = $process.ExitCode
        $size = (Get-Item -LiteralPath $stdout -ErrorAction Stop).Length
        if ($size -eq 0 -or $size -gt 65536) { throw 'result_size_invalid' }
        $bytes = [byte[]]::new(65537)
        $length = 0
        $stream = [IO.File]::OpenRead($stdout)
        try {
            while ($length -lt $bytes.Length) {
                $read = $stream.Read($bytes, $length, $bytes.Length - $length)
                if ($read -eq 0) { break }
                $length += $read
            }
        } finally { $stream.Dispose() }
        if ($length -eq 0 -or $length -gt 65536) { throw 'result_size_invalid' }
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes, 0, $length)
        $report = $text | ConvertFrom-Json -Depth 16
        if ($report -is [array]) { throw 'single_result_required' }
        if ($report.schema -ceq 'native-event-delivery-termination/v1') {
            if ($nativeExit -ne 125 -or $report.status -cne 'cleanup_unverified' -or
                $report.cleanup_verified -isnot [bool] -or $report.cleanup_verified -ne $false -or $report.exit_code -ne 125 -or
                $report.reason -cnotin @('listener_join_unverified', 'watchdog_deadline_or_wait', 'watchdog_signal_failed', 'watchdog_join_unverified')) {
                throw 'termination_record_invalid'
            }
            Assert-Integer -Value $report.cleanup_hresult
            Assert-Integer -Value $report.wait_result
            Write-Output ($text.Trim())
        } elseif ($report.schema -ceq 'native-event-delivery/v1') {
            if ($report.status -cnotin @('verified', 'failed', 'unavailable')) { throw 'result_status_invalid' }
            Assert-FalseScope -Report $report
            if ($nativeExit -eq 0) {
                Assert-NativePass -Report $report
                $outcome = 0
            } elseif ($nativeExit -eq 77 -and $report.status -ceq 'unavailable' -and
                $report.cleanup_verified -is [bool] -and $report.cleanup_verified -eq $true) {
                $outcome = 77
            } elseif ($report.status -ceq 'verified') { throw 'verified_with_failed_exit' }
            Write-Output ($text.Trim())
        } else { throw 'result_schema_invalid' }
        if ((Get-Item -LiteralPath $stderr -ErrorAction Stop).Length -ne 0) { throw 'unexpected_native_stderr' }
    }
} catch {
    [ordered]@{ schema = 'native-event-delivery-launch/v1'; status = 'failed'; exception_type = $_.Exception.GetType().Name } | ConvertTo-Json -Compress
    $outcome = 1
} finally {
    $stopped = $true
    if ($null -ne $process) {
        try {
            if (-not $process.HasExited) { $process.Kill(); $stopped = $process.WaitForExit(5000) }
        } catch { $stopped = $false }
        $process.Dispose()
    }
    $removed = $true
    if ($null -ne $ownedDirectory) {
        try { Remove-Item -LiteralPath $ownedDirectory -Recurse -Force -ErrorAction Stop }
        catch { $removed = $false }
    }
    if (-not $stopped -or -not $removed) {
        [ordered]@{ schema = 'native-event-delivery-launch/v1'; status = 'cleanup_unverified'; own_process_stopped = $stopped; own_files_removed = $removed } | ConvertTo-Json -Compress
        $outcome = 1
    }
}
exit $outcome
