param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$process = $null
$ownedDirectory = $null
$outcome = 1
try {
    $resolved = (Resolve-Path -LiteralPath $Executable).ProviderPath
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw 'executable_missing' }
    $candidate = Join-Path ([IO.Path]::GetTempPath()) ('component-contract-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $candidate -ErrorAction Stop | Out-Null
    $ownedDirectory = $candidate
    $stdout = Join-Path $ownedDirectory 'stdout.json'
    $stderr = Join-Path $ownedDirectory 'stderr.txt'
    $process = Start-Process -FilePath $resolved -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null = $process.Handle
    if (-not $process.WaitForExit(20000)) {
        [ordered]@{schema='native-component-contract-launch/v1';status='timeout';rdp_connect_called=$false} | ConvertTo-Json -Compress
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
        $result = $text | ConvertFrom-Json -Depth 16
        if ($result.schema -ne 'native-component-contract/v1' -or $result.status -notin @('verified','failed','unavailable')) { throw 'result_schema_invalid' }
        foreach ($name in @('rdp_connect_called','password_methods_called','request_close_called','events_subscribed','events_delivered_verified',
                'credentials_ui_called','accounts_created','session_creation_verified','remote_frame_verified','input_channel_verified','physical_multiseat_verified')) {
            if ($result.$name -isnot [bool] -or $result.$name -ne $false) { throw 'scope_flag_invalid' }
        }
        if ($result.unhosted_control -isnot [bool] -or $result.unhosted_control -ne $true) { throw 'control_scope_invalid' }
        if ($nativeExit -eq 0) {
            if ($result.status -ne 'verified' -or $result.connected_before -ne 0 -or $result.connected_after -ne 0 -or
                $result.error_hresult -ne 0 -or $result.close_hresult -ne 0) { throw 'native_result_contradiction' }
            foreach ($name in @('sta_verified','control_class_verified','native_contracts_verified','event_metadata_verified','connection_point_verified',
                    'required_properties_verified','owned_references_released','control_closed','ole_uninitialized','cleanup_verified')) {
                if ($result.$name -isnot [bool] -or $result.$name -ne $true) { throw 'required_gate_missing' }
            }
            if (@($result.native_interfaces).Count -ne 4 -or @($result.events).Count -ne 10 -or @($result.properties).Count -ne 15) { throw 'result_count_invalid' }
            foreach ($item in $result.native_interfaces) {
                if ($item.verified -isnot [bool] -or $item.verified -ne $true -or $item.qi_verified -isnot [bool] -or $item.qi_verified -ne $true) { throw 'native_contract_gate_missing' }
            }
            foreach ($item in $result.events) {
                if ($item.verified -isnot [bool] -or $item.verified -ne $true) { throw 'event_metadata_gate_missing' }
            }
            $required = @($result.properties | Where-Object { $_.required -is [bool] -and $_.required -eq $true })
            if ($required.Count -ne 14) { throw 'required_property_count_invalid' }
            foreach ($item in $required) {
                if ($item.attempted -isnot [bool] -or $item.attempted -ne $true -or $item.verified -isnot [bool] -or $item.verified -ne $true) { throw 'property_gate_missing' }
            }
            $outcome = 0
        } elseif ($nativeExit -eq 77 -and $result.status -eq 'unavailable' -and $result.cleanup_verified -is [bool] -and $result.cleanup_verified -eq $true) {
            $outcome = 77
        } elseif ($result.status -eq 'verified') { throw 'verified_with_failed_exit' }
        Write-Output ($text.Trim())
    }
} catch {
    [ordered]@{schema='native-component-contract-launch/v1';status='failed';exception_type=$_.Exception.GetType().Name;rdp_connect_called=$false} | ConvertTo-Json -Compress
    $outcome = 1
} finally {
    $stopped = $true
    if ($null -ne $process) {
        try { if (-not $process.HasExited) { $process.Kill(); $stopped = $process.WaitForExit(5000) } }
        catch { $stopped = $false }
        $process.Dispose()
    }
    $removed = $true
    if ($null -ne $ownedDirectory) {
        try { Remove-Item -LiteralPath $ownedDirectory -Recurse -Force -ErrorAction Stop }
        catch { $removed = $false }
    }
    if (-not $stopped -or -not $removed) {
        [ordered]@{schema='native-component-contract-launch/v1';status='cleanup_unverified';own_process_stopped=$stopped;own_files_removed=$removed} | ConvertTo-Json -Compress
        $outcome = 1
    }
}
exit $outcome
