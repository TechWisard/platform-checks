param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$process = $null
$directory = $null
$outcome = 1
try {
    $resolved = (Resolve-Path -LiteralPath $Executable).ProviderPath
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('input-contract-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
    $stdout = Join-Path $directory 'stdout.json'
    $stderr = Join-Path $directory 'stderr.txt'
    $process = Start-Process -FilePath $resolved -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null = $process.Handle
    if (-not $process.WaitForExit(20000)) { throw 'native_timeout' }
    $process.Refresh()
    $size = (Get-Item -LiteralPath $stdout).Length
    if ($size -le 0 -or $size -gt 32768) { throw 'output_size' }
    $text = [IO.File]::ReadAllText($stdout, [Text.UTF8Encoding]::new($false, $true))
    $result = $text | ConvertFrom-Json -Depth 12
    if ($result.schema -ne 'native-input-contract/v1' -or $result.status -notin @('verified','failed')) { throw 'output_schema' }
    foreach ($name in @('rdp_connect_called','input_methods_called','credentials_used','remote_frame_verified','input_delivery_verified','physical_multiseat_verified')) {
        if ($result.$name -isnot [bool] -or $result.$name) { throw 'scope_flag' }
    }
    if ($process.ExitCode -eq 0) {
        if ($result.status -ne 'verified' -or $result.error_hresult -ne 0 -or $result.close_hresult -ne 0 -or $result.connected_before -ne 0 -or $result.connected_after -ne 0) { throw 'native_contradiction' }
        foreach ($name in @('sta_verified','metadata_verified','qi_verified','cleanup_verified','ole_uninitialized')) {
            if ($result.$name -isnot [bool] -or -not $result.$name) { throw 'required_gate' }
        }
        if (@($result.methods).Count -ne 3 -or @($result.enums).Count -ne 2) { throw 'metadata_count' }
        $outcome = 0
    } elseif ($result.status -eq 'verified') { throw 'verified_failed_exit' }
    Write-Output ($text.Trim())
} catch {
    [ordered]@{schema='native-input-contract-launch/v1';status='failed';exception_type=$_.Exception.GetType().Name;input_methods_called=$false} | ConvertTo-Json -Compress
} finally {
    $stopped = $true
    if ($null -ne $process) {
        try { if (-not $process.HasExited) { $process.Kill(); $stopped = $process.WaitForExit(5000) } } catch { $stopped = $false }
        $process.Dispose()
    }
    $removed = $true
    if ($null -ne $directory) { try { Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction Stop } catch { $removed = $false } }
    if (-not $stopped -or -not $removed) {
        [ordered]@{schema='native-input-contract-launch/v1';status='cleanup_unverified';own_process_stopped=$stopped;own_files_removed=$removed} | ConvertTo-Json -Compress
        $outcome = 1
    }
}
exit $outcome
