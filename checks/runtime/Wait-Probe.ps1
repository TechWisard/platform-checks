[CmdletBinding()]
param([switch]$CleanupOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$success = $false
$removed = $false
$stopped = $false
$root = $null
$ownedRoot = $false
$phase = 'context'
$receiverFound = $false
$receiverRunning = $false
$reportFound = $false
$reportProjected = $false
function Read-Boolean($Value) {
    if ($Value -isnot [bool]) { throw 'boolean_type' }
    return $Value
}
function Read-String($Value) {
    if ($Value -isnot [string]) { throw 'string_type' }
    return $Value
}
function Read-Integer($Value, [long]$Minimum, [long]$Maximum) {
    if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt $Minimum -or $Value -gt $Maximum) { throw 'integer_type' }
    return [long]$Value
}
function Read-BoundedUtf8([string]$Path, [int]$Maximum) {
    if (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'read_reparse' }
    $stream = [IO.File]::OpenRead($Path)
    try {
        if ($stream.Length -gt $Maximum) { throw 'read_size' }
        $buffer = [byte[]]::new($Maximum + 1)
        $used = 0
        do {
            $count = $stream.Read($buffer, $used, $buffer.Length - $used)
            $used += $count
            if ($used -gt $Maximum) { throw 'read_size' }
        } while ($count -gt 0)
        return [Text.UTF8Encoding]::new($false, $true).GetString($buffer, 0, $used)
    } finally { $stream.Dispose() }
}
function Test-CaseSuccess([bool]$ReportedPass, [bool]$FilesRemoved, [long]$ErrorCode, [object[]]$Cases) {
    $valid = $ReportedPass -and $FilesRemoved -and $Cases.Count -eq 4 -and $ErrorCode -eq 0
    for ($index = 0; $index -lt $Cases.Count; $index++) {
        $case = $Cases[$index]
        $expectedExit = if ($index -eq 2) { 64 } else { 0 }
        $valid = $valid -and $case.index -eq ($index + 1) -and $case.passed -and $case.process_started -and $case.exit_observed -and $case.exit_code -eq $expectedExit -and $case.stdout_matches -and $case.stderr_matches -and $case.job_empty -and $case.cleanup_verified -and -not $case.forced_termination -and $case.error -eq 0
        if ($index -eq 3) { $valid = $valid -and $case.window_observed -and $case.window_responsive -and $case.close_sent }
        else { $valid = $valid -and -not $case.window_observed -and -not $case.window_responsive -and -not $case.close_sent }
    }
    return $valid
}
function Remove-OwnedTree([string]$Directory) {
    $item = Get-Item -LiteralPath $Directory -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
    foreach ($childItem in Get-ChildItem -LiteralPath $Directory -Force) {
        if (($childItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
        if ($childItem.PSIsContainer) { Remove-OwnedTree $childItem.FullName }
        else { [IO.File]::Delete($childItem.FullName) }
    }
    [IO.Directory]::Delete($Directory, $false)
}
try {
    if ([string]::IsNullOrEmpty($env:RUNTIME_PROBE_ROOT)) { throw 'missing_root' }
    $root = [IO.Path]::GetFullPath($env:RUNTIME_PROBE_ROOT)
    $prefix = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    if (-not $root.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($root) -notmatch '^runtime-probe-[0-9a-f]{32}$') { throw 'root' }
    $ownedRoot = $true
    $phase = 'receipt'
    $receiptText = Read-BoundedUtf8 (Join-Path $root 'process.json') 4096
    $receipt = $receiptText | ConvertFrom-Json
    $receiptNames = @($receipt.PSObject.Properties.Name | Sort-Object)
    if ((Read-String $receipt.schema) -cne 'runtime-process/v1' -or ($receiptNames -join ',') -cne 'executable,pid,schema,startUtcTicks') { throw 'receipt' }
    $processId = Read-Integer $receipt.pid 1 2147483647
    $startTicks = Read-Integer $receipt.startUtcTicks 1 ([datetime]::MaxValue.Ticks)
    $runtime = (Get-Command dotnet -CommandType Application).Source
    if ($receipt.executable -isnot [string] -or $receipt.executable.Length -gt 1024 -or $receipt.executable -cne $runtime) { throw 'receipt_executable' }
    $phase = 'receiver_lookup'
    $child = $null
    try { $child = [Diagnostics.Process]::GetProcessById([int]$processId) }
    catch [ArgumentException] { $child = $null }
    if ($null -ne $child) {
        $receiverFound = $true
        $phase = 'receiver_identity'
        # Open a handle before checking lifetime identity; access/query failures
        # remain failures and are never interpreted as proof of process absence.
        $null = $child.Handle
        if ($child.StartTime.ToUniversalTime().Ticks -ne $startTicks -or $child.Path -cne $runtime) { throw 'identity' }
        $receiverRunning = -not $child.HasExited
        $phase = 'receiver_wait'
        if (-not $CleanupOnly) { [void]$child.WaitForExit(1580000) }
        $child.Refresh()
        if (-not $child.HasExited) { $child.Kill(); [void]$child.WaitForExit(5000) }
        $stopped = $child.HasExited
    } else { $stopped = $true }
    if (-not $stopped) { throw 'still_running' }
    $phase = 'report_lookup'
    $path = Join-Path $root 'result.json'
    $reportFound = Test-Path -LiteralPath $path -PathType Leaf
    if ($reportFound) {
        $phase = 'report_parse'
        $report = (Read-BoundedUtf8 $path 16384) | ConvertFrom-Json
        $phase = 'report_validate'
        if ((Read-String $report.schema) -cne 'runtime-result/v1' -or $report.cases -isnot [System.Array] -or $report.cases.Count -gt 4) { throw 'result' }
        # Reconstruct a strict scalar whitelist. Never forward process text or arbitrary JSON fields.
        $cases = @($report.cases | ForEach-Object {
            $entry = @{index=(Read-Integer $_.index 1 4); error=(Read-Integer $_.error -2147483648 2147483647); exit_code=$null}
            foreach ($name in @('process_started','exit_observed','stdout_matches','stderr_matches','window_observed','window_responsive','close_sent','job_empty','cleanup_verified','forced_termination','passed')) { $entry[$name] = Read-Boolean $_.$name }
            if ($null -ne $_.exit_code) { $entry.exit_code = Read-Integer $_.exit_code 0 4294967295 }
            $entry
        })
        $stage = Read-String $report.stage
        if ($stage -cnotmatch '^(startup|wait_envelope|decrypt|case_[1-4]|cleanup)$') { throw 'stage' }
        $passed = Read-Boolean $report.passed
        $filesRemoved = Read-Boolean $report.plaintext_files_removed
        $errorCode = Read-Integer $report.error -2147483648 2147483647
        $success = Test-CaseSuccess $passed $filesRemoved $errorCode $cases
        # Emit the derived result only after the exact case implications hold.
        @{schema='runtime-result/v1'; passed=$success; stage=$stage; error=$errorCode; cases=$cases; plaintext_files_removed=$filesRemoved} | ConvertTo-Json -Depth 5 -Compress
        $reportProjected = $true
        $phase = 'complete'
    }
    else { $phase = 'report_missing' }
} catch {
    $success = $false
} finally {
    if ($ownedRoot -and $stopped) {
        try { Remove-OwnedTree $root; $removed = -not (Test-Path -LiteralPath $root) }
        catch { $removed = $false }
    }
}
@{schema='runtime-observation/v1'; phase=$phase; receiver_found=$receiverFound; receiver_running_on_lookup=$receiverRunning; report_found=$reportFound; report_projected=$reportProjected} | ConvertTo-Json -Compress
@{schema='runtime-cleanup/v1'; receiver_stopped=$stopped; work_directory_removed=$removed; passed=($stopped -and $removed)} | ConvertTo-Json -Compress
if (-not ($success -and $stopped -and $removed)) { exit 1 }
