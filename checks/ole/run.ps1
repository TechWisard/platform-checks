param([Parameter(Mandatory = $true)][string] $Program)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$start = [System.Diagnostics.ProcessStartInfo]::new()
$start.FileName = [System.IO.Path]::GetFullPath($Program)
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $start
$started = $false
try {
    $started = $process.Start()
    if (-not $started) { throw 'Native probe could not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(45000)) {
        $process.Kill($true)
        $null = $process.WaitForExit(5000)
        '{"schema":"native-ole-host-runner/v1","status":"external_timeout","cleanup_verified":false,"hosting_verified":false}'
        exit 124
    }
    $result = $process.ExitCode
    if (-not $stdout.Wait(2000) -or -not $stderr.Wait(2000)) {
        '{"schema":"native-ole-host-runner/v1","status":"output_timeout","cleanup_verified":false,"hosting_verified":false}'
        exit 1
    }
    if ($stdout.Result.Length -gt 16384 -or $stderr.Result.Length -gt 4096) {
        '{"schema":"native-ole-host-runner/v1","status":"output_limit","cleanup_verified":false,"hosting_verified":false}'
        exit 1
    }
    $value = $stdout.Result.Trim() | ConvertFrom-Json -Depth 8
    if ($value.schema -ne 'native-ole-host-probe/v1') { throw 'Unexpected probe schema.' }
    # The native program has one fixed, bounded JSON record. No stderr text,
    # screenshots, memory dumps, or files are collected or uploaded.
    Write-Output $stdout.Result.Trim()
    if ($result -eq 0 -and ($value.status -ne 'verified' -or -not $value.cleanup_verified)) { exit 1 }
    exit $result
} finally {
    # A wrapper exception must not leave a blocked COM call running. This is
    # only the process created above, never a process found by name or PID scan.
    if ($started) {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(5000)) {
                    '{"schema":"native-ole-host-runner/v1","status":"own_process_stop_unverified","cleanup_verified":false,"hosting_verified":false}'
                }
            }
        } catch {
            '{"schema":"native-ole-host-runner/v1","status":"own_process_stop_unverified","cleanup_verified":false,"hosting_verified":false}'
        }
    }
    $process.Dispose()
}
