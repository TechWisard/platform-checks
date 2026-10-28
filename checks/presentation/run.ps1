param([Parameter(Mandatory=$true)][string]$Program)
$ErrorActionPreference = 'Stop'
$start = [Diagnostics.ProcessStartInfo]::new([IO.Path]::GetFullPath($Program))
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [Diagnostics.Process]::new()
$process.StartInfo = $start
$started = $false
$stopped = $false
$code = 1
try {
    $started = $process.Start()
    if (-not $started) { throw 'Owned probe did not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $stopped = $process.WaitForExit(20000)
    if (-not $stopped) {
        $process.Kill($true)
        $stopped = $process.WaitForExit(5000)
        [ordered]@{schema='startup-presentation-launch/v1';status='timeout';own_process_stopped=$stopped;input_sent=$false} | ConvertTo-Json -Compress
        $code = 124
    } else {
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),3000)) {
            throw 'Owned probe streams did not close.'
        }
        $text = $stdout.GetAwaiter().GetResult()
        $errors = $stderr.GetAwaiter().GetResult()
        if ($text.Length -gt 16384 -or $errors.Length -ne 0) { throw 'Unexpected owned probe output.' }
        $result = $text | ConvertFrom-Json
        if ($result.schema -ne 'startup-presentation/v1' -or $result.input_sent -ne $false -or $result.window_changed -ne $false) {
            throw 'Unexpected probe contract.'
        }
        $text.Trim()
        $code = $process.ExitCode
    }
} catch {
    [ordered]@{schema='startup-presentation-launch/v1';status='failed';exception_type=$_.Exception.GetType().Name;input_sent=$false} | ConvertTo-Json -Compress
    $code = 1
} finally {
    if ($started -and -not $stopped) {
        try {
            if (-not $process.HasExited) { $process.Kill($true) }
            $stopped = $process.WaitForExit(5000)
        } catch { $stopped = $false }
    }
    if ($started -and -not $stopped) {
        [ordered]@{schema='startup-presentation-launch/v1';status='cleanup_unverified';own_process_stopped=$false} | ConvertTo-Json -Compress
        $code = 125
    }
    $process.Dispose()
}
exit $code
