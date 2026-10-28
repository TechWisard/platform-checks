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
if (-not $process.Start()) { throw 'Could not start the native calibration.' }
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
$completed = $process.WaitForExit(45000)
if (-not $completed) {
    # Stop only the process tree created by this wrapper. Forced termination is
    # never evidence of the native program's own cleanup or functional success.
    $process.Kill($true)
    $null = $process.WaitForExit(5000)
    $result = 124
    '{"schema":"native-window-calibration-runner/v1","status":"external_timeout","cleanup_verified":false,"functional_pass":false}'
} else { $result = $process.ExitCode }
if ($stdout.Wait(2000)) { Write-Output $stdout.Result }
if ($stderr.Wait(2000) -and $stderr.Result) { Write-Output $stderr.Result }
$process.Dispose()
"native_calibration_exit=$result"
exit $result
