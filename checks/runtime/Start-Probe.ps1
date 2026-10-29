[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$child = $null
try {
    if ($env:GITHUB_REPOSITORY -cne 'TechWisard/platform-checks' -or $env:GITHUB_REF -cne 'refs/heads/main' -or $env:GITHUB_RUN_ID -notmatch '^[1-9][0-9]{0,19}$' -or $env:GITHUB_RUN_ATTEMPT -notmatch '^[1-9][0-9]{0,19}$') { throw 'context' }
    $request = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'request.json') -Raw | ConvertFrom-Json
    if ($request.schema -isnot [string] -or $request.nonce -isnot [string] -or $request.schema -cne 'runtime-request/v1' -or $request.nonce -cnotmatch '^[0-9a-f]{64}$') { throw 'request' }
    $root = Join-Path $env:RUNNER_TEMP ('runtime-probe-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $root)
    Add-Content -LiteralPath $env:GITHUB_ENV -Value ('RUNTIME_PROBE_ROOT=' + $root) -Encoding utf8NoBOM
    $program = Join-Path $PSScriptRoot 'bin/Release/net8.0/RuntimeProbe.dll'
    $runtime = (Get-Command dotnet -CommandType Application).Source
    # The native launcher inherits only explicit NUL handles. Start-Process's
    # broad handle inheritance would retain the runner step's pipe handles.
    & $runtime $program --launch $root $request.nonce
    if ($LASTEXITCODE -ne 0) { throw 'receiver_launch' }
    $receipt = Get-Content -LiteralPath (Join-Path $root 'process.json') -Raw | ConvertFrom-Json
    if ($receipt.schema -isnot [string] -or $receipt.executable -isnot [string] -or $receipt.schema -cne 'runtime-process/v1' -or $receipt.executable -cne $runtime -or ($receipt.pid -isnot [int] -and $receipt.pid -isnot [long]) -or $receipt.pid -lt 1 -or $receipt.pid -gt 2147483647 -or $receipt.startUtcTicks -isnot [long] -or $receipt.startUtcTicks -lt 1 -or $receipt.startUtcTicks -gt [datetime]::MaxValue.Ticks) { throw 'receiver_receipt' }
    $observed = [Diagnostics.Process]::GetProcessById([int]$receipt.pid)
    $null = $observed.Handle
    if ($observed.StartTime.ToUniversalTime().Ticks -ne $receipt.startUtcTicks -or $observed.Path -cne $runtime) { throw 'receiver_identity' }
    $child = $observed
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $challenge = Join-Path $root 'challenge.json'
    while (-not (Test-Path -LiteralPath $challenge -PathType Leaf)) {
        $child.Refresh()
        if ($child.HasExited -or $timer.Elapsed.TotalSeconds -ge 30) { throw 'receiver_start' }
        Start-Sleep -Milliseconds 100
    }
    $bytes = [IO.File]::ReadAllBytes($challenge)
    if ($bytes.Length -gt 8192) { throw 'challenge_size' }
    $parsed = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    foreach ($name in @('schema','runId','runAttempt','executionSha','requestNonce')) { if ($parsed.$name -isnot [string]) { throw 'challenge_type' } }
    if ($parsed.schema -cne 'runtime-challenge/v1' -or $parsed.runId -cne $env:GITHUB_RUN_ID -or $parsed.runAttempt -cne $env:GITHUB_RUN_ATTEMPT -or $parsed.executionSha -cne $env:GITHUB_SHA -or $parsed.requestNonce -cne $request.nonce) { throw 'challenge_identity' }
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value ('challenge=' + $challenge) -Encoding utf8NoBOM
    '{"schema":"runtime-start/v1","started":true}'
} catch {
    if ($null -ne $child) {
        try { $child.Refresh(); if (-not $child.HasExited) { $child.Kill(); [void]$child.WaitForExit(5000) } } catch { }
    }
    # Never print exception messages, arguments, environment values or captured output.
    '{"schema":"runtime-start/v1","started":false}'
    exit 1
}
