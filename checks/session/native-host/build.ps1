param([Parameter(Mandatory = $true)][string] $HarnessExecutable)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [OperatingSystem]::IsWindows()) { throw 'Windows is required.' }
$exe = (Resolve-Path -LiteralPath $HarnessExecutable).ProviderPath
# Inspect the emitted managed apphost's real PE machine, so the native DLL
# matches the executable even if PowerShell runs under another architecture.
$stream = [IO.File]::OpenRead($exe)
$reader = [IO.BinaryReader]::new($stream)
try {
    if ($stream.Length -lt 128 -or $reader.ReadUInt16() -ne 0x5A4D) { throw 'Harness apphost PE header missing.' }
    $stream.Position = 0x3C
    $offset = $reader.ReadUInt32()
    if ($offset -lt 64 -or $offset -gt $stream.Length - 24) { throw 'Harness PE offset invalid.' }
    $stream.Position = $offset
    if ($reader.ReadUInt32() -ne 0x4550) { throw 'Harness PE signature invalid.' }
    $architecture = switch ($reader.ReadUInt16()) {
        0x8664 { 'x64'; break }
        0xAA64 { 'ARM64'; break }
        default { throw 'Only the explicitly tested 64-bit native targets are supported.' }
    }
} finally { $reader.Dispose(); $stream.Dispose() }
$build = Join-Path $PSScriptRoot ('bin\' + $architecture)
& cmake -S $PSScriptRoot -B $build -A $architecture
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cmake --build $build --config Release --parallel 2
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$library = Join-Path $build 'Release\NativeHostBridge.dll'
if (-not (Test-Path -LiteralPath $library -PathType Leaf)) { throw 'Native bridge build did not produce the DLL.' }
Copy-Item -LiteralPath $library -Destination (Join-Path ([IO.Path]::GetDirectoryName($exe)) 'NativeHostBridge.dll')
