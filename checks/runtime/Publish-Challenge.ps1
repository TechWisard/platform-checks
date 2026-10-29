[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BundlePath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
try {
    if ($env:GITHUB_REPOSITORY -cne 'TechWisard/platform-checks' -or $env:GITHUB_REF -cne 'refs/heads/main' -or $env:GITHUB_SHA -cnotmatch '^[0-9a-f]{40}$' -or $env:GITHUB_RUN_ID -notmatch '^[1-9][0-9]{0,19}$' -or $env:GITHUB_RUN_ATTEMPT -notmatch '^[1-9][0-9]{0,19}$') { throw 'context' }
    $root = [IO.Path]::GetFullPath($env:RUNTIME_PROBE_ROOT)
    $prefix = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    if (-not $root.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($root) -notmatch '^runtime-probe-[0-9a-f]{32}$') { throw 'root' }
    $challenge = [IO.File]::ReadAllBytes((Join-Path $root 'challenge.json'))
    $bundle = [IO.File]::ReadAllBytes($BundlePath)
    if ($challenge.Length -gt 8192 -or $bundle.Length -gt 262144) { throw 'size' }
    $headers = @{ Authorization=('Bearer ' + $env:RUNTIME_CONTENT_TOKEN); Accept='application/vnd.github+json'; 'X-GitHub-Api-Version'='2022-11-28' }
    $base = 'https://api.github.com/repos/TechWisard/platform-checks'
    function Api([string]$Method, [string]$Suffix, $Body) {
        $options = @{ Uri=($base + $Suffix); Method=$Method; Headers=$headers; MaximumRedirection=0; TimeoutSec=20; ErrorAction='Stop' }
        if ($null -ne $Body) { $options.Body=($Body | ConvertTo-Json -Depth 10 -Compress); $options.ContentType='application/json; charset=utf-8' }
        return Invoke-RestMethod @options
    }
    $parent = Api 'GET' ('/git/commits/' + $env:GITHUB_SHA) $null
    if ($parent.sha -cne $env:GITHUB_SHA -or $parent.tree.sha -cnotmatch '^[0-9a-f]{40}$') { throw 'parent' }
    $elements = @()
    foreach ($file in @(@{path='runtime/challenge.json'; bytes=$challenge}, @{path='runtime/challenge.sigstore.json'; bytes=$bundle})) {
        $blob = Api 'POST' '/git/blobs' @{content=[Convert]::ToBase64String($file.bytes); encoding='base64'}
        if ($blob.sha -cnotmatch '^[0-9a-f]{40}$') { throw 'blob' }
        $elements += @{path=$file.path; mode='100644'; type='blob'; sha=$blob.sha}
    }
    $tree = Api 'POST' '/git/trees' @{base_tree=$parent.tree.sha; tree=$elements}
    $commit = Api 'POST' '/git/commits' @{message='Record public per-run test challenge and attestation [skip ci]'; tree=$tree.sha; parents=@($env:GITHUB_SHA)}
    if ($commit.sha -cnotmatch '^[0-9a-f]{40}$') { throw 'commit' }
    $branch = 'refs/heads/runtime-probe/' + $env:GITHUB_RUN_ID + '-' + $env:GITHUB_RUN_ATTEMPT
    # Create exactly one new branch. A conflict fails; never update or force an existing ref.
    $published = Api 'POST' '/git/refs' @{ref=$branch; sha=$commit.sha}
    if ($published.ref -cne $branch -or $published.object.sha -cne $commit.sha) { throw 'publication' }
    '{"schema":"runtime-publication/v1","published":true}'
} catch {
    '{"schema":"runtime-publication/v1","published":false}'
    exit 1
}
