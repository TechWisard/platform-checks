param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $Executable).ProviderPath
$native = & $resolved --disposable-root-probe
$nativeExit = $LASTEXITCODE
if ($null -eq $native) { throw 'probe_output_missing' }
$text = $native -join "`n"
if ($text.Length -eq 0 -or $text.Length -gt 32768) { throw 'probe_output_size_invalid' }
$result = $text | ConvertFrom-Json -Depth 12
if ($result.schema -ne 'root-device-property-observation/v1') { throw 'probe_schema_invalid' }
foreach ($field in @('driver_package_added','kernel_driver_service_created','kernel_driver_load_requested',
        'class_filters_modified','private_product_present','native_multiseat_verified','reboot_required')) {
    if ($result.$field -isnot [bool] -or $result.$field -ne $false) { throw "scope_or_reboot_gate_failed:$field" }
}
if ($result.cleanup_verified -isnot [bool] -or $result.cleanup_verified -ne $true) { throw 'probe_cleanup_not_verified' }
if ($result.owned_node_created -isnot [bool]) { throw 'ownership_flag_invalid' }
if ($result.owned_node_created -and ($result.node_absent_after -isnot [bool] -or -not $result.node_absent_after)) {
    throw 'owned_root_device_remains'
}
if ($nativeExit -eq 0) {
    if ($result.status -ne 'observed' -or $result.setter_observed -isnot [bool] -or -not $result.setter_observed -or
            $result.identity_verified -isnot [bool] -or -not $result.identity_verified -or
            $result.owned_node_created -ne $true) { throw 'missing_native_observation' }
    if ($result.setter_accepted -isnot [bool] -or $result.service_set.success -isnot [bool] -or
            $result.setter_accepted -ne $result.service_set.success) { throw 'setter_result_contradiction' }
    if ($result.setter_accepted -and $result.after.exact_service -ne $true) { throw 'accepted_setter_readback_missing' }
    if (-not $result.setter_accepted -and ($result.before.absent -ne $result.after.absent -or
            $result.before.empty -ne $result.after.empty)) { throw 'rejected_setter_changed_property' }
} elseif ($nativeExit -eq 77) {
    if ($result.status -ne 'unavailable' -or $result.setter_observed -ne $false) { throw 'unavailable_status_contradiction' }
} else {
    Write-Output $text
    throw "native_probe_failed:$nativeExit"
}
Write-Output $text
[ordered]@{
    schema = 'root-device-property-launch/v1'
    execution_commit = $env:GITHUB_SHA
    native_exit = $nativeExit
    runner_os = [Environment]::OSVersion.VersionString
    executable_sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    native_observation_completed = ($nativeExit -eq 0)
} | ConvertTo-Json -Compress
if ($nativeExit -eq 77) {
    Write-Output '::notice::Root-device property observation unavailable; no driver was installed or loaded.'
}
exit 0
