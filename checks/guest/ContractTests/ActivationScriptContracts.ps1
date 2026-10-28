param(
  [Parameter(Mandatory=$true)][string]$ScriptDirectory,
  [switch]$RequireWindowsPowerShell51
)
# Only local mock functions execute. The compiled production script text is
# parsed unchanged, and command resolution is checked before either script runs.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($RequireWindowsPowerShell51 -and (
    $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or
    $PSVersionTable.PSEdition -cne 'Desktop' -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT)){
  throw 'windows_powershell_51_required'
}
$script:Groups=0
function Assert-Condition([bool]$Condition){if(-not $Condition){
  $caller=(Get-PSCallStack)[1].ScriptLineNumber
  throw "synthetic_script_contract_failed_group_$script:Groups`_line_$caller"
}}
$blocks=@()
foreach($name in @('query.ps1','activate.ps1')){
  $text=[IO.File]::ReadAllText((Join-Path $ScriptDirectory $name))
  $tokens=$null;$errors=$null
  $null=[System.Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
  Assert-Condition ($errors.Count -eq 0)
  $blocks+=,[scriptblock]::Create($text)
}
$script:Groups++
function Reset-Scenario {
  $script:Products=@([pscustomobject]@{ID='00000000-0000-0000-0000-000000000001';LicenseStatus=[uint32]5;
    LicenseStatusReason=[uint32]3221549065;GracePeriodRemaining=[uint32]0;EvaluationEndDate=$null;TrustedTime=$null})
  $script:Calls=0;$script:QueryCalls=0;$script:ThrowQuery=$false;$script:ThrowMethod=$false;$script:ReturnValue=[uint32]0
  $script:OutputMode='return'
}
function Get-CimInstance {
  param([string]$Query,[uint32]$OperationTimeoutSec)
  Assert-Condition ($Query.StartsWith('SELECT ID,LicenseStatus,LicenseStatusReason,GracePeriodRemaining,EvaluationEndDate,TrustedTime FROM SoftwareLicensingProduct WHERE '))
  Assert-Condition ($Query.Contains('PartialProductKey IS NOT NULL AND LicenseIsAddon=FALSE') -and $OperationTimeoutSec -eq 20)
  $script:QueryCalls++
  if($script:ThrowQuery){throw 'synthetic_provider_error'}
  $script:Products
}
function Invoke-CimMethod {
  param($InputObject,[string]$MethodName,[uint32]$OperationTimeoutSec)
  Assert-Condition ($MethodName -ceq 'Activate' -and $OperationTimeoutSec -eq 60)
  Assert-Condition ([object]::ReferenceEquals($InputObject,$script:Products[0]))
  $script:Calls++
  if($script:ThrowMethod){throw 'synthetic_method_error'}
  if($script:OutputMode -eq 'empty'){return}
  if($script:OutputMode -eq 'missing'){[pscustomobject]@{};return}
  if($script:OutputMode -eq 'multiple'){
    [pscustomobject]@{ReturnValue=[uint32]0}
    [pscustomobject]@{ReturnValue=[uint32]0}
    return
  }
  if($script:OutputMode -eq 'scalar'){[uint32]0;return}
  if($script:OutputMode -eq 'projection-error'){
    $result=[pscustomobject]@{}
    $result|Add-Member -MemberType ScriptProperty -Name ReturnValue -Value {throw 'synthetic_projection_error'}
    $result
    return
  }
  [pscustomobject]@{ReturnValue=$script:ReturnValue}
}
foreach($name in @('Get-CimInstance','Invoke-CimMethod')){
  $selected=Get-Command -Name $name
  Assert-Condition ($selected.CommandType -eq [Management.Automation.CommandTypes]::Function -and
    $selected.ScriptBlock.File -ceq $PSCommandPath)
}
Reset-Scenario
$v=(& $blocks[0])|ConvertFrom-Json
Assert-Condition ($v.candidate_count -eq 1 -and $v.license_status -eq 5 -and $v.license_status_reason -eq 3221549065)
Assert-Condition ($null -eq $v.evaluation_end_utc -and $null -eq $v.trusted_time_utc -and $v.grace_period_remaining -eq 0)
Assert-Condition ($v.identity_digest -cmatch '^[0-9A-F]{64}$' -and $v.guest_utc -gt 946684800 -and $script:Calls -eq 0)
$script:Groups++
Reset-Scenario
$script:Products[0].EvaluationEndDate=[datetime]::SpecifyKind([datetime]'2031-01-01T00:00:00',[DateTimeKind]::Utc)
$script:Products[0].TrustedTime=[datetime]::SpecifyKind([datetime]'2030-01-01T00:00:00',[DateTimeKind]::Utc)
$v=(& $blocks[0])|ConvertFrom-Json
Assert-Condition ($v.evaluation_end_utc -eq 1924992000 -and $v.trusted_time_utc -eq 1893456000)
$script:Groups++
Reset-Scenario
$v=(& $blocks[1])|ConvertFrom-Json
Assert-Condition ($script:Calls -eq 1 -and $script:QueryCalls -eq 1 -and $v.invocation_started -and $v.invocation_returned)
Assert-Condition ($v.guard_code -eq 0 -and $v.same_product_verified -and $v.return_value -eq 0 -and $null -eq $v.error_hresult)
Assert-Condition ($v.result_shape -eq 3 -and $null -eq $v.result_error_hresult)
$script:Groups++
Reset-Scenario
$script:Products[0].LicenseStatus=[uint32]1
$v=(& $blocks[1])|ConvertFrom-Json
Assert-Condition ($script:Calls -eq 0 -and $v.guard_code -eq 1 -and $v.same_product_verified -and -not $v.invocation_started -and $null -eq $v.return_value)
$script:Groups++
Reset-Scenario
$script:Products[0].EvaluationEndDate=[datetime]::UtcNow.AddMinutes(-1)
$v=(& $blocks[1])|ConvertFrom-Json
Assert-Condition ($script:Calls -eq 0 -and $v.guard_code -eq 2 -and -not $v.invocation_started)
Reset-Scenario
$script:Products[0].EvaluationEndDate=[datetime]::UtcNow.AddMinutes(10)
$script:Products[0].TrustedTime=[datetime]::UtcNow.AddMinutes(11)
$v=(& $blocks[1])|ConvertFrom-Json
Assert-Condition ($script:Calls -eq 0 -and $v.guard_code -eq 2 -and -not $v.invocation_started)
$script:Groups++
foreach($kind in 0..2){
  Reset-Scenario
  if($kind -eq 0){$script:Products[0].ID='00000000-0000-0000-0000-000000000002'}
  elseif($kind -eq 1){$script:Products=@()}
  else{$script:Products+=,$script:Products[0]}
  $v=(& $blocks[1])|ConvertFrom-Json
  Assert-Condition ($script:Calls -eq 0 -and $v.guard_code -eq 3 -and -not $v.same_product_verified -and -not $v.invocation_started)
}
$script:Groups++
Reset-Scenario
$script:ThrowMethod=$true
$v=(& $blocks[1])|ConvertFrom-Json
Assert-Condition ($script:Calls -eq 1 -and $v.guard_code -eq 0 -and $v.invocation_started -and -not $v.invocation_returned)
Assert-Condition ($null -eq $v.return_value -and $null -ne $v.error_hresult)
Assert-Condition ($v.result_shape -eq 0 -and $null -eq $v.result_error_hresult)
$script:Groups++
Reset-Scenario
$script:ThrowQuery=$true
$v=(& $blocks[1])|ConvertFrom-Json
Assert-Condition ($script:Calls -eq 0 -and $v.guard_code -eq 4 -and -not $v.invocation_started -and $null -ne $v.error_hresult)
Reset-Scenario
$script:Products[0].LicenseStatus=$null
$v=(& $blocks[1])|ConvertFrom-Json
Assert-Condition ($script:Calls -eq 0 -and $v.guard_code -eq 4 -and -not $v.invocation_started -and $null -ne $v.error_hresult)
$script:Groups++
Reset-Scenario
$script:ReturnValue=[uint32]3221549065
$v=(& $blocks[1])|ConvertFrom-Json
Assert-Condition ($script:Calls -eq 1 -and $v.invocation_returned -and $v.return_value -eq 3221549065)
Reset-Scenario
$script:ReturnValue=$null
$v=(& $blocks[1])|ConvertFrom-Json
Assert-Condition ($script:Calls -eq 1 -and $v.invocation_returned -and $null -eq $v.return_value -and $null -eq $v.error_hresult)
Assert-Condition ($v.result_shape -eq 2 -and $null -eq $v.result_error_hresult)
$script:Groups++
foreach($scenario in @(@('empty',1),@('missing',2),@('multiple',5),@('scalar',2))){
  Reset-Scenario
  $script:OutputMode=$scenario[0]
  $v=(& $blocks[1])|ConvertFrom-Json
  Assert-Condition ($script:Calls -eq 1 -and $script:QueryCalls -eq 1 -and $v.invocation_started -and $v.invocation_returned)
  Assert-Condition ($v.result_shape -eq $scenario[1] -and $null -eq $v.return_value -and $null -eq $v.error_hresult -and $null -eq $v.result_error_hresult)
}
$script:Groups++
foreach($unsupported in @('0',[bool]$false,[int]-1,[long]0,[uint64]4294967296)){
  Reset-Scenario
  $script:ReturnValue=$unsupported
  $v=(& $blocks[1])|ConvertFrom-Json
  Assert-Condition ($script:Calls -eq 1 -and $v.invocation_returned -and $v.result_shape -eq 4)
  Assert-Condition ($null -eq $v.return_value -and $null -eq $v.error_hresult -and $null -eq $v.result_error_hresult)
}
$script:Groups++
Reset-Scenario
$script:OutputMode='projection-error'
$v=(& $blocks[1])|ConvertFrom-Json
# PowerShell can surface a throwing ScriptProperty getter as a null value.
# Either that unavailable value or an actual caught projection exception must
# preserve normal invocation completion and never invent a provider error.
Assert-Condition ($script:Calls -eq 1 -and $v.invocation_started -and $v.invocation_returned -and $v.result_shape -in @(2,6))
Assert-Condition ($null -eq $v.return_value -and $null -eq $v.error_hresult)
Assert-Condition (($v.result_shape -eq 6) -eq ($null -ne $v.result_error_hresult))
$script:Groups++
[ordered]@{schema='activation-script-contracts/v1';powershell_version=$PSVersionTable.PSVersion.ToString();windows_host=([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT);passed=$script:Groups;failed=0;exact_compiled_scripts=2;throwing_getter_observed_result_shape=$v.result_shape;guest_executed=$false;native_provider_invoked=$false}|ConvertTo-Json -Compress
