namespace SessionContractExperiment;

internal static class ActivationScripts
{
    // ID is read solely to bind the later method to this exact primary product.
    // Only its SHA-256 travels through the owned pipe and it is never logged.
    // PartialProductKey remains a provider-side presence predicate; no key
    // value, activation server, product name or installation ID is selected.
    private const string Prelude = """
        $ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue';
        function Read-Primary {
          @(Get-CimInstance -Query "SELECT ID,LicenseStatus,LicenseStatusReason,GracePeriodRemaining,EvaluationEndDate,TrustedTime FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL AND LicenseIsAddon=FALSE" -OperationTimeoutSec 20)
        }
        function Unix-Time($value) {
          if($null -eq $value){return $null}
          if($value -is [datetime]){$date=$value}else{$date=[System.Management.ManagementDateTimeConverter]::ToDateTime([string]$value)}
          if($date.Year -le 1970){return $null}
          ([DateTimeOffset]$date.ToUniversalTime()).ToUnixTimeSeconds()
        }
        function Identity-Digest($value) {
          $id=[guid]::Empty
          if(-not [guid]::TryParse([string]$value.ID,[ref]$id)){throw 'product_identity_invalid'}
          $sha=[System.Security.Cryptography.SHA256]::Create()
          try{([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($id.ToString('D'))))).Replace('-','')}
          finally{$sha.Dispose()}
        }
        """;

    internal static string Query => Prelude + """

        try {
          $p=@(Read-Primary); $s=$null; $r=$null; $g=$null; $end=$null; $trusted=$null; $identity=$null
          if($p.Count -eq 1){
            if($null -eq $p[0].LicenseStatus -or $null -eq $p[0].LicenseStatusReason){throw 'license_status_missing'}
            $s=[uint32]$p[0].LicenseStatus; $r=[uint32]$p[0].LicenseStatusReason
            if($null -ne $p[0].GracePeriodRemaining){$g=[uint32]$p[0].GracePeriodRemaining}
            $end=Unix-Time $p[0].EvaluationEndDate; $trusted=Unix-Time $p[0].TrustedTime
            $identity=Identity-Digest $p[0]
          }
          [ordered]@{candidate_count=$p.Count;license_status=$s;license_status_reason=$r;grace_period_remaining=$g;evaluation_end_utc=$end;trusted_time_utc=$trusted;guest_utc=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();identity_digest=$identity}|ConvertTo-Json -Compress
        } catch { exit 1 }
        """;

    internal static string Activate(string expectedDigest)
    {
        if (expectedDigest.Length != 64 || !expectedDigest.All(char.IsAsciiHexDigit))
            throw new ArgumentException("product_digest_invalid", nameof(expectedDigest));
        return Prelude + "\n$expected='" + expectedDigest.ToUpperInvariant() + "';\n" + """
            $started=$false; $returned=$false; $rv=$null; $errorCode=$null; $guard=4; $same=$false
            try {
              $p=@(Read-Primary)
              if($p.Count -ne 1 -or (Identity-Digest $p[0]) -cne $expected){$guard=3}
              else {
                $same=$true
                if($null -eq $p[0].LicenseStatus -or [uint32]$p[0].LicenseStatus -gt 6){throw 'license_status_invalid'}
                $end=Unix-Time $p[0].EvaluationEndDate; $trusted=Unix-Time $p[0].TrustedTime
                $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                if($null -ne $end -and ($end -le $now -or ($null -ne $trusted -and $end -le $trusted))){$guard=2}
                elseif($null -ne $p[0].LicenseStatus -and [uint32]$p[0].LicenseStatus -eq 1){$guard=1}
                else {
                  $guard=0; $started=$true
                  $reply=Invoke-CimMethod -InputObject $p[0] -MethodName Activate -OperationTimeoutSec 60
                  $returned=$true
                  if($null -eq $reply.ReturnValue){throw 'activation_return_value_missing'}
                  $rv=[uint32]$reply.ReturnValue
                }
              }
            } catch { $errorCode=[int]$_.Exception.HResult }
            [ordered]@{invocation_started=$started;invocation_returned=$returned;return_value=$rv;error_hresult=$errorCode;guard_code=$guard;same_product_verified=$same}|ConvertTo-Json -Compress
            """;
    }
}
