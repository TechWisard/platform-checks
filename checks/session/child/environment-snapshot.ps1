# Read-only diagnostic helpers. Dot-sourcing defines functions without running a probe.
# No service, registry, trust, audit-policy, account, or network-connect operations.
# The caller decides when to capture output; these helpers never write files.

function Get-SessionProbeError {
    param([System.Management.Automation.ErrorRecord] $Record)
    $exception = $Record.Exception
    $availability = 'unavailable'
    $code = [int]$exception.HResult
    for ($depth = 0; $null -ne $exception -and $depth -lt 8; $depth++) {
        if ($exception -is [System.UnauthorizedAccessException] -or
            $exception -is [System.Security.SecurityException] -or
            [int]$exception.HResult -eq -2147024891) {
            $availability = 'access_denied'
            $code = -2147024891
            break
        }
        $code = [int]$exception.HResult
        $exception = $exception.InnerException
    }
    [ordered]@{ availability = $availability; hresult = $code }
}

function Get-SessionProbeAddressClass {
    param([AllowNull()][string] $Address)
    if ([string]::IsNullOrWhiteSpace($Address) -or $Address -eq '-') {
        return 'not_recorded'
    }
    $parsedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsedAddress)) {
        return 'unparseable'
    }
    if ($parsedAddress.IsIPv4MappedToIPv6) { $parsedAddress = $parsedAddress.MapToIPv4() }
    if ([System.Net.IPAddress]::IsLoopback($parsedAddress)) { return 'loopback' }
    if ($parsedAddress.Equals([System.Net.IPAddress]::Any) -or
        $parsedAddress.Equals([System.Net.IPAddress]::IPv6Any)) { return 'wildcard' }
    return 'other'
}

function Get-SessionProbeRegistryDword {
    param([string] $Id, [string] $Path, [string] $Name)
    $baseKey = $null
    $key = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $key = $baseKey.OpenSubKey($Path, $false)
        if ($null -eq $key) {
            return [ordered]@{ id = $Id; availability = 'absent'; hresult = 0; value = $null }
        }
        $rawValue = $key.GetValue($Name, $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $rawValue) {
            return [ordered]@{ id = $Id; availability = 'absent'; hresult = 0; value = $null }
        }
        if ($key.GetValueKind($Name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
            return [ordered]@{ id = $Id; availability = 'unexpected_type'; hresult = -2147024883; value = $null }
        }
        return [ordered]@{ id = $Id; availability = 'available'; hresult = 0
            value = [long]([long]$rawValue -band 4294967295L) }
    } catch {
        $failure = Get-SessionProbeError $_
        return [ordered]@{ id = $Id; availability = $failure.availability
            hresult = $failure.hresult; value = $null }
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

function Get-SessionProbeService {
    param([ValidateSet('TermService', 'UmRdpService')][string] $Name)
    try {
        $rows = @(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Service `
            -Filter ("Name='{0}'" -f $Name) `
            -Property State, StartMode, ProcessId, ExitCode, ServiceSpecificExitCode `
            -OperationTimeoutSec 5 -ErrorAction Stop -WarningAction SilentlyContinue `
            -InformationAction SilentlyContinue -Verbose:$false -Debug:$false)
        if ($rows.Count -eq 0) {
            return [ordered]@{ name = $Name; availability = 'absent'; hresult = 0 }
        }
        if ($rows.Count -ne 1) {
            return [ordered]@{ name = $Name; availability = 'unexpected_count'; hresult = -2147024883 }
        }
        $states = @{ 'Stopped' = 1; 'Start Pending' = 2; 'Stop Pending' = 3;
            'Running' = 4; 'Continue Pending' = 5; 'Pause Pending' = 6; 'Paused' = 7 }
        $startModes = @{ 'Boot' = 0; 'System' = 1; 'Auto' = 2; 'Manual' = 3; 'Disabled' = 4 }
        $serviceRow = $rows[0]
        $state = $states[[string]$serviceRow.State]
        $startMode = $startModes[[string]$serviceRow.StartMode]
        $processIdUsable = $state -in @(4, 5, 6, 7) -and [uint32]$serviceRow.ProcessId -gt 0
        return [ordered]@{ name = $Name; availability = 'available'; hresult = 0
            state = $state; start_mode = $startMode; process_id_usable = $processIdUsable
            process_id = $(if ($processIdUsable) { [uint32]$serviceRow.ProcessId } else { $null })
            win32_exit_code = [uint32]$serviceRow.ExitCode
            service_exit_code = [uint32]$serviceRow.ServiceSpecificExitCode }
    } catch {
        $failure = Get-SessionProbeError $_
        return [ordered]@{ name = $Name; availability = $failure.availability; hresult = $failure.hresult }
    }
}

function Get-SessionProbeTcpListeners {
    param($PortRecord, $ServiceRecord)
    $limit = 16
    if ($PortRecord.availability -ne 'available' -or
        $PortRecord.value -lt 1 -or $PortRecord.value -gt 65535) {
        return [ordered]@{ availability = 'port_unavailable'; hresult = 0; entries = @(); limit = $limit }
    }
    try {
        # Query only the configured RDP-Tcp local port, never all system connections.
        $connections = @(Get-NetTCPConnection -LocalPort ([uint16]$PortRecord.value) `
            -State Listen -ErrorAction Stop -WarningAction SilentlyContinue `
            -InformationAction SilentlyContinue -Verbose:$false -Debug:$false | Select-Object -First 17)
        $entries = @($connections | Select-Object -First $limit | ForEach-Object {
            $isTermService = $null
            if ($ServiceRecord.availability -eq 'available' -and $ServiceRecord.process_id_usable) {
                $isTermService = [uint32]$_.OwningProcess -eq [uint32]$ServiceRecord.process_id
            }
            [ordered]@{ local_port = [uint16]$_.LocalPort; state = 'listen'
                address_class = Get-SessionProbeAddressClass ([string]$_.LocalAddress)
                owner_process_id = [uint32]$_.OwningProcess; owner_is_termservice = $isTermService }
        })
        return [ordered]@{ availability = $(if ($entries.Count) { 'available' } else { 'no_listeners' })
            hresult = 0; limit = $limit; truncated = ($connections.Count -gt $limit); entries = $entries }
    } catch {
        # NetTCPIP reports an empty filtered result as ObjectNotFound on some hosts.
        if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*') {
            return [ordered]@{ availability = 'no_listeners'; hresult = 0; limit = $limit; truncated = $false; entries = @() }
        }
        $failure = Get-SessionProbeError $_
        return [ordered]@{ availability = $failure.availability; hresult = $failure.hresult; limit = $limit; entries = @() }
    }
}

function Write-SessionProbeJson {
    param($Value)
    try {
        $json = ConvertTo-Json -InputObject $Value -Depth 8 -Compress -ErrorAction Stop
        if ($json.Length -le 32768) { Write-Output $json; return }
        Write-Output '{"schema":"session-probe-error/v1","availability":"output_limit","hresult":-2147024774}'
    } catch {
        $failure = Get-SessionProbeError $_
        Write-Output ('{"schema":"session-probe-error/v1","availability":"serialization_failed","hresult":' + $failure.hresult + '}')
    }
}

function Write-SessionEnvironmentSnapshot {
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'Stop'
    try {
        $machinePath = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
        $policyPath = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        $listenerPath = $machinePath + '\WinStations\RDP-Tcp'
        $credentialPath = 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
        $definitions = @(
            @('machine_fDenyTSConnections', $machinePath, 'fDenyTSConnections'),
            @('policy_fDenyTSConnections', $policyPath, 'fDenyTSConnections'),
            @('listener_fEnableWinStation', $listenerPath, 'fEnableWinStation'),
            @('listener_PortNumber', $listenerPath, 'PortNumber'),
            @('listener_SecurityLayer', $listenerPath, 'SecurityLayer'),
            @('listener_UserAuthentication', $listenerPath, 'UserAuthentication'),
            @('listener_fPromptForPassword', $listenerPath, 'fPromptForPassword'),
            @('policy_SecurityLayer', $policyPath, 'SecurityLayer'),
            @('policy_UserAuthentication', $policyPath, 'UserAuthentication'),
            @('policy_fPromptForPassword', $policyPath, 'fPromptForPassword'),
            @('policy_AllowDefaultCredentials', $credentialPath, 'AllowDefaultCredentials'),
            @('policy_AllowDefaultCredentialsWhenNTLMOnly', $credentialPath, 'AllowDefaultCredentialsWhenNTLMOnly'),
            @('policy_DenyDefaultCredentials', $credentialPath, 'DenyDefaultCredentials')
        )
        $registry = @(foreach ($definition in $definitions) {
            Get-SessionProbeRegistryDword -Id $definition[0] -Path $definition[1] -Name $definition[2]
        })
        $services = @(Get-SessionProbeService TermService; Get-SessionProbeService UmRdpService)
        $tcp = Get-SessionProbeTcpListeners -PortRecord $registry[3] -ServiceRecord $services[0]
        Write-SessionProbeJson ([ordered]@{
            schema = 'session-environment/v1'; utc = [datetime]::UtcNow.ToString('o')
            availability = 'snapshot'; registry_view = 64; services = $services
            registry = $registry; tcp = $tcp
        })
    } catch {
        $failure = Get-SessionProbeError $_
        Write-SessionProbeJson ([ordered]@{ schema = 'session-environment/v1'
            availability = $failure.availability; hresult = $failure.hresult })
    }
}

function ConvertTo-SessionProbeUInt32 {
    param([AllowNull()][string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $number = [uint32]0
    if ($Text -match '^0[xX][0-9a-fA-F]{1,8}$') {
        if ([uint32]::TryParse($Text.Substring(2), [System.Globalization.NumberStyles]::AllowHexSpecifier,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number)) { return [long]$number }
    } elseif ($Text -match '^[0-9]{1,10}$') {
        if ([uint32]::TryParse($Text, [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number)) { return [long]$number }
    }
    return $null
}

function ConvertFrom-SessionProbeAuthEvent {
    param($Record)
    $reader = $null
    $textReader = $null
    try {
        $xmlText = $Record.ToXml()
        if ($xmlText.Length -gt 65536) { throw [System.IO.InvalidDataException]::new() }
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 65536
        $textReader = [System.IO.StringReader]::new($xmlText)
        $reader = [System.Xml.XmlReader]::Create($textReader, $settings)
        $document = [System.Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        $namespaces = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
        $namespaces.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
        $fields = @{}
        foreach ($node in $document.SelectNodes('/e:Event/e:EventData/e:Data', $namespaces)) {
            $fieldName = $node.GetAttribute('Name')
            if ($fieldName -in @('Status', 'SubStatus', 'LogonType', 'AuthenticationPackageName', 'IpAddress')) {
                if ($fields.ContainsKey($fieldName)) { throw [System.IO.InvalidDataException]::new() }
                $fields[$fieldName] = $node.InnerText
            }
        }
        $status = ConvertTo-SessionProbeUInt32 $fields['Status']
        $substatus = ConvertTo-SessionProbeUInt32 $fields['SubStatus']
        $logonType = ConvertTo-SessionProbeUInt32 $fields['LogonType']
        if ($null -eq $status -or $null -eq $substatus -or $null -eq $logonType -or
            $null -eq $Record.TimeCreated -or $null -eq $Record.RecordId) {
            throw [System.IO.InvalidDataException]::new()
        }
        # Emit fixed canonical package labels, never an arbitrary event string.
        $package = 'other'
        if ([string]::IsNullOrEmpty($fields['AuthenticationPackageName'])) { $package = 'not_recorded' }
        foreach ($knownPackage in @('NTLM', 'Kerberos', 'Negotiate', 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0')) {
            if ($fields['AuthenticationPackageName'] -ieq $knownPackage) { $package = $knownPackage; break }
        }
        return [ordered]@{ availability = 'available'; hresult = 0
            status = $status; substatus = $substatus; logon_type = $logonType
            utc = $Record.TimeCreated.ToUniversalTime().ToString('o'); record_id = [long]$Record.RecordId
            authentication_package = $package
            source_address_class = Get-SessionProbeAddressClass $fields['IpAddress'] }
    } catch {
        $failure = Get-SessionProbeError $_
        return [ordered]@{ availability = 'invalid_event'; hresult = $failure.hresult }
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $textReader) { $textReader.Dispose() }
    }
}

function Write-RecentAuthFailures {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][datetime] $StartTime)
    $ErrorActionPreference = 'Stop'
    $records = @()
    $limit = 16
    try {
        $endUtc = [datetime]::UtcNow
        $startUtc = $StartTime.ToUniversalTime()
        if ($startUtc -gt $endUtc) { throw [System.ArgumentOutOfRangeException]::new() }
        $rangeClamped = $startUtc -lt $endUtc.AddMinutes(-30)
        if ($rangeClamped) { $startUtc = $endUtc.AddMinutes(-30) }
        $query = @{ LogName = 'Security'; Id = 4625; StartTime = $startUtc; EndTime = $endUtc }
        $records = @(Get-WinEvent -FilterHashtable $query -MaxEvents $limit `
            -ErrorAction Stop -WarningAction SilentlyContinue `
            -InformationAction SilentlyContinue -Verbose:$false -Debug:$false)
        $events = @(foreach ($record in $records) { ConvertFrom-SessionProbeAuthEvent $record })
        Write-SessionProbeJson ([ordered]@{
            schema = 'session-auth-failures/v1'
            attribution = 'time_window_only'
            availability = $(if ($events.Count) { 'available' } else { 'no_events' }); hresult = 0
            start_utc = $startUtc.ToString('o'); end_utc = $endUtc.ToString('o')
            time_range_clamped = $rangeClamped; limit = $limit; limit_reached = ($records.Count -eq $limit)
            events = $events
        })
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            Write-SessionProbeJson ([ordered]@{ schema = 'session-auth-failures/v1'
                attribution = 'time_window_only'
                availability = 'no_events'; hresult = 0; limit = $limit; events = @() })
        } else {
            $failure = Get-SessionProbeError $_
            Write-SessionProbeJson ([ordered]@{ schema = 'session-auth-failures/v1'
                attribution = 'time_window_only'
                availability = $failure.availability; hresult = $failure.hresult; limit = $limit; events = @() })
        }
    } finally {
        foreach ($record in $records) {
            if ($record -is [System.IDisposable]) { $record.Dispose() }
        }
    }
}

function ConvertTo-SessionProbeErrorCode {
    param([AllowNull()][string] $Text)
    $unsignedCode = ConvertTo-SessionProbeUInt32 $Text
    if ($null -ne $unsignedCode) { return $unsignedCode }
    # HRESULTs may be recorded as signed decimal Int32 values. Preserve their bits.
    if ($null -ne $Text -and $Text -match '^-[0-9]{1,10}$') {
        $signedCode = [int]0
        if ([int]::TryParse($Text, [System.Globalization.NumberStyles]::AllowLeadingSign,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$signedCode)) {
            return [long]([long]$signedCode -band 4294967295L)
        }
    }
    return $null
}

function ConvertFrom-SessionProbeRdpEvent {
    param($Record)
    $reader = $null
    $textReader = $null
    try {
        # The same bounds and XML restrictions as the 4625 parser above.
        $xmlText = $Record.ToXml()
        if ($xmlText.Length -gt 65536) { throw [System.IO.InvalidDataException]::new() }
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 65536
        $textReader = [System.IO.StringReader]::new($xmlText)
        $reader = [System.Xml.XmlReader]::Create($textReader, $settings)
        $document = [System.Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        $namespaces = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
        $namespaces.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
        $allowedFields = @{
            'ErrorCode' = 'error_code'; 'Error Code' = 'error_code'; 'HResult' = 'hresult'
            'Status' = 'status'; 'SubStatus' = 'substatus'; 'Reason' = 'reason'
            'ReasonCode' = 'reason_code'; 'Reason Code' = 'reason_code'
            'PreviousState' = 'previous_state'; 'NewState' = 'new_state'; 'Event' = 'state_event'
        }
        $numericFields = [ordered]@{}
        $rejectedFields = 0
        $dataNodes = @($document.SelectNodes('/e:Event/e:EventData/e:Data', $namespaces))
        $userNodes = @($document.SelectNodes('/e:Event/e:UserData//*[not(*)]', $namespaces))
        foreach ($node in @($dataNodes + $userNodes)) {
            $fieldName = $node.LocalName
            if ($node.ParentNode.LocalName -eq 'EventData' -and $node.LocalName -eq 'Data') {
                $fieldName = $node.GetAttribute('Name')
            }
            if (-not $allowedFields.ContainsKey($fieldName)) { continue }
            $code = ConvertTo-SessionProbeErrorCode $node.InnerText
            if ($null -eq $code) { $rejectedFields++; continue }
            $canonicalName = $allowedFields[$fieldName]
            if ($numericFields.Contains($canonicalName)) {
                if ($numericFields[$canonicalName] -ne $code) { throw [System.IO.InvalidDataException]::new() }
            } else {
                $numericFields.Add($canonicalName, $code)
            }
        }
        if ($null -eq $Record.TimeCreated -or $null -eq $Record.RecordId) {
            throw [System.IO.InvalidDataException]::new()
        }
        return [ordered]@{ availability = 'available'; hresult = 0
            event_id = [int]$Record.Id
            version = $(if ($null -ne $Record.Version) { [int]$Record.Version } else { $null })
            level = $(if ($null -ne $Record.Level) { [int]$Record.Level } else { $null })
            record_id = [long]$Record.RecordId; utc = $Record.TimeCreated.ToUniversalTime().ToString('o')
            numeric_fields = $numericFields; rejected_numeric_fields = $rejectedFields }
    } catch {
        $failure = Get-SessionProbeError $_
        return [ordered]@{ availability = 'invalid_event'; hresult = $failure.hresult }
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $textReader) { $textReader.Dispose() }
    }
}

function Get-SessionProbeRdpChannelEvents {
    param(
        [ValidateSet('rdp_client', 'rdp_core_ts', 'local_session_manager')][string] $Channel,
        [datetime] $StartUtc,
        [datetime] $EndUtc
    )
    $channelNames = @{
        'rdp_client' = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'
        'rdp_core_ts' = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
        'local_session_manager' = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    }
    $limit = 16
    $logConfigurations = @()
    $records = @()
    $enabled = $null
    try {
        $logConfigurations = @(Get-WinEvent -ListLog $channelNames[$Channel] `
            -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction SilentlyContinue `
            -Verbose:$false -Debug:$false)
        if ($logConfigurations.Count -eq 0) {
            return [ordered]@{ channel = $Channel; availability = 'absent'; hresult = 0
                enabled = $null; limit = $limit; events = @() }
        }
        if ($logConfigurations.Count -ne 1) { throw [System.IO.InvalidDataException]::new() }
        $enabled = [bool]$logConfigurations[0].IsEnabled
        if (-not $enabled) {
            return [ordered]@{ channel = $Channel; availability = 'disabled'; hresult = 0
                enabled = $false; limit = $limit; events = @() }
        }
        $query = @{ LogName = $channelNames[$Channel]; StartTime = $StartUtc; EndTime = $EndUtc }
        $records = @(Get-WinEvent -FilterHashtable $query -MaxEvents $limit `
            -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction SilentlyContinue `
            -Verbose:$false -Debug:$false)
        $events = @(foreach ($record in $records) { ConvertFrom-SessionProbeRdpEvent $record })
        return [ordered]@{ channel = $Channel
            availability = $(if ($events.Count) { 'available' } else { 'no_events' }); hresult = 0
            enabled = $true; limit = $limit; limit_reached = ($records.Count -eq $limit); events = $events }
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return [ordered]@{ channel = $Channel; availability = 'no_events'; hresult = 0
                enabled = $enabled; limit = $limit; events = @() }
        }
        $failure = Get-SessionProbeError $_
        $availability = $failure.availability
        if ($_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*') { $availability = 'absent' }
        return [ordered]@{ channel = $Channel; availability = $availability; hresult = $failure.hresult
            enabled = $enabled; limit = $limit; events = @() }
    } finally {
        foreach ($record in $records) {
            if ($record -is [System.IDisposable]) { $record.Dispose() }
        }
        foreach ($configuration in $logConfigurations) {
            if ($configuration -is [System.IDisposable]) { $configuration.Dispose() }
        }
    }
}

function Write-RecentRdpEvents {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][datetime] $StartTime)
    $ErrorActionPreference = 'Stop'
    try {
        $endUtc = [datetime]::UtcNow
        $startUtc = $StartTime.ToUniversalTime()
        if ($startUtc -gt $endUtc) { throw [System.ArgumentOutOfRangeException]::new() }
        $rangeClamped = $startUtc -lt $endUtc.AddMinutes(-30)
        if ($rangeClamped) { $startUtc = $endUtc.AddMinutes(-30) }
        $channels = @(foreach ($channel in @('rdp_client', 'rdp_core_ts', 'local_session_manager')) {
            Get-SessionProbeRdpChannelEvents -Channel $channel -StartUtc $startUtc -EndUtc $endUtc
        })
        Write-SessionProbeJson ([ordered]@{ schema = 'session-rdp-events/v1'
            attribution = 'time_window_only'; availability = 'snapshot'
            start_utc = $startUtc.ToString('o'); end_utc = $endUtc.ToString('o')
            time_range_clamped = $rangeClamped; channel_limit = 3; events_per_channel_limit = 16
            channels = $channels })
    } catch {
        $failure = Get-SessionProbeError $_
        Write-SessionProbeJson ([ordered]@{ schema = 'session-rdp-events/v1'
            attribution = 'time_window_only'; availability = $failure.availability
            hresult = $failure.hresult; channels = @() })
    }
}
