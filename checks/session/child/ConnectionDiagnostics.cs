using Microsoft.Win32;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml;

namespace SessionContractExperiment;

// Read-only observations at the failing boundary. No policy/service changes,
// event-channel enablement, account names, SIDs, paths or formatted event text.
internal static class ConnectionDiagnostics
{
    private static readonly string[] Channels = {
        "Microsoft-Windows-TerminalServices-RDPClient/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "Security" };
    private static readonly Dictionary<string, string> CodeNames = new(StringComparer.OrdinalIgnoreCase) {
        ["ErrorCode"] = "error_code", ["Error Code"] = "error_code", ["HResult"] = "hresult",
        ["Status"] = "status", ["SubStatus"] = "substatus", ["Reason"] = "reason",
        ["ReasonCode"] = "reason_code", ["Reason Code"] = "reason_code", ["PreviousState"] = "previous_state",
        ["NewState"] = "new_state", ["Event"] = "state_event", ["LogonType"] = "logon_type" };

    internal static JsonObject Snapshot()
    {
        JsonObject result = new();
        void Observe(string field, Func<JsonNode?> read)
        {
            try { result[field] = read(); }
            catch (Exception ex) { result[field] = null; result[field + "_error"] = ErrorCode(ex); }
        }
        Observe("process_session", () => JsonValue.Create(Process.GetCurrentProcess().SessionId));
        Observe("console_session", () => JsonValue.Create(Native.WTSGetActiveConsoleSessionId()));
        Observe("wts_state", () => JsonValue.Create(Native.State((uint)Process.GetCurrentProcess().SessionId)));
        Observe("child_enabled", () => {
            if (!Native.WTSIsChildSessionsEnabled(out bool enabled)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return JsonValue.Create(enabled);
        });
        Observe("input_desktop_matches_thread", () => {
            IntPtr input = OpenInputDesktop(0, false, 1);
            if (input == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try { return JsonValue.Create(DesktopName(input) == DesktopName(GetThreadDesktop(GetCurrentThreadId()))); }
            finally { CloseDesktop(input); }
        });
        using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        Observe("os_build", () => {
            using RegistryKey? key = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return uint.TryParse(key?.GetValue("CurrentBuildNumber") as string, NumberStyles.None, CultureInfo.InvariantCulture,
                out uint value) ? JsonValue.Create(value) : null;
        });
        Observe("os_ubr", () => {
            using RegistryKey? key = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return key?.GetValue("UBR") is int value ? JsonValue.Create(unchecked((uint)value)) : null;
        });
        Observe("os_product_type", () => {
            Version version = Environment.OSVersion.Version;
            if (!GetProductInfo((uint)version.Major, (uint)version.Minor, 0, 0, out uint product))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return JsonValue.Create(product);
        });
        Observe("mstscax_version", () => {
            using Process process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
                if (string.Equals(module.ModuleName, "mstscax.dll", StringComparison.OrdinalIgnoreCase))
                {
                    FileVersionInfo version = module.FileVersionInfo;
                    return new JsonArray(version.FileMajorPart, version.FileMinorPart, version.FileBuildPart, version.FilePrivatePart);
                }
            return null;
        });
        string ts = @"SYSTEM\CurrentControlSet\Control\Terminal Server", policy = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
        string listener = ts + @"\WinStations\RDP-Tcp", credentials = @"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation";
        (string Path, string Name)[] registry = {
            (ts, "fDenyTSConnections"), (policy, "fDenyTSConnections"), (listener, "fEnableWinStation"), (listener, "PortNumber"),
            (listener, "SecurityLayer"), (listener, "UserAuthentication"), (listener, "fPromptForPassword"),
            (policy, "SecurityLayer"), (policy, "UserAuthentication"), (policy, "fPromptForPassword"),
            (credentials, "AllowDefaultCredentials"), (credentials, "AllowDefaultCredentialsWhenNTLMOnly"), (credentials, "DenyDefaultCredentials") };
        JsonArray values = new();
        for (int index = 0; index < registry.Length; index++)
        {
            JsonObject item = new() { ["id"] = index + 1, ["availability"] = 1, ["value"] = null, ["error"] = null };
            try
            {
                using RegistryKey? key = machine.OpenSubKey(registry[index].Path);
                object? value = key?.GetValue(registry[index].Name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (value is int number && key!.GetValueKind(registry[index].Name) == RegistryValueKind.DWord)
                { item["availability"] = 0; item["value"] = unchecked((uint)number); }
                else if (value is not null) item["availability"] = 3;
            }
            catch (Exception ex) { item["availability"] = 2; item["error"] = ErrorCode(ex); }
            values.Add(item);
        }
        result["registry"] = values;
        result["services"] = new JsonArray(Service(1, "TermService"), Service(2, "UmRdpService"));
        return result;
    }

    private static JsonObject Service(int id, string name)
    {
        JsonObject result = new() { ["id"] = id, ["state"] = null, ["win32_exit_code"] = null,
            ["service_exit_code"] = null, ["error"] = null };
        IntPtr manager = IntPtr.Zero, service = IntPtr.Zero;
        try
        {
            manager = OpenSCManager(null, null, 1);
            if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            service = OpenService(manager, name, 4);
            if (service == IntPtr.Zero || !QueryServiceStatusEx(service, 0, out ServiceStatus value,
                (uint)Marshal.SizeOf<ServiceStatus>(), out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            result["state"] = value.CurrentState; result["win32_exit_code"] = value.Win32ExitCode;
            result["service_exit_code"] = value.ServiceSpecificExitCode;
        }
        catch (Exception ex) { result["error"] = ErrorCode(ex); }
        finally { if (service != IntPtr.Zero) CloseServiceHandle(service); if (manager != IntPtr.Zero) CloseServiceHandle(manager); }
        return result;
    }

    internal static JsonObject RecentEvents(DateTimeOffset started)
    {
        JsonObject result = new() { ["attribution"] = "time_window_only", ["events_per_channel_limit"] = 8 };
        JsonArray channels = new(); result["channels"] = channels;
        DateTimeOffset end = DateTimeOffset.UtcNow;
        if (started > end || started < end.AddMinutes(-5)) started = end.AddMinutes(-5);
        string startText = started.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        string endText = end.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        Stopwatch budget = Stopwatch.StartNew();
        for (int index = 0; index < Channels.Length; index++)
        {
            JsonArray events = new();
            JsonObject channel = new() { ["id"] = index + 1, ["availability"] = 0,
                ["error"] = null, ["limit_reached"] = false, ["events"] = events };
            channels.Add(channel);
            if (budget.Elapsed > TimeSpan.FromSeconds(3)) { channel["availability"] = 3; continue; }
            try
            {
                using EventLogConfiguration configuration = new(Channels[index]);
                if (!configuration.IsEnabled) { channel["availability"] = 1; continue; }
                string filter = "*[System[" + (index == 4 ? "EventID=4625 and " : "") +
                    "TimeCreated[@SystemTime >= '" + startText + "' and @SystemTime <= '" + endText + "']]]";
                using EventLogReader reader = new(new EventLogQuery(Channels[index], PathType.LogName, filter) { ReverseDirection = true });
                for (int count = 0; count <= 8; count++)
                {
                    if (budget.Elapsed > TimeSpan.FromSeconds(3)) { channel["availability"] = 3; break; }
                    using EventRecord? record = reader.ReadEvent(TimeSpan.FromMilliseconds(100));
                    if (record is null) break;
                    if (count == 8) { channel["limit_reached"] = true; break; }
                    JsonObject item = new() { ["event_id"] = record.Id, ["version"] = record.Version,
                        ["level"] = record.Level, ["codes"] = NumericCodes(record) };
                    if (record.TimeCreated is DateTime time) item["utc"] = time.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
                    events.Add(item);
                }
            }
            catch (Exception ex) { channel["availability"] = 2; channel["error"] = ErrorCode(ex); }
        }
        return result;
    }

    private static JsonObject NumericCodes(EventRecord record)
    {
        string xml = record.ToXml();
        if (xml.Length > 65536) throw new InvalidDataException();
        using StringReader text = new(xml);
        using XmlReader reader = XmlReader.Create(text, new XmlReaderSettings {
            DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 65536 });
        XmlDocument document = new() { XmlResolver = null }; document.Load(reader);
        XmlNamespaceManager names = new(document.NameTable); names.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event");
        JsonObject result = new();
        foreach (XmlNode node in document.SelectNodes("/e:Event/e:EventData/e:Data | /e:Event/e:UserData//*[not(*)]", names)!)
        {
            string field = node.ParentNode?.LocalName == "EventData" ? node.Attributes?["Name"]?.Value ?? "" : node.LocalName;
            if (!CodeNames.TryGetValue(field, out string? key)) continue;
            string raw = node.InnerText;
            uint code;
            bool parsed = raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && raw.Length <= 10
                ? uint.TryParse(raw.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out code)
                : uint.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out code);
            if (!parsed && int.TryParse(raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int signed))
            { code = unchecked((uint)signed); parsed = true; }
            if (!parsed) continue;
            if (result[key] is JsonNode previous && previous.GetValue<uint>() != code) throw new InvalidDataException();
            result[key] = code;
        }
        return result;
    }

    private static int ErrorCode(Exception error) => error is Win32Exception win32 ? win32.NativeErrorCode :
        error is ExperimentFailure contract ? contract.Code : error.HResult;

    private static string DesktopName(IntPtr handle)
    {
        StringBuilder name = new(256);
        if (handle == IntPtr.Zero || !GetUserObjectInformation(handle, 2, name, 512, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return name.ToString();
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus {
        internal uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode,
            CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] private static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll")] private static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetUserObjectInformation(IntPtr handle, int index, StringBuilder text, uint length, out uint needed);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProductInfo(uint major, uint minor, uint serviceMajor, uint serviceMinor, out uint product);
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, uint size, out uint needed);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
}
