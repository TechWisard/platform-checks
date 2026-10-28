using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SessionContractExperiment;

// This fixture runs before the witness palette/Form/input observers exist.
// Its native process receives only a distinct preparation receipt and fixed
// Escape policy, never the rendering nonce, frame colors or input challenge.
internal static class ChildSearchPreparation
{
    internal const string HelperName = "child_search_prepare.exe";
    internal const string ReceiptName = "child-search-receipt.bin";
    internal const string ReportName = "witness-preparation.json";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
    private static readonly string[] FlagNames = {
        "receipt_verified", "receipt_owner_verified", "receipt_readonly_verified", "directory_owner_verified", "directory_readonly_verified",
        "identity_verified", "nonadministrator_verified", "active_child_verified", "input_default_desktop_verified", "console_parent_unchanged",
        "target_found", "owner_verified", "owner_reverified", "first_page_verified", "recheck_page_verified", "same_root_reverified",
        "keyboard_state_query_succeeded", "send_attempted", "pair_inserted", "release_cleanup_attempted", "release_event_inserted",
        "escape_up_observed", "key_cleanup_verified", "target_observation_valid", "target_hidden_or_destroyed", "target_exists", "target_visible", "target_foreground", "com_uninitialized", "cleanup_verified"
    };
    private static readonly Dictionary<string, uint> NumberBounds = new(StringComparer.Ordinal)
    {
        ["hresult"] = uint.MaxValue, ["elapsed_ms"] = 20000, ["receipt_error"] = 9,
        ["initial_search_count"] = 8, ["recheck_search_count"] = 8, ["queue_down_mask"] = 4095, ["async_down_mask"] = 4095,
        ["send_call_count"] = 1, ["requested_input_count"] = 2, ["inserted_input_count"] = 2, ["send_last_error"] = uint.MaxValue,
        ["cleanup_call_count"] = 1, ["cleanup_inserted_count"] = 1, ["cleanup_last_error"] = uint.MaxValue,
        ["release_observations"] = 26, ["target_observations"] = 64, ["cleanup_hresult"] = uint.MaxValue
    };
    private static readonly string[] Preconditions = FlagNames.Take(10).ToArray();

    private sealed class WitnessReport
    {
        public string Schema { get; } = "witness-preparation/v2";
        public required string Nonce { get; init; }
        public required string IdentityDigest { get; init; }
        public uint SessionId { get; init; }
        public string PreparationNonce { get; set; } = "";
        public string Status { get; set; } = "failed";
        public bool ProcessStarted { get; set; }
        public bool ProcessExited { get; set; }
        public bool ProcessCleanupVerified { get; set; } = true;
        public bool OutputCompleted { get; set; }
        public int? ExitCode { get; set; }
        public bool NativeBindingVerified { get; set; }
        public bool NativeAccepted { get; set; }
        public bool NativeForegroundUnresolved { get; set; }
        public bool RenderProbeEligible { get; set; }
        public JsonElement? Helper { get; set; }
        public string? ErrorCategory { get; set; }
        public int? ErrorHresult { get; set; }
        public long ElapsedMs { get; set; }
    }

    internal sealed record Observation(bool Verified, bool CleanupVerified, bool RenderProbeEligible,
        bool ForegroundUnresolved, Dictionary<string, object?> Public);

    private static void Need(bool condition, string code)
    { if (!condition) throw new ExperimentFailure(code); }

    // Fixed little-endian receipt; parsing is shared by synthetic contract
    // tests and the caller. Windows independently checks its owner and ACL.
    internal static byte[] CreateReceipt(uint parent, uint child, uint console, long issued,
        ReadOnlySpan<byte> parentSid, ReadOnlySpan<byte> childSid, ReadOnlySpan<byte> preparationNonce)
    {
        Need(parent is > 0 and < uint.MaxValue && child is > 0 and < uint.MaxValue && parent != child && console == parent,
            "child_preparation_receipt_sessions_invalid");
        Need(issued is >= 946684800 and <= 4102444800 && ValidSid(parentSid) && ValidSid(childSid) &&
            !parentSid.SequenceEqual(childSid) && preparationNonce.Length == 24 && preparationNonce.IndexOfAnyExcept((byte)0) >= 0,
            "child_preparation_receipt_values_invalid");
        byte[] result = new byte[72 + parentSid.Length + childSid.Length];
        "CHSEARCH"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12), parent);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(16), child);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(20), console);
        BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(24), checked((ulong)issued));
        BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(32), checked((ulong)(issued + 90)));
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(40), checked((uint)parentSid.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(44), checked((uint)childSid.Length));
        preparationNonce.CopyTo(result.AsSpan(48));
        parentSid.CopyTo(result.AsSpan(72)); childSid.CopyTo(result.AsSpan(72 + parentSid.Length));
        return result;
    }

    private static bool ValidSid(ReadOnlySpan<byte> value) => value.Length is >= 8 and <= 68 && value[0] == 1 &&
        value[1] <= 15 && value.Length == 8 + value[1] * 4;

    internal static string ReadReceiptBinding(ReadOnlySpan<byte> data, uint expectedChild, long now, ReadOnlySpan<byte> expectedSid)
    {
        Need(data.Length is >= 88 and <= 208 && data[..8].SequenceEqual("CHSEARCH"u8) &&
            BinaryPrimitives.ReadUInt32LittleEndian(data[8..]) == 1, "child_preparation_receipt_format_invalid");
        uint parent = BinaryPrimitives.ReadUInt32LittleEndian(data[12..]), child = BinaryPrimitives.ReadUInt32LittleEndian(data[16..]);
        uint console = BinaryPrimitives.ReadUInt32LittleEndian(data[20..]);
        ulong issued = BinaryPrimitives.ReadUInt64LittleEndian(data[24..]), expires = BinaryPrimitives.ReadUInt64LittleEndian(data[32..]);
        uint parentBytes = BinaryPrimitives.ReadUInt32LittleEndian(data[40..]), childBytes = BinaryPrimitives.ReadUInt32LittleEndian(data[44..]);
        Need(parent is > 0 and < uint.MaxValue && child is > 0 and < uint.MaxValue && parent != child && console == parent && child == expectedChild &&
            issued is >= 946684800 and <= 4102444800 && expires == issued + 90 && now >= 0 && (ulong)now >= issued && (ulong)now < expires &&
            parentBytes is >= 8 and <= 68 && childBytes is >= 8 and <= 68 && data.Length == 72 + parentBytes + childBytes,
            "child_preparation_receipt_binding_invalid");
        ReadOnlySpan<byte> parentSid = data.Slice(72, (int)parentBytes), childSid = data.Slice(72 + (int)parentBytes, (int)childBytes);
        Need(ValidSid(parentSid) && ValidSid(childSid) && !parentSid.SequenceEqual(childSid) && childSid.SequenceEqual(expectedSid) &&
            data.Slice(48, 24).IndexOfAnyExcept((byte)0) >= 0, "child_preparation_receipt_identity_invalid");
        return Convert.ToHexString(data.Slice(48, 24));
    }

    [SupportedOSPlatform("windows")]
    internal static string Install(string binaryDirectory, string sourceHelper, string parentSid, string childSid,
        uint parentSession, uint childSession, uint consoleSession)
    {
        SecurityIdentifier parent = new(parentSid), child = new(childSid);
        Need(parent != child && Directory.Exists(binaryDirectory), "child_preparation_install_scope_invalid");
        DirectoryInfo directory = new(binaryDirectory);
        Need((directory.Attributes & FileAttributes.ReparsePoint) == 0, "child_preparation_directory_reparse_point");
        DirectorySecurity security = new();
        security.SetOwner(parent); security.SetAccessRuleProtection(true, false);
        foreach ((SecurityIdentifier who, FileSystemRights rights) in Principals(parent, child))
            security.AddAccessRule(new(who, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(security);
        string source = Path.GetFullPath(sourceHelper), executable = Path.Combine(binaryDirectory, HelperName);
        Need(!File.Exists(executable) && File.Exists(source) && (File.GetAttributes(source) & FileAttributes.ReparsePoint) == 0,
            "child_preparation_helper_source_invalid");
        using (FileStream original = new(source, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Need(original.Length is > 0 and <= 4 * 1024 * 1024, "child_preparation_helper_size_invalid");
            using FileStream copied = new(executable, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            original.CopyTo(copied); original.Position = copied.Position = 0;
            Need(CryptographicOperations.FixedTimeEquals(SHA256.HashData(original), SHA256.HashData(copied)),
                "child_preparation_helper_copy_mismatch");
        }
        SetFileSecurity(executable, parent, child);
        byte[] parentBytes = new byte[parent.BinaryLength], childBytes = new byte[child.BinaryLength];
        parent.GetBinaryForm(parentBytes, 0); child.GetBinaryForm(childBytes, 0);
        byte[] preparationNonce = RandomNumberGenerator.GetBytes(24);
        byte[] receipt = CreateReceipt(parentSession, childSession, consoleSession, DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            parentBytes, childBytes, preparationNonce);
        string receiptFile = Path.Combine(binaryDirectory, ReceiptName);
        using (FileStream file = new(receiptFile, FileMode.CreateNew, FileAccess.Write, FileShare.None)) file.Write(receipt);
        SetFileSecurity(receiptFile, parent, child);
        return Convert.ToHexString(preparationNonce);
    }

    [SupportedOSPlatform("windows")]
    private static IEnumerable<(SecurityIdentifier, FileSystemRights)> Principals(SecurityIdentifier parent, SecurityIdentifier child)
    {
        yield return (parent, FileSystemRights.FullControl);
        yield return (new(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl);
        yield return (new(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl);
        yield return (child, FileSystemRights.ReadAndExecute);
    }

    [SupportedOSPlatform("windows")]
    private static void SetFileSecurity(string path, SecurityIdentifier parent, SecurityIdentifier child)
    {
        FileSecurity security = new(); security.SetOwner(parent); security.SetAccessRuleProtection(true, false);
        foreach ((SecurityIdentifier who, FileSystemRights rights) in Principals(parent, child))
            security.AddAccessRule(new(who, rights, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    internal static async Task RunAndWrite(string identityOutput, string witnessNonce, uint session, string identityDigest, string actualSid)
    {
        WitnessReport report = new() { Nonce = witnessNonce, SessionId = session, IdentityDigest = identityDigest };
        Stopwatch watch = Stopwatch.StartNew();
        Process? process = null;
        Task<string>? stdout = null, stderr = null;
        using CancellationTokenSource ioCancellation = new();
        try
        {
            string binary = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
            string expectedOutput = Path.Combine(Path.GetDirectoryName(binary) ?? "", "result", "witness.json");
            Need(Path.GetFileName(binary) == "bin" && string.Equals(Path.GetFullPath(identityOutput), expectedOutput, StringComparison.OrdinalIgnoreCase),
                "child_preparation_witness_path_invalid");
            string receiptPath = Path.Combine(binary, ReceiptName), executable = Path.Combine(binary, HelperName);
            Need(File.Exists(executable) && (File.GetAttributes(executable) & FileAttributes.ReparsePoint) == 0 &&
                (File.GetAttributes(receiptPath) & FileAttributes.ReparsePoint) == 0, "child_preparation_payload_invalid");
            SecurityIdentifier sid = new(actualSid); byte[] sidBytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(sidBytes, 0);
            byte[] receipt;
            using (FileStream file = new(receiptPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Need(file.Length is >= 88 and <= 208, "child_preparation_receipt_size_invalid");
                receipt = new byte[(int)file.Length]; file.ReadExactly(receipt);
            }
            report.PreparationNonce = ReadReceiptBinding(receipt, session, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), sidBytes);
            ProcessStartInfo start = new(executable) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = binary,
                RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add("--allow-owned-child-search");
            // Native creation itself is synchronous. The independent parent
            // experiment/task deadline still covers a stalled Process.Start.
            process = Process.Start(start) ?? throw new ExperimentFailure("child_preparation_process_not_created");
            report.ProcessStarted = true; report.ProcessCleanupVerified = false;
            stdout = ReadBounded(process.StandardOutput.BaseStream, 16384, ioCancellation.Token);
            stderr = ReadBounded(process.StandardError.BaseStream, 1024, ioCancellation.Token);
            TimeSpan remaining = TimeSpan.FromSeconds(15) - watch.Elapsed;
            Need(remaining > TimeSpan.Zero, "child_preparation_start_budget_exhausted");
            await Task.WhenAll(process.WaitForExitAsync(), stdout, stderr).WaitAsync(remaining).ConfigureAwait(false);
            report.ProcessExited = true; report.ProcessCleanupVerified = true; report.OutputCompleted = true;
            report.ExitCode = process.ExitCode;
            Need((await stderr.ConfigureAwait(false)).Length == 0, "child_preparation_unexpected_stderr");
            using JsonDocument parsed = ParseJson(await stdout.ConfigureAwait(false), 16384);
            (bool binding, bool accepted) = ValidateNative(parsed.RootElement, report.PreparationNonce);
            report.Helper = parsed.RootElement.Clone(); report.NativeBindingVerified = binding; report.NativeAccepted = accepted;
            report.NativeForegroundUnresolved = IsCleanForegroundObservation(parsed.RootElement, report.PreparationNonce);
            if (report.ExitCode == 0 && binding && accepted) report.Status = "verified";
            // A fully observed but unresolved Search window permits creating
            // our own witness. It remains a preparation failure, not a claim
            // that Escape was delivered or the target left the foreground.
            report.RenderProbeEligible = report.Status == "verified" ||
                (report.ExitCode == 1 && binding && report.NativeForegroundUnresolved);
        }
        catch (Exception error)
        {
            report.Status = "failed";
            report.RenderProbeEligible = false;
            report.ErrorCategory = ErrorCategory(error); report.ErrorHresult = error.HResult;
            if (process is not null)
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
                    report.ProcessExited = true; report.ProcessCleanupVerified = true; report.ExitCode = process.ExitCode;
                }
                catch (Exception cleanup)
                {
                    report.ProcessCleanupVerified = false;
                    report.ErrorCategory = "owned_process_cleanup"; report.ErrorHresult = cleanup.HResult;
                }
            }
        }
        finally
        {
            ioCancellation.Cancel();
            if (stdout is not null && stderr is not null)
            {
                try { await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
                catch { /* Raw output and exceptions never reach public logs. */ }
            }
            process?.Dispose();
            report.ElapsedMs = watch.ElapsedMilliseconds;
            string path = Path.Combine(Path.GetDirectoryName(identityOutput)!, ReportName);
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (FileStream file = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    JsonSerializer.Serialize(file, report, JsonOptions);
                File.Move(temporary, path, false);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        Need(report.RenderProbeEligible, "child_search_render_probe_not_eligible");
    }

    private static async Task<string> ReadBounded(Stream stream, int cap, CancellationToken cancellation)
    {
        using MemoryStream data = new(); byte[] buffer = new byte[2048];
        int bytes;
        while ((bytes = await stream.ReadAsync(buffer, cancellation).ConfigureAwait(false)) != 0)
        {
            Need(data.Length + bytes <= cap, "child_preparation_output_limit");
            data.Write(buffer, 0, bytes);
        }
        return new UTF8Encoding(false, true).GetString(data.ToArray());
    }

    private static string ErrorCategory(Exception error) => error switch
    {
        TimeoutException => "timeout", UnauthorizedAccessException => "access_denied", IOException => "io",
        JsonException or InvalidDataException or DecoderFallbackException => "invalid_report",
        System.ComponentModel.Win32Exception => "process", ExperimentFailure => "precondition", _ => "other"
    };

    private static JsonDocument ParseJson(string text, int cap)
    {
        Need(text.Length is > 0 && Encoding.UTF8.GetByteCount(text) <= cap, "child_preparation_json_size_invalid");
        return JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 6 });
    }

    private static void Keys(JsonElement value, IEnumerable<string> keys)
    {
        Need(value.ValueKind == JsonValueKind.Object, "child_preparation_json_not_object");
        string[] expected = keys.ToArray(), actual = value.EnumerateObject().Select(item => item.Name).ToArray();
        Need(actual.Length == expected.Length && actual.Distinct(StringComparer.Ordinal).Count() == expected.Length &&
            actual.All(item => expected.Contains(item, StringComparer.Ordinal)), "child_preparation_json_fields_invalid");
    }

    internal static (bool Binding, bool Accepted) ValidateNative(JsonElement value, string expectedNonce)
    {
        Keys(value, new[] { "schema", "status", "stage", "binding_nonce" }.Concat(FlagNames).Concat(NumberBounds.Keys));
        Need(value.GetProperty("schema").GetString() == "child-search-prepare/v1", "child_preparation_native_schema_invalid");
        string? status = value.GetProperty("status").GetString(), stage = value.GetProperty("stage").GetString();
        string? binding = value.GetProperty("binding_nonce").GetString();
        Need(status is "prepared" or "not_needed" or "failed" && stage is { Length: > 0 and <= 80 } &&
            stage.All(character => char.IsAsciiLetterOrDigit(character) || character == '_') &&
            binding is not null && (binding.Length == 0 || (binding.Length == 48 && binding.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F'))),
            "child_preparation_native_text_invalid");
        foreach (string name in FlagNames) Need(value.GetProperty(name).ValueKind is JsonValueKind.True or JsonValueKind.False,
            "child_preparation_native_flag_invalid");
        foreach ((string name, uint maximum) in NumberBounds)
            Need(value.GetProperty(name).TryGetUInt32(out uint number) && number <= maximum, "child_preparation_native_number_invalid");
        bool Flag(string key) => value.GetProperty(key).GetBoolean();
        uint Number(string key) => value.GetProperty(key).GetUInt32();
        bool bound = expectedNonce.Length == 48 && binding == expectedNonce;
        bool common = bound && Preconditions.All(Flag) && Number("receipt_error") == 0 && Flag("cleanup_verified") &&
            Flag("key_cleanup_verified") && Number("cleanup_hresult") == 0 && Number("hresult") == 0;
        bool targetConsistent = Flag("target_observation_valid") &&
            Flag("target_hidden_or_destroyed") == (!Flag("target_exists") || !Flag("target_visible")) &&
            (Flag("target_exists") || (!Flag("target_visible") && !Flag("target_foreground")));
        bool prepared = status == "prepared" && stage == "pinned_search_left_foreground" && common && targetConsistent && new[] { "target_found", "owner_verified", "owner_reverified", "first_page_verified",
            "recheck_page_verified", "same_root_reverified", "keyboard_state_query_succeeded", "send_attempted", "pair_inserted",
            "release_event_inserted", "escape_up_observed", "target_observation_valid", "com_uninitialized" }.All(Flag) &&
            (Flag("target_hidden_or_destroyed") || !Flag("target_foreground")) &&
            Number("initial_search_count") == 1 && Number("recheck_search_count") == 1 && Number("queue_down_mask") == 0 && Number("async_down_mask") == 0 &&
            Number("send_call_count") == 1 && Number("requested_input_count") == 2 && Number("inserted_input_count") == 2 &&
            !Flag("release_cleanup_attempted") && Number("cleanup_call_count") == 0 && Number("cleanup_inserted_count") == 0 &&
            Number("cleanup_last_error") == 0 && Number("release_observations") > 0 && Number("target_observations") > 0;
        bool unnecessary = status == "not_needed" && stage == "exact_search_not_observed" && common && new[] { "target_found", "first_page_verified", "recheck_page_verified", "same_root_reverified",
            "send_attempted", "pair_inserted", "release_cleanup_attempted", "release_event_inserted", "escape_up_observed" }.All(key => !Flag(key)) &&
            new[] { "initial_search_count", "recheck_search_count", "send_call_count", "requested_input_count", "inserted_input_count", "send_last_error",
                "cleanup_call_count", "cleanup_inserted_count", "cleanup_last_error", "release_observations", "target_observations" }.All(key => Number(key) == 0);
        return (bound, prepared || unnecessary);
    }

    // This is observation eligibility only. The unchanged native helper must
    // have completed its exact single pair and final owner/desktop observation.
    // Every API/receipt/identity/cleanup failure remains ineligible.
    internal static bool IsCleanForegroundObservation(JsonElement value, string expectedNonce)
    {
        (bool binding, bool accepted) = ValidateNative(value, expectedNonce);
        if (!binding || accepted) return false;
        bool Flag(string key) => value.GetProperty(key).GetBoolean();
        uint Number(string key) => value.GetProperty(key).GetUInt32();
        return value.GetProperty("status").GetString() == "failed" &&
            value.GetProperty("stage").GetString() == "search_target_still_foreground" &&
            Number("hresult") == 2147549183U /* E_UNEXPECTED at this exact terminal guard */ &&
            Number("elapsed_ms") is >= 3000 and < 10000 &&
            Preconditions.All(Flag) && Number("receipt_error") == 0 &&
            new[] { "target_found", "owner_verified", "owner_reverified", "first_page_verified", "recheck_page_verified",
                "same_root_reverified", "keyboard_state_query_succeeded", "send_attempted", "pair_inserted",
                "release_event_inserted", "escape_up_observed", "key_cleanup_verified", "target_observation_valid",
                "target_exists", "target_visible", "target_foreground", "com_uninitialized", "cleanup_verified" }.All(Flag) &&
            !Flag("target_hidden_or_destroyed") && !Flag("release_cleanup_attempted") &&
            Number("initial_search_count") == 1 && Number("recheck_search_count") == 1 &&
            Number("queue_down_mask") == 0 && Number("async_down_mask") == 0 &&
            Number("send_call_count") == 1 && Number("requested_input_count") == 2 && Number("inserted_input_count") == 2 &&
            Number("send_last_error") == 0 && Number("cleanup_call_count") == 0 && Number("cleanup_inserted_count") == 0 &&
            Number("cleanup_last_error") == 0 && Number("release_observations") > 0 &&
            Number("target_observations") >= 2 && Number("cleanup_hresult") == 0;
    }

    internal static Observation ReadReport(string path, string nonce, uint session, string identityDigest, string expectedPreparationNonce)
    {
        using FileStream file = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Need(file.Length is > 0 and <= 32768 && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0,
            "child_preparation_report_size_or_type_invalid");
        using JsonDocument document = JsonDocument.Parse(file, new JsonDocumentOptions { MaxDepth = 6 });
        JsonElement root = document.RootElement;
        string[] keys = { "schema", "nonce", "identity_digest", "session_id", "preparation_nonce", "status", "process_started", "process_exited",
            "process_cleanup_verified", "output_completed", "exit_code", "native_binding_verified", "native_accepted", "native_foreground_unresolved", "render_probe_eligible", "helper", "error_category", "error_hresult", "elapsed_ms" };
        Keys(root, keys);
        Need(root.GetProperty("schema").GetString() == "witness-preparation/v2" && root.GetProperty("nonce").GetString() == nonce &&
            root.GetProperty("identity_digest").GetString() == identityDigest && root.GetProperty("session_id").GetUInt32() == session &&
            root.GetProperty("preparation_nonce").GetString() == expectedPreparationNonce, "child_preparation_report_binding_invalid");
        string? status = root.GetProperty("status").GetString(), category = root.GetProperty("error_category").GetString();
        Need(status is "verified" or "failed" && category is null or "timeout" or "access_denied" or "io" or "invalid_report" or "process" or
            "precondition" or "other" or "owned_process_cleanup", "child_preparation_report_category_invalid");
        string[] flags = { "process_started", "process_exited", "process_cleanup_verified", "output_completed", "native_binding_verified", "native_accepted", "native_foreground_unresolved", "render_probe_eligible" };
        foreach (string key in flags) Need(root.GetProperty(key).ValueKind is JsonValueKind.True or JsonValueKind.False,
            "child_preparation_report_flag_invalid");
        int? exit = root.GetProperty("exit_code").ValueKind == JsonValueKind.Null ? null : root.GetProperty("exit_code").GetInt32();
        int? error = root.GetProperty("error_hresult").ValueKind == JsonValueKind.Null ? null : root.GetProperty("error_hresult").GetInt32();
        Need(root.GetProperty("elapsed_ms").TryGetInt64(out long elapsed) && elapsed is >= 0 and <= 180000,
            "child_preparation_report_elapsed_invalid");
        bool Flag(string key) => root.GetProperty(key).GetBoolean();
        Need((!Flag("process_exited") || Flag("process_started")) && (Flag("process_exited") == exit.HasValue) &&
            (Flag("process_started") || (Flag("process_cleanup_verified") && !Flag("output_completed"))) &&
            (!Flag("output_completed") || Flag("process_exited")) &&
            (!Flag("process_started") || !Flag("process_cleanup_verified") || Flag("process_exited")),
            "child_preparation_report_process_inconsistent");
        JsonElement helper = root.GetProperty("helper"); bool binding = false, accepted = false, nativeCleanup = false, foregroundUnresolved = false;
        Dictionary<string, JsonElement>? publicHelper = null;
        if (helper.ValueKind != JsonValueKind.Null)
        {
            (binding, accepted) = ValidateNative(helper, expectedPreparationNonce);
            foregroundUnresolved = IsCleanForegroundObservation(helper, expectedPreparationNonce);
            nativeCleanup = binding && helper.GetProperty("cleanup_verified").GetBoolean() && helper.GetProperty("key_cleanup_verified").GetBoolean();
            publicHelper = helper.EnumerateObject().Where(item => item.Name != "binding_nonce")
                .ToDictionary(item => item.Name, item => item.Value.Clone(), StringComparer.Ordinal);
        }
        Need(binding == Flag("native_binding_verified") && accepted == Flag("native_accepted") &&
            foregroundUnresolved == Flag("native_foreground_unresolved") &&
            (helper.ValueKind == JsonValueKind.Null || Flag("output_completed")), "child_preparation_report_native_inconsistent");
        bool cleanup = Flag("process_cleanup_verified") && (!Flag("process_started") || nativeCleanup);
        bool verified = status == "verified" && Flag("process_started") && Flag("process_exited") && Flag("output_completed") &&
            exit == 0 && binding && accepted && cleanup && category is null && error is null;
        bool renderProbeEligible = verified || (status == "failed" && Flag("process_started") && Flag("process_exited") &&
            Flag("output_completed") && exit == 1 && binding && foregroundUnresolved && cleanup && category is null && error is null);
        Need(renderProbeEligible == Flag("render_probe_eligible"), "child_preparation_report_eligibility_inconsistent");
        Dictionary<string, object?> output = new(StringComparer.Ordinal)
        {
            ["schema"] = "witness-preparation/v2", ["status"] = status, ["session_id"] = session, ["verified"] = verified,
            ["cleanup_verified"] = cleanup, ["render_probe_eligible"] = renderProbeEligible,
            ["foreground_unresolved"] = foregroundUnresolved, ["exit_code"] = exit, ["error_category"] = category, ["error_hresult"] = error,
            ["elapsed_ms"] = elapsed, ["helper"] = publicHelper
        };
        foreach (string key in flags) output[key] = Flag(key);
        return new(verified, cleanup, renderProbeEligible, foregroundUnresolved, output);
    }
}
