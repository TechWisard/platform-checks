using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SessionContractExperiment;

internal static class GuestSupervisor
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
    private sealed class Result
    {
        public string Schema { get; } = "windows-guest-session-result/v1";
        public string Nonce { get; set; } = "";
        public string Status { get; set; } = "failed";
        public string Stage { get; set; } = "first_logon";
        public bool GuestIdentityVerified { get; set; }
        public bool Elevated { get; set; }
        public bool InteractiveConsoleVerified { get; set; }
        public bool SecureBootVerified { get; set; }
        public bool Tpm2Verified { get; set; }
        public bool FixturePresentationVerified { get; set; }
        public int? FirstLogonAnimationValue { get; set; }
        public int? PrivacyExperienceValue { get; set; }
        public bool SetupMediaWasReadable { get; set; }
        public bool SetupMediaUnavailableVerified { get; set; }
        public int? SetupMediaReadErrorCode { get; set; }
        public int CachedAnswerFilesRemoved { get; set; }
        public bool CachedAnswerFilesAbsentVerified { get; set; }
        public bool ActivationLicensedObserved { get; set; }
        public bool OfflineRuntimeVerified { get; set; }
        public bool HarnessCompiled { get; set; }
        public bool AutologonDisabled { get; set; }
        public bool HarnessCleanupVerified { get; set; }
        public bool GuestWorkDirectoriesRemoved { get; set; }
        public bool CleanupUnverified { get; set; }
        public bool PhysicalInputIsolationVerified { get; } = false;
        public bool NativeMultiseatVerified { get; } = false;
        public int? TestExitCode { get; set; }
        public JsonObject? Test { get; set; }
        public string? ErrorType { get; set; }
        public string? FailureCode { get; set; }
        public int? ErrorHresult { get; set; }
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("user32.dll")]
    private static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDesktopInput(IntPtr desktop, int index, out int value, uint bytes, out uint needed);
    [DllImport("user32.dll")]
    private static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint process, out uint session);
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QuerySession(IntPtr server, uint session, int query, out IntPtr memory, out uint bytes);
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int information, out uint value, uint bytes, out uint needed);
    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, IntPtr security);

    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 2 || args[0] != "--media-root") return 64;
        Result result = new();
        string? work = null, runtime = null;
        bool ownWork = false, ownRuntime = false;
        using SerialChannel serial = new();
        serial.Phase("supervisor_started");
        try
        {
            string media = Path.GetFullPath(args[1]);
            DriveInfo drive = new(media);
            Require(drive.DriveType == DriveType.CDRom && drive.VolumeLabel == "SESSIONPAYLOAD", "payload_media_invalid");
            string configPath = Path.Combine(media, "guest-config.json");
            Require(new FileInfo(configPath).Length is > 0 and <= 4096, "guest_config_size_invalid");
            using JsonDocument config = JsonDocument.Parse(File.ReadAllBytes(configPath));
            JsonElement settings = config.RootElement;
            result.Nonce = settings.GetProperty("nonce").GetString() ?? "";
            Require(result.Nonce.Length == 48 && result.Nonce.All(Uri.IsHexDigit), "guest_nonce_invalid");
            Guid uuid = settings.GetProperty("firmware_uuid").GetGuid();
            string account = settings.GetProperty("account_name").GetString() ?? "";
            Require(account.Length is >= 8 and <= 20 && account.All(char.IsAsciiLetterOrDigit), "guest_account_name_invalid");
            Require(RuntimeInformation.OSArchitecture == Architecture.X64 && RuntimeInformation.ProcessArchitecture == Architecture.X64,
                "guest_x64_required");
            Require(DisposableGuestReceipt.FirmwareUuid() == uuid, "owned_guest_uuid_mismatch");
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            Require(!identity.IsSystem && identity.User is not null && Environment.UserName.Equals(account, StringComparison.OrdinalIgnoreCase),
                "created_parent_account_mismatch");
            Require(GetTokenInformation(identity.AccessToken, 20 /* TokenElevation */, out uint elevation, sizeof(uint), out uint tokenBytes) &&
                tokenBytes == sizeof(uint) && elevation != 0 && new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator),
                "first_logon_process_not_elevated");
            result.Elevated = true;
            result.GuestIdentityVerified = true;
            using RegistryKey currentVersion = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion") ??
                throw new InvalidOperationException("os_version_registry_unavailable");
            Require(string.Equals(currentVersion.GetValue("EditionID") as string, settings.GetProperty("edition").GetString(), StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(currentVersion.GetValue("CurrentBuildNumber") as string, out int build) && build == settings.GetProperty("build").GetInt32(),
                "installed_edition_or_build_mismatch");
            result.Stage = "disable_owned_autologon";
            DisableOwnedAutologon(account);
            result.AutologonDisabled = true;
            serial.Phase("elevated_owned_parent_verified");
            result.Stage = "remove_owned_setup_media";
            DriveInfo[] setupDrives = DriveInfo.GetDrives().Where(item => item.DriveType == DriveType.CDRom &&
                item.IsReady && item.VolumeLabel == "SESSIONSETUP").ToArray();
            Require(setupDrives.Length == 1, "unique_owned_setup_media_not_observed");
            string setupRoot = setupDrives[0].RootDirectory.FullName;
            string setupAnswer = Path.Combine(setupRoot, "Autounattend.xml");
            // Open and immediately close our known setup file to establish
            // readability without extracting, printing, or retaining a secret.
            using (FileStream answer = File.OpenRead(setupAnswer))
                Require(answer.Length is > 0 and < 65536, "owned_setup_answer_size_invalid");
            result.SetupMediaWasReadable = true;
            serial.Phase("setup_media_detach_requested");
            result.SetupMediaReadErrorCode = await WaitSetupMediaRemoval(setupRoot, setupAnswer);
            result.SetupMediaUnavailableVerified = true;
            serial.Phase("setup_media_unavailable_verified");
            result.Stage = "verify_fixture_presentation";
            result.FirstLogonAnimationValue = ReadDword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableFirstLogonAnimation");
            result.PrivacyExperienceValue = ReadDword(@"SOFTWARE\Policies\Microsoft\Windows\OOBE", "DisablePrivacyExperience");
            result.FixturePresentationVerified = result.FirstLogonAnimationValue == 0 && result.PrivacyExperienceValue == 1;
            Require(result.FixturePresentationVerified, "fixture_presentation_policy_not_observed");
            serial.Phase("fixture_presentation_verified");
            result.Stage = "wait_interactive_desktop";
            await WaitDesktop();
            result.InteractiveConsoleVerified = true;
            serial.Phase("interactive_console_observed");
            result.Stage = "remove_owned_cached_answers";
            result.CachedAnswerFilesRemoved = OwnedAnswerFiles.RemoveOwned(result.Nonce);
            result.CachedAnswerFilesAbsentVerified = true;
            serial.Phase("owned_setup_cache_removed");

            result.Stage = "secure_boot_and_tpm";
            // Ordinary inline built-in commands, with no ExecutionPolicy change,
            // credential prompt, RunAs, TPM initialization, or trust enrollment.
            const string securityQuery = "$ErrorActionPreference='Stop'; $s=Confirm-SecureBootUEFI; $t=Get-Tpm; " +
                "$v=Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -ClassName Win32_Tpm; " +
                "[ordered]@{secure_boot=($s -eq $true);tpm_present=[bool]$t.TpmPresent;tpm_ready=[bool]$t.TpmReady;" +
                "tpm_enabled=[bool]$t.TpmEnabled;tpm_activated=[bool]$t.TpmActivated;spec=[string]$v.SpecVersion}|ConvertTo-Json -Compress";
            (int securityExit, string securityJson) = await RunProcess(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", Encoded(securityQuery) },
                Environment.SystemDirectory, TimeSpan.FromSeconds(90), null, null);
            Require(securityExit == 0, "security_query_failed");
            using JsonDocument security = JsonDocument.Parse(securityJson);
            JsonElement proof = security.RootElement;
            result.SecureBootVerified = proof.GetProperty("secure_boot").GetBoolean();
            result.Tpm2Verified = proof.GetProperty("tpm_present").GetBoolean() && proof.GetProperty("tpm_ready").GetBoolean() &&
                proof.GetProperty("tpm_enabled").GetBoolean() && proof.GetProperty("tpm_activated").GetBoolean() &&
                proof.GetProperty("spec").GetString()?.Split(',')[0].Trim() == "2.0";
            Require(result.SecureBootVerified && result.Tpm2Verified, "secure_boot_or_tpm2_not_verified");
            serial.Phase("secure_boot_tpm2_verified");
            result.Stage = "observe_standard_activation";
            serial.Phase("awaiting_standard_activation");
            result.ActivationLicensedObserved = await ObserveActivation();
            Require(result.ActivationLicensedObserved, "activation_not_observed");
            serial.Phase("standard_activation_observed");

            string suffix = Guid.NewGuid().ToString("N");
            work = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GuestContract-" + suffix);
            runtime = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "GuestContractRuntime-" + suffix);
            Require(!Directory.Exists(work) && !Directory.Exists(runtime), "owned_path_collision");
            Require(CreateDirectory(work, IntPtr.Zero), "owned_work_directory_creation_failed");
            ownWork = true;
            result.Stage = "copy_offline_runtime";
            CopyTree(Path.Combine(media, "dotnet"), runtime, () => ownRuntime = true);
            string dotnet = Path.Combine(runtime, "dotnet.exe");
            Require(File.Exists(dotnet) && Directory.Exists(Path.Combine(runtime, "shared", "Microsoft.WindowsDesktop.App", "8.0.33")) &&
                Directory.Exists(Path.Combine(runtime, "packs", "Microsoft.WindowsDesktop.App.Ref", "8.0.33")) &&
                Directory.Exists(Path.Combine(runtime, "sdk", "8.0.427")), "offline_windowsdesktop_sdk_missing");
            result.OfflineRuntimeVerified = true;
            serial.Phase("offline_runtime_verified");
            string source = Path.Combine(work, "source");
            CopyTree(Path.Combine(media, "source"), source);
            File.Copy(Path.Combine(media, "NuGet.Config"), Path.Combine(work, "NuGet.Config"), false);
            File.Copy(Path.Combine(media, "global.json"), Path.Combine(work, "global.json"), false);
            string receipt = Path.Combine(work, "guest-receipt.json");
            using (FileStream file = new(receipt, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                JsonSerializer.Serialize(file, new { schema = "owned-disposable-guest/v1", nonce = result.Nonce,
                    firmware_uuid = uuid, parent_session_id = Process.GetCurrentProcess().SessionId,
                    parent_identity_digest = DisposableGuestReceipt.IdentityDigest(result.Nonce, identity.User!.Value),
                    expires_utc = DateTimeOffset.UtcNow.AddMinutes(30), secure_boot_verified = true, tpm2_verified = true });
            Dictionary<string, string> environment = new()
            {
                ["DOTNET_ROOT"] = runtime, ["DOTNET_CLI_HOME"] = Path.Combine(work, "dotnet-home"),
                ["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1", ["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1",
                ["DOTNET_GENERATE_ASPNET_CERTIFICATE"] = "false", ["DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER"] = "1",
                ["MSBUILDDISABLENODEREUSE"] = "1", ["NUGET_PACKAGES"] = Path.Combine(work, "packages"),
                ["SESSION_CONTRACT_GUEST_RECEIPT"] = receipt
            };
            result.Stage = "compile_harness_offline";
            string output = Path.Combine(work, "build");
            (int compileExit, _) = await RunProcess(dotnet, new[] { "build", Path.Combine(source, "SessionContractExperiment.csproj"),
                "--configuration", "Release", "--output", output, "--configfile", Path.Combine(work, "NuGet.Config"), "--nologo",
                "-p:UseAppHost=false", "-p:UseSharedCompilation=false", "-p:NuGetAudit=false", "-nodeReuse:false" },
                work, TimeSpan.FromMinutes(5), environment, null);
            Require(compileExit == 0, "offline_harness_compile_failed");
            result.HarnessCompiled = true;
            serial.Phase("harness_compiled");
            result.Stage = "verify_setup_cache_before_accounts";
            result.CachedAnswerFilesAbsentVerified = false;
            OwnedAnswerFiles.VerifyAbsent();
            result.CachedAnswerFilesAbsentVerified = true;
            result.Stage = "run_session_contract";
            string evidenceFile = Path.Combine(work, "result.json");
            (int testExit, _) = await RunProcess(dotnet, new[] { Path.Combine(output, "SessionContractExperiment.dll"),
                "--output", evidenceFile, "--allow-enable-child-sessions", "--alternate-test-account", "--test-direct-input",
                "--timeout-seconds", "180" }, work, TimeSpan.FromSeconds(225), environment, serial);
            result.TestExitCode = testExit;
            Require(File.Exists(evidenceFile) && new FileInfo(evidenceFile).Length is > 0 and <= 1048576, "harness_evidence_missing_or_large");
            using JsonDocument evidence = JsonDocument.Parse(File.ReadAllBytes(evidenceFile));
            JsonElement root = evidence.RootElement;
            result.Test = SelectEvidence(root);
            string[] cleanupFields = { "child_removed", "enable_state_restored", "task_removed", "task_instances_stopped",
                "test_account_removed", "witness_sandbox_removed", "parent_still_active_after_cleanup", "console_session_unchanged" };
            result.HarnessCleanupVerified = cleanupFields.All(name => root.TryGetProperty(name, out JsonElement element) && element.ValueKind == JsonValueKind.True);
            result.CleanupUnverified = !result.HarnessCleanupVerified;
            Require(testExit == 0 && result.HarnessCleanupVerified && root.GetProperty("frame_challenge_verified").GetBoolean() &&
                root.GetProperty("different_account_verified").GetBoolean() && root.GetProperty("direct_input_channel_verified").GetBoolean(),
                "session_contract_did_not_pass");
            result.Status = "verified";
            result.Stage = "completed";
        }
        catch (Exception exception)
        {
            result.Status = "failed";
            result.ErrorType = exception.GetType().Name;
            result.FailureCode = exception is GuestFailure failure ? failure.Code :
                exception is OwnedAnswerFiles.Failure cached ? cached.Code : null;
            result.ErrorHresult = exception.HResult;
            if (result.Stage == "run_session_contract" && !result.HarnessCleanupVerified) result.CleanupUnverified = true;
        }
        finally
        {
            bool removed = true;
            foreach ((bool owned, string? path) in new[] { (ownWork, work), (ownRuntime, runtime) })
            {
                try
                {
                    if (owned && path is not null && Directory.Exists(path)) Directory.Delete(path, true);
                }
                catch { removed = false; }
            }
            result.GuestWorkDirectoriesRemoved = removed;
            if (!removed) { result.CleanupUnverified = true; result.Status = "failed"; }
            serial.Result(JsonSerializer.SerializeToUtf8Bytes(result, JsonOptions));
        }
        return result.Status == "verified" ? 0 : 1;
    }

    private sealed class GuestFailure(string code) : Exception
    { internal string Code { get; } = code; }
    private static void Require(bool condition, string stage)
    { if (!condition) throw new GuestFailure(stage); }

    private static string Encoded(string command) => Convert.ToBase64String(Encoding.Unicode.GetBytes(command));

    private static int? ReadDword(string path, string name)
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(path);
        return key?.GetValue(name) is int value && key.GetValueKind(name) == RegistryValueKind.DWord ? value : null;
    }

    private static async Task<int> WaitSetupMediaRemoval(string root, string answer)
    {
        Stopwatch watch = Stopwatch.StartNew();
        int consecutive = 0, lastCode = 0;
        while (watch.Elapsed < TimeSpan.FromSeconds(60))
        {
            DriveInfo drive = new(root);
            Require(drive.DriveType == DriveType.CDRom, "setup_cd_device_changed");
            bool unavailable = false;
            if (!drive.IsReady)
            {
                try { using FileStream file = File.OpenRead(answer); }
                catch (IOException error)
                {
                    lastCode = error.HResult & 0xFFFF;
                    // Missing file/path or ERROR_NOT_READY on the previously
                    // readable exact CD, plus IsReady=false. Access denied and
                    // other unknown errors are failures, never removal proof.
                    Require(lastCode is 2 or 3 or 21, "setup_media_unavailable_error_unexpected");
                    unavailable = true;
                }
            }
            consecutive = unavailable ? consecutive + 1 : 0;
            if (consecutive >= 3) return lastCode;
            await Task.Delay(1000);
        }
        throw new GuestFailure("setup_media_still_readable_timeout");
    }

    private static async Task<bool> ObserveActivation()
    {
        // Observe only LicenseStatus. No product key is read, installed, or
        // changed; no rearm, expiry edit, or activation workaround is attempted.
        const string query = "$ErrorActionPreference='Stop'; " +
            "$p=@(Get-CimInstance -Query \"SELECT LicenseStatus FROM SoftwareLicensingProduct WHERE " +
            "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND LicenseStatus=1\"); " +
            "($p.Count -gt 0)|ConvertTo-Json -Compress";
        Stopwatch watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromMinutes(3))
        {
            (int code, string text) = await RunProcess(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", Encoded(query) },
                Environment.SystemDirectory, TimeSpan.FromSeconds(25), null, null);
            Require(code == 0, "activation_status_query_failed");
            using JsonDocument value = JsonDocument.Parse(text);
            if (value.RootElement.ValueKind == JsonValueKind.True) return true;
            Require(value.RootElement.ValueKind == JsonValueKind.False, "activation_status_format_invalid");
            await Task.Delay(10000);
        }
        return false;
    }

    private static async Task WaitDesktop()
    {
        uint session = checked((uint)Process.GetCurrentProcess().SessionId);
        Stopwatch wait = Stopwatch.StartNew();
        int consecutive = 0;
        while (wait.Elapsed < TimeSpan.FromMinutes(3))
        {
            bool active = false;
            if (QuerySession(IntPtr.Zero, session, 8, out IntPtr memory, out uint bytes))
            {
                try { active = bytes >= sizeof(int) && Marshal.ReadInt32(memory) == 0; }
                finally { WTSFreeMemory(memory); }
            }
            bool input = GetDesktopInput(GetThreadDesktop(GetCurrentThreadId()), 6, out int receives, sizeof(int), out uint needed) &&
                needed == sizeof(int) && receives != 0;
            IntPtr shell = GetShellWindow();
            bool shellInSession = shell != IntPtr.Zero && GetWindowThreadProcessId(shell, out uint pid) != 0 &&
                ProcessIdToSessionId(pid, out uint shellSession) && shellSession == session;
            bool ready = Environment.UserInteractive && session != 0 && WTSGetActiveConsoleSessionId() == session && active && input && shellInSession;
            consecutive = ready ? consecutive + 1 : 0;
            if (consecutive >= 10) return;
            await Task.Delay(1000);
        }
        throw new TimeoutException("interactive_desktop_not_observed");
    }

    private static void DisableOwnedAutologon(string account)
    {
        using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", true) ??
            throw new InvalidOperationException("autologon_registry_unavailable");
        Require(string.Equals(key.GetValue("DefaultUserName") as string, account, StringComparison.OrdinalIgnoreCase), "autologon_account_not_owned");
        // Delete the value without reading its contents. These settings belong
        // to the fresh account on the exact guest UUID just verified above.
        key.DeleteValue("DefaultPassword", false);
        key.SetValue("AutoAdminLogon", "0", RegistryValueKind.String);
        key.SetValue("AutoLogonCount", 0, RegistryValueKind.DWord);
        Require(key.GetValue("AutoAdminLogon") as string == "0" && key.GetValue("AutoLogonCount") is int count && count == 0 &&
            !key.GetValueNames().Contains("DefaultPassword", StringComparer.OrdinalIgnoreCase), "owned_autologon_readback_failed");
    }

    private static void CopyTree(string source, string destination, Action? created = null)
    {
        Require(Directory.Exists(source) && !Directory.Exists(destination), "copy_source_or_destination_invalid");
        Require(CreateDirectory(destination, IntPtr.Zero), "owned_copy_root_creation_failed");
        created?.Invoke();
        foreach (string file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            Require((File.GetAttributes(file) & FileAttributes.ReparsePoint) == 0, "payload_reparse_point_rejected");
            string target = Path.Combine(destination, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, false);
            using FileStream original = File.OpenRead(file);
            using FileStream copied = File.OpenRead(target);
            Require(CryptographicOperations.FixedTimeEquals(SHA256.HashData(original), SHA256.HashData(copied)), "payload_copy_hash_mismatch");
        }
    }

    private static async Task<(int ExitCode, string Output)> RunProcess(string executable, IEnumerable<string> arguments,
        string directory, TimeSpan timeout, Dictionary<string, string>? environment, SerialChannel? serial)
    {
        ProcessStartInfo start = new(executable) { WorkingDirectory = directory, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string value in arguments) start.ArgumentList.Add(value);
        if (environment is not null) foreach ((string key, string value) in environment) start.Environment[key] = value;
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("own_process_not_created");
        Task<string> output = ReadBounded(process.StandardOutput, serial);
        Task<string> error = ReadBounded(process.StandardError, null);
        Task exited = process.WaitForExitAsync();
        Stopwatch watch = Stopwatch.StartNew();
        try
        {
            List<Task> pending = new() { exited, output, error };
            while (!exited.IsCompleted)
            {
                TimeSpan remaining = timeout - watch.Elapsed;
                if (remaining <= TimeSpan.Zero) throw new TimeoutException("owned_process_timeout_cleanup_unverified");
                Task completed = await Task.WhenAny(pending).WaitAsync(remaining);
                await completed; // An output cap fault stops the owned process promptly.
                pending.Remove(completed);
            }
            await exited;
            string captured = await output.WaitAsync(TimeSpan.FromSeconds(5));
            _ = await error.WaitAsync(TimeSpan.FromSeconds(5));
            return (process.ExitCode, captured);
        }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            throw;
        }
    }

    private static async Task<string> ReadBounded(StreamReader reader, SerialChannel? serial)
    {
        StringBuilder result = new();
        StringBuilder line = new();
        bool lineOverflow = false;
        char[] buffer = new char[2048];
        string[] stages = { "simultaneous_sessions_observed", "witness_process_verified", "rendered_frame_challenge_matched",
            "direct_input_channel_verified", "cleanup_started", "test_account_cleanup_verified" };
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0)
        {
            if (result.Length + count > 262144) throw new InvalidOperationException("own_process_output_limit");
            result.Append(buffer, 0, count);
            if (serial is null) continue;
            for (int i = 0; i < count; i++)
            {
                if (buffer[i] == '\n')
                {
                    string text = line.ToString().TrimEnd('\r');
                    if (!lineOverflow && text.StartsWith("experiment_stage=", StringComparison.Ordinal))
                    {
                        string stage = text["experiment_stage=".Length..];
                        if (stages.Contains(stage, StringComparer.Ordinal)) serial.Phase("test_" + stage);
                    }
                    line.Clear(); lineOverflow = false;
                }
                else if (line.Length < 200) line.Append(buffer[i]);
                else lineOverflow = true;
            }
        }
        return result.ToString();
    }

    private static JsonObject SelectEvidence(JsonElement value)
    {
        JsonObject result = new();
        string[] names = { "status", "parent_and_child_active", "same_user_sid", "different_account_verified", "witness_in_expected_session",
            "witness_identity_matches", "witness_administrator_group_present", "frame_challenge_verified", "direct_input_channel_verified",
            "child_received_expected_text", "child_received_expected_button_sequence", "parent_probe_input_event_count", "parent_cursor_unchanged",
            "child_removed", "enable_state_restored", "task_removed", "task_instances_stopped", "test_account_removed", "witness_sandbox_removed",
            "parent_still_active_after_cleanup", "console_session_unchanged" };
        foreach (string name in names)
            if (value.TryGetProperty(name, out JsonElement item)) result[name] = JsonNode.Parse(item.GetRawText());
        JsonArray failures = new();
        if (value.TryGetProperty("events", out JsonElement events))
        {
            foreach (JsonElement item in events.EnumerateArray())
            {
                string? stage = item.GetProperty("stage").GetString();
                if (stage is null || stage.Length > 96 || !stage.All(c => char.IsAsciiLetterOrDigit(c) || c == '_')) continue;
                if (!item.TryGetProperty("details", out JsonElement details) || details.ValueKind != JsonValueKind.Object ||
                    !details.TryGetProperty("code", out JsonElement code) || !code.TryGetInt32(out int number)) continue;
                if (failures.Count >= 16) break;
                JsonObject failure = new() { ["stage"] = stage, ["code"] = number };
                if (details.TryGetProperty("operation", out JsonElement operation) && operation.GetString() is string name &&
                    name.Length <= 128 && name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_')) failure["operation"] = name;
                failures.Add(failure);
            }
        }
        result["failures"] = failures;
        return result;
    }
}

internal sealed class SerialChannel : IDisposable
{
    private readonly SafeFileHandle handle;
    private readonly object gate = new();
    private int phases;
    [StructLayout(LayoutKind.Sequential)]
    private struct Dcb
    {
        internal uint Length, Baud, Flags;
        internal ushort Reserved, XonLimit, XoffLimit;
        internal byte ByteSize, Parity, StopBits, Xon, Xoff, Error, Eof, Event;
        internal ushort Reserved1;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct CommTimeouts { internal uint ReadInterval, ReadMultiplier, ReadConstant, WriteMultiplier, WriteConstant; }
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCommState(SafeFileHandle file, ref Dcb dcb);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCommState(SafeFileHandle file, ref Dcb dcb);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCommTimeouts(SafeFileHandle file, ref CommTimeouts timeouts);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(SafeFileHandle file, byte[] bytes, uint count, out uint written, IntPtr overlapped);

    internal SerialChannel()
    {
        handle = CreateFile(@"\\.\COM1", 0x40000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        try
        {
            if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            Dcb state = new() { Length = checked((uint)Marshal.SizeOf<Dcb>()) };
            if (!GetCommState(handle, ref state)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            state.Baud = 115200; state.Flags = 1; state.ByteSize = 8; state.Parity = 0; state.StopBits = 0;
            CommTimeouts timeout = new() { WriteConstant = 5000 };
            if (!SetCommState(handle, ref state) || !SetCommTimeouts(handle, ref timeout))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        catch { handle.Dispose(); throw; }
    }

    internal void Phase(string value)
    {
        if (!value.All(c => char.IsAsciiLetterOrDigit(c) || c == '_') || value.Length > 100) throw new InvalidOperationException("invalid_phase");
        lock (gate) { if (phases++ < 32) Write(Encoding.ASCII.GetBytes("GUEST_PHASE_V1 " + value + "\n")); }
    }

    internal void Result(byte[] json)
    {
        if (json.Length is <= 0 or > 65536) throw new InvalidOperationException("serial_result_size_invalid");
        lock (gate)
        {
            string header = "GUEST_RESULT_V1 " + json.Length + " " + Convert.ToHexString(SHA256.HashData(json)) + "\n";
            Write(Encoding.ASCII.GetBytes(header)); Write(json); Write(new byte[] { 10 });
        }
    }

    private void Write(byte[] bytes)
    {
        if (!WriteFile(handle, bytes, checked((uint)bytes.Length), out uint written, IntPtr.Zero) || written != bytes.Length)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
    public void Dispose() => handle.Dispose();
}
