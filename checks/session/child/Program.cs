using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using FUNCDESC = System.Runtime.InteropServices.ComTypes.FUNCDESC;
using INVOKEKIND = System.Runtime.InteropServices.ComTypes.INVOKEKIND;
using TYPEATTR = System.Runtime.InteropServices.ComTypes.TYPEATTR;
using TYPEKIND = System.Runtime.InteropServices.ComTypes.TYPEKIND;
using ELEMDESC = System.Runtime.InteropServices.ComTypes.ELEMDESC;
using TYPEDESC = System.Runtime.InteropServices.ComTypes.TYPEDESC;
using PARAMFLAG = System.Runtime.InteropServices.ComTypes.PARAMFLAG;
using FUNCKIND = System.Runtime.InteropServices.ComTypes.FUNCKIND;
using CALLCONV = System.Runtime.InteropServices.ComTypes.CALLCONV;

namespace SessionContractExperiment;

internal static class Native
{
    internal const uint NoSession = uint.MaxValue;
    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSIsChildSessionsEnabled([MarshalAs(UnmanagedType.Bool)] out bool enabled);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSEnableChildSessions([MarshalAs(UnmanagedType.Bool)] bool enabled);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSGetChildSessionId(out uint sessionId);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSLogoffSession(IntPtr server, uint sessionId, [MarshalAs(UnmanagedType.Bool)] bool wait);
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Query(IntPtr server, uint id, int info, out IntPtr buffer, out uint size);
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Enumerate(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("kernel32.dll")]
    internal static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("oleaut32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    internal static extern int LoadTypeLibEx(string file, int kind, out ITypeLib typeLib);
    [DllImport("oleaut32.dll")]
    internal static extern int VariantClear(IntPtr value);

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSession { public uint Id; public IntPtr Name; public int State; }

    internal static void Require(bool ok, string operation)
    {
        if (!ok) throw new ExperimentFailure(operation, Marshal.GetLastWin32Error());
    }
    internal static uint ChildId()
    {
        if (WTSGetChildSessionId(out uint id)) return id;
        int error = Marshal.GetLastWin32Error();
        // Both observed Windows 11/Server images report no child with
        // ERROR_NOT_FOUND. The independent probe records the raw result.
        // All other errors remain failures, never an assumed empty state.
        if (error == 1168 /* ERROR_NOT_FOUND */) return NoSession;
        throw new ExperimentFailure("WTSGetChildSessionId", error);
    }
    internal static HashSet<uint> SessionIds()
    {
        Require(Enumerate(IntPtr.Zero, 0, 1, out IntPtr data, out int count), "WTSEnumerateSessions");
        try
        {
            if (count < 0 || count > 16384) throw new ExperimentFailure("invalid_session_count");
            HashSet<uint> ids = new();
            int size = Marshal.SizeOf<WtsSession>();
            for (int i = 0; i < count; i++) ids.Add(Marshal.PtrToStructure<WtsSession>(IntPtr.Add(data, checked(i * size))).Id);
            return ids;
        }
        finally { WTSFreeMemory(data); }
    }
    internal static int State(uint id)
    {
        Require(Query(IntPtr.Zero, id, 8, out IntPtr value, out uint bytes), "WTSConnectState");
        try
        {
            if (bytes < sizeof(int)) throw new ExperimentFailure("invalid_session_state_size");
            return Marshal.ReadInt32(value);
        }
        finally { WTSFreeMemory(value); }
    }
    private static string Text(uint id, int field)
    {
        Require(Query(IntPtr.Zero, id, field, out IntPtr value, out uint bytes), "WTSQuerySessionInformation");
        try
        {
            if (bytes > 32768 || bytes % 2 != 0) throw new ExperimentFailure("invalid_session_string_size");
            return bytes < 2 ? "" : Marshal.PtrToStringUni(value, checked((int)bytes / 2)).TrimEnd('\0');
        }
        finally { WTSFreeMemory(value); }
    }
    internal static string SessionSid(uint id)
    {
        string user = Text(id, 5);
        if (string.IsNullOrEmpty(user)) throw new ExperimentFailure("session_has_no_logged_on_user");
        string domain = Text(id, 7);
        NTAccount account = string.IsNullOrEmpty(domain) ? new NTAccount(user) : new NTAccount(domain, user);
        return ((SecurityIdentifier)account.Translate(typeof(SecurityIdentifier))).Value;
    }
}

internal sealed class ExperimentFailure : Exception
{
    internal string Stage { get; }
    internal int Code { get; }
    internal ExperimentFailure(string stage, int code = 0) { Stage = stage; Code = code; }
}

// The documented interface is IUnknown-based, not IDispatch. Read the installed
// type library before calling its property slots; never assume a vtable order.
internal sealed class ExtendedSettings : IDisposable
{
    private static readonly Guid InterfaceId = new("302D8188-0052-4807-806A-362B628F9AC5");
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int PropertyCall(IntPtr self, IntPtr name, IntPtr variant);
    private IntPtr instance;
    private readonly PropertyCall put;
    private readonly PropertyCall get;
    internal int PutSlot { get; }
    internal int GetSlot { get; }

    internal ExtendedSettings(object control, Action<string, object?> record)
    {
        string dll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "mstscax.dll");
        Marshal.ThrowExceptionForHR(Native.LoadTypeLibEx(dll, 2 /* REGKIND_NONE */, out ITypeLib library));
        int putOffset = -1, getOffset = -1;
        ITypeInfo? info = null;
        try
        {
            Guid iid = InterfaceId;
            library.GetTypeInfoOfGuid(ref iid, out info);
            info.GetTypeAttr(out IntPtr attribute);
            try
            {
                TYPEATTR type = Marshal.PtrToStructure<TYPEATTR>(attribute);
                if (type.guid != InterfaceId || type.typekind != TYPEKIND.TKIND_INTERFACE)
                    throw new ExperimentFailure("unexpected_extended_settings_type");
                for (int i = 0; i < type.cFuncs; i++)
                {
                    info.GetFuncDesc(i, out IntPtr descriptor);
                    try
                    {
                        FUNCDESC function = Marshal.PtrToStructure<FUNCDESC>(descriptor);
                        info.GetDocumentation(function.memid, out string name, out _, out _, out _);
                        record("extended_settings_type_member", new { name, parameters = function.cParams,
                            invocation = function.invkind.ToString(), vtable_offset = function.oVft,
                            vtable_bytes = type.cbSizeVft, return_type = function.elemdescFunc.tdesc.vt,
                            calling_convention = function.callconv.ToString(), function_kind = function.funckind.ToString() });
                        if (function.cParams != 2) continue;
                        bool setter = name == "put_Property" || (name == "Property" &&
                            (function.invkind == INVOKEKIND.INVOKE_PROPERTYPUT || function.invkind == INVOKEKIND.INVOKE_PROPERTYPUTREF));
                        bool getter = name == "get_Property" || (name == "Property" && function.invkind == INVOKEKIND.INVOKE_PROPERTYGET);
                        if (!setter && !getter) continue;
                        if (function.elemdescFunc.tdesc.vt != (short)VarEnum.VT_HRESULT ||
                            function.callconv != CALLCONV.CC_STDCALL ||
                            (function.funckind != FUNCKIND.FUNC_PUREVIRTUAL && function.funckind != FUNCKIND.FUNC_VIRTUAL) ||
                            function.oVft < 3 * IntPtr.Size || function.oVft + IntPtr.Size > type.cbSizeVft ||
                            function.lprgelemdescParam == IntPtr.Zero)
                            throw new ExperimentFailure("unexpected_extended_property_signature");
                        ELEMDESC first = Marshal.PtrToStructure<ELEMDESC>(function.lprgelemdescParam);
                        ELEMDESC second = Marshal.PtrToStructure<ELEMDESC>(IntPtr.Add(function.lprgelemdescParam, Marshal.SizeOf<ELEMDESC>()));
                        if (first.tdesc.vt != (short)VarEnum.VT_BSTR ||
                            (first.desc.paramdesc.wParamFlags & PARAMFLAG.PARAMFLAG_FIN) == 0 ||
                            second.tdesc.vt != (short)VarEnum.VT_PTR || second.tdesc.lpValue == IntPtr.Zero ||
                            Marshal.PtrToStructure<TYPEDESC>(second.tdesc.lpValue).vt != (short)VarEnum.VT_VARIANT ||
                            (setter && (second.desc.paramdesc.wParamFlags & PARAMFLAG.PARAMFLAG_FIN) == 0) ||
                            (getter && (second.desc.paramdesc.wParamFlags & PARAMFLAG.PARAMFLAG_FOUT) == 0))
                            throw new ExperimentFailure("unexpected_extended_property_parameter_types");
                        if (setter)
                            putOffset = function.oVft;
                        if (getter)
                            getOffset = function.oVft;
                    }
                    finally { info.ReleaseFuncDesc(descriptor); }
                }
            }
            finally { info.ReleaseTypeAttr(attribute); }
        }
        finally
        {
            if (info is not null) Marshal.ReleaseComObject(info);
            Marshal.ReleaseComObject(library);
        }
        if (putOffset < 3 * IntPtr.Size || getOffset < 3 * IntPtr.Size ||
            putOffset % IntPtr.Size != 0 || getOffset % IntPtr.Size != 0 || putOffset == getOffset)
            throw new ExperimentFailure("unverified_extended_settings_vtable");
        IntPtr unknown = Marshal.GetIUnknownForObject(control);
        try
        {
            Guid iid = InterfaceId;
            Marshal.ThrowExceptionForHR(Marshal.QueryInterface(unknown, ref iid, out instance));
            IntPtr table = Marshal.ReadIntPtr(instance);
            put = Marshal.GetDelegateForFunctionPointer<PropertyCall>(Marshal.ReadIntPtr(table, putOffset));
            get = Marshal.GetDelegateForFunctionPointer<PropertyCall>(Marshal.ReadIntPtr(table, getOffset));
            PutSlot = putOffset / IntPtr.Size;
            GetSlot = getOffset / IntPtr.Size;
        }
        catch { Dispose(); throw; }
        finally { Marshal.Release(unknown); }
    }
    internal void Set(string name, object value)
    {
        IntPtr variant = Marshal.AllocCoTaskMem(24), property = Marshal.StringToBSTR(name);
        try
        {
            for (int i = 0; i < 24; i++) Marshal.WriteByte(variant, i, 0);
            Marshal.GetNativeVariantForObject(value, variant);
            Marshal.ThrowExceptionForHR(put(instance, property, variant));
        }
        finally { Native.VariantClear(variant); Marshal.FreeCoTaskMem(variant); Marshal.FreeBSTR(property); }
    }
    internal object? Get(string name)
    {
        IntPtr variant = Marshal.AllocCoTaskMem(24), property = Marshal.StringToBSTR(name);
        try
        {
            for (int i = 0; i < 24; i++) Marshal.WriteByte(variant, i, 0);
            Marshal.ThrowExceptionForHR(get(instance, property, variant));
            return Marshal.GetObjectForNativeVariant(variant);
        }
        finally { Native.VariantClear(variant); Marshal.FreeCoTaskMem(variant); Marshal.FreeBSTR(property); }
    }
    public void Dispose()
    {
        if (instance != IntPtr.Zero) { Marshal.Release(instance); instance = IntPtr.Zero; }
    }
}

internal sealed class RdpHost : AxHost
{
    // Microsoft-documented MsRdpClient10NotSafeForScripting.
    internal RdpHost() : base("A0C63C30-F08D-4AB4-907C-34905D770C7D") { }
    internal object ControlObject => GetOcx();
}

internal static class Dispatch
{
    internal static object? Get(object target, string member) => target.GetType().InvokeMember(
        member, BindingFlags.GetProperty, null, target, null, CultureInfo.InvariantCulture);
    internal static void Set(object target, string member, object value) => target.GetType().InvokeMember(
        member, BindingFlags.SetProperty, null, target, new[] { value }, CultureInfo.InvariantCulture);
    internal static void Call(object target, string member) => target.GetType().InvokeMember(
        member, BindingFlags.InvokeMethod, null, target, null, CultureInfo.InvariantCulture);
}

internal sealed class Evidence
{
    public string Schema { get; set; } = "session-contract-experiment/v1";
    public string Status { get; set; } = "starting";
    public string StartedUtc { get; set; } = DateTimeOffset.UtcNow.ToString("O");
    public string? FinishedUtc { get; set; }
    public string OsDescription { get; set; } = RuntimeInformation.OSDescription;
    public string OsArchitecture { get; set; } = RuntimeInformation.OSArchitecture.ToString();
    public string ProcessArchitecture { get; set; } = RuntimeInformation.ProcessArchitecture.ToString();
    public uint ParentSessionId { get; set; }
    public uint? ChildSessionId { get; set; }
    public uint ConsoleSessionBefore { get; set; }
    public uint? ConsoleSessionAfter { get; set; }
    public bool ConsoleSessionUnchanged { get; set; }
    public bool Interactive { get; set; }
    public bool? InitiallyEnabled { get; set; }
    public bool EnableChanged { get; set; }
    public bool ConnectCalled { get; set; }
    public bool ChildCreated { get; set; }
    public bool ParentAndChildActive { get; set; }
    public bool? SameUserSid { get; set; }
    public bool WitnessInExpectedSession { get; set; }
    public bool WitnessIdentityMatches { get; set; }
    public bool FrameChallengeVerified { get; set; }
    public bool PhysicalInputIsolationVerified { get; set; }
    public bool NativeMultiseatVerified { get; set; }
    public bool ChildRemoved { get; set; }
    public bool EnableStateRestored { get; set; }
    public bool TaskRemoved { get; set; } = true;
    public bool ParentStillActiveAfterCleanup { get; set; }
    public List<object> Events { get; set; } = new();
    internal void Event(string stage, object? details = null) => Events.Add(new { utc = DateTimeOffset.UtcNow.ToString("O"), stage, details });
    internal void Error(string stage, Exception exception)
    {
        Exception ex = exception is TargetInvocationException { InnerException: Exception inner } ? inner : exception;
        Event(stage, new { exception_type = ex.GetType().Name, code = ex is ExperimentFailure failure ? failure.Code : ex.HResult,
            operation = ex is ExperimentFailure known ? known.Stage : null });
    }
}

internal sealed class ExperimentForm : Form
{
    private readonly Evidence evidence;
    private readonly bool allowEnable;
    private readonly TimeSpan timeout;
    private readonly RdpHost host = new() { Dock = DockStyle.Fill };
    private readonly string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    private readonly string work = Path.Combine(Path.GetTempPath(), "session-contract-" + Guid.NewGuid().ToString("N"));
    private readonly string taskName = "SessionContractExperiment-" + Guid.NewGuid().ToString("N");
    private HashSet<uint> baseline = new();
    private string parentSid = "";
    private object? control;
    private ExtendedSettings? extended;
    private dynamic? taskFolder;
    private dynamic? registeredTask;
    private bool ownTask;
    private bool closing;
    private bool preconditions;
    internal int ExitCode { get; private set; } = 1;

    internal ExperimentForm(Evidence evidence, bool allowEnable, TimeSpan timeout)
    {
        this.evidence = evidence; this.allowEnable = allowEnable; this.timeout = timeout;
        Text = "Session contract experiment — local child session";
        ClientSize = new Size(1024, 768);
        StartPosition = FormStartPosition.Manual;
        Location = new Point(0, 0);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        Controls.Add(host);
        Shown += async (_, _) => await RunExperiment();
        FormClosing += (_, args) => { if (!closing) args.Cancel = true; };
    }

    private async Task RunExperiment()
    {
        try
        {
            evidence.ParentSessionId = (uint)Process.GetCurrentProcess().SessionId;
            evidence.ConsoleSessionBefore = Native.WTSGetActiveConsoleSessionId();
            evidence.Interactive = Environment.UserInteractive && evidence.ParentSessionId != 0;
            if (!evidence.Interactive || Native.State(evidence.ParentSessionId) != 0)
            { Skip("active_interactive_parent_required"); return; }
            Native.Require(Native.WTSIsChildSessionsEnabled(out bool enabled), "WTSIsChildSessionsEnabled");
            evidence.InitiallyEnabled = enabled;
            if (Native.ChildId() != Native.NoSession)
            { Skip("existing_child_session_untouched"); return; }
            if (!enabled && !allowEnable)
            { Skip("explicit_enable_permission_required"); return; }
            baseline = Native.SessionIds();
            parentSid = Native.SessionSid(evidence.ParentSessionId);
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (identity.User?.Value != parentSid) { Skip("process_identity_differs_from_parent_user"); return; }
            }
            preconditions = true;
            if (!enabled)
            {
                Native.Require(Native.WTSEnableChildSessions(true), "WTSEnableChildSessions_enable");
                evidence.EnableChanged = true;
            }
            control = host.ControlObject;
            extended = new ExtendedSettings(control, evidence.Event);
            evidence.Event("extended_settings_typelib_verified", new { put_slot = extended.PutSlot, get_slot = extended.GetSlot });
            Dispatch.Set(control, "Server", "localhost");
            Dispatch.Set(control, "DesktopWidth", 1024);
            Dispatch.Set(control, "DesktopHeight", 768);
            Dispatch.Set(control, "ColorDepth", 32);
            object advanced = Dispatch.Get(control, "AdvancedSettings9") ?? throw new ExperimentFailure("advanced_settings_missing");
            bool credSspBefore = Convert.ToBoolean(Dispatch.Get(advanced, "EnableCredSspSupport"), CultureInfo.InvariantCulture);
            Dispatch.Set(advanced, "EnableCredSspSupport", true);
            bool credSspAfter = Convert.ToBoolean(Dispatch.Get(advanced, "EnableCredSspSupport"), CultureInfo.InvariantCulture);
            evidence.Event("connection_credssp", new { before = credSspBefore, after = credSspAfter });
            if (!credSspAfter) throw new ExperimentFailure("connection_credssp_not_enabled");
            foreach (string property in new[] { "RedirectClipboard", "RedirectDrives", "RedirectPrinters", "RedirectPorts", "RedirectSmartCards" })
                Dispatch.Set(advanced, property, false);
            extended.Set("ConnectToChildSession", true);
            if (extended.Get("ConnectToChildSession") is not bool selected || !selected)
                throw new ExperimentFailure("child_session_property_not_set");
            try
            {
                extended.Set("EnableFrameBufferRedirection", true);
                evidence.Event("shared_framebuffer_requested");
            }
            catch (Exception ex) { evidence.Error("optional_shared_framebuffer_request_failed", ex); }
            Stopwatch deadline = Stopwatch.StartNew();
            evidence.ConnectCalled = true;
            Dispatch.Call(control, "Connect");
            evidence.Event("connect_called");
            while (deadline.Elapsed < timeout)
            {
                uint id = Native.ChildId();
                if (id != Native.NoSession)
                {
                    if (baseline.Contains(id) || id == evidence.ParentSessionId)
                        throw new ExperimentFailure("child_ownership_not_proven");
                    evidence.ChildSessionId = id;
                    evidence.ChildCreated = true;
                    if (Native.State(id) == 0 && Native.State(evidence.ParentSessionId) == 0 &&
                        Convert.ToInt32(Dispatch.Get(control, "Connected"), CultureInfo.InvariantCulture) == 1)
                    {
                        try
                        {
                            string childSid = Native.SessionSid(id);
                            evidence.SameUserSid = childSid == parentSid;
                            evidence.ParentAndChildActive = true;
                            break;
                        }
                        catch (ExperimentFailure ex) when (ex.Stage == "session_has_no_logged_on_user")
                        {
                            // Connected can precede completed logon. The same
                            // finite deadline applies while credentials/UI wait.
                        }
                    }
                }
                await Task.Delay(250);
            }
            if (!evidence.ParentAndChildActive) throw new ExperimentFailure("child_connection_timeout");
            if (Native.WTSGetActiveConsoleSessionId() != evidence.ConsoleSessionBefore)
                throw new ExperimentFailure("console_session_changed_during_child_connect");
            evidence.Event("simultaneous_sessions_observed", new { same_user_sid = evidence.SameUserSid });
            if (evidence.SameUserSid != true)
                throw new ExperimentFailure("child_identity_is_not_current_user_witness_not_started");
            Directory.CreateDirectory(work);
            string witnessFile = Path.Combine(work, "witness.json");
            StartWitness(evidence.ChildSessionId!.Value, witnessFile);
            bool witnessVerified = false;
            while (deadline.Elapsed < timeout)
            {
                if (!evidence.ParentAndChildActive || Native.State(evidence.ParentSessionId) != 0 ||
                    Native.State(evidence.ChildSessionId!.Value) != 0)
                    throw new ExperimentFailure("parallel_session_lost");
                if (!witnessVerified && File.Exists(witnessFile))
                {
                    using JsonDocument witness = JsonDocument.Parse(File.ReadAllText(witnessFile));
                    JsonElement root = witness.RootElement;
                    if (root.GetProperty("nonce").GetString() != nonce) throw new ExperimentFailure("witness_nonce_mismatch");
                    evidence.WitnessInExpectedSession = root.GetProperty("session_id").GetUInt32() == evidence.ChildSessionId;
                    evidence.WitnessIdentityMatches = root.GetProperty("identity_digest").GetString() == Program.IdentityDigest(nonce, parentSid);
                    if (!evidence.WitnessInExpectedSession || !evidence.WitnessIdentityMatches)
                        throw new ExperimentFailure("witness_session_or_identity_mismatch");
                    witnessVerified = true;
                    evidence.Event("witness_process_verified");
                }
                if (witnessVerified && CheckFrame())
                {
                    evidence.FrameChallengeVerified = true;
                    evidence.Status = "child_session_and_frame_verified";
                    ExitCode = 0;
                    break;
                }
                await Task.Delay(500);
            }
            if (!evidence.FrameChallengeVerified) throw new ExperimentFailure("frame_challenge_timeout");
        }
        catch (Exception ex)
        {
            evidence.Status = "failed";
            evidence.Error("experiment_failed", ex);
            ExitCode = 1;
        }
        finally
        {
            await Cleanup();
            closing = true;
            Close();
        }
    }

    private void Skip(string reason)
    {
        evidence.Status = "unsupported_environment";
        evidence.Event(reason);
        ExitCode = 77;
    }

    private void StartWitness(uint session, string result)
    {
        // These checks precede registration and execution. Never run a helper in
        // another account or a pre-existing session.
        if (!evidence.ChildCreated || baseline.Contains(session) || Native.ChildId() != session ||
            Native.SessionSid(session) != parentSid)
            throw new ExperimentFailure("witness_ownership_recheck_failed");
        Type schedulerType = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!;
        dynamic service = Activator.CreateInstance(schedulerType)!;
        service.Connect();
        taskFolder = service.GetFolder("\\");
        dynamic definition = service.NewTask(0);
        definition.RegistrationInfo.Description = "Temporary local child-session rendering contract test";
        definition.Principal.UserId = parentSid;
        definition.Principal.LogonType = 3; // TASK_LOGON_INTERACTIVE_TOKEN: no password.
        definition.Principal.RunLevel = 0;  // TASK_RUNLEVEL_LUA.
        definition.Settings.Enabled = true;
        definition.Settings.AllowDemandStart = true;
        definition.Settings.DisallowStartIfOnBatteries = false;
        definition.Settings.StopIfGoingOnBatteries = false;
        definition.Settings.ExecutionTimeLimit = "PT3M";
        dynamic action = definition.Actions.Create(0); // TASK_ACTION_EXEC.
        string executable = Environment.ProcessPath ?? throw new ExperimentFailure("process_path_missing");
        List<string> arguments = new();
        if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
            arguments.Add(Assembly.GetExecutingAssembly().Location);
        arguments.AddRange(new[] { "--witness", session.ToString(CultureInfo.InvariantCulture), nonce, result });
        action.Path = executable;
        action.Arguments = string.Join(" ", arguments.Select(Program.QuoteArgument));
        action.WorkingDirectory = AppContext.BaseDirectory;
        registeredTask = taskFolder.RegisterTaskDefinition(taskName, definition, 2 /* TASK_CREATE */, parentSid, null, 3, null);
        ownTask = true;
        evidence.TaskRemoved = false;
        registeredTask.RunEx(null, 4 /* TASK_RUN_USE_SESSION_ID */, checked((int)session), null);
        evidence.Event("witness_task_requested");
    }

    private bool CheckFrame()
    {
        if (control is null || Convert.ToInt32(Dispatch.Get(control, "Connected"), CultureInfo.InvariantCulture) != 1) return false;
        Rectangle region = host.RectangleToScreen(host.ClientRectangle);
        if (region.Width <= 0 || region.Height <= 0 || region.Width > 4096 || region.Height > 4096) return false;
        Color[] palette = Program.ChallengeColors(nonce);
        int[] counts = new int[palette.Length];
        using Bitmap bitmap = new(region.Width, region.Height);
        using (Graphics graphics = Graphics.FromImage(bitmap))
            graphics.CopyFromScreen(region.Location, Point.Empty, region.Size, CopyPixelOperation.SourceCopy);
        // No screenshot is written or uploaded. Only the random challenge colors
        // drawn by our own process are counted; no desktop text is extracted.
        for (int y = 0; y < bitmap.Height; y += 4)
        for (int x = 0; x < bitmap.Width; x += 4)
        {
            Color pixel = bitmap.GetPixel(x, y);
            for (int i = 0; i < palette.Length; i++)
                if (Math.Abs(pixel.R - palette[i].R) <= 3 && Math.Abs(pixel.G - palette[i].G) <= 3 && Math.Abs(pixel.B - palette[i].B) <= 3)
                    counts[i]++;
        }
        bool match = counts.All(count => count >= 80);
        if (match) evidence.Event("rendered_frame_challenge_matched", new { distinct_colors = palette.Length, matched_samples = counts });
        return match;
    }

    private async Task Cleanup()
    {
        bool cleanupFailed = false;
        if (ownTask)
        {
            try
            {
                if (registeredTask!.GetInstances(0).Count > 0) registeredTask.Stop(0);
            }
            catch (Exception ex) { evidence.Error("own_task_stop_failed", ex); }
            try
            {
                taskFolder!.DeleteTask(taskName, 0);
                evidence.TaskRemoved = true;
            }
            catch (Exception ex) { evidence.Error("own_task_cleanup_failed", ex); cleanupFailed = true; }
        }
        if (preconditions && evidence.ConnectCalled)
        {
            try
            {
                uint observedChild = Native.ChildId();
                uint child = evidence.ChildSessionId ?? Native.NoSession;
                if (child == Native.NoSession && observedChild != Native.NoSession)
                    throw new ExperimentFailure("late_child_creation_ownership_not_recorded");
                if (child != Native.NoSession)
                {
                    // A cached numeric ID alone does not establish ownership:
                    // Windows may reuse it after logoff. Keep the control
                    // connected and require a fresh link to our parent before
                    // requesting logoff. Never kill by a stale cached ID.
                    if (!evidence.ChildCreated || baseline.Contains(child) || child == evidence.ParentSessionId)
                        throw new ExperimentFailure("cleanup_child_ownership_not_proven");
                    if (Native.SessionIds().Contains(child))
                    {
                        if (observedChild != child || Native.ChildId() != child)
                            throw new ExperimentFailure("cleanup_child_link_lost_id_may_be_reused");
                        Native.Require(Native.WTSLogoffSession(IntPtr.Zero, child, false), "WTSLogoffSession_owned_child");
                    }
                    Stopwatch wait = Stopwatch.StartNew();
                    while (wait.Elapsed < TimeSpan.FromSeconds(20) && Native.SessionIds().Contains(child)) await Task.Delay(250);
                    if (Native.SessionIds().Contains(child)) throw new ExperimentFailure("owned_child_logoff_timeout");
                }
                evidence.ChildRemoved = true;
            }
            catch (Exception ex) { evidence.Error("own_child_cleanup_failed", ex); cleanupFailed = true; }
        }
        else evidence.ChildRemoved = !evidence.ChildCreated;
        if (control is not null)
        {
            try
            {
                if (Convert.ToInt32(Dispatch.Get(control, "Connected"), CultureInfo.InvariantCulture) != 0)
                    Dispatch.Call(control, "Disconnect");
            }
            catch (Exception ex) { evidence.Error("control_disconnect_failed", ex); cleanupFailed = true; }
        }
        if (evidence.InitiallyEnabled.HasValue)
        {
            try
            {
                if (evidence.EnableChanged)
                {
                    if (!evidence.ChildRemoved) throw new ExperimentFailure("enable_state_restore_waits_for_child_cleanup");
                    Native.Require(Native.WTSEnableChildSessions(evidence.InitiallyEnabled.Value), "WTSEnableChildSessions_restore");
                }
                Native.Require(Native.WTSIsChildSessionsEnabled(out bool now), "WTSIsChildSessionsEnabled_after");
                evidence.EnableStateRestored = now == evidence.InitiallyEnabled.Value;
                if (!evidence.EnableStateRestored) throw new ExperimentFailure("enable_state_not_restored");
            }
            catch (Exception ex) { evidence.Error("enable_state_restore_failed", ex); cleanupFailed = true; }
        }
        try
        {
            evidence.ConsoleSessionAfter = Native.WTSGetActiveConsoleSessionId();
            evidence.ConsoleSessionUnchanged = evidence.ConsoleSessionAfter == evidence.ConsoleSessionBefore;
            evidence.ParentStillActiveAfterCleanup = evidence.Interactive && Native.State(evidence.ParentSessionId) == 0;
            if (preconditions && !evidence.ParentStillActiveAfterCleanup) throw new ExperimentFailure("parent_not_active_after_cleanup");
            if (preconditions && !evidence.ConsoleSessionUnchanged) throw new ExperimentFailure("console_session_changed_after_cleanup");
        }
        catch (Exception ex) { evidence.Error("parent_cleanup_check_failed", ex); cleanupFailed = true; }
        extended?.Dispose();
        try { if (Directory.Exists(work)) Directory.Delete(work, true); }
        catch (Exception ex) { evidence.Error("temporary_files_cleanup_failed", ex); cleanupFailed = true; }
        if (cleanupFailed) { evidence.Status = "cleanup_failed"; ExitCode = 1; }
    }
}

internal sealed class WitnessForm : Form
{
    private readonly Color[] colors;
    private readonly System.Windows.Forms.Timer lifetime = new() { Interval = 150000 };
    internal WitnessForm(string nonce)
    {
        colors = Program.ChallengeColors(nonce);
        Text = "Session rendering witness";
        FormBorderStyle = FormBorderStyle.None;
        WindowState = FormWindowState.Maximized;
        TopMost = true;
        BackColor = Color.Black;
        DoubleBuffered = true;
        lifetime.Tick += (_, _) => Close();
        Shown += (_, _) => lifetime.Start();
        FormClosed += (_, _) => lifetime.Dispose();
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        for (int i = 0; i < colors.Length; i++)
        {
            using SolidBrush brush = new(colors[i]);
            e.Graphics.FillRectangle(brush, 40 + (i % 4) * 150, 40 + (i / 4) * 150, 120, 120);
        }
    }
}

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 4 && args[0] == "--witness") return RunWitness(args);
        string? output = null;
        bool allowEnable = false;
        int timeout = 120;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--output" && i + 1 < args.Length) output = Path.GetFullPath(args[++i]);
            else if (args[i] == "--allow-enable-child-sessions") allowEnable = true;
            else if (args[i] == "--timeout-seconds" && i + 1 < args.Length && int.TryParse(args[++i], out int value) && value is >= 15 and <= 300) timeout = value;
            else { Console.Error.WriteLine("Usage: SessionContractExperiment --output FILE [--allow-enable-child-sessions] [--timeout-seconds 15..300]"); return 64; }
        }
        if (output is null || File.Exists(output)) { Console.Error.WriteLine("A new --output file is required."); return 64; }
        Evidence evidence = new();
        int result = 1;
        using Mutex mutex = new(false, "Local\\SessionContractExperiment");
        bool acquired = false;
        try
        {
            try { acquired = mutex.WaitOne(0); } catch (AbandonedMutexException) { acquired = true; }
            if (!acquired) throw new ExperimentFailure("another_experiment_is_running");
            // Check before creating any ActiveX window. Session 0 is not a valid
            // parent; attempting COM activation there would obscure this fact.
            evidence.ParentSessionId = (uint)Process.GetCurrentProcess().SessionId;
            evidence.Interactive = Environment.UserInteractive && evidence.ParentSessionId != 0;
            if (!evidence.Interactive)
            {
                evidence.Status = "unsupported_environment";
                evidence.Event("active_interactive_parent_required");
                result = 77;
            }
            else
            {
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                using ExperimentForm form = new(evidence, allowEnable, TimeSpan.FromSeconds(timeout));
                Application.Run(form);
                result = form.ExitCode;
            }
        }
        catch (Exception ex) { evidence.Status = "failed"; evidence.Error("main_failed", ex); result = 1; }
        finally
        {
            if (acquired) mutex.ReleaseMutex();
            evidence.FinishedUtc = DateTimeOffset.UtcNow.ToString("O");
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(output)!);
                using FileStream file = new(output, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                JsonSerializer.Serialize(file, evidence, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
            }
            catch (Exception ex) { Console.Error.WriteLine("Evidence write failed: " + ex.GetType().Name); result = 1; }
            Console.WriteLine("status=" + evidence.Status + "; exit=" + result.ToString(CultureInfo.InvariantCulture));
        }
        return result;
    }

    private static int RunWitness(string[] args)
    {
        if (!uint.TryParse(args[1], out uint expected) || expected == 0 || args[2].Length != 48 || !args[2].All(Uri.IsHexDigit)) return 64;
        uint actual = (uint)Process.GetCurrentProcess().SessionId;
        if (actual != expected || !Environment.UserInteractive) return 2;
        string output = Path.GetFullPath(args[3]);
        if (File.Exists(output)) return 2;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        string? sid = identity.User?.Value;
        if (sid is null) return 2;
        string json = JsonSerializer.Serialize(new { nonce = args[2], session_id = actual, identity_digest = IdentityDigest(args[2], sid) });
        string temporary = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllText(temporary, json, new UTF8Encoding(false));
        File.Move(temporary, output, false);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new WitnessForm(args[2]));
        return 0;
    }

    internal static string IdentityDigest(string nonce, string sid) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(nonce + ":" + sid)));

    internal static Color[] ChallengeColors(string nonce)
    {
        byte[] hash = SHA256.HashData(Convert.FromHexString(nonce));
        // The large grid separation prevents color collisions after compression.
        return Enumerable.Range(0, 8).Select(i => Color.FromArgb(
            24 + (i & 1) * 160 + hash[i * 3] % 24,
            24 + ((i >> 1) & 1) * 160 + hash[i * 3 + 1] % 24,
            24 + ((i >> 2) & 1) * 160 + hash[i * 3 + 2] % 24)).ToArray();
    }

    internal static string QuoteArgument(string value)
    {
        StringBuilder quoted = new("\"");
        int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') quoted.Append('\\', slashes * 2 + 1).Append('"');
            else quoted.Append('\\', slashes).Append(c);
            slashes = 0;
        }
        return quoted.Append('\\', slashes * 2).Append('"').ToString();
    }
}
