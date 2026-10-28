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
    internal static Dictionary<uint, int> SessionStatesForAccountCleanup()
    {
        Require(Enumerate(IntPtr.Zero, 0, 1, out IntPtr data, out int count), "WTSEnumerateSessions_cleanup");
        try
        {
            if (count < 0 || count > 16384 || (count != 0 && data == IntPtr.Zero))
                throw new ExperimentFailure("invalid_cleanup_session_inventory");
            Dictionary<uint, int> sessions = new();
            int size = Marshal.SizeOf<WtsSession>();
            for (int i = 0; i < count; i++)
            {
                WtsSession item = Marshal.PtrToStructure<WtsSession>(IntPtr.Add(data, checked(i * size)));
                if (item.State is < 0 or > 9 || !sessions.TryAdd(item.Id, item.State))
                    throw new ExperimentFailure("unknown_or_duplicate_cleanup_session_entry");
            }
            return sessions;
        }
        finally { WTSFreeMemory(data); }
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
    internal static object? Call(object target, string member, params object[] arguments) => target.GetType().InvokeMember(
        member, BindingFlags.InvokeMethod, null, target, arguments, CultureInfo.InvariantCulture);
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
    public bool AlternateTestAccountRequested { get; set; }
    public bool TestAccountCreated { get; set; }
    public bool TestAccountNonAdministratorVerified { get; set; }
    public bool TestAccountRemoteDesktopUsersMembership { get; set; }
    public bool TestCredentialsApplied { get; set; }
    public bool? ChildMatchesCreatedAccountSid { get; set; }
    public bool? WitnessAdministratorGroupPresent { get; set; }
    public bool DifferentAccountVerified { get; set; }
    public bool TestAccountRemoved { get; set; } = true;
    public bool WitnessSandboxRemoved { get; set; } = true;
    public bool WitnessInExpectedSession { get; set; }
    public bool WitnessIdentityMatches { get; set; }
    public bool ChildSearchPreparationRequested { get; set; }
    public bool ChildSearchPreparationVerified { get; set; }
    public bool ChildSearchRenderProbeEligible { get; set; }
    public bool ChildSearchForegroundUnresolved { get; set; }
    public bool ChildSearchPreparationCleanupVerified { get; set; } = true;
    public bool FrameChallengeVerified { get; set; }
    public bool WindowInputRequested { get; set; }
    public bool WindowInputVerified { get; set; }
    public bool? WindowInputCleanupVerified { get; set; }
    public bool WindowChildReceivedExpectedText { get; set; }
    public bool WindowChildReceivedExpectedButtonSequence { get; set; }
    public bool DirectInputRequested { get; set; }
    public bool DirectInputChannelVerified { get; set; }
    public bool ChildReceivedExpectedText { get; set; }
    public bool ChildReceivedExpectedButtonSequence { get; set; }
    public int? ParentProbeInputEventCount { get; set; }
    public bool? ParentCursorUnchanged { get; set; }
    public bool PhysicalInputIsolationVerified { get; set; }
    public bool NativeMultiseatVerified { get; set; }
    public bool ChildRemoved { get; set; }
    public bool EnableStateRestored { get; set; }
    public bool TaskRemoved { get; set; } = true;
    public bool TaskInstancesStopped { get; set; } = true;
    public bool ParentStillActiveAfterCleanup { get; set; }
    public List<object> Events { get; set; } = new();
    internal void Event(string stage, object? details = null)
    {
        Events.Add(new { utc = DateTimeOffset.UtcNow.ToString("O"), stage, details });
        Console.WriteLine("experiment_stage=" + stage);
        Console.Out.Flush();
    }
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
    private readonly bool alternateTestAccount;
    private readonly bool testDirectInput;
    private readonly bool testWindowInput;
    private readonly string? childSearchHelper;
    private readonly TimeSpan timeout;
    private readonly RdpHost host = new() { Dock = DockStyle.Fill };
    private readonly FrameProbe frameProbe = new();
    private readonly string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    private readonly string work = Path.Combine(Path.GetTempPath(), "session-contract-" + Guid.NewGuid().ToString("N"));
    private readonly string taskName = "SessionContractExperiment-" + Guid.NewGuid().ToString("N");
    private HashSet<uint> baseline = new();
    private string parentSid = "";
    private string expectedWitnessSid = "";
    private object? control;
    private ExtendedSettings? extended;
    private RdpConnectionEvents? connectionEvents;
    private OwnedTestAccount? testAccount;
    private RdpPasswordControl? passwordControl;
    private WitnessSandbox? witnessSandbox;
    private string? witnessRenderPath;
    private string? witnessPreparationPath;
    private bool witnessPreparationObserved;
    private long witnessRenderSequence = -1;
    private bool witnessRenderReadErrorReported;
    private dynamic? taskFolder;
    private dynamic? registeredTask;
    private bool ownTask;
    private bool closing;
    private bool preconditions;
    internal int ExitCode { get; private set; } = 1;

    internal ExperimentForm(Evidence evidence, bool allowEnable, TimeSpan timeout, bool alternateTestAccount, bool testDirectInput, bool testWindowInput, string? childSearchHelper)
    {
        this.evidence = evidence; this.allowEnable = allowEnable; this.timeout = timeout;
        this.alternateTestAccount = alternateTestAccount;
        this.testDirectInput = testDirectInput;
        this.testWindowInput = testWindowInput;
        this.childSearchHelper = childSearchHelper;
        Text = "Session contract experiment — local child session";
        OwnWindowPresentation.Configure(this);
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
            expectedWitnessSid = parentSid;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (identity.User?.Value != parentSid) { Skip("process_identity_differs_from_parent_user"); return; }
                if (alternateTestAccount && !OwnedTestAccount.DisposableHostedRunnerRequested())
                { Skip("alternate_account_requires_disposable_github_hosted_vm"); return; }
                if (alternateTestAccount && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                { Skip("alternate_account_requires_existing_elevated_test_process"); return; }
            }
            if (alternateTestAccount) _ = WitnessSandbox.ResolveSystemRuntimeExecutable();
            preconditions = true;
            if (!enabled)
            {
                Native.Require(Native.WTSEnableChildSessions(true), "WTSEnableChildSessions_enable");
                evidence.EnableChanged = true;
            }
            control = host.ControlObject;
            connectionEvents = new RdpConnectionEvents(control, evidence.Event);
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
            int authenticationBefore = Convert.ToInt32(Dispatch.Get(advanced, "AuthenticationLevel"), CultureInfo.InvariantCulture);
            // Require server authentication. Value 1 fails instead of asking the
            // unattended host to continue after an authentication failure.
            Dispatch.Set(advanced, "AuthenticationLevel", 1);
            int authenticationAfter = Convert.ToInt32(Dispatch.Get(advanced, "AuthenticationLevel"), CultureInfo.InvariantCulture);
            evidence.Event("server_authentication_required", new { before = authenticationBefore, after = authenticationAfter });
            if (authenticationAfter != 1) throw new ExperimentFailure("server_authentication_requirement_not_set");
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
            using (CredentialPromptControl prompts = new(control, evidence.Event))
                prompts.DisableAndVerify(evidence.Event);
            if (alternateTestAccount)
            {
                evidence.Event("test_account_creation_started");
                // Assign before Create: cleanup retains the ownership receipt
                // even if a later SID/group read fails after NetUserAdd succeeds.
                testAccount = new OwnedTestAccount(evidence.Event);
                try { testAccount.Create(); }
                finally
                {
                    evidence.TestAccountCreated = testAccount.Created;
                    evidence.TestAccountRemoved = !testAccount.Created;
                }
                if (testAccount.Sid == parentSid) throw new ExperimentFailure("test_account_is_not_a_different_sid");
                expectedWitnessSid = testAccount.Sid;
                evidence.TestAccountNonAdministratorVerified = testAccount.NonAdministratorVerified;
                evidence.TestAccountRemoteDesktopUsersMembership = testAccount.RemoteDesktopUsersMembership;
                evidence.Event("distinct_nonadministrator_test_account_created");
                passwordControl = new RdpPasswordControl(control, evidence.Event);
                if (Convert.ToInt32(Dispatch.Get(control, "Connected"), CultureInfo.InvariantCulture) != 0)
                    throw new ExperimentFailure("credential_properties_require_disconnected_control");
                Dispatch.Set(control, "UserName", testAccount.Name);
                Dispatch.Set(control, "Domain", Environment.MachineName);
                testAccount.SetControlPassword(passwordControl);
                evidence.TestCredentialsApplied = true;
                evidence.Event("owned_test_credentials_applied");
            }
            Stopwatch deadline = Stopwatch.StartNew();
            evidence.ConnectCalled = true;
            evidence.Event("connect_invocation_started");
            connectionEvents.Arm();
            Dispatch.Call(control, "Connect");
            evidence.Event("connect_called");
            connectionEvents.ThrowIfConnectionFailed();
            while (deadline.Elapsed < timeout)
            {
                connectionEvents.ThrowIfConnectionFailed();
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
                            if (alternateTestAccount) evidence.ChildMatchesCreatedAccountSid = childSid == expectedWitnessSid;
                            if (Native.SessionSid(evidence.ParentSessionId) != parentSid)
                                throw new ExperimentFailure("parent_identity_changed_during_connect");
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
            if (alternateTestAccount)
            {
                if (evidence.SameUserSid != false || evidence.ChildMatchesCreatedAccountSid != true)
                    throw new ExperimentFailure("child_identity_is_not_created_account_witness_not_started");
            }
            else if (evidence.SameUserSid != true)
                throw new ExperimentFailure("child_identity_is_not_current_user_witness_not_started");
            string witnessFile;
            if (alternateTestAccount)
            {
                witnessSandbox = new WitnessSandbox();
                try { witnessSandbox.Create(parentSid, expectedWitnessSid); }
                finally { evidence.WitnessSandboxRemoved = !witnessSandbox.Created; }
                witnessFile = witnessSandbox.ResultPath;
                evidence.Event("owned_witness_payload_prepared");
                if (childSearchHelper is not null)
                {
                    VerifyWitnessOwnership(evidence.ChildSessionId!.Value);
                    witnessSandbox.PrepareChildSearch(childSearchHelper, parentSid, expectedWitnessSid,
                        evidence.ParentSessionId, evidence.ChildSessionId.Value, evidence.ConsoleSessionBefore);
                    witnessPreparationPath = Path.Combine(Path.GetDirectoryName(witnessFile)!, ChildSearchPreparation.ReportName);
                    evidence.Event("owned_child_search_payload_prepared");
                }
            }
            else
            {
                Directory.CreateDirectory(work);
                witnessFile = Path.Combine(work, "witness.json");
            }
            witnessRenderPath = Path.Combine(Path.GetDirectoryName(witnessFile)!, "witness-render.json");
            // One request for our parent form, after connection and before the
            // frame phase. Retry/capture loops never reassert activation.
            OwnWindowCoverage beforePresentation = OwnWindowPresentation.Observe(this);
            OwnWindowPresentation.Present(this);
            evidence.Event("parent_window_presentation", new
                { before = beforePresentation, after = OwnWindowPresentation.Observe(this) });
            StartWitness(evidence.ChildSessionId!.Value, witnessFile);
            bool witnessVerified = false;
            while (deadline.Elapsed < timeout)
            {
                connectionEvents.ThrowIfConnectionFailed();
                if (!evidence.ParentAndChildActive || Native.State(evidence.ParentSessionId) != 0 ||
                    Native.State(evidence.ChildSessionId!.Value) != 0 || Native.SessionSid(evidence.ParentSessionId) != parentSid ||
                    Native.WTSGetActiveConsoleSessionId() != evidence.ConsoleSessionBefore)
                    throw new ExperimentFailure("parallel_session_lost");
                if (!witnessVerified && File.Exists(witnessFile))
                {
                    using JsonDocument witness = JsonDocument.Parse(File.ReadAllText(witnessFile));
                    JsonElement root = witness.RootElement;
                    if (root.GetProperty("nonce").GetString() != nonce) throw new ExperimentFailure("witness_nonce_mismatch");
                    evidence.WitnessInExpectedSession = root.GetProperty("session_id").GetUInt32() == evidence.ChildSessionId;
                    evidence.WitnessIdentityMatches = root.GetProperty("identity_digest").GetString() == Program.IdentityDigest(nonce, expectedWitnessSid);
                    evidence.WitnessAdministratorGroupPresent = root.GetProperty("administrator_group_present").GetBoolean();
                    if (!evidence.WitnessInExpectedSession || !evidence.WitnessIdentityMatches)
                        throw new ExperimentFailure("witness_session_or_identity_mismatch");
                    if (alternateTestAccount && evidence.WitnessAdministratorGroupPresent != false)
                        throw new ExperimentFailure("witness_test_account_has_administrator_group");
                    witnessVerified = true;
                    evidence.Event("witness_process_verified");
                }
                if (witnessVerified) ReadWitnessRendering();
                if (witnessVerified && childSearchHelper is not null && !witnessPreparationObserved)
                    ReadWitnessPreparation();
                if (witnessVerified && (childSearchHelper is null || evidence.ChildSearchRenderProbeEligible) && CheckFrame())
                {
                    evidence.FrameChallengeVerified = true;
                    evidence.DifferentAccountVerified = alternateTestAccount && evidence.SameUserSid == false &&
                        evidence.ChildMatchesCreatedAccountSid == true && evidence.WitnessIdentityMatches;
                    evidence.Status = alternateTestAccount ? "different_account_child_and_frame_verified" : "child_session_and_frame_verified";
                    ExitCode = 0;
                    break;
                }
                await Task.Delay(500);
            }
            if (!evidence.FrameChallengeVerified) throw new ExperimentFailure("frame_challenge_timeout");
            if (testWindowInput)
            {
                await WindowInputExperiment.Run(this, host, control, evidence, witnessFile, nonce,
                    evidence.ChildSessionId!.Value, Program.IdentityDigest(nonce, expectedWitnessSid),
                    () => { connectionEvents.ThrowIfConnectionFailed(); VerifyWitnessOwnership(evidence.ChildSessionId!.Value); },
                    timeout - deadline.Elapsed);
                evidence.Status = "different_account_child_frame_and_window_input_verified";
            }
            if (testDirectInput)
            {
                await DirectInputExperiment.Run(this, control, evidence, witnessFile, nonce,
                    evidence.ChildSessionId!.Value, Program.IdentityDigest(nonce, expectedWitnessSid),
                    () => { connectionEvents.ThrowIfConnectionFailed(); VerifyWitnessOwnership(evidence.ChildSessionId!.Value); },
                    timeout - deadline.Elapsed);
                evidence.Status = "different_account_child_frame_and_input_verified";
            }
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

    private void ReadWitnessPreparation()
    {
        if (witnessPreparationPath is null || !File.Exists(witnessPreparationPath)) return;
        if (witnessSandbox?.PreparationNonce is not string preparationNonce)
            throw new ExperimentFailure("child_preparation_parent_receipt_missing");
        VerifyWitnessOwnership(evidence.ChildSessionId!.Value);
        ChildSearchPreparation.Observation observation = ChildSearchPreparation.ReadReport(witnessPreparationPath,
            nonce, evidence.ChildSessionId.Value, Program.IdentityDigest(nonce, expectedWitnessSid), preparationNonce);
        witnessPreparationObserved = true;
        evidence.ChildSearchPreparationCleanupVerified = observation.CleanupVerified;
        evidence.ChildSearchPreparationVerified = observation.Verified;
        evidence.ChildSearchRenderProbeEligible = observation.RenderProbeEligible;
        evidence.ChildSearchForegroundUnresolved = observation.ForegroundUnresolved;
        evidence.Event("child_search_preparation_observed", observation.Public);
        if (!observation.RenderProbeEligible) throw new ExperimentFailure("child_search_render_probe_not_eligible");
    }

    private void ReadWitnessRendering()
    {
        if (witnessRenderPath is null || !File.Exists(witnessRenderPath)) return;
        try
        {
            using FileStream file = new(witnessRenderPath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (file.Length is <= 0 or > 65536) throw new ExperimentFailure("witness_render_report_size_invalid");
            using JsonDocument document = JsonDocument.Parse(file);
            JsonElement root = document.RootElement;
            if (root.GetProperty("schema").GetString() != "witness-render/v1" ||
                root.GetProperty("nonce").GetString() != nonce ||
                root.GetProperty("session_id").GetUInt32() != evidence.ChildSessionId ||
                root.GetProperty("identity_digest").GetString() != Program.IdentityDigest(nonce, expectedWitnessSid))
                throw new ExperimentFailure("witness_render_report_binding_invalid");
            long sequence = root.GetProperty("sequence").GetInt64();
            if (sequence <= witnessRenderSequence) return;
            Dictionary<string, JsonElement> observation = new(StringComparer.Ordinal);
            foreach (JsonProperty property in root.EnumerateObject())
                if (property.Name is not "nonce" and not "identity_digest")
                    observation.Add(property.Name, property.Value.Clone());
            evidence.Event("witness_render_observation", observation);
            witnessRenderSequence = sequence;
            witnessRenderReadErrorReported = false;
        }
        catch (Exception ex)
        {
            // This is supplementary diagnostics. Its absence or failure cannot
            // satisfy or weaken the independent rendered-frame challenge.
            if (!witnessRenderReadErrorReported) evidence.Error("witness_render_report_unavailable", ex);
            witnessRenderReadErrorReported = true;
        }
    }

    private void StartWitness(uint session, string result)
    {
        VerifyWitnessOwnership(session);
        Type schedulerType = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!;
        dynamic service = Activator.CreateInstance(schedulerType)!;
        service.Connect();
        taskFolder = service.GetFolder("\\");
        dynamic definition = service.NewTask(0);
        definition.RegistrationInfo.Description = "Temporary local child-session rendering contract test";
        definition.Principal.UserId = expectedWitnessSid;
        definition.Principal.LogonType = 3; // TASK_LOGON_INTERACTIVE_TOKEN: no password.
        definition.Principal.RunLevel = 0;  // TASK_RUNLEVEL_LUA.
        definition.Settings.Enabled = true;
        definition.Settings.AllowDemandStart = true;
        definition.Settings.DisallowStartIfOnBatteries = false;
        definition.Settings.StopIfGoingOnBatteries = false;
        definition.Settings.ExecutionTimeLimit = "PT3M";
        dynamic action = definition.Actions.Create(0); // TASK_ACTION_EXEC.
        string executable;
        List<string> arguments = new();
        if (witnessSandbox is not null)
        {
            executable = witnessSandbox.RuntimeExecutable;
            arguments.Add(witnessSandbox.AssemblyPath);
        }
        else
        {
            executable = Environment.ProcessPath ?? throw new ExperimentFailure("process_path_missing");
            if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
                arguments.Add(Assembly.GetExecutingAssembly().Location);
        }
        arguments.AddRange(new[] { "--witness", session.ToString(CultureInfo.InvariantCulture), nonce, result });
        if (testDirectInput || testWindowInput) arguments.Add("--prepare-input");
        if (childSearchHelper is not null) arguments.Add("--prepare-child-search");
        action.Path = executable;
        action.Arguments = string.Join(" ", arguments.Select(Program.QuoteArgument));
        action.WorkingDirectory = witnessSandbox?.BinaryDirectory ?? AppContext.BaseDirectory;
        registeredTask = taskFolder.RegisterTaskDefinition(taskName, definition, 2 /* TASK_CREATE */, expectedWitnessSid, null, 3, null);
        ownTask = true;
        evidence.TaskRemoved = false;
        evidence.TaskInstancesStopped = false;
        // Recheck after registration, immediately before RunEx. An account or
        // session change during registration never authorizes execution there.
        VerifyWitnessOwnership(session);
        registeredTask.RunEx(null, 4 | 8 /* TASK_RUN_USE_SESSION_ID | TASK_RUN_USER_SID */, checked((int)session), expectedWitnessSid);
        evidence.Event("witness_task_requested");
    }

    private void VerifyWitnessOwnership(uint session)
    {
        if (!evidence.ChildCreated || baseline.Contains(session) || session == evidence.ParentSessionId ||
            Native.ChildId() != session || Native.State(session) != 0 || Native.State(evidence.ParentSessionId) != 0 ||
            Native.SessionSid(session) != expectedWitnessSid || Native.SessionSid(evidence.ParentSessionId) != parentSid ||
            Native.WTSGetActiveConsoleSessionId() != evidence.ConsoleSessionBefore)
            throw new ExperimentFailure("witness_ownership_recheck_failed");
        if (alternateTestAccount)
        {
            if (testAccount is null || expectedWitnessSid != testAccount.Sid || expectedWitnessSid == parentSid)
                throw new ExperimentFailure("witness_test_account_receipt_missing");
            testAccount.RequireOwnership();
            testAccount.VerifyNoAdministratorMembership();
        }
        else if (expectedWitnessSid != parentSid) throw new ExperimentFailure("witness_default_identity_mismatch");
    }

    private bool CheckFrame()
    {
        if (control is null || Convert.ToInt32(Dispatch.Get(control, "Connected"), CultureInfo.InvariantCulture) != 1) return false;
        FrameSamples? samples = frameProbe.Capture(host, this, Program.ChallengeColors(nonce), evidence.Event);
        bool match = samples?.MatchesChallenge == true;
        if (match) evidence.Event("rendered_frame_challenge_matched", new { distinct_colors = 8, matched_samples = samples!.CountsWithin3 });
        return match;
    }

    private async Task Cleanup()
    {
        bool cleanupFailed = false;
        bool controlDisconnected = control is null;
        frameProbe.RecordFinal(evidence.Event);
        evidence.Event("cleanup_started");
        ReadWitnessRendering();
        try { connectionEvents?.BeginCleanup(); }
        catch (Exception ex) { evidence.Error("event_cleanup_start_failed", ex); cleanupFailed = true; }
        if (ownTask)
        {
            try
            {
                if (registeredTask!.GetInstances(0).Count > 0) registeredTask.Stop(0);
                // Stop can return S_FALSE without throwing. Observe that all
                // instances of this unique task actually stopped before delete.
                Stopwatch taskWait = Stopwatch.StartNew();
                while (registeredTask!.GetInstances(0).Count != 0 && taskWait.Elapsed < TimeSpan.FromSeconds(5))
                    await Task.Delay(250);
                if (registeredTask!.GetInstances(0).Count != 0)
                    throw new ExperimentFailure("own_task_instances_not_stopped");
                evidence.TaskInstancesStopped = true;
            }
            catch (Exception ex) { evidence.Error("own_task_stop_failed", ex); cleanupFailed = true; }
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
                Stopwatch disconnectWait = Stopwatch.StartNew();
                while (Convert.ToInt32(Dispatch.Get(control, "Connected"), CultureInfo.InvariantCulture) != 0 &&
                    disconnectWait.Elapsed < TimeSpan.FromSeconds(20)) await Task.Delay(250);
                controlDisconnected = Convert.ToInt32(Dispatch.Get(control, "Connected"), CultureInfo.InvariantCulture) == 0;
                if (!controlDisconnected) throw new ExperimentFailure("control_disconnect_timeout");
                if (passwordControl is not null)
                {
                    passwordControl.ResetAfterDisconnect();
                    evidence.Event("control_password_reset");
                }
                if (evidence.ConnectCalled && Native.ChildId() != Native.NoSession)
                {
                    evidence.ChildRemoved = false;
                    throw new ExperimentFailure("child_link_present_after_disconnect_do_not_delete_account");
                }
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
        if (witnessSandbox is not null)
        {
            try
            {
                witnessSandbox.Remove(evidence.ChildRemoved, evidence.TaskRemoved && evidence.TaskInstancesStopped);
                evidence.WitnessSandboxRemoved = !witnessSandbox.Created || witnessSandbox.Removed;
            }
            catch (Exception ex) { evidence.Error("witness_sandbox_cleanup_failed", ex); cleanupFailed = true; }
        }
        if (testAccount is not null)
        {
            try
            {
                evidence.Event("test_account_cleanup_started");
                testAccount.DeleteAfterSessionsRemoved(evidence.ChildRemoved, evidence.TaskRemoved && evidence.TaskInstancesStopped, controlDisconnected);
                evidence.TestAccountRemoved = !testAccount.Created || testAccount.Removed;
                evidence.Event("test_account_cleanup_verified");
            }
            catch (Exception ex) { evidence.Error("own_test_account_cleanup_failed", ex); cleanupFailed = true; }
            finally { testAccount.Dispose(); }
        }
        passwordControl?.Dispose();
        try { connectionEvents?.Dispose(); }
        catch (Exception ex) { evidence.Error("event_cleanup_failed", ex); cleanupFailed = true; }
        extended?.Dispose();
        try { if (Directory.Exists(work)) Directory.Delete(work, true); }
        catch (Exception ex) { evidence.Error("temporary_files_cleanup_failed", ex); cleanupFailed = true; }
        if (cleanupFailed) { evidence.Status = "cleanup_failed"; ExitCode = 1; }
    }
}

internal sealed class WitnessForm : Form
{
    private readonly Color[] colors;
    private readonly WitnessRenderEvidence render;
    private WitnessInputEvidence? input;
    private readonly System.Windows.Forms.Timer lifetime = new() { Interval = 150000 };
    private readonly System.Windows.Forms.Timer diagnostics = new() { Interval = 1000 };
    private readonly Stopwatch shownFor = new();
    private static readonly int[] SnapshotSeconds = { 1, 5, 15, 30, 45, 60, 75, 90, 105, 115 };
    private int nextSnapshot;
    internal WitnessForm(string nonce, WitnessRenderEvidence render)
    {
        this.render = render;
        colors = Program.ChallengeColors(nonce);
        Text = "Session rendering witness";
        OwnWindowPresentation.Configure(this);
        BackColor = Color.Black;
        DoubleBuffered = true;
        lifetime.Tick += (_, _) => Close();
        Shown += (_, _) =>
        {
            render.Shown(this);
            // Already TopMost before this point; explicitly request presentation
            // once, then observe whether it actually took effect.
            OwnWindowPresentation.Present(this);
            render.Capture(this, "presentation_requested", captureFrame: false);
            shownFor.Start();
            lifetime.Start();
            diagnostics.Start();
        };
        diagnostics.Tick += (_, _) =>
        {
            if (nextSnapshot < SnapshotSeconds.Length && shownFor.Elapsed.TotalSeconds >= SnapshotSeconds[nextSnapshot])
            {
                // Coalesce missed intervals instead of emitting a burst after a
                // busy UI thread. Sampling occurs outside OnPaint/double buffering.
                while (nextSnapshot < SnapshotSeconds.Length && shownFor.Elapsed.TotalSeconds >= SnapshotSeconds[nextSnapshot]) nextSnapshot++;
                render.Capture(this, "timer", captureFrame: true);
            }
            if (nextSnapshot == SnapshotSeconds.Length) diagnostics.Stop();
        };
        FormClosed += (_, _) => { lifetime.Dispose(); diagnostics.Dispose(); shownFor.Stop(); };
    }
    internal WitnessInputEvidence AttachInputProbe(string identityOutput, string nonce, uint session, string digest)
    {
        if (input is not null || IsHandleCreated) throw new ExperimentFailure("input_probe_attachment_must_precede_window_creation");
        input = new WitnessInputEvidence(this, identityOutput, nonce, session, digest);
        return input;
    }
    protected override void WndProc(ref Message message)
    {
        if (input?.Observe(ref message) == true) return;
        base.WndProc(ref message);
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        try
        {
            base.OnPaint(e);
            for (int i = 0; i < colors.Length; i++)
            {
                using SolidBrush brush = new(colors[i]);
                e.Graphics.FillRectangle(brush, 40 + (i % 4) * 150, 40 + (i / 4) * 150, 120, 120);
            }
            render.PaintCompleted();
        }
        catch (Exception ex) { render.RecordException("paint", ex); throw; }
    }
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        input?.Dispose();
        render.Capture(this, "form_closing", captureFrame: false, final: true, closeReason: (int)e.CloseReason);
        base.OnFormClosing(e);
    }
}

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length >= 4 && args[0] == "--witness")
        {
            string[] options = args.Skip(4).ToArray();
            if (options.Length > 2 || options.Distinct(StringComparer.Ordinal).Count() != options.Length ||
                options.Any(value => value is not "--prepare-input" and not "--prepare-child-search")) return 64;
            return RunWitness(args);
        }
        string? output = null;
        string? childSearchHelper = null;
        bool allowEnable = false;
        bool alternateTestAccount = false;
        bool testDirectInput = false;
        bool testWindowInput = false;
        int timeout = 120;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--output" && i + 1 < args.Length) output = Path.GetFullPath(args[++i]);
            else if (args[i] == "--allow-enable-child-sessions") allowEnable = true;
            else if (args[i] == "--alternate-test-account") alternateTestAccount = true;
            else if (args[i] == "--test-direct-input") testDirectInput = true;
            else if (args[i] == "--test-window-input") testWindowInput = true;
            else if (args[i] == "--child-search-helper" && i + 1 < args.Length && childSearchHelper is null) childSearchHelper = Path.GetFullPath(args[++i]);
            else if (args[i] == "--timeout-seconds" && i + 1 < args.Length && int.TryParse(args[++i], out int value) && value is >= 15 and <= 300) timeout = value;
            else { Console.Error.WriteLine("Usage: SessionContractExperiment --output FILE [--allow-enable-child-sessions] [--timeout-seconds 15..300] [--alternate-test-account] [--test-direct-input | --test-window-input] [--child-search-helper FILE]"); return 64; }
        }
        if ((testDirectInput || testWindowInput) && !alternateTestAccount)
        { Console.Error.WriteLine("An input experiment requires --alternate-test-account."); return 64; }
        if (testDirectInput && testWindowInput)
        { Console.Error.WriteLine("--test-direct-input and --test-window-input are mutually exclusive."); return 64; }
        if (childSearchHelper is not null && !alternateTestAccount) { Console.Error.WriteLine("--child-search-helper requires --alternate-test-account."); return 64; }
        if (output is null || File.Exists(output)) { Console.Error.WriteLine("A new --output file is required."); return 64; }
        Evidence evidence = new() { AlternateTestAccountRequested = alternateTestAccount, DirectInputRequested = testDirectInput, WindowInputRequested = testWindowInput,
            ChildSearchPreparationRequested = childSearchHelper is not null, ChildSearchPreparationCleanupVerified = childSearchHelper is null };
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
                using ExperimentForm form = new(evidence, allowEnable, TimeSpan.FromSeconds(timeout), alternateTestAccount, testDirectInput, testWindowInput, childSearchHelper);
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
        WitnessRenderEvidence? render = null;
        WitnessInputEvidence? input = null;
        ThreadExceptionEventHandler? uiException = null;
        int result = 2;
        try
        {
            bool administratorGroupPresent = TokenEvidence.HasAdministratorGroupIncludingDenyOnly(identity);
            string digest = IdentityDigest(args[2], sid);
            string json = JsonSerializer.Serialize(new { nonce = args[2], session_id = actual, identity_digest = digest,
                administrator_group_present = administratorGroupPresent });
            string temporary = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllText(temporary, json, new UTF8Encoding(false));
            File.Move(temporary, output, false);
            if (args.Contains("--prepare-child-search", StringComparer.Ordinal))
            {
                if (administratorGroupPresent) throw new ExperimentFailure("child_preparation_requires_nonadministrator_witness");
                ChildSearchPreparation.RunAndWrite(output, args[2], actual, digest, sid).GetAwaiter().GetResult();
            }
            // Native preparation and its input cleanup finish first. A narrowly
            // verified unresolved Search observation may allow this own-window
            // experiment; actual parent pixels and child input still decide.
            // The native preparation finishes before computing the palette,
            // creating a Form, or registering the witness input baseline.
            render = new WitnessRenderEvidence(output, args[2], actual, digest);
            render.IdentityWritten();
            // Handle this test process's own UI errors without opening an error
            // dialog. Record only numeric errors and then terminate its UI loop.
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            uiException = (_, error) =>
            {
                result = 2;
                render.RecordException("ui_thread", error.Exception);
                input?.RecordException(error.Exception);
                Application.ExitThread();
            };
            Application.ThreadException += uiException;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using WitnessForm form = new(args[2], render);
            if (args.Contains("--prepare-input", StringComparer.Ordinal)) input = form.AttachInputProbe(output, args[2], actual, digest);
            result = 0;
            Application.Run(form);
            if (render.UiFailed) result = 2;
        }
        catch (Exception ex)
        {
            result = 2;
            render?.RecordException("startup_or_message_loop", ex);
            input?.RecordException(ex);
            Console.Error.WriteLine("witness_ui_failed;hresult=" + ex.HResult.ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            if (uiException is not null) Application.ThreadException -= uiException;
            input?.Dispose();
            render?.Returning(result);
        }
        return result;
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
