using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using FUNCDESC = System.Runtime.InteropServices.ComTypes.FUNCDESC;
using TYPEATTR = System.Runtime.InteropServices.ComTypes.TYPEATTR;
using TYPEKIND = System.Runtime.InteropServices.ComTypes.TYPEKIND;
using ELEMDESC = System.Runtime.InteropServices.ComTypes.ELEMDESC;
using PARAMFLAG = System.Runtime.InteropServices.ComTypes.PARAMFLAG;
using FUNCKIND = System.Runtime.InteropServices.ComTypes.FUNCKIND;
using INVOKEKIND = System.Runtime.InteropServices.ComTypes.INVOKEKIND;

namespace SessionContractExperiment;

// Event-only diagnostics. No credentials, certificate data, usernames, free-form
// server messages, authentication changes or UI responses are received here.
internal sealed class RdpConnectionEvents : IDisposable
{
    // Microsoft: IMsTscAxEvents event dispinterface, mstscax.dll.
    private static readonly Guid EventInterfaceId = new("336D5562-EFA8-482E-8CB3-C5C0FC7A7DB6");
    private sealed record Spec(string Name, int Dispid, bool Numeric, bool Required = true);
    private static readonly Spec[] Specifications = {
        new("OnConnecting", 1, false),
        new("OnConnected", 2, false),
        new("OnLoginComplete", 3, false),
        new("OnDisconnected", 4, true),
        new("OnFatalError", 10, true),
        new("OnWarning", 11, true),
        new("OnLogonError", 22, true),
        new("OnAuthenticationWarningDisplayed", 18, false, false),
        new("OnAuthenticationWarningDismissed", 19, false, false)
    };
    private sealed record Observed(string Name, int Dispid, int? Code, bool DuringCleanup);
    private sealed record Failure(string Stage, int Code);
    private sealed record Binding(int Dispid, Delegate Handler);
    private const int MaximumEvents = 256;
    private readonly object control;
    private readonly Action<string, object?> record;
    private readonly int ownerThread = Environment.CurrentManagedThreadId;
    private readonly List<Binding> bindings = new(Specifications.Length);
    private readonly ConcurrentQueue<Observed> pending = new();
    private Failure? failure;
    private int totalEvents;
    private int armed;
    private int cleaning;
    private int disposed;
    private int connecting;
    private int connected;
    private int loggedOn;

    internal bool ConnectingSeen => Volatile.Read(ref connecting) != 0;
    internal bool ConnectedSeen => Volatile.Read(ref connected) != 0;
    internal bool LoginCompleteSeen => Volatile.Read(ref loggedOn) != 0;
    internal int EventCount => Volatile.Read(ref totalEvents);

    internal RdpConnectionEvents(object control, Action<string, object?> record)
    {
        this.control = control; this.record = record;
        Dictionary<string, Spec> verified = ReadAndVerifyTypeLibrary(record);
        Guid iid = EventInterfaceId;
        ((IConnectionPointContainer)control).FindConnectionPoint(ref iid, out IConnectionPoint? point);
        if (point is null) throw new ExperimentFailure("rdp_events_connection_point_missing");
        try
        {
            point.GetConnectionInterface(out Guid actual);
            if (actual != EventInterfaceId) throw new ExperimentFailure("rdp_events_wrong_connection_point");
        }
        finally { Marshal.ReleaseComObject(point); }
        try
        {
            foreach (Spec spec in Specifications)
            {
                if (!verified.ContainsKey(spec.Name)) continue;
                Delegate callback = spec.Numeric
                    ? new Action<int>(code => Receive(spec, code))
                    : new Action(() => Receive(spec, null));
                ComEventsHelper.Combine(control, EventInterfaceId, spec.Dispid, callback);
                bindings.Add(new Binding(spec.Dispid, callback));
                record("rdp_event_subscribed", new { stage = spec.Name, dispid = spec.Dispid });
            }
        }
        catch
        {
            // Keep the original failure but still attempt every completed
            // subscription's removal. Removal failures are explicitly recorded.
            RemoveSubscriptions(throwOnFailure: false);
            throw;
        }
    }

    private static Dictionary<string, Spec> ReadAndVerifyTypeLibrary(Action<string, object?> record)
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "mstscax.dll");
        Marshal.ThrowExceptionForHR(Native.LoadTypeLibEx(path, 2 /* REGKIND_NONE */, out ITypeLib library));
        ITypeInfo? info = null;
        Dictionary<string, Spec> found = new(StringComparer.Ordinal);
        try
        {
            Guid iid = EventInterfaceId;
            library.GetTypeInfoOfGuid(ref iid, out info);
            info.GetTypeAttr(out IntPtr attribute);
            try
            {
                TYPEATTR type = Marshal.PtrToStructure<TYPEATTR>(attribute);
                if (type.guid != EventInterfaceId || type.typekind != TYPEKIND.TKIND_DISPATCH ||
                    type.cFuncs < 7 || type.cFuncs > 256)
                    throw new ExperimentFailure("rdp_events_unexpected_dispinterface");
                for (int i = 0; i < type.cFuncs; i++)
                {
                    info.GetFuncDesc(i, out IntPtr descriptor);
                    try
                    {
                        FUNCDESC method = Marshal.PtrToStructure<FUNCDESC>(descriptor);
                        info.GetDocumentation(method.memid, out string name, out _, out _, out _);
                        Spec? spec = Specifications.FirstOrDefault(item => item.Name == name);
                        if (spec is null) continue;
                        record("rdp_event_type_member", new { stage = name, dispid = method.memid,
                            parameters = method.cParams, return_type = method.elemdescFunc.tdesc.vt,
                            invocation = method.invkind.ToString(), function_kind = method.funckind.ToString() });
                        if (method.memid != spec.Dispid || method.cParams != (spec.Numeric ? 1 : 0) ||
                            method.cParamsOpt != 0 || method.invkind != INVOKEKIND.INVOKE_FUNC ||
                            method.funckind != FUNCKIND.FUNC_DISPATCH ||
                            method.elemdescFunc.tdesc.vt != (short)VarEnum.VT_VOID)
                            throw new ExperimentFailure("rdp_events_unexpected_event_signature");
                        if (spec.Numeric)
                        {
                            if (method.lprgelemdescParam == IntPtr.Zero)
                                throw new ExperimentFailure("rdp_events_missing_numeric_parameter");
                            ELEMDESC parameter = Marshal.PtrToStructure<ELEMDESC>(method.lprgelemdescParam);
                            PARAMFLAG flags = parameter.desc.paramdesc.wParamFlags;
                            if (parameter.tdesc.vt != (short)VarEnum.VT_I4 ||
                                (flags & PARAMFLAG.PARAMFLAG_FIN) == 0 ||
                                (flags & (PARAMFLAG.PARAMFLAG_FOUT | PARAMFLAG.PARAMFLAG_FRETVAL | PARAMFLAG.PARAMFLAG_FOPT)) != 0)
                                throw new ExperimentFailure("rdp_events_unexpected_numeric_parameter");
                        }
                        if (!found.TryAdd(name, spec)) throw new ExperimentFailure("rdp_events_duplicate_type_member");
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
        if (Specifications.Any(spec => spec.Required && !found.ContainsKey(spec.Name)))
            throw new ExperimentFailure("rdp_events_required_type_member_missing");
        return found;
    }

    // Call immediately before Connect(). The handler never makes a reentrant
    // COM call or throws into the control: it records data and marks a failure.
    internal void Arm()
    {
        RequireOwner();
        if (Volatile.Read(ref cleaning) != 0) throw new ExperimentFailure("rdp_events_already_cleaning");
        Volatile.Write(ref armed, 1);
    }

    private void Receive(Spec spec, int? code)
    {
        if (Volatile.Read(ref disposed) != 0) return;
        try
        {
            int count = Interlocked.Increment(ref totalEvents);
            if (count > MaximumEvents)
            {
                Interlocked.CompareExchange(ref failure, new Failure("rdp_events_limit_exceeded", count), null);
                return;
            }
            bool duringCleanup = Volatile.Read(ref cleaning) != 0;
            pending.Enqueue(new Observed(spec.Name, spec.Dispid, code, duringCleanup));
            // Numeric/static data only, also visible if Connect() blocks before
            // returning to the caller's polling loop or evidence drain.
            Console.WriteLine("RDP_EVENT stage=" + spec.Name + ";dispid=" + spec.Dispid +
                ";code=" + (code?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "none") +
                ";cleanup=" + (duringCleanup ? "1" : "0"));
            if (spec.Name == "OnConnecting") Interlocked.Exchange(ref connecting, 1);
            if (spec.Name == "OnConnected") Interlocked.Exchange(ref connected, 1);
            if (spec.Name == "OnLoginComplete") Interlocked.Exchange(ref loggedOn, 1);
            if (duringCleanup || Volatile.Read(ref armed) == 0) return;
            Failure? terminal = spec.Name switch {
                "OnDisconnected" => new Failure("rdp_disconnected_before_acceptance", code!.Value),
                "OnFatalError" => new Failure("rdp_control_fatal_error", code!.Value),
                "OnLogonError" => ClassifyLogon(code!.Value),
                "OnAuthenticationWarningDisplayed" => new Failure("rdp_authentication_dialog_required", 0),
                _ => null
            };
            if (terminal is not null) Interlocked.CompareExchange(ref failure, terminal, null);
        }
        catch (Exception ex)
        {
            Interlocked.CompareExchange(ref failure, new Failure("rdp_event_callback_failed", ex.HResult), null);
        }
    }

    private static Failure? ClassifyLogon(int code) => code switch {
        // Microsoft: these are progress/warning notifications, not failures.
        -2 or 3 => null,
        // Windows requires UI interaction or is terminating this logon.
        -3 or -4 or -5 or -6 or -7 => new Failure("rdp_logon_interaction_or_termination", code),
        // Code 0 is LOGON_FAILED_BAD_PASSWORD, not success.
        -1 or 0 or 1 or 2 => new Failure("rdp_logon_failed", code),
        unchecked((int)0xC000006D) or unchecked((int)0xC000006E) or unchecked((int)0xC0000224)
            => new Failure("rdp_logon_failed", code),
        // The published list is non-exhaustive. Unknown values remain evidence;
        // do not invent an interpretation or suppress a later fatal/disconnect.
        _ => null
    };

    internal void Drain()
    {
        RequireOwner();
        while (pending.TryDequeue(out Observed? item))
            record("rdp_connection_event", new { stage = item.Name, dispid = item.Dispid,
                code = item.Code, cleanup = item.DuringCleanup });
    }

    internal void ThrowIfConnectionFailed()
    {
        Drain();
        Failure? observed = Volatile.Read(ref failure);
        if (observed is not null) throw new ExperimentFailure(observed.Stage, observed.Code);
    }

    // Call before deliberate logoff/disconnect so expected cleanup events do not
    // turn a previously successful functional result into a false connection error.
    internal void BeginCleanup()
    {
        RequireOwner();
        Volatile.Write(ref cleaning, 1);
        Volatile.Write(ref armed, 0);
        Drain();
    }

    private void RequireOwner()
    {
        if (Environment.CurrentManagedThreadId != ownerThread)
            throw new ExperimentFailure("rdp_events_wrong_apartment_thread");
        if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException(nameof(RdpConnectionEvents));
    }

    private void RemoveSubscriptions(bool throwOnFailure)
    {
        int? removalError = null;
        for (int i = bindings.Count - 1; i >= 0; i--)
        {
            Binding binding = bindings[i];
            try
            {
                Delegate? removed = ComEventsHelper.Remove(control, EventInterfaceId, binding.Dispid, binding.Handler);
                if (removed is null) throw new ExperimentFailure("rdp_event_subscription_not_found", binding.Dispid);
                record("rdp_event_unsubscribed", new { dispid = binding.Dispid });
            }
            catch (Exception ex)
            {
                int code = ex is ExperimentFailure failure ? failure.Code : ex.HResult;
                removalError ??= code;
                record("rdp_event_unsubscribe_failed", new { dispid = binding.Dispid, code });
            }
        }
        bindings.Clear();
        Volatile.Write(ref disposed, 1);
        if (throwOnFailure && removalError.HasValue)
            throw new ExperimentFailure("rdp_events_unadvise_failed", removalError.Value);
    }

    public void Dispose()
    {
        if (Volatile.Read(ref disposed) != 0) return;
        BeginCleanup();
        RemoveSubscriptions(throwOnFailure: true);
    }
}
