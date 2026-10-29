using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text.Json;
using TYPEATTR = System.Runtime.InteropServices.ComTypes.TYPEATTR;
using TYPEKIND = System.Runtime.InteropServices.ComTypes.TYPEKIND;

Assembly fixture = Assembly.LoadFrom(Path.GetFullPath(args.Single()));
const BindingFlags Private = BindingFlags.Static | BindingFlags.NonPublic;
Type adapter = fixture.GetType("SessionContractExperiment.ValidatedSendKeys", true)!;
MethodInfo encode = adapter.GetMethod("EncodePairs", Private)!;
MethodInfo validate = adapter.GetMethod("ValidateMethod", Private)!;
Type experiment = fixture.GetType("SessionContractExperiment.BackgroundKeyboardExperiment", true)!;
Type reportType = fixture.GetType("SessionContractExperiment.InputObservation", true)!;
MethodInfo baseline = experiment.GetMethod("RequireBaseline", Private)!;
MethodInfo final = experiment.GetMethod("RequireFinal", Private)!;
int tests = 0;
void Need(bool ok, string name) { if (!ok) throw new Exception(name); tests++; }
object? Invoke(MethodInfo method, params object?[] parameters)
{
    try { return method.Invoke(null, parameters); }
    catch (TargetInvocationException ex) when (ex.InnerException is not null) { throw ex.InnerException; }
}
void Reject(MethodInfo method, params object?[] parameters)
{
    try { Invoke(method, parameters); }
    catch (Exception ex) when (ex.GetType().FullName == "SessionContractExperiment.ExperimentFailure") { tests++; return; }
    throw new Exception("Must reject: " + method.Name);
}

Type backgroundType = fixture.GetType("SessionContractExperiment.BackgroundInputConfiguration", true)!;
MethodInfo prepareBackground = backgroundType.GetMethod("Prepare", Private)!;
MethodInfo checkBackground = backgroundType.GetMethod("RequireEnabled", BindingFlags.Instance | BindingFlags.NonPublic)!;
void CheckBackground(object configuration)
{
    try { checkBackground.Invoke(configuration, null); }
    catch (TargetInvocationException ex) when (ex.InnerException is not null) { throw ex.InnerException; }
}
void RejectBackground(Action action, string stage, int? code = null)
{
    try { action(); }
    catch (Exception error) when (error.GetType().FullName == "SessionContractExperiment.ExperimentFailure")
    {
        const BindingFlags properties = BindingFlags.Instance | BindingFlags.NonPublic;
        Need((string)error.GetType().GetProperty("Stage", properties)!.GetValue(error)! == stage, "background failure stage");
        if (code is not null)
            Need((int)error.GetType().GetProperty("Code", properties)!.GetValue(error)! == code, "background HRESULT preserved");
        return;
    }
    throw new Exception("background configuration must reject");
}
Action<string, object?> IgnoreSettingEvent = (_, _) => { };
{
    int accesses = 0;
    object? disabled = Invoke(prepareBackground, false,
        (Func<object?>)(() => { accesses++; throw new Exception(); }),
        (Action<int>)(_ => { accesses++; throw new Exception(); }),
        (Action<string, object?>)((_, _) => { accesses++; throw new Exception(); }));
    Need(disabled is null && accesses == 0, "ordinary mode never reads/writes/logs optional setting");
}
foreach (int initialSetting in new[] { 0, 1, -1, 2, int.MinValue, int.MaxValue })
{
    int reads = 0, writes = 0; object? actual = initialSetting;
    List<(string Stage, JsonElement Data)> settingEvents = new();
    object prepared = Invoke(prepareBackground, true,
        (Func<object?>)(() => { reads++; return actual; }),
        (Action<int>)(value => { writes++; Need(value == 1, "requested exact LONG 1"); actual = value; }),
        (Action<string, object?>)((stage, details) => settingEvents.Add((stage, JsonSerializer.SerializeToElement(details)))))!;
    Need(reads == 2 && writes == 1, "one initial read, one write, one readback");
    Need(settingEvents.Count == 1 && settingEvents[0].Stage == "sendkeys_background_input_configuration", "preconnect configuration event");
    JsonElement data = settingEvents[0].Data;
    Need(data.GetProperty("initial").GetInt32() == initialSetting && data.GetProperty("requested").GetInt32() == 1 &&
        data.GetProperty("readback").GetInt32() == 1 && data.GetProperty("before_connect").GetBoolean(), "configuration scalar evidence");
    CheckBackground(prepared);
    Need(reads == 3 && writes == 1, "presend recheck only reads");
    Need(settingEvents.Count == 2 && settingEvents[1].Stage == "sendkeys_background_input_presend" &&
        settingEvents[1].Data.GetProperty("readback").GetInt32() == 1, "presend scalar evidence");
}
object?[] wrongLongTypes = { null, false, true, (short)1, (ushort)1, (byte)1, 1L, 1U, 1.0, 1.0m, "1", DayOfWeek.Monday };
foreach (object? wrong in wrongLongTypes)
{
    int writes = 0;
    RejectBackground(() => Invoke(prepareBackground, true, (Func<object?>)(() => wrong), (Action<int>)(_ => writes++), IgnoreSettingEvent),
        "sendkeys_background_input_initial_type_mismatch", unchecked((int)0x80020005));
    Need(writes == 0, "wrong initial Automation type prevents write and input");
    int reads = 0;
    RejectBackground(() => Invoke(prepareBackground, true, (Func<object?>)(() => ++reads == 1 ? 0 : wrong), (Action<int>)(_ => writes++), IgnoreSettingEvent),
        "sendkeys_background_input_readback_type_mismatch", unchecked((int)0x80020005));
    Need(reads == 2 && writes == 1, "wrong readback type is not converted or retried");
}
foreach (int wrong in new[] { 0, -1, 2, int.MinValue, int.MaxValue })
{
    int reads = 0, writes = 0;
    RejectBackground(() => Invoke(prepareBackground, true, (Func<object?>)(() => ++reads == 1 ? 0 : wrong), (Action<int>)(_ => writes++), IgnoreSettingEvent),
        "sendkeys_background_input_not_enabled");
    Need(reads == 2 && writes == 1, "non-one readback rejected without retry");
}
foreach (object? changed in wrongLongTypes.Concat(new object?[] { 0, -1, 2 }))
{
    object? actual = 0; int writes = 0, sends = 0;
    object prepared = Invoke(prepareBackground, true, (Func<object?>)(() => actual),
        (Action<int>)(value => { writes++; actual = value; }), IgnoreSettingEvent)!;
    actual = changed;
    RejectBackground(() => { CheckBackground(prepared); sends++; }, changed is int
        ? "sendkeys_background_input_changed" : "sendkeys_background_input_presend_type_mismatch");
    Need(writes == 1 && sends == 0, "changed setting blocks send; no second write or input fallback");
}
foreach (bool wrapped in new[] { false, true })
{
    const int failureCode = unchecked((int)0x80070005);
    Exception failure = new COMException("synthetic failure", failureCode);
    if (wrapped) failure = new TargetInvocationException(failure);
    int writes = 0;
    RejectBackground(() => Invoke(prepareBackground, true, (Func<object?>)(() => throw failure), (Action<int>)(_ => writes++), IgnoreSettingEvent),
        "sendkeys_background_input_initial_failed", failureCode);
    Need(writes == 0, "failed initial read stops before write");
    int reads = 0;
    RejectBackground(() => Invoke(prepareBackground, true, (Func<object?>)(() => { reads++; return 0; }), (Action<int>)(_ => { writes++; throw failure; }), IgnoreSettingEvent),
        "sendkeys_background_input_set_failed", failureCode);
    Need(reads == 1 && writes == 1, "failed setter is not retried");
    reads = 0; writes = 0;
    RejectBackground(() => Invoke(prepareBackground, true, (Func<object?>)(() => ++reads == 1 ? 0 : throw failure), (Action<int>)(_ => writes++), IgnoreSettingEvent),
        "sendkeys_background_input_readback_failed", failureCode);
    Need(reads == 2 && writes == 1, "failed verification does not repeat setting");
    bool failRead = false; int sends = 0; object? actual = 0;
    object prepared = Invoke(prepareBackground, true, (Func<object?>)(() => failRead ? throw failure : actual),
        (Action<int>)(value => actual = value), IgnoreSettingEvent)!;
    failRead = true;
    RejectBackground(() => { CheckBackground(prepared); sends++; }, "sendkeys_background_input_presend_failed", failureCode);
    Need(sends == 0, "failed presend read stops input");
}

Type guardTraceType = fixture.GetType("SessionContractExperiment.WindowTargetGuardTrace", true)!;
Type guardPredicateType = fixture.GetType("SessionContractExperiment.WindowTargetPredicate", true)!;
const BindingFlags GuardMembers = BindingFlags.Instance | BindingFlags.NonPublic;
MethodInfo traceFailed = guardTraceType.GetMethod("Failed", GuardMembers)!;
MethodInfo traceRecord = guardTraceType.GetMethod("Record", GuardMembers)!;
string[] operandNames = { "owner_thread_matches", "parent_alive", "host_alive", "parent_handle_created",
    "host_handle_created", "parent_handle_matches", "host_handle_matches", "invoke_not_required",
    "host_inside_parent", "control_is_not_parent", "control_inside_host", "parent_visible",
    "control_visible", "control_enabled", "parent_not_iconic", "parent_foreground_matches" };
for (int firstFailure = 1; firstFailure <= 16; firstFailure++)
{
    object trace = Activator.CreateInstance(guardTraceType)!;
    for (int predicate = 1; predicate <= 16; predicate++)
        if ((bool)traceFailed.Invoke(trace, new object[] { predicate == firstFailure || predicate == 16,
            Enum.ToObject(guardPredicateType, predicate) })!) break;
    int logged = 0; JsonElement snapshot = default;
    Action<string, object?> observer = (stage, details) =>
    {
        logged++; Need(stage == "window_input_target_guard_failure", "guard event name");
        snapshot = JsonSerializer.SerializeToElement(details);
    };
    traceRecord.Invoke(trace, new object[] { observer, 3 });
    Need(logged == 1, "one diagnostic for rejected guard");
    Need(snapshot.GetProperty("first_failed_predicate_id").GetInt32() == firstFailure &&
        snapshot.GetProperty("checked_mask").GetUInt32() == (1U << firstFailure) - 1U, "actual first failure and prefix mask");
    Need(snapshot.GetProperty("validation_phase_id").GetInt32() == 3 &&
        snapshot.GetProperty("original_guard_code").GetInt32() == 0 &&
        !snapshot.GetProperty("native_error_code_captured").GetBoolean(), "guard code is not a sampled native error");
    Need(snapshot.GetProperty("focus_observation").GetString() == "not_reached" &&
        snapshot.GetProperty("geometry_observation").GetString() == "not_reached", "later groups are unobserved");
    JsonElement operands = snapshot.GetProperty("operands");
    for (int predicate = 1; predicate <= 16; predicate++)
    {
        JsonElement value = operands.GetProperty(operandNames[predicate - 1]);
        Need(predicate > firstFailure ? value.ValueKind == JsonValueKind.Null :
            value.ValueKind == (predicate == firstFailure ? JsonValueKind.False : JsonValueKind.True), "exact observed operand or null");
    }
    Action<string, object?> failedObserver = (_, _) => throw new InvalidOperationException("synthetic logger failure");
    traceRecord.Invoke(trace, new object[] { failedObserver, 3 });
    Need(true, "diagnostic failure contained");
}
{
    object trace = Activator.CreateInstance(guardTraceType)!;
    for (int predicate = 1; predicate <= 16; predicate++)
        Need(!(bool)traceFailed.Invoke(trace, new object[] { false, Enum.ToObject(guardPredicateType, predicate) })!, "passing predicate remains false in OR guard");
    int logged = 0;
    Action<string, object?> observer = (_, _) => logged++;
    traceRecord.Invoke(trace, new object[] { observer, 3 });
    Need(logged == 0, "successful guard does not log even if Record is requested");
    Need((uint)guardTraceType.GetProperty("CheckedMask", GuardMembers)!.GetValue(trace)! == 65535U, "successful trace evaluated all original operands");
}

for (int scan = 1; scan <= 255; scan++)
{
    var pair = (ValueTuple<short[], int[]>)Invoke(encode, new ushort[] { (ushort)scan })!;
    Need(pair.Item1.SequenceEqual(new short[] { 0, -1 }), "VARIANT_BOOL values");
    Need(pair.Item2[0] == (1 | scan << 16), "down lParam exact");
    Need(unchecked((uint)pair.Item2[1]) == (0xc0000001u | (uint)scan << 16), "up lParam exact");
}
var max = (ValueTuple<short[], int[]>)Invoke(encode, Enumerable.Repeat((ushort)1, 10).ToArray())!;
Need(max.Item1.Length == 20 && max.Item2.Length == 20, "20-entry boundary");
Reject(encode, Array.Empty<ushort>());
Reject(encode, new ushort[] { 0 });
Reject(encode, new ushort[] { 256 });
Reject(encode, new ushort[] { 0xe02a });
Reject(encode, Enumerable.Repeat((ushort)1, 11).ToArray());
Reject(encode, new object?[] { null });

int elementSize = Marshal.SizeOf<ELEMDESC>();
IntPtr parameters = Marshal.AllocHGlobal(elementSize * 3);
IntPtr boolType = Marshal.AllocHGlobal(Marshal.SizeOf<TYPEDESC>());
IntPtr longType = Marshal.AllocHGlobal(Marshal.SizeOf<TYPEDESC>());
try
{
    Marshal.StructureToPtr(new TYPEDESC { vt = (short)VarEnum.VT_BOOL }, boolType, false);
    Marshal.StructureToPtr(new TYPEDESC { vt = (short)VarEnum.VT_I4 }, longType, false);
    ELEMDESC[] valid = {
        new() { tdesc = new() { vt = (short)VarEnum.VT_I4 }, desc = new() { paramdesc = new() { wParamFlags = PARAMFLAG.PARAMFLAG_FIN } } },
        new() { tdesc = new() { vt = (short)VarEnum.VT_PTR, lpValue = boolType }, desc = new() { paramdesc = new() { wParamFlags = PARAMFLAG.PARAMFLAG_FIN } } },
        new() { tdesc = new() { vt = (short)VarEnum.VT_PTR, lpValue = longType }, desc = new() { paramdesc = new() { wParamFlags = PARAMFLAG.PARAMFLAG_FIN } } }
    };
    void Reset() { for (int i = 0; i < 3; i++) Marshal.StructureToPtr(valid[i], IntPtr.Add(parameters, i * elementSize), false); }
    TYPEATTR type = new() { guid = Guid.Parse("2F079C4C-87B2-4AFD-97AB-20CDB43038AE"), typekind = TYPEKIND.TKIND_INTERFACE, cbSizeVft = (short)(32 * IntPtr.Size), cFuncs = 2 };
    FUNCDESC method = new() { cParams = 3, cParamsOpt = 0, invkind = INVOKEKIND.INVOKE_FUNC,
        callconv = CALLCONV.CC_STDCALL, funckind = FUNCKIND.FUNC_PUREVIRTUAL,
        oVft = (short)(15 * IntPtr.Size), elemdescFunc = new() { tdesc = new() { vt = (short)VarEnum.VT_HRESULT } },
        lprgelemdescParam = parameters };
    Reset(); Invoke(validate, type, method); Need(true, "valid method");
    foreach (short count in new short[] { -1, 0, 2, 4 }) { var wrong = method; wrong.cParams = count; Reject(validate, type, wrong); }
    foreach (short offset in new short[] { -1, 0, (short)(2*IntPtr.Size), (short)(15*IntPtr.Size+1), type.cbSizeVft })
    { var wrong = method; wrong.oVft = offset; Reject(validate, type, wrong); }
    { var wrong=method; wrong.cParamsOpt=1; Reject(validate,type,wrong); }
    { var wrong=method; wrong.invkind=INVOKEKIND.INVOKE_PROPERTYGET; Reject(validate,type,wrong); }
    { var wrong=method; wrong.callconv=CALLCONV.CC_CDECL; Reject(validate,type,wrong); }
    { var wrong=method; wrong.funckind=FUNCKIND.FUNC_DISPATCH; Reject(validate,type,wrong); }
    { var wrong=method; wrong.elemdescFunc.tdesc.vt=(short)VarEnum.VT_I4; Reject(validate,type,wrong); }
    { var wrong=method; wrong.lprgelemdescParam=IntPtr.Zero; Reject(validate,type,wrong); }
    for (int i=0;i<3;i++)
    {
        foreach (PARAMFLAG flags in new[] { PARAMFLAG.PARAMFLAG_NONE, PARAMFLAG.PARAMFLAG_FIN|PARAMFLAG.PARAMFLAG_FOUT,
            PARAMFLAG.PARAMFLAG_FIN|PARAMFLAG.PARAMFLAG_FRETVAL, PARAMFLAG.PARAMFLAG_FIN|PARAMFLAG.PARAMFLAG_FOPT })
        {
            Reset(); var wrong=valid[i]; wrong.desc.paramdesc.wParamFlags=flags;
            Marshal.StructureToPtr(wrong,IntPtr.Add(parameters,i*elementSize),false); Reject(validate,type,method);
        }
        Reset(); var width=valid[i];width.tdesc.vt=(short)VarEnum.VT_UI8;
        Marshal.StructureToPtr(width,IntPtr.Add(parameters,i*elementSize),false); Reject(validate,type,method);
    }
    for(int i=1;i<3;i++)
    {
        Reset();var wrong=valid[i];wrong.tdesc.lpValue=IntPtr.Zero;
        Marshal.StructureToPtr(wrong,IntPtr.Add(parameters,i*elementSize),false);Reject(validate,type,method);
        Reset();wrong=valid[i];wrong.tdesc.lpValue=i==1?longType:boolType;
        Marshal.StructureToPtr(wrong,IntPtr.Add(parameters,i*elementSize),false);Reject(validate,type,method);
    }
}
finally { Marshal.FreeHGlobal(parameters);Marshal.FreeHGlobal(boolType);Marshal.FreeHGlobal(longType); }

void Set(object target,string name,object value)=>reportType.GetProperty(name)!.SetValue(target,value);
object Make(int count,long sequence)
{
    object report=Activator.CreateInstance(reportType)!;
    foreach(string name in new[]{"Shown","WindowVisible","ForegroundOwn","FocusOwn","DesktopInputQuerySucceeded","DesktopReceivesInput","PhysicalEqualsLogical","CursorQuerySucceeded"})Set(report,name,true);
    foreach(string name in new[]{"CharacterCount","KeyDownCount","KeyUpCount"})Set(report,name,count);
    Set(report,"CharacterLimit",16);Set(report,"LeftDownCount",1);Set(report,"LeftUpCount",1);Set(report,"Sequence",sequence);
    Set(report,"MonitorCount",1);Set(report,"ReceivedHex",count==8?"12345678":"1234567801928374");
    return report;
}
object initial=Make(8,10),complete=Make(16,15);
Invoke(baseline,initial);Need(true,"valid baseline");Invoke(final,complete,initial,"1234567801928374");Need(true,"valid final receipt");
foreach(string name in new[]{"Shown","WindowVisible","ForegroundOwn","FocusOwn","DesktopInputQuerySucceeded","DesktopReceivesInput","CursorQuerySucceeded"})
{object value=Make(16,15);Set(value,name,false);Reject(final,value,initial,"1234567801928374");}
foreach(string name in new[]{"CharacterCount","KeyDownCount","KeyUpCount","CharacterLimit"})
{foreach(int value in new[]{0,7,8,15,17}){object report=Make(16,15);Set(report,name,value);Reject(final,report,initial,"1234567801928374");}}
foreach(string name in new[]{"UnexpectedCharacters","RepeatedCharacters","OverflowCharacters","UnexpectedButtons","SystemCharacters"})
{object value=Make(16,15);Set(value,name,1);Reject(final,value,initial,"1234567801928374");}
foreach(long value in new[]{0L,9L,10L}){object report=Make(16,value);Reject(final,report,initial,"1234567801928374");}
{object report=Make(16,15);Set(report,"ReceivedHex","1234567899999999");Reject(final,report,initial,"1234567801928374");}
{object report=Make(16,15);Set(report,"Closed",true);Reject(final,report,initial,"1234567801928374");}
foreach(string name in new[]{"LeftDownCount","LeftUpCount"}){object report=Make(16,15);Set(report,name,2);Reject(final,report,initial,"1234567801928374");}
{object report=Make(16,15);Set(report,"MonitorCount",2);Reject(final,report,initial,"1234567801928374");}
{object report=Make(16,15);Set(report,"PhysicalEqualsLogical",false);Reject(final,report,initial,"1234567801928374");}

// Execute the actual optional witness diagnostics without a window or Windows API.
Type keyTraceType = fixture.GetType("SessionContractExperiment.KeyUpDiagnosticTrace", true)!;
Type failureDiagnostics = fixture.GetType("SessionContractExperiment.SendKeysFailureDiagnostics", true)!;
MethodInfo createKeyTrace = keyTraceType.GetMethod("TryCreate", Private)!;
MethodInfo observeKeyUp = keyTraceType.GetMethod("Observe", BindingFlags.Instance | BindingFlags.NonPublic)!;
MethodInfo snapshotKeyUp = keyTraceType.GetMethod("Snapshot", BindingFlags.Instance | BindingFlags.NonPublic)!;
MethodInfo recordFailure = failureDiagnostics.GetMethod("Record", Private)!;
JsonSerializerOptions diagnosticJson = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
object NewKeyTrace() => Invoke(createKeyTrace)!;
void ObserveKey(object trace, int message, int ordinal, long key, long packed) =>
    observeKeyUp.Invoke(trace, new object[] { message, ordinal, key, packed });
JsonElement KeySnapshot(object trace) => (JsonElement)snapshotKeyUp.Invoke(trace, null)!;
JsonElement FailureSnapshot(object? report, string? expected, long? before, int calls)
{
    int records = 0; JsonElement result = default;
    Action<string, object?> capture = (stage, details) =>
    {
        records++; Need(stage == "sendkeys_failure_diagnostic", "failure diagnostic event name");
        result = JsonSerializer.SerializeToElement(details, diagnosticJson);
    };
    Invoke(recordFailure, capture, report, expected, before, calls);
    Need(records == 1, "one best-effort diagnostic record");
    return result;
}
{
    object trace = NewKeyTrace();
    ObserveKey(trace, 0x100, 1, 0x31, 0xC0020001L);
    Need(KeySnapshot(trace).GetProperty("stored").GetInt32() == 0, "non-keyup ignored");
    for (int digit = 0; digit < 10; digit++)
        ObserveKey(trace, 0x101, digit + 1, 0x30 + digit, 0xC0000001L | ((digit + 2L) << 16));
    foreach (JsonElement item in KeySnapshot(trace).GetProperty("entries").EnumerateArray())
    {
        Need(item.GetProperty("virtual_key").ValueKind == JsonValueKind.Null &&
            item.GetProperty("scan_code").ValueKind == JsonValueKind.Null, "digit VK and scan redacted at source");
        Need(item.GetProperty("key_category").GetInt32() == 1 && item.GetProperty("repeat_count").GetInt32() == 1 &&
            item.GetProperty("previous_state").GetBoolean() && item.GetProperty("transition").GetBoolean(), "digit flags only");
    }
    ObserveKey(trace, 0x105, 11, 0x12, 0xFF38FFFFL);
    JsonElement modifier = KeySnapshot(trace).GetProperty("entries")[10];
    Need(modifier.GetProperty("virtual_key").GetInt32() == 0x12 && modifier.GetProperty("scan_code").GetInt32() == 0x38,
        "allowlisted modifier codes preserved");
    Need(modifier.GetProperty("system_message").GetBoolean() && modifier.GetProperty("repeat_count").GetInt32() == 65535 &&
        modifier.GetProperty("extended").GetBoolean() && modifier.GetProperty("reserved_bits").GetInt32() == 15 &&
        modifier.GetProperty("context").GetBoolean() && modifier.GetProperty("previous_state").GetBoolean() &&
        modifier.GetProperty("transition").GetBoolean(), "exact bounded keyup flag projection");
    for (int i = 11; i < 1000; i++) ObserveKey(trace, 0x101, i + 1, 0x41, 0xC01E0001L);
    JsonElement full = KeySnapshot(trace);
    Need(full.GetProperty("stored").GetInt32() == 32 && full.GetProperty("entries").GetArrayLength() == 32 &&
        full.GetProperty("dropped").GetInt32() == 968, "fixed capacity with visible dropped count");
    Need(System.Text.Encoding.UTF8.GetByteCount(full.GetRawText()) < 16000, "bounded full JSON size");
    keyTraceType.GetField("dropped", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(trace, int.MaxValue - 1);
    ObserveKey(trace, 0x101, 1001, 0x41, 0); ObserveKey(trace, 0x101, 1002, 0x41, 0);
    Need(KeySnapshot(trace).GetProperty("dropped").GetInt32() == int.MaxValue, "dropped count saturates");
    foreach (JsonElement item in full.GetProperty("entries").EnumerateArray().Skip(11))
        Need(item.GetProperty("virtual_key").ValueKind == JsonValueKind.Null &&
            item.GetProperty("scan_code").ValueKind == JsonValueKind.Null, "unknown and printable codes redacted");
}
foreach (int key in new[] { 0x10, 0x11, 0x12, 0x5B, 0x5C, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x14, 0x90, 0x91 })
{
    object trace = NewKeyTrace(); ObserveKey(trace, 0x101, 1, key, 0xC02A0001L);
    Need(KeySnapshot(trace).GetProperty("entries")[0].GetProperty("virtual_key").GetInt32() == key,
        "explicit modifier or lock allowlist");
}
{
    object trace = NewKeyTrace(); ObserveKey(trace, 0x101, 1, 0x10, 0xC0020001L);
    JsonElement item = KeySnapshot(trace).GetProperty("entries")[0];
    Need(item.GetProperty("virtual_key").GetInt32() == 0x10 && item.GetProperty("scan_code").ValueKind == JsonValueKind.Null,
        "modifier VK never authorizes a printable scan at the witness");
    object report = Make(16, 15);
    Set(report, "KeyUpDiagnostics", JsonDocument.Parse("""{"stored":1,"dropped":0,"entries":[{"ordinal":1,"key_category":2,"virtual_key":16,"scan_code":2}]}""").RootElement.Clone());
    JsonElement projected = FailureSnapshot(report, "1234567801928374", 10L, 1).GetProperty("key_up_entries")[0];
    Need(projected.GetProperty("virtual_key").GetInt32() == 0x10 && projected.GetProperty("scan_code").ValueKind == JsonValueKind.Null,
        "modifier VK never authorizes a printable scan at the parent");
}
foreach (long key in new[] { -1L, 0x20L, 0x41L, 0x60L, 0x69L, 0xFFL, 0x100L, long.MinValue, long.MaxValue })
{
    object trace = NewKeyTrace(); ObserveKey(trace, 0x101, 1, key, 0xC01E0001L);
    JsonElement item = KeySnapshot(trace).GetProperty("entries")[0];
    Need(item.GetProperty("virtual_key").ValueKind == JsonValueKind.Null && item.GetProperty("scan_code").ValueKind == JsonValueKind.Null,
        "numpad and all other non-allowlisted values redacted");
}
{
    JsonElement equal = FailureSnapshot(complete, "1234567801928374", 10L, 1);
    Need(equal.GetProperty("expected_text_comparison_performed").GetBoolean() &&
        equal.GetProperty("expected_text_equals").GetBoolean() && !equal.GetProperty("comparison_is_acceptance").GetBoolean(),
        "fresh exact equality is diagnostic only");
    JsonElement different = FailureSnapshot(complete, "9999999999999999", 10L, 1);
    Need(!different.GetProperty("expected_text_equals").GetBoolean() &&
        !different.GetRawText().Contains("9999999999999999") && !different.GetRawText().Contains("1234567801928374"),
        "only equality boolean, no expected or received text");
    foreach (var sample in new (object? Report, string? Expected, long? Before, int Calls)[] {
        (null,"1234567801928374",10L,1), (complete,null,10L,1), (complete,"1234567801928374",null,1),
        (complete,"1234567801928374",15L,1), (complete,"1234567801928374",16L,1),
        (complete,"1234567801928374",10L,0), (complete,"1234567801928374",10L,2) })
    {
        JsonElement result = FailureSnapshot(sample.Report, sample.Expected, sample.Before, sample.Calls);
        Need(!result.GetProperty("expected_text_comparison_performed").GetBoolean() &&
            result.GetProperty("expected_text_equals").ValueKind == JsonValueKind.Null, "old or unavailable receipt is not a mismatch");
    }
    Invoke(recordFailure, (Action<string, object?>)((_, _) => throw new Exception("synthetic logger failure")), complete,
        "1234567801928374", 10L, 1);
    Need(true, "logger failure cannot replace original experiment failure");
}
{
    Type inputReport = fixture.GetType("SessionContractExperiment.InputReport", true)!;
    MethodInfo readReport = inputReport.GetMethod("Read", Private)!;
    object receipt = Make(16, 15);
    Set(receipt, "Nonce", "local-test-binding"); Set(receipt, "SessionId", 1U); Set(receipt, "IdentityDigest", "local-test-digest");
    string normalJson = JsonSerializer.Serialize(receipt, reportType, diagnosticJson);
    Need(!normalJson.Contains("key_up_diagnostics"), "ordinary absent diagnostics do not change JSON shape");
    string path = Path.GetTempFileName();
    try
    {
        foreach (string malformed in new[] { "42", "\"untrusted-text-not-to-log\"", "[]", "{}",
            "{\"stored\":1,\"dropped\":0,\"entries\":[{\"ordinal\":\"untrusted-text-not-to-log\"}]}",
            "{\"stored\":1,\"dropped\":0,\"entries\":[{\"ordinal\":1,\"key_category\":2,\"virtual_key\":49,\"scan_code\":2}]}" })
        {
            Set(receipt, "KeyUpDiagnostics", JsonDocument.Parse(malformed).RootElement.Clone());
            File.WriteAllText(path, JsonSerializer.Serialize(receipt, reportType, diagnosticJson));
            object parsed = Invoke(readReport, path, "local-test-binding", 1U, "local-test-digest")!;
            Invoke(final, parsed, initial, "1234567801928374");
            Need(true, "malformed optional metadata is never an acceptance or parsing gate");
            JsonElement result = FailureSnapshot(parsed, "1234567801928374", 10L, 1);
            Need(!result.GetRawText().Contains("untrusted-text-not-to-log"), "malformed strings are not logged");
            foreach (JsonElement entry in result.GetProperty("key_up_entries").EnumerateArray())
                Need(entry.GetProperty("virtual_key").ValueKind == JsonValueKind.Null &&
                    entry.GetProperty("scan_code").ValueKind == JsonValueKind.Null, "untrusted category cannot unredact a digit");
        }
        string entries = string.Join(",", Enumerable.Repeat("{\"ordinal\":1,\"key_category\":3,\"virtual_key\":65,\"scan_code\":30}", 100));
        Set(receipt, "KeyUpDiagnostics", JsonDocument.Parse("{\"stored\":100,\"dropped\":0,\"entries\":[" + entries + "]}").RootElement.Clone());
        JsonElement bounded = FailureSnapshot(receipt, "1234567801928374", 10L, 1);
        Need(bounded.GetProperty("key_up_entries").GetArrayLength() == 32 &&
            bounded.GetProperty("key_up_metadata_truncated").GetBoolean() && bounded.GetProperty("key_up_metadata_malformed").GetBoolean(),
            "failure projection bounds untrusted arrays too");
        Need(System.Text.Encoding.UTF8.GetByteCount(bounded.GetRawText()) < 16000, "public failure JSON remains bounded");
        // Metadata must not soften the existing extra-release rejection.
        Set(receipt, "KeyUpCount", 17);
        Reject(final, receipt, initial, "1234567801928374");
    }
    finally { File.Delete(path); }
}
Console.WriteLine(JsonSerializer.Serialize(new{schema="sendkeys-local-contracts/v1",passed=true,checks=tests,actual_compiled_harness=true,windows_api_executed=false}));
