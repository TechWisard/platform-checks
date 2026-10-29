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
Console.WriteLine(JsonSerializer.Serialize(new{schema="sendkeys-local-contracts/v1",passed=true,checks=tests,actual_compiled_harness=true,windows_api_executed=false}));
