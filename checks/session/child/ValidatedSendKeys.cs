using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using FUNCDESC = System.Runtime.InteropServices.ComTypes.FUNCDESC;
using TYPEATTR = System.Runtime.InteropServices.ComTypes.TYPEATTR;
using TYPEKIND = System.Runtime.InteropServices.ComTypes.TYPEKIND;

namespace SessionContractExperiment;

// A single documented keyboard method on a separately queried interface.
// The installed type library supplies its slot; no inherited vtable layout is
// guessed. This helper never calls SendInput, changes focus, or injects a mouse.
internal sealed class ValidatedSendKeys : IDisposable
{
    internal static readonly Guid InterfaceId = new("2F079C4C-87B2-4AFD-97AB-20CDB43038AE");
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SendCall(IntPtr self, int count, IntPtr keyUp, IntPtr keyData);
    private IntPtr instance;
    private readonly SendCall send;
    private readonly uint thread = InputNative.GetCurrentThreadId();
    internal int Calls { get; private set; }
    internal int Entries { get; private set; }
    internal int? Hresult { get; private set; }
    internal bool Released { get; private set; }

    internal ValidatedSendKeys(object control, Action<string, object?> record)
    {
        int offset = -1;
        int vtableBytes = 0;
        ITypeLib? library = null;
        ITypeInfo? info = null;
        try
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "mstscax.dll");
            Marshal.ThrowExceptionForHR(Native.LoadTypeLibEx(path, 2, out library));
            Guid iid = InterfaceId;
            library.GetTypeInfoOfGuid(ref iid, out info);
            info.GetTypeAttr(out IntPtr attribute);
            try
            {
                TYPEATTR type = Marshal.PtrToStructure<TYPEATTR>(attribute);
                if (type.guid != InterfaceId || type.typekind != TYPEKIND.TKIND_INTERFACE ||
                    type.cFuncs is < 1 or > 64 || type.cbSizeVft < 3 * IntPtr.Size || type.cbSizeVft > 4096)
                    throw new ExperimentFailure("sendkeys_interface_type_mismatch");
                vtableBytes = type.cbSizeVft;
                for (int index = 0; index < type.cFuncs; index++)
                {
                    info.GetFuncDesc(index, out IntPtr descriptor);
                    try
                    {
                        FUNCDESC method = Marshal.PtrToStructure<FUNCDESC>(descriptor);
                        info.GetDocumentation(method.memid, out string name, out _, out _, out _);
                        if (name != "SendKeys") continue;
                        if (offset >= 0) throw new ExperimentFailure("sendkeys_duplicate_method");
                        ValidateMethod(type, method);
                        offset = method.oVft;
                    }
                    finally { info.ReleaseFuncDesc(descriptor); }
                }
            }
            finally { info.ReleaseTypeAttr(attribute); }
        }
        finally
        {
            if (info is not null) Marshal.ReleaseComObject(info);
            if (library is not null) Marshal.ReleaseComObject(library);
        }
        if (offset < 0) throw new ExperimentFailure("sendkeys_method_missing");
        IntPtr unknown = Marshal.GetIUnknownForObject(control);
        try
        {
            Guid iid = InterfaceId;
            int result = Marshal.QueryInterface(unknown, ref iid, out instance);
            if (result != 0 || instance == IntPtr.Zero)
                throw new ExperimentFailure("sendkeys_query_interface_failed", result);
            IntPtr table = Marshal.ReadIntPtr(instance);
            if (table == IntPtr.Zero) throw new ExperimentFailure("sendkeys_null_vtable");
            IntPtr entry = Marshal.ReadIntPtr(table, offset);
            if (entry == IntPtr.Zero) throw new ExperimentFailure("sendkeys_null_method");
            send = Marshal.GetDelegateForFunctionPointer<SendCall>(entry);
            record("sendkeys_contract_verified", new { interface_id = InterfaceId,
                vtable_offset = offset, vtable_bytes = vtableBytes, parameters = 3,
                key_up_element_bytes = sizeof(short), key_data_element_bytes = sizeof(int),
                maximum_entries_per_call = 20, input_called = false });
        }
        catch { Dispose(); throw; }
        finally { Marshal.Release(unknown); }
    }

    // Kept independent of COM invocation so malformed metadata can be rejected
    // in contract tests before it ever becomes a callable function pointer.
    internal static void ValidateMethod(TYPEATTR type, FUNCDESC method)
    {
        if (method.cParams != 3 || method.cParamsOpt != 0 ||
            method.invkind != INVOKEKIND.INVOKE_FUNC || method.callconv != CALLCONV.CC_STDCALL ||
            method.funckind is not FUNCKIND.FUNC_PUREVIRTUAL and not FUNCKIND.FUNC_VIRTUAL ||
            method.elemdescFunc.tdesc.vt != (short)VarEnum.VT_HRESULT ||
            method.oVft < 3 * IntPtr.Size || method.oVft % IntPtr.Size != 0 ||
            method.oVft + IntPtr.Size > type.cbSizeVft || method.lprgelemdescParam == IntPtr.Zero)
            throw new ExperimentFailure("sendkeys_method_signature_mismatch");
        for (int i = 0; i < 3; i++)
        {
            ELEMDESC parameter = Marshal.PtrToStructure<ELEMDESC>(IntPtr.Add(method.lprgelemdescParam,
                checked(i * Marshal.SizeOf<ELEMDESC>())));
            PARAMFLAG flags = parameter.desc.paramdesc.wParamFlags;
            if ((flags & PARAMFLAG.PARAMFLAG_FIN) == 0 ||
                (flags & (PARAMFLAG.PARAMFLAG_FOUT | PARAMFLAG.PARAMFLAG_FRETVAL | PARAMFLAG.PARAMFLAG_FOPT)) != 0)
                throw new ExperimentFailure("sendkeys_parameter_direction_mismatch");
            if (i == 0)
            {
                if (parameter.tdesc.vt != (short)VarEnum.VT_I4)
                    throw new ExperimentFailure("sendkeys_count_width_mismatch");
            }
            else
            {
                if (parameter.tdesc.vt != (short)VarEnum.VT_PTR || parameter.tdesc.lpValue == IntPtr.Zero ||
                    Marshal.PtrToStructure<TYPEDESC>(parameter.tdesc.lpValue).vt !=
                        (short)(i == 1 ? VarEnum.VT_BOOL : VarEnum.VT_I4))
                    throw new ExperimentFailure("sendkeys_array_element_mismatch");
            }
        }
    }

    internal static (short[] Up, int[] Data) EncodePairs(ushort[] scans)
    {
        if (scans is null || scans.Length is < 1 or > 10) throw new ExperimentFailure("sendkeys_entry_count_out_of_range");
        short[] up = new short[scans.Length * 2];
        int[] data = new int[up.Length];
        for (int i = 0; i < scans.Length; i++)
        {
            if (scans[i] is 0 or > 0xff) throw new ExperimentFailure("sendkeys_nonextended_scan_required");
            int down = 1 | (scans[i] << 16);
            up[2 * i] = 0; up[2 * i + 1] = -1; // VARIANT_FALSE / VARIANT_TRUE.
            data[2 * i] = down;
            data[2 * i + 1] = unchecked(down | (int)0xc0000000u);
        }
        return (up, data);
    }

    internal void SendEightDigits(string digits, IntPtr layout)
    {
        if (instance == IntPtr.Zero || Released || thread != InputNative.GetCurrentThreadId() || Calls != 0)
            throw new ExperimentFailure("sendkeys_single_sta_call_required");
        if (digits.Length != 8 || layout == IntPtr.Zero) throw new ExperimentFailure("sendkeys_challenge_shape_invalid");
        ushort[] scans = new ushort[digits.Length];
        for (int i = 0; i < scans.Length; i++)
        {
            char digit = digits[i];
            if (digit is < '0' or > '9') throw new ExperimentFailure("sendkeys_decimal_digit_required");
            short key = WindowInputNative.VkKeyScanExW(digit, layout);
            uint scan = WindowInputNative.MapVirtualKeyExW(digit, 4, layout);
            if (key != digit || scan is 0 or > 0xff)
                throw new ExperimentFailure("sendkeys_digit_layout_requires_modifier");
            scans[i] = checked((ushort)scan);
        }
        var batch = EncodePairs(scans);
        GCHandle up = GCHandle.Alloc(batch.Up, GCHandleType.Pinned);
        try
        {
            GCHandle data = GCHandle.Alloc(batch.Data, GCHandleType.Pinned);
            try
            {
                Calls = 1; Entries = batch.Up.Length;
                Hresult = send(instance, Entries, up.AddrOfPinnedObject(), data.AddrOfPinnedObject());
                if (Hresult != 0) throw new ExperimentFailure("sendkeys_call_failed", Hresult.Value);
            }
            finally { data.Free(); }
        }
        finally { up.Free(); }
    }

    public void Dispose()
    {
        if (instance != IntPtr.Zero)
        {
            IntPtr owned = instance; instance = IntPtr.Zero;
            Marshal.Release(owned);
        }
        Released = true;
    }
}
