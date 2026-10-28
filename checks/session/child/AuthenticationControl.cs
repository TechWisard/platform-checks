using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security;
using CALLCONV = System.Runtime.InteropServices.ComTypes.CALLCONV;
using ELEMDESC = System.Runtime.InteropServices.ComTypes.ELEMDESC;
using FUNCDESC = System.Runtime.InteropServices.ComTypes.FUNCDESC;
using FUNCKIND = System.Runtime.InteropServices.ComTypes.FUNCKIND;
using INVOKEKIND = System.Runtime.InteropServices.ComTypes.INVOKEKIND;
using PARAMFLAG = System.Runtime.InteropServices.ComTypes.PARAMFLAG;
using TYPEATTR = System.Runtime.InteropServices.ComTypes.TYPEATTR;
using TYPEDESC = System.Runtime.InteropServices.ComTypes.TYPEDESC;
using TYPEKIND = System.Runtime.InteropServices.ComTypes.TYPEKIND;

namespace SessionContractExperiment;

// Only public, documented RDP authentication properties. Slot numbers are
// obtained and signature-checked against the installed Microsoft type library.
// This helper does not change authentication policy or answer security dialogs.
internal sealed class CredentialPromptControl : IDisposable
{
    private static readonly Guid InterfaceId = new("4f6996d5-d7b1-412c-b0ff-063718566907");
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SetBoolean(IntPtr self, short value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int GetBoolean(IntPtr self, out short value);
    private readonly VerifiedAuthenticationInterface api;
    private readonly SetBoolean put;
    private readonly GetBoolean get;

    internal CredentialPromptControl(object control, Action<string, object?> record)
    {
        api = new VerifiedAuthenticationInterface(control, InterfaceId, record,
            new("AllowPromptingForCredentials", INVOKEKIND.INVOKE_PROPERTYPUT, AuthenticationSignature.BooleanIn),
            new("AllowPromptingForCredentials", INVOKEKIND.INVOKE_PROPERTYGET, AuthenticationSignature.BooleanOut));
        try
        {
            put = api.Bind<SetBoolean>(0);
            get = api.Bind<GetBoolean>(1);
        }
        catch { api.Dispose(); throw; }
    }

    internal void DisableAndVerify(Action<string, object?> record)
    {
        record("credential_prompt_disable_start", null);
        bool before = Read();
        Marshal.ThrowExceptionForHR(put(api.Instance, 0 /* VARIANT_FALSE */));
        bool after = Read();
        record("credential_prompt_disabled", new { before, after });
        if (after) throw new ExperimentFailure("credential_prompt_disable_readback_failed");
    }

    private bool Read()
    {
        Marshal.ThrowExceptionForHR(get(api.Instance, out short value));
        if (value is not 0 and not -1) throw new ExperimentFailure("invalid_variant_bool_prompt_value");
        return value != 0;
    }

    public void Dispose() => api.Dispose();
}

internal sealed class RdpPasswordControl : IDisposable
{
    private static readonly Guid InterfaceId = new("c1e6743a-41c1-4a74-832a-0dd06c1c7a0e");
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SetBstr(IntPtr self, IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int Reset(IntPtr self);
    private readonly VerifiedAuthenticationInterface api;
    private readonly SetBstr put;
    private readonly Reset reset;

    internal RdpPasswordControl(object control, Action<string, object?> record)
    {
        api = new VerifiedAuthenticationInterface(control, InterfaceId, record,
            new("ClearTextPassword", INVOKEKIND.INVOKE_PROPERTYPUT, AuthenticationSignature.BstrIn),
            new("ResetPassword", INVOKEKIND.INVOKE_FUNC, AuthenticationSignature.NoArguments));
        try
        {
            put = api.Bind<SetBstr>(0);
            reset = api.Bind<Reset>(1);
        }
        catch { api.Dispose(); throw; }
    }

    internal void Set(SecureString password)
    {
        IntPtr bstr = Marshal.SecureStringToBSTR(password);
        try { Marshal.ThrowExceptionForHR(put(api.Instance, bstr)); }
        finally { Marshal.ZeroFreeBSTR(bstr); }
    }

    // The caller must first verify Connected == 0, as required by Microsoft.
    internal void ResetAfterDisconnect() => Marshal.ThrowExceptionForHR(reset(api.Instance));
    public void Dispose() => api.Dispose();
}

internal enum AuthenticationSignature { BooleanIn, BooleanOut, BstrIn, NoArguments }
internal readonly record struct AuthenticationMember(string Name, INVOKEKIND Invocation, AuthenticationSignature Signature);

internal sealed class VerifiedAuthenticationInterface : IDisposable
{
    private IntPtr instance;
    private readonly int[] offsets;
    internal IntPtr Instance => instance != IntPtr.Zero ? instance : throw new ObjectDisposedException(nameof(VerifiedAuthenticationInterface));

    internal VerifiedAuthenticationInterface(object control, Guid interfaceId, Action<string, object?> record,
        params AuthenticationMember[] members)
    {
        offsets = Enumerable.Repeat(-1, members.Length).ToArray();
        string dll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "mstscax.dll");
        Marshal.ThrowExceptionForHR(Native.LoadTypeLibEx(dll, 2 /* REGKIND_NONE */, out ITypeLib library));
        ITypeInfo? info = null;
        try
        {
            Guid iid = interfaceId;
            library.GetTypeInfoOfGuid(ref iid, out info);
            info.GetTypeAttr(out IntPtr attribute);
            try
            {
                TYPEATTR type = Marshal.PtrToStructure<TYPEATTR>(attribute);
                if (type.guid != interfaceId || type.typekind != TYPEKIND.TKIND_INTERFACE)
                    throw new ExperimentFailure("unexpected_authentication_interface_type");
                for (int index = 0; index < type.cFuncs; index++)
                {
                    info.GetFuncDesc(index, out IntPtr descriptor);
                    try
                    {
                        FUNCDESC function = Marshal.PtrToStructure<FUNCDESC>(descriptor);
                        info.GetDocumentation(function.memid, out string name, out _, out _, out _);
                        for (int member = 0; member < members.Length; member++)
                        {
                            if (!Matches(name, function.invkind, members[member])) continue;
                            if (offsets[member] >= 0) throw new ExperimentFailure("duplicate_authentication_member");
                            Validate(function, type, members[member].Signature);
                            offsets[member] = function.oVft;
                            record("authentication_typelib_member_verified", new { name, invocation = function.invkind.ToString(),
                                parameters = function.cParams, vtable_offset = function.oVft, vtable_bytes = type.cbSizeVft,
                                return_type = function.elemdescFunc.tdesc.vt, calling_convention = function.callconv.ToString(),
                                function_kind = function.funckind.ToString() });
                        }
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
        if (offsets.Any(offset => offset < 0) || offsets.Distinct().Count() != offsets.Length)
            throw new ExperimentFailure("unverified_authentication_vtable");
        IntPtr unknown = Marshal.GetIUnknownForObject(control);
        try
        {
            Guid iid = interfaceId;
            Marshal.ThrowExceptionForHR(Marshal.QueryInterface(unknown, ref iid, out instance));
        }
        catch { Dispose(); throw; }
        finally { Marshal.Release(unknown); }
    }

    private static bool Matches(string name, INVOKEKIND invocation, AuthenticationMember expected)
    {
        if (name == expected.Name && invocation == expected.Invocation) return true;
        string? prefix = expected.Invocation switch
        {
            INVOKEKIND.INVOKE_PROPERTYPUT => "put_",
            INVOKEKIND.INVOKE_PROPERTYGET => "get_",
            _ => null
        };
        return prefix is not null && name == prefix + expected.Name &&
            (invocation == expected.Invocation || invocation == INVOKEKIND.INVOKE_FUNC);
    }

    private static void Validate(FUNCDESC function, TYPEATTR type, AuthenticationSignature signature)
    {
        int parameters = signature == AuthenticationSignature.NoArguments ? 0 : 1;
        if (function.cParams != parameters || function.cParamsOpt != 0 ||
            function.elemdescFunc.tdesc.vt != (short)VarEnum.VT_HRESULT || function.callconv != CALLCONV.CC_STDCALL ||
            (function.funckind != FUNCKIND.FUNC_PUREVIRTUAL && function.funckind != FUNCKIND.FUNC_VIRTUAL) ||
            function.oVft < 3 * IntPtr.Size || function.oVft % IntPtr.Size != 0 ||
            function.oVft + IntPtr.Size > type.cbSizeVft)
            throw new ExperimentFailure("unexpected_authentication_method_signature");
        if (parameters == 0) return;
        if (function.lprgelemdescParam == IntPtr.Zero) throw new ExperimentFailure("authentication_parameter_missing");
        ELEMDESC parameter = Marshal.PtrToStructure<ELEMDESC>(function.lprgelemdescParam);
        PARAMFLAG flags = parameter.desc.paramdesc.wParamFlags;
        bool valid = signature switch
        {
            AuthenticationSignature.BooleanIn => parameter.tdesc.vt == (short)VarEnum.VT_BOOL &&
                (flags & PARAMFLAG.PARAMFLAG_FIN) != 0 && (flags & PARAMFLAG.PARAMFLAG_FOUT) == 0,
            AuthenticationSignature.BstrIn => parameter.tdesc.vt == (short)VarEnum.VT_BSTR &&
                (flags & PARAMFLAG.PARAMFLAG_FIN) != 0 && (flags & PARAMFLAG.PARAMFLAG_FOUT) == 0,
            AuthenticationSignature.BooleanOut => parameter.tdesc.vt == (short)VarEnum.VT_PTR &&
                parameter.tdesc.lpValue != IntPtr.Zero && Marshal.PtrToStructure<TYPEDESC>(parameter.tdesc.lpValue).vt == (short)VarEnum.VT_BOOL &&
                (flags & PARAMFLAG.PARAMFLAG_FOUT) != 0 && (flags & PARAMFLAG.PARAMFLAG_FRETVAL) != 0 &&
                (flags & PARAMFLAG.PARAMFLAG_FIN) == 0,
            _ => false
        };
        if (!valid) throw new ExperimentFailure("unexpected_authentication_parameter_type");
    }

    internal T Bind<T>(int member) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(Marshal.ReadIntPtr(Instance), offsets[member]));

    public void Dispose()
    {
        if (instance != IntPtr.Zero) { Marshal.Release(instance); instance = IntPtr.Zero; }
    }
}
