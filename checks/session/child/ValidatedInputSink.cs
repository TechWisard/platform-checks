using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using FUNCDESC = System.Runtime.InteropServices.ComTypes.FUNCDESC;
using TYPEATTR = System.Runtime.InteropServices.ComTypes.TYPEATTR;
using TYPEKIND = System.Runtime.InteropServices.ComTypes.TYPEKIND;
using ELEMDESC = System.Runtime.InteropServices.ComTypes.ELEMDESC;
using TYPEDESC = System.Runtime.InteropServices.ComTypes.TYPEDESC;
using VARDESC = System.Runtime.InteropServices.ComTypes.VARDESC;
using PARAMFLAG = System.Runtime.InteropServices.ComTypes.PARAMFLAG;
using FUNCKIND = System.Runtime.InteropServices.ComTypes.FUNCKIND;
using CALLCONV = System.Runtime.InteropServices.ComTypes.CALLCONV;
using INVOKEKIND = System.Runtime.InteropServices.ComTypes.INVOKEKIND;

namespace SessionContractExperiment;

// Only the existing RDP connection receives these calls. This class never calls
// SendInput, installs hooks/drivers, changes desktop, or opens a network socket.
// A successful HRESULT is transport acceptance, not proof of received input.
internal sealed class ValidatedInputSink : IDisposable
{
    private static readonly Guid InterfaceId = new("4606850E-76A7-4E28-A47E-C7174F619351");

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int KeyboardCall(IntPtr self, int codeType, ushort keycode,
        short keyUp, short repeat, short extended);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int MouseButtonCall(IntPtr self, int buttonType, short down, uint x, uint y);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int MouseMoveCall(IntPtr self, uint x, uint y);

    private readonly Action<string, object?> record;
    private readonly int thread = Environment.CurrentManagedThreadId;
    private readonly uint width;
    private readonly uint height;
    private IntPtr instance;
    private readonly KeyboardCall keyboard;
    private readonly MouseButtonCall button;
    private readonly MouseMoveCall move;
    private readonly int unicodeType;
    private readonly int leftButton;

    internal IReadOnlyDictionary<string, int> KeyboardCodeTypes { get; }
    internal IReadOnlyDictionary<string, int> MouseButtonTypes { get; }

    internal ValidatedInputSink(object control, uint desktopWidth, uint desktopHeight,
        Action<string, object?> record)
    {
        if (desktopWidth is 0 or > 4096 || desktopHeight is 0 or > 4096)
            throw new ExperimentFailure("input_sink_invalid_desktop_bounds");
        width = desktopWidth; height = desktopHeight; this.record = record;
        string file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "mstscax.dll");
        Marshal.ThrowExceptionForHR(Native.LoadTypeLibEx(file, 2 /* REGKIND_NONE */, out ITypeLib library));
        ITypeInfo? info = null;
        Dictionary<string, int>? keyTypes = null, buttonTypes = null;
        int keyOffset = -1, buttonOffset = -1, moveOffset = -1;
        try
        {
            Guid iid = InterfaceId;
            library.GetTypeInfoOfGuid(ref iid, out info);
            info.GetTypeAttr(out IntPtr typePtr);
            try
            {
                TYPEATTR type = Marshal.PtrToStructure<TYPEATTR>(typePtr);
                if (type.guid != InterfaceId || type.typekind != TYPEKIND.TKIND_INTERFACE ||
                    type.cFuncs < 3 || type.cFuncs > 64)
                    throw new ExperimentFailure("input_sink_unexpected_interface_type");
                for (int i = 0; i < type.cFuncs; i++)
                {
                    info.GetFuncDesc(i, out IntPtr descriptor);
                    try
                    {
                        FUNCDESC function = Marshal.PtrToStructure<FUNCDESC>(descriptor);
                        info.GetDocumentation(function.memid, out string name, out _, out _, out _);
                        record("input_sink_type_member", new { name, parameters = function.cParams,
                            vtable_offset = function.oVft, vtable_bytes = type.cbSizeVft,
                            return_type = function.elemdescFunc.tdesc.vt,
                            calling_convention = function.callconv.ToString(), function_kind = function.funckind.ToString() });
                        int parameters = name switch {
                            "SendKeyboardEvent" => 5,
                            "SendMouseButtonEvent" => 4,
                            "SendMouseMoveEvent" => 2,
                            _ => 0
                        };
                        if (parameters == 0) continue;
                        ValidateFunction(type, function, parameters);
                        if (name == "SendKeyboardEvent")
                        {
                            if (keyOffset >= 0) throw new ExperimentFailure("input_sink_duplicate_key_method");
                            keyTypes = EnumParameter(info, Parameter(function, 0), "KbdCodeType");
                            ValidateScalar(Parameter(function, 1), VarEnum.VT_UI2);
                            for (int p = 2; p < 5; p++) ValidateScalar(Parameter(function, p), VarEnum.VT_BOOL);
                            keyOffset = function.oVft;
                        }
                        else if (name == "SendMouseButtonEvent")
                        {
                            if (buttonOffset >= 0) throw new ExperimentFailure("input_sink_duplicate_button_method");
                            buttonTypes = EnumParameter(info, Parameter(function, 0), "MouseButtonType");
                            ValidateScalar(Parameter(function, 1), VarEnum.VT_BOOL);
                            ValidateScalar(Parameter(function, 2), VarEnum.VT_UI4);
                            ValidateScalar(Parameter(function, 3), VarEnum.VT_UI4);
                            buttonOffset = function.oVft;
                        }
                        else
                        {
                            if (moveOffset >= 0) throw new ExperimentFailure("input_sink_duplicate_move_method");
                            ValidateScalar(Parameter(function, 0), VarEnum.VT_UI4);
                            ValidateScalar(Parameter(function, 1), VarEnum.VT_UI4);
                            moveOffset = function.oVft;
                        }
                    }
                    finally { info.ReleaseFuncDesc(descriptor); }
                }
            }
            finally { info.ReleaseTypeAttr(typePtr); }
        }
        finally
        {
            if (info is not null) Marshal.ReleaseComObject(info);
            Marshal.ReleaseComObject(library);
        }
        if (keyOffset < 0 || buttonOffset < 0 || moveOffset < 0 || keyTypes is null || buttonTypes is null ||
            new[] { keyOffset, buttonOffset, moveOffset }.Distinct().Count() != 3)
            throw new ExperimentFailure("input_sink_required_methods_missing");
        KeyboardCodeTypes = keyTypes;
        MouseButtonTypes = buttonTypes;
        record("input_sink_enum_constants", new { keyboard = keyTypes, mouse = buttonTypes });
        // Numeric enum values come from Microsoft's installed type library.
        // Select exactly one semantically named member; never guess a numeric
        // value or silently use another encoding/button if the type differs.
        KeyValuePair<string, int> unicode = SelectMember(keyTypes, "unicode");
        KeyValuePair<string, int> left = SelectMember(buttonTypes, "left");
        unicodeType = unicode.Value; leftButton = left.Value;
        record("input_sink_selected_constants", new { keyboard_name = unicode.Key, keyboard_value = unicode.Value,
            button_name = left.Key, button_value = left.Value });
        IntPtr unknown = Marshal.GetIUnknownForObject(control);
        try
        {
            Guid iid = InterfaceId;
            Marshal.ThrowExceptionForHR(Marshal.QueryInterface(unknown, ref iid, out instance));
            IntPtr table = Marshal.ReadIntPtr(instance);
            keyboard = Marshal.GetDelegateForFunctionPointer<KeyboardCall>(Marshal.ReadIntPtr(table, keyOffset));
            button = Marshal.GetDelegateForFunctionPointer<MouseButtonCall>(Marshal.ReadIntPtr(table, buttonOffset));
            move = Marshal.GetDelegateForFunctionPointer<MouseMoveCall>(Marshal.ReadIntPtr(table, moveOffset));
            record("input_sink_abi_verified", new { key_slot = keyOffset / IntPtr.Size,
                button_slot = buttonOffset / IntPtr.Size, move_slot = moveOffset / IntPtr.Size });
        }
        catch { Dispose(); throw; }
        finally { Marshal.Release(unknown); }
    }

    private static void ValidateFunction(TYPEATTR type, FUNCDESC function, int parameters)
    {
        if (function.cParams != parameters || function.cParamsOpt != 0 ||
            function.invkind != INVOKEKIND.INVOKE_FUNC ||
            function.elemdescFunc.tdesc.vt != (short)VarEnum.VT_HRESULT ||
            function.callconv != CALLCONV.CC_STDCALL ||
            (function.funckind != FUNCKIND.FUNC_PUREVIRTUAL && function.funckind != FUNCKIND.FUNC_VIRTUAL) ||
            function.oVft < 3 * IntPtr.Size || function.oVft % IntPtr.Size != 0 ||
            function.oVft + IntPtr.Size > type.cbSizeVft || function.lprgelemdescParam == IntPtr.Zero)
            throw new ExperimentFailure("input_sink_unexpected_method_signature");
    }

    private static ELEMDESC Parameter(FUNCDESC function, int index) =>
        Marshal.PtrToStructure<ELEMDESC>(IntPtr.Add(function.lprgelemdescParam, checked(index * Marshal.SizeOf<ELEMDESC>())));

    private static void ValidateInput(ELEMDESC parameter)
    {
        PARAMFLAG flags = parameter.desc.paramdesc.wParamFlags;
        if ((flags & PARAMFLAG.PARAMFLAG_FIN) == 0 ||
            (flags & (PARAMFLAG.PARAMFLAG_FOUT | PARAMFLAG.PARAMFLAG_FRETVAL | PARAMFLAG.PARAMFLAG_FOPT)) != 0)
            throw new ExperimentFailure("input_sink_unexpected_parameter_direction");
    }

    private static void ValidateScalar(ELEMDESC parameter, VarEnum expected)
    {
        ValidateInput(parameter);
        if (parameter.tdesc.vt != (short)expected)
            throw new ExperimentFailure("input_sink_unexpected_parameter_type");
    }

    private static Dictionary<string, int> EnumParameter(ITypeInfo source, ELEMDESC parameter, string expectedType)
    {
        ValidateInput(parameter);
        if (parameter.tdesc.vt != (short)VarEnum.VT_USERDEFINED)
            throw new ExperimentFailure("input_sink_enum_parameter_not_typed");
        int reference = unchecked((int)parameter.tdesc.lpValue.ToInt64());
        source.GetRefTypeInfo(reference, out ITypeInfo info);
        try
        {
            info.GetDocumentation(-1, out string typeName, out _, out _, out _);
            info.GetTypeAttr(out IntPtr pointer);
            try
            {
                TYPEATTR type = Marshal.PtrToStructure<TYPEATTR>(pointer);
                if (type.typekind != TYPEKIND.TKIND_ENUM || typeName != expectedType || type.cVars < 1 || type.cVars > 64)
                    throw new ExperimentFailure("input_sink_unexpected_enum_type");
                Dictionary<string, int> result = new(StringComparer.Ordinal);
                for (int i = 0; i < type.cVars; i++)
                {
                    info.GetVarDesc(i, out IntPtr description);
                    try
                    {
                        VARDESC value = Marshal.PtrToStructure<VARDESC>(description);
                        if (value.varkind != VARKIND.VAR_CONST || value.desc.lpvarValue == IntPtr.Zero)
                            throw new ExperimentFailure("input_sink_enum_value_not_constant");
                        info.GetDocumentation(value.memid, out string name, out _, out _, out _);
                        int number = Convert.ToInt32(Marshal.GetObjectForNativeVariant(value.desc.lpvarValue), CultureInfo.InvariantCulture);
                        if (!result.TryAdd(name, number)) throw new ExperimentFailure("input_sink_duplicate_enum_name");
                    }
                    finally { info.ReleaseVarDesc(description); }
                }
                return result;
            }
            finally { info.ReleaseTypeAttr(pointer); }
        }
        finally { Marshal.ReleaseComObject(info); }
    }

    private static KeyValuePair<string, int> SelectMember(Dictionary<string, int> values, string semanticName)
    {
        KeyValuePair<string, int>[] found = values.Where(pair => pair.Key.Contains(semanticName, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (found.Length != 1) throw new ExperimentFailure("input_sink_enum_selection_ambiguous_or_missing");
        return found[0];
    }

    private void Ready()
    {
        if (instance == IntPtr.Zero) throw new ObjectDisposedException(nameof(ValidatedInputSink));
        if (Environment.CurrentManagedThreadId != thread) throw new ExperimentFailure("input_sink_wrong_apartment_thread");
    }

    private void Coordinates(uint x, uint y)
    {
        if (x >= width || y >= height) throw new ExperimentFailure("input_sink_coordinates_out_of_range");
    }

    internal void MoveTo(uint x, uint y)
    {
        Ready(); Coordinates(x, y);
        int hr = move(instance, x, y);
        record("input_sink_move_call", new { x, y, hresult = hr });
        Marshal.ThrowExceptionForHR(hr);
    }

    internal void LeftClick(uint x, uint y)
    {
        Ready(); Coordinates(x, y);
        int down = unchecked((int)0x80004005), up = unchecked((int)0x80004005);
        try { down = button(instance, leftButton, -1 /* VARIANT_TRUE */, x, y); }
        finally { up = button(instance, leftButton, 0 /* VARIANT_FALSE */, x, y); }
        record("input_sink_button_pair", new { x, y, down_hresult = down, up_hresult = up });
        Marshal.ThrowExceptionForHR(down);
        Marshal.ThrowExceptionForHR(up);
    }

    internal void HexCharacter(char value)
    {
        Ready();
        if (!Uri.IsHexDigit(value)) throw new ExperimentFailure("input_sink_challenge_character_not_hex");
        int down = unchecked((int)0x80004005), up = unchecked((int)0x80004005);
        try { down = keyboard(instance, unicodeType, value, 0, 0, 0); }
        finally { up = keyboard(instance, unicodeType, value, -1, 0, 0); }
        // Only transport status is logged here. The witness must independently
        // observe WM_CHAR before input delivery can be claimed.
        record("input_sink_character_pair", new { down_hresult = down, up_hresult = up });
        Marshal.ThrowExceptionForHR(down);
        Marshal.ThrowExceptionForHR(up);
    }

    public void Dispose()
    {
        if (instance != IntPtr.Zero) { Marshal.Release(instance); instance = IntPtr.Zero; }
    }
}
