#include "abi_contract.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <iterator>

using namespace native_contract_probe;
namespace {
constexpr CLSID ControlClass{0xa0c63c30,0xf08d,0x4ab4,{0x90,0x7c,0x34,0x90,0x5d,0x77,0x0c,0x7d}};
constexpr IID ExtendedId{0x302d8188,0x0052,0x4807,{0x80,0x6a,0x36,0x2b,0x62,0x8f,0x9a,0xc5}};
constexpr IID PasswordId{0xc1e6743a,0x41c1,0x4a74,{0x83,0x2a,0x0d,0xd0,0x6c,0x1c,0x7a,0x0e}};
constexpr IID PromptId{0x4f6996d5,0xd7b1,0x412c,{0xb0,0xff,0x06,0x37,0x18,0x56,0x69,0x07}};
constexpr IID ClientId{0x92b4a539,0x7115,0x4b7c,{0xa5,0xa9,0xe5,0xd9,0xef,0xc2,0x78,0x0a}};
constexpr IID EventsId{0x336d5562,0xefa8,0x482e,{0x8c,0xb3,0xc5,0xc0,0xfc,0x7a,0x7d,0xb6}};
struct Parameter { int type{-1}, pointee{-1}, flags{}; };
struct Method {
    const char* id{""}; bool seen{}, verified{};
    int dispid{-1}, invocation{-1}, parameters{-1}, optional{-1}, result_type{-1};
    int function_kind{-1}, convention{-1}, offset{-1};
    std::array<Parameter, 2> parameter{};
};
struct Native {
    const char* id{""}; const char* failure{""}; HRESULT error{S_OK};
    int original_kind{-1}, native_kind{-1}, functions{}, vtable_bytes{};
    bool dual{}, verified{}, qi{}; std::size_t count{};
    std::array<Method, 2> methods{};
};
struct NamedSpec { const char* id; MethodSpec specification; };
struct Property {
    const char* id{""}; bool required{true}, attempted{}, verified{};
    int expected_type{-1}, actual_type{-1}; HRESULT error{S_OK}; const char* failure{""};
};
struct EnumConstant {
    bool seen{}, identifier_accepted{}, value_present{}, integer_present{}, integer_unsigned{};
    std::array<char, 129> identifier{};
    int variable_kind{-1}, declared_type{-1}, variant_type{-1};
    unsigned known_name_bits{}, strict_constant_bits{};
    std::int64_t signed_value{}; std::uint64_t unsigned_value{};
};
struct CloseEnumDiagnostic {
    bool attempted{}, referenced_type_read{}, attributes_read{}, identifier_accepted{}, type_name_matches{}, complete{}, truncated{};
    std::array<char, 129> identifier{};
    int type_kind{-1}, variable_count{-1}, alias_type{-1}, alias_pointee{-1};
    unsigned type_flags{}, instance_bytes{}, count{}, known_name_bits{}, strict_constant_bits{};
    HRESULT error{S_OK}; const char* failure{""};
    std::array<EnumConstant, 16> constants{};
};
struct Result {
    HRESULT error{S_OK}, close_error{S_OK}; const char* failure{""};
    unsigned architecture{}, pointer_bits{sizeof(void*) * 8}; int apartment{-1};
    int connected_before{-1}, connected_after{-1};
    bool ole_initialized{}, sta{}, control_created{}, class_verified{};
    bool events_verified{}, point_verified{}, references_released{}, control_closed{}, ole_uninitialized{};
    HRESULT event_error{S_OK}; const char* event_failure{""};
    std::array<Native, 4> native{};
    std::array<Method, 10> events{};
    std::array<Property, 15> properties{};
    CloseEnumDiagnostic close_enum_diagnostic{}, close_enum_alias_target_diagnostic{};
};
void failed(Result& result, const char* stage, HRESULT error) noexcept {
    if (SUCCEEDED(result.error)) { result.error = error; result.failure = stage; }
}
void capture(Method& output, const FUNCDESC& value) noexcept {
    output.seen = true; output.dispid = value.memid; output.invocation = value.invkind;
    output.parameters = value.cParams; output.optional = value.cParamsOpt;
    output.result_type = value.elemdescFunc.tdesc.vt; output.function_kind = value.funckind;
    output.convention = value.callconv; output.offset = value.oVft;
    for (int i = 0; i < value.cParams && i < 2 && value.lprgelemdescParam; ++i) {
        const ELEMDESC& parameter = value.lprgelemdescParam[i];
        auto& row = output.parameter[static_cast<std::size_t>(i)];
        row.type = parameter.tdesc.vt; row.flags = parameter.paramdesc.wParamFlags;
        if (parameter.tdesc.vt == VT_PTR && parameter.tdesc.lptdesc) row.pointee = parameter.tdesc.lptdesc->vt;
    }
}
bool copy_identifier(std::wstring_view name, std::array<char, 129>& destination) noexcept {
    if (name.empty() || name.size() >= destination.size()) return false;
    for (const wchar_t value : name)
        if (!((value >= L'A' && value <= L'Z') || (value >= L'a' && value <= L'z') ||
            (value >= L'0' && value <= L'9') || value == L'_')) return false;
    for (std::size_t i = 0; i < name.size(); ++i) destination[i] = static_cast<char>(name[i]);
    return true;
}
void capture_integer(const VARIANT& value, EnumConstant& output) noexcept {
    output.integer_present = true;
    switch (value.vt) {
    case VT_I1: output.signed_value = value.cVal; break;
    case VT_I2: output.signed_value = value.iVal; break;
    case VT_I4: output.signed_value = value.lVal; break;
    case VT_I8: output.signed_value = value.llVal; break;
    case VT_INT: output.signed_value = value.intVal; break;
    case VT_UI1: output.integer_unsigned = true; output.unsigned_value = value.bVal; break;
    case VT_UI2: output.integer_unsigned = true; output.unsigned_value = value.uiVal; break;
    case VT_UI4: output.integer_unsigned = true; output.unsigned_value = value.ulVal; break;
    case VT_UI8: output.integer_unsigned = true; output.unsigned_value = value.ullVal; break;
    case VT_UINT: output.integer_unsigned = true; output.unsigned_value = value.uintVal; break;
    default: output.integer_present = false; break;
    }
}
void capture_enum_type(ITypeInfo* info, CloseEnumDiagnostic& output) {
    output.referenced_type_read = true;
    TypeAttribute attributes(info); const TYPEATTR& type = *attributes.value;
    output.attributes_read = true; output.type_kind = type.typekind; output.variable_count = type.cVars;
    output.type_flags = type.wTypeFlags; output.instance_bytes = type.cbSizeInstance;
    if (type.typekind == TKIND_ALIAS) {
        output.alias_type = type.tdescAlias.vt;
        if (type.tdescAlias.vt == VT_PTR && type.tdescAlias.lptdesc) output.alias_pointee = type.tdescAlias.lptdesc->vt;
    }
    TextResult name;
    require(info->GetDocumentation(MEMBERID_NIL, &name.value, nullptr, nullptr, nullptr), "enum_diagnostic_type_name");
    output.identifier_accepted = copy_identifier(name.view(), output.identifier);
    output.type_name_matches = name.view() == L"ControlCloseStatus";
    output.truncated = type.cVars > output.constants.size();
    for (UINT index = 0; index < type.cVars && index < output.constants.size(); ++index) {
        EnumConstant& row = output.constants[index]; ++output.count;
        struct Variable {
            ITypeInfo* owner; VARDESC* value{};
            ~Variable() { if (value) owner->ReleaseVarDesc(value); }
        } variable{info};
        require(info->GetVarDesc(index, &variable.value), "enum_diagnostic_variable");
        check(variable.value != nullptr, "enum_diagnostic_null_variable");
        row.seen = true; row.variable_kind = variable.value->varkind;
        row.declared_type = variable.value->elemdescVar.tdesc.vt;
        TextResult member;
        require(info->GetDocumentation(variable.value->memid, &member.value, nullptr, nullptr, nullptr), "enum_diagnostic_member_name");
        row.identifier_accepted = copy_identifier(member.view(), row.identifier);
        row.known_name_bits = member.view() == L"controlCloseCanProceed" ? 1U :
            member.view() == L"controlCloseWaitForEvents" ? 2U : 0U;
        output.known_name_bits |= row.known_name_bits;
        if (variable.value->varkind == VAR_CONST && variable.value->lpvarValue) {
            const VARIANT& value = *variable.value->lpvarValue;
            row.value_present = true; row.variant_type = value.vt; capture_integer(value, row);
            if (value.vt == VT_I4 && ((row.known_name_bits == 1 && value.lVal == 0) ||
                (row.known_name_bits == 2 && value.lVal == 1))) row.strict_constant_bits = row.known_name_bits;
            output.strict_constant_bits |= row.strict_constant_bits;
        }
    }
    output.complete = !output.truncated;
}
void inspect_close_enum(ITypeInfo* owner, const FUNCDESC& method, CloseEnumDiagnostic& output,
    CloseEnumDiagnostic& alias_target) noexcept {
    output.attempted = true; ComPtr<ITypeInfo> info;
    try {
        check(method.cParams == 1 && method.lprgelemdescParam, "enum_diagnostic_parameter_shape");
        const TYPEDESC& descriptor = method.lprgelemdescParam[0].tdesc;
        check(descriptor.vt == VT_PTR && descriptor.lptdesc && descriptor.lptdesc->vt == VT_USERDEFINED,
            "enum_diagnostic_reference_shape");
        require(owner->GetRefTypeInfo(descriptor.lptdesc->hreftype, info.put()), "enum_diagnostic_reference");
        check(info.get() != nullptr, "enum_diagnostic_null_reference");
        capture_enum_type(info.get(), output);
    } catch (const Failure& error) { output.error = error.result(); output.failure = error.what(); return; }
    catch (...) { output.error = E_UNEXPECTED; output.failure = "enum_diagnostic_unexpected_exception"; return; }
    // Only the measured named, 4-byte alias with no own constants can resolve
    // one additional type. There are still at most 16 constant rows in total.
    if (!output.type_name_matches || output.type_kind != TKIND_ALIAS || output.instance_bytes != sizeof(LONG) ||
        output.variable_count != 0 || output.alias_type != VT_USERDEFINED) return;
    alias_target.attempted = true;
    try {
        TypeAttribute attributes(info.get()); const TYPEATTR& type = *attributes.value;
        check(type.typekind == TKIND_ALIAS && type.cbSizeInstance == sizeof(LONG) && type.cVars == 0 &&
            type.tdescAlias.vt == VT_USERDEFINED, "enum_diagnostic_alias_shape_changed");
        ComPtr<ITypeInfo> target;
        require(info->GetRefTypeInfo(type.tdescAlias.hreftype, target.put()), "enum_diagnostic_alias_target");
        check(target.get() != nullptr, "enum_diagnostic_null_alias_target");
        capture_enum_type(target.get(), alias_target);
    } catch (const Failure& error) { alias_target.error = error.result(); alias_target.failure = error.what(); }
    catch (...) { alias_target.error = E_UNEXPECTED; alias_target.failure = "enum_diagnostic_alias_exception"; }
}

ComPtr<ITypeLib> type_library() {
    std::array<wchar_t, 32768> path{};
    const UINT length = GetSystemDirectoryW(path.data(), static_cast<UINT>(path.size()));
    constexpr wchar_t suffix[] = L"\\mstscax.dll";
    check(length && length + std::size(suffix) <= path.size(), "system_type_library_path");
    std::memcpy(path.data() + length, suffix, sizeof(suffix));
    ComPtr<ITypeLib> library;
    require(LoadTypeLibEx(path.data(), REGKIND_NONE, library.put()), "load_system_type_library");
    check(library.get() != nullptr, "null_type_library"); return library;
}
void inspect_native(IUnknown* control, ITypeLib* library, REFIID iid, const char* id,
    std::initializer_list<NamedSpec> specs, Native& output, ComPtr<IUnknown>& instance, Result& result) {
    output.id = id;
    try {
        check(specs.size() <= output.methods.size(), "native_specification_limit");
        output.count = specs.size();
        std::size_t slot{}; for (const auto& spec : specs) output.methods[slot++].id = spec.id;
        ComPtr<ITypeInfo> info;
        require(library->GetTypeInfoOfGuid(iid, info.put()), "native_type_information");
        {
            TypeAttribute type(info.get()); output.original_kind = type.value->typekind;
            output.dual = type.value->typekind == TKIND_DISPATCH && (type.value->wTypeFlags & TYPEFLAG_FDUAL);
        }
        if (output.dual) {
            HREFTYPE reference{}; require(info->GetRefTypeOfImplType(static_cast<UINT>(-1), &reference), "resolve_dual_native_type");
            ComPtr<ITypeInfo> native; require(info->GetRefTypeInfo(reference, native.put()), "read_dual_native_type"); info = std::move(native);
        }
        TypeAttribute attributes(info.get()); const TYPEATTR& type = *attributes.value;
        output.native_kind = type.typekind; output.functions = type.cFuncs; output.vtable_bytes = type.cbSizeVft;
        check(type.guid == iid && type.typekind == TKIND_INTERFACE && type.cFuncs <= 512 && type.cbSizeVft <= 16384,
            "native_interface_shape", TYPE_E_TYPEMISMATCH);
        for (UINT index = 0; index < type.cFuncs; ++index) {
            FunctionDescription descriptor(info.get(), index); TextResult name;
            require(info->GetDocumentation(descriptor.value->memid, &name.value, nullptr, nullptr, nullptr), "native_member_name");
            slot = 0;
            for (const auto& spec : specs) {
                Method& method = output.methods[slot++];
                if (!matches(name.view(), descriptor.value->invkind, spec.specification)) continue;
                check(!method.seen, "duplicate_native_member", TYPE_E_AMBIGUOUSNAME);
                capture(method, *descriptor.value);
                if (spec.specification.signature == Signature::close_out)
                    inspect_close_enum(info.get(), *descriptor.value, result.close_enum_diagnostic, result.close_enum_alias_target_diagnostic);
                validate_method(info.get(), type, *descriptor.value, spec.specification.signature);
                method.verified = true;
            }
        }
        for (std::size_t i = 0; i < output.count; ++i) {
            check(output.methods[i].verified, "native_member_missing", DISP_E_MEMBERNOTFOUND);
            for (std::size_t j = 0; j < i; ++j) check(output.methods[i].offset != output.methods[j].offset,
                "duplicate_native_slot", TYPE_E_TYPEMISMATCH);
        }
        instance = query<IUnknown>(control, iid, "native_query_interface"); output.qi = true; output.verified = true;
    } catch (const Failure& error) { output.error = error.result(); output.failure = error.what(); failed(result, id, error.result()); }
}
void inspect_events(IUnknown* control, ITypeLib* library, Result& result) {
    struct Spec { const char* id; const wchar_t* name; int shape; };
    constexpr Spec specs[] = {
        {"OnConnecting", L"OnConnecting", 0}, {"OnConnected", L"OnConnected", 0},
        {"OnLoginComplete", L"OnLoginComplete", 0}, {"OnDisconnected", L"OnDisconnected", 1},
        {"OnFatalError", L"OnFatalError", 1}, {"OnWarning", L"OnWarning", 1},
        {"OnLogonError", L"OnLogonError", 1}, {"OnAuthenticationWarningDisplayed", L"OnAuthenticationWarningDisplayed", 0},
        {"OnAuthenticationWarningDismissed", L"OnAuthenticationWarningDismissed", 0}, {"OnConfirmClose", L"OnConfirmClose", 2}
    };
    for (std::size_t i = 0; i < std::size(specs); ++i) result.events[i].id = specs[i].id;
    try {
        ComPtr<ITypeInfo> info; require(library->GetTypeInfoOfGuid(EventsId, info.put()), "event_type_information");
        TypeAttribute attributes(info.get());
        check(attributes.value->guid == EventsId && attributes.value->typekind == TKIND_DISPATCH && attributes.value->cFuncs <= 256,
            "event_interface_shape", TYPE_E_TYPEMISMATCH);
        for (UINT index = 0; index < attributes.value->cFuncs; ++index) {
            FunctionDescription descriptor(info.get(), index); const FUNCDESC& value = *descriptor.value; TextResult name;
            require(info->GetDocumentation(value.memid, &name.value, nullptr, nullptr, nullptr), "event_member_name");
            for (std::size_t i = 0; i < std::size(specs); ++i) {
                if (name.view() != specs[i].name) continue;
                Method& method = result.events[i]; check(!method.seen, "duplicate_event_member", TYPE_E_AMBIGUOUSNAME); capture(method, value);
                check(value.memid > 0 && value.cParamsOpt == 0 && value.invkind == INVOKE_FUNC && value.funckind == FUNC_DISPATCH &&
                    value.elemdescFunc.tdesc.vt == VT_VOID && value.cParams == (specs[i].shape ? 1 : 0), "event_method_shape", TYPE_E_TYPEMISMATCH);
                if (specs[i].shape) {
                    check(value.lprgelemdescParam != nullptr, "event_parameter_missing");
                    check(specs[i].shape == 1 ? in_parameter(value.lprgelemdescParam[0], VT_I4) :
                        out_parameter(value.lprgelemdescParam[0], VT_BOOL, false), "event_parameter_shape", TYPE_E_TYPEMISMATCH);
                }
                method.verified = true;
            }
        }
        for (std::size_t i = 0; i < result.events.size(); ++i) {
            check(result.events[i].verified, "event_missing", DISP_E_MEMBERNOTFOUND);
            for (std::size_t j = 0; j < i; ++j) check(result.events[i].dispid != result.events[j].dispid, "duplicate_event_dispid");
        }
        result.events_verified = true;
        auto container = query<IConnectionPointContainer>(control, IID_IConnectionPointContainer, "connection_point_container");
        ComPtr<IConnectionPoint> point; require(container->FindConnectionPoint(EventsId, point.put()), "find_event_connection_point");
        check(point.get() != nullptr, "null_connection_point"); IID actual{};
        require(point->GetConnectionInterface(&actual), "read_connection_point_interface"); check(actual == EventsId, "connection_point_interface_mismatch");
        result.point_verified = true;
    } catch (const Failure& error) { result.event_error = error.result(); result.event_failure = error.what(); failed(result, "event_contract", error.result()); }
}
void dispatch(IDispatch* object, const wchar_t* name, WORD flags, VARIANT* argument, VARIANT* result) {
    LPOLESTR member = const_cast<LPOLESTR>(name); DISPID id{};
    require(object->GetIDsOfNames(IID_NULL, &member, 1, LOCALE_INVARIANT, &id), "dispatch_member");
    DISPID named = DISPID_PROPERTYPUT; DISPPARAMS parameters{};
    parameters.rgvarg = argument; parameters.cArgs = argument ? 1U : 0U;
    if (flags == DISPATCH_PROPERTYPUT) { parameters.rgdispidNamedArgs = &named; parameters.cNamedArgs = 1; }
    struct Exception { EXCEPINFO value{}; ~Exception() { erase_bstr(value.bstrSource); erase_bstr(value.bstrDescription); erase_bstr(value.bstrHelpFile); } } exception;
    UINT index{}; const HRESULT status = object->Invoke(id, IID_NULL, LOCALE_INVARIANT, flags, &parameters, result, &exception.value, &index);
    if (exception.value.pfnDeferredFillIn) exception.value.pfnDeferredFillIn(&exception.value);
    require(status, "dispatch_invocation");
}
LONG number(const VARIANT& value) {
    if (value.vt == VT_I4) return value.lVal;
    if (value.vt == VT_I2) return value.iVal;
    if (value.vt == VT_UI4 && value.ulVal <= static_cast<ULONG>((std::numeric_limits<LONG>::max)())) return static_cast<LONG>(value.ulVal);
    throw Failure("dispatch_numeric_type", DISP_E_TYPEMISMATCH);
}
int connected(IDispatch* object) {
    Value value; dispatch(object, L"Connected", DISPATCH_PROPERTYGET, nullptr, &value.value);
    const LONG state = number(value.value); check(state >= 0 && state <= 2, "connected_state_range"); return static_cast<int>(state);
}
template<class Call> void property(Property& property, Result& result, Call call) {
    property.attempted = true;
    try { call(); property.verified = true; }
    catch (const Failure& error) {
        property.error = error.result(); property.failure = error.what();
        if (property.required) failed(result, property.id, error.result());
    }
}
template<class Function> Function native_call(IUnknown* instance, const Method& method) {
    check(instance && method.verified && method.offset >= 0, "unverified_native_call");
    const auto table = *reinterpret_cast<void* const* const*>(instance);
    void* address = table[static_cast<std::size_t>(method.offset) / sizeof(void*)]; check(address != nullptr, "null_native_method");
    static_assert(sizeof(Function) == sizeof(address)); Function function{}; std::memcpy(&function, &address, sizeof(function)); return function;
}
void configuration(IDispatch* control, std::array<ComPtr<IUnknown>, 4>& native, Result& result) {
    struct Spec { const char* id; const wchar_t* name; VARTYPE type; LONG value; };
    constexpr Spec specs[] = {
        {"Server", L"Server", VT_BSTR, 0}, {"DesktopWidth", L"DesktopWidth", VT_I4, 1024},
        {"DesktopHeight", L"DesktopHeight", VT_I4, 768}, {"ColorDepth", L"ColorDepth", VT_I4, 32},
        {"EnableCredSspSupport", L"EnableCredSspSupport", VT_BOOL, -1}, {"AuthenticationLevel", L"AuthenticationLevel", VT_I4, 1},
        {"RedirectClipboard", L"RedirectClipboard", VT_BOOL, 0}, {"RedirectDrives", L"RedirectDrives", VT_BOOL, 0},
        {"RedirectPrinters", L"RedirectPrinters", VT_BOOL, 0}, {"RedirectPorts", L"RedirectPorts", VT_BOOL, 0},
        {"RedirectSmartCards", L"RedirectSmartCards", VT_BOOL, 0}, {"EnableAutoReconnect", L"EnableAutoReconnect", VT_BOOL, 0}
    };
    Value advanced_value;
    HRESULT advanced_error = S_OK; const char* advanced_failure = "";
    for (std::size_t i = 0; i < std::size(specs); ++i) {
        Property& row = result.properties[i]; row.id = specs[i].id; row.expected_type = specs[i].type;
        if (i == 4) {
            try {
                dispatch(control, L"AdvancedSettings9", DISPATCH_PROPERTYGET, nullptr, &advanced_value.value);
                check(advanced_value.value.vt == VT_DISPATCH && advanced_value.value.pdispVal, "advanced_settings_dispatch", E_NOINTERFACE);
            } catch (const Failure& error) {
                advanced_error = error.result(); advanced_failure = error.what(); failed(result, "AdvancedSettings9", advanced_error);
            }
        }
        if (i >= 4 && FAILED(advanced_error)) { row.error = advanced_error; row.failure = advanced_failure; continue; }
        property(row, result, [&] {
            IDispatch* object = i < 4 ? control : advanced_value.value.pdispVal;
            Value argument; argument.value.vt = specs[i].type;
            if (specs[i].type == VT_BOOL) argument.value.boolVal = static_cast<VARIANT_BOOL>(specs[i].value);
            else if (specs[i].type == VT_I4) argument.value.lVal = specs[i].value;
            else { argument.value.bstrVal = SysAllocString(L"localhost"); check(argument.value.bstrVal != nullptr, "fixed_server_allocation", E_OUTOFMEMORY); }
            Value ignored; dispatch(object, specs[i].name, DISPATCH_PROPERTYPUT, &argument.value, &ignored.value);
            Value actual; dispatch(object, specs[i].name, DISPATCH_PROPERTYGET, nullptr, &actual.value); row.actual_type = actual.value.vt;
            if (specs[i].type == VT_BOOL) check(actual.value.vt == VT_BOOL && actual.value.boolVal == argument.value.boolVal, "boolean_readback", TYPE_E_TYPEMISMATCH);
            else if (specs[i].type == VT_I4) check(number(actual.value) == specs[i].value, "numeric_readback");
            else check(actual.value.vt == VT_BSTR && actual.value.bstrVal && SysStringLen(actual.value.bstrVal) == 9 &&
                std::wstring_view(actual.value.bstrVal, 9) == L"localhost", "fixed_server_readback");
        });
    }
    using PropertyCall = HRESULT (STDMETHODCALLTYPE*)(void*, BSTR, VARIANT*);
    const wchar_t* names[]{L"ConnectToChildSession", L"EnableFrameBufferRedirection"};
    for (std::size_t i = 0; i < 2; ++i) {
        Property& row = result.properties[12 + i]; row.id = i ? "EnableFrameBufferRedirection" : "ConnectToChildSession";
        row.required = i == 0; row.expected_type = VT_BOOL;
        if (!result.native[0].verified) continue;
        property(row, result, [&] {
            String name(names[i]); Value desired; desired.value.vt = VT_BOOL; desired.value.boolVal = VARIANT_TRUE;
            auto put = native_call<PropertyCall>(native[0].get(), result.native[0].methods[0]);
            auto get = native_call<PropertyCall>(native[0].get(), result.native[0].methods[1]);
            require(put(native[0].get(), name.value, &desired.value), "extended_property_put");
            Value actual; require(get(native[0].get(), name.value, &actual.value), "extended_property_get"); row.actual_type = actual.value.vt;
            check(actual.value.vt == VT_BOOL && actual.value.boolVal == VARIANT_TRUE, "extended_property_readback", TYPE_E_TYPEMISMATCH);
        });
    }
    Property& prompt = result.properties[14]; prompt.id = "AllowPromptingForCredentials"; prompt.expected_type = VT_BOOL;
    if (result.native[2].verified) property(prompt, result, [&] {
        using Put = HRESULT (STDMETHODCALLTYPE*)(void*, VARIANT_BOOL);
        using Get = HRESULT (STDMETHODCALLTYPE*)(void*, VARIANT_BOOL*);
        const auto put = native_call<Put>(native[2].get(), result.native[2].methods[0]);
        const auto get = native_call<Get>(native[2].get(), result.native[2].methods[1]);
        require(put(native[2].get(), VARIANT_FALSE), "credential_prompt_property_put");
        VARIANT_BOOL actual = VARIANT_TRUE; require(get(native[2].get(), &actual), "credential_prompt_property_get");
        prompt.actual_type = VT_BOOL; check(actual == VARIANT_FALSE, "credential_prompt_property_readback");
    });
}
void execute(Result& result) {
    ComPtr<IUnknown> control; ComPtr<IOleObject> ole;
    try {
        require(CoCreateInstance(ControlClass, nullptr, CLSCTX_INPROC_SERVER, IID_IUnknown, reinterpret_cast<void**>(control.put())), "create_fresh_control");
        check(control.get() != nullptr, "null_control"); result.control_created = true;
        ole = query<IOleObject>(control.get(), IID_IOleObject, "control_ole_object");
        CLSID actual{}; require(ole->GetUserClassID(&actual), "control_class_identity"); check(actual == ControlClass, "control_class_mismatch"); result.class_verified = true;
        {
            auto library = type_library(); auto automation = query<IDispatch>(control.get(), IID_IDispatch, "control_dispatch");
            result.connected_before = connected(automation.get()); check(result.connected_before == 0, "fresh_control_not_disconnected");
            std::array<ComPtr<IUnknown>, 4> native;
            inspect_native(control.get(), library.get(), ExtendedId, "extended", {
                {"Property.put", {L"Property", INVOKE_PROPERTYPUT, Signature::property_in}},
                {"Property.get", {L"Property", INVOKE_PROPERTYGET, Signature::property_out}}}, result.native[0], native[0], result);
            inspect_native(control.get(), library.get(), PasswordId, "password_metadata_only", {
                {"ClearTextPassword.put", {L"ClearTextPassword", INVOKE_PROPERTYPUT, Signature::bstr_in}},
                {"ResetPassword", {L"ResetPassword", INVOKE_FUNC, Signature::no_arguments}}}, result.native[1], native[1], result);
            inspect_native(control.get(), library.get(), PromptId, "prompt", {
                {"AllowPromptingForCredentials.put", {L"AllowPromptingForCredentials", INVOKE_PROPERTYPUT, Signature::boolean_in}},
                {"AllowPromptingForCredentials.get", {L"AllowPromptingForCredentials", INVOKE_PROPERTYGET, Signature::boolean_out}}}, result.native[2], native[2], result);
            inspect_native(control.get(), library.get(), ClientId, "close_metadata_only", {
                {"RequestClose", {L"RequestClose", INVOKE_FUNC, Signature::close_out}}}, result.native[3], native[3], result);
            inspect_events(control.get(), library.get(), result);
            configuration(automation.get(), native, result);
            result.connected_after = connected(automation.get()); check(result.connected_after == 0, "configuration_changed_connection_state");
        }
    } catch (const Failure& error) { failed(result, error.what(), error.result()); }
    catch (...) { failed(result, "unexpected_test_exception", E_UNEXPECTED); }
    result.close_error = ole ? ole->Close(OLECLOSE_NOSAVE) : result.control_created ? E_NOINTERFACE : S_OK;
    result.control_closed = SUCCEEDED(result.close_error);
    if (FAILED(result.close_error)) failed(result, "close_owned_control", result.close_error);
    ole.reset(); control.reset(); result.references_released = true;
}
void method_json(const Method& value) {
    std::cout << "{\"id\":\"" << value.id << "\",\"seen\":" << value.seen << ",\"verified\":" << value.verified
        << ",\"dispid\":" << value.dispid << ",\"invocation\":" << value.invocation << ",\"parameters\":" << value.parameters
        << ",\"optional_parameters\":" << value.optional << ",\"return_type\":" << value.result_type
        << ",\"function_kind\":" << value.function_kind << ",\"calling_convention\":" << value.convention << ",\"vtable_offset\":" << value.offset << ",\"parameter_shapes\":[";
    for (int i = 0; i < value.parameters && i < 2; ++i) {
        if (i) std::cout << ',';
        const auto& parameter = value.parameter[static_cast<std::size_t>(i)];
        std::cout << "{\"type\":" << parameter.type << ",\"pointee\":" << parameter.pointee << ",\"flags\":" << parameter.flags << '}';
    }
    std::cout << "]}";
}
void close_enum_json(const CloseEnumDiagnostic& value) {
    std::cout << "{\"attempted\":" << value.attempted << ",\"referenced_type_read\":" << value.referenced_type_read
        << ",\"attributes_read\":" << value.attributes_read << ",\"identifier_accepted\":" << value.identifier_accepted
        << ",\"identifier\":\"" << value.identifier.data() << "\",\"exact_type_name_match\":" << value.type_name_matches
        << ",\"type_kind\":" << value.type_kind << ",\"variable_count\":" << value.variable_count
        << ",\"type_flags\":" << value.type_flags << ",\"instance_bytes\":" << value.instance_bytes
        << ",\"alias_type\":" << value.alias_type << ",\"alias_pointee\":" << value.alias_pointee
        << ",\"complete\":" << value.complete << ",\"truncated\":" << value.truncated
        << ",\"hresult\":" << static_cast<std::uint32_t>(value.error) << ",\"failure_operation\":\"" << value.failure
        << "\",\"known_name_bits\":" << value.known_name_bits << ",\"strict_constant_bits\":" << value.strict_constant_bits
        << ",\"constants\":[";
    for (unsigned i = 0; i < value.count; ++i) {
        if (i) std::cout << ',';
        const EnumConstant& row = value.constants[i];
        std::cout << "{\"seen\":" << row.seen << ",\"identifier_accepted\":" << row.identifier_accepted
            << ",\"identifier\":\"" << row.identifier.data() << "\",\"variable_kind\":" << row.variable_kind
            << ",\"declared_type\":" << row.declared_type << ",\"value_present\":" << row.value_present
            << ",\"variant_type\":" << row.variant_type << ",\"known_name_bits\":" << row.known_name_bits
            << ",\"strict_constant_bits\":" << row.strict_constant_bits << ",\"integer_unsigned\":";
        if (row.integer_present) std::cout << row.integer_unsigned; else std::cout << "null";
        std::cout << ",\"integer_value_decimal\":";
        if (!row.integer_present) std::cout << "null";
        else {
            std::cout << '"';
            if (row.integer_unsigned) std::cout << row.unsigned_value; else std::cout << row.signed_value;
            std::cout << '"';
        }
        std::cout << '}';
    }
    std::cout << "]}";
}
int report(Result& result, ULONGLONG elapsed) {
    bool natives = true, properties = true;
    for (const auto& value : result.native) natives = natives && value.verified && value.qi;
    for (const auto& value : result.properties) if (value.required) properties = properties && value.attempted && value.verified;
    const bool cleanup = result.control_closed && result.references_released && (!result.ole_initialized || result.ole_uninitialized);
    const bool passed = SUCCEEDED(result.error) && result.sta && result.class_verified && natives && result.events_verified && result.point_verified &&
        properties && result.connected_before == 0 && result.connected_after == 0 && cleanup;
    const bool unavailable = result.error == REGDB_E_CLASSNOTREG && cleanup;
    std::cout << std::boolalpha << "{\"schema\":\"native-component-contract/v1\",\"status\":\"" << (passed ? "verified" : unavailable ? "unavailable" : "failed")
        << "\",\"failure_operation\":\"" << result.failure << "\",\"error_hresult\":" << static_cast<std::uint32_t>(result.error)
        << ",\"close_hresult\":" << static_cast<std::uint32_t>(result.close_error) << ",\"elapsed_ms\":" << elapsed
        << ",\"native_architecture\":" << result.architecture << ",\"pointer_bits\":" << result.pointer_bits << ",\"apartment_type\":" << result.apartment
        << ",\"sta_verified\":" << result.sta << ",\"control_class_verified\":" << result.class_verified
        << ",\"connected_before\":" << result.connected_before << ",\"connected_after\":" << result.connected_after
        << ",\"native_contracts_verified\":" << natives << ",\"event_metadata_verified\":" << result.events_verified
        << ",\"connection_point_verified\":" << result.point_verified << ",\"required_properties_verified\":" << properties
        << ",\"owned_references_released\":" << result.references_released << ",\"control_closed\":" << result.control_closed
        << ",\"ole_uninitialized\":" << result.ole_uninitialized << ",\"cleanup_verified\":" << cleanup << ",\"native_interfaces\":[";
    for (std::size_t i = 0; i < result.native.size(); ++i) {
        if (i) std::cout << ',';
        const Native& value = result.native[i];
        std::cout << "{\"id\":\"" << value.id << "\",\"original_type_kind\":" << value.original_kind << ",\"native_type_kind\":" << value.native_kind
            << ",\"dual\":" << value.dual << ",\"function_count\":" << value.functions << ",\"vtable_bytes\":" << value.vtable_bytes
            << ",\"verified\":" << value.verified << ",\"qi_verified\":" << value.qi << ",\"hresult\":" << static_cast<std::uint32_t>(value.error)
            << ",\"failure_operation\":\"" << value.failure << "\",\"methods\":[";
        for (std::size_t j = 0; j < value.count; ++j) { if (j) std::cout << ','; method_json(value.methods[j]); }
        std::cout << "]}";
    }
    std::cout << "],\"close_enum_diagnostic\":"; close_enum_json(result.close_enum_diagnostic);
    std::cout << ",\"close_enum_alias_target_diagnostic\":"; close_enum_json(result.close_enum_alias_target_diagnostic);
    std::cout << ",\"events\":[";
    for (std::size_t i = 0; i < result.events.size(); ++i) { if (i) std::cout << ','; method_json(result.events[i]); }
    std::cout << "],\"event_error_hresult\":" << static_cast<std::uint32_t>(result.event_error) << ",\"event_failure_operation\":\"" << result.event_failure << "\",\"properties\":[";
    for (std::size_t i = 0; i < result.properties.size(); ++i) {
        if (i) std::cout << ',';
        const auto& value = result.properties[i];
        std::cout << "{\"id\":\"" << value.id << "\",\"required\":" << value.required << ",\"attempted\":" << value.attempted
            << ",\"verified\":" << value.verified << ",\"expected_type\":" << value.expected_type << ",\"actual_type\":" << value.actual_type
            << ",\"hresult\":" << static_cast<std::uint32_t>(value.error) << ",\"failure_operation\":\"" << value.failure << "\"}";
    }
    std::cout << "],\"unhosted_control\":true,\"rdp_connect_called\":false,\"password_methods_called\":false,\"request_close_called\":false,"
        "\"events_subscribed\":false,\"events_delivered_verified\":false,\"credentials_ui_called\":false,\"accounts_created\":false,"
        "\"session_creation_verified\":false,\"remote_frame_verified\":false,\"input_channel_verified\":false,\"physical_multiseat_verified\":false}\n";
    return passed ? 0 : unavailable ? 77 : 1;
}
} // namespace

int main() {
    const ULONGLONG started = GetTickCount64(); Result result;
    SYSTEM_INFO system{}; GetNativeSystemInfo(&system); result.architecture = system.wProcessorArchitecture;
    try {
        require(OleInitialize(nullptr), "initialize_sta"); result.ole_initialized = true;
        APTTYPE apartment{}; APTTYPEQUALIFIER qualifier{}; require(CoGetApartmentType(&apartment, &qualifier), "apartment_type");
        result.apartment = static_cast<int>(apartment); result.sta = apartment == APTTYPE_STA || apartment == APTTYPE_MAINSTA;
        check(result.sta, "sta_required"); execute(result);
    } catch (const Failure& error) { failed(result, error.what(), error.result()); }
    catch (...) { failed(result, "unexpected_initialization_exception", E_UNEXPECTED); }
    if (result.ole_initialized) { OleUninitialize(); result.ole_uninitialized = true; }
    return report(result, GetTickCount64() - started);
}
