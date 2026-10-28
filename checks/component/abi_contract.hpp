#pragma once
#include "probe_support.hpp"
#include <ocidl.h>

namespace native_contract_probe {

struct TextResult {
    BSTR value{};
    ~TextResult() { erase_bstr(value); }
    std::wstring_view view() const noexcept { return {value ? value : L"", value ? SysStringLen(value) : 0}; }
};
struct TypeAttribute {
    ITypeInfo* info; TYPEATTR* value{};
    explicit TypeAttribute(ITypeInfo* owner) : info(owner) {
        require(info->GetTypeAttr(&value), "Read type attributes");
        if (!value) throw Failure("Null type attributes", E_UNEXPECTED);
    }
    ~TypeAttribute() { if (value) info->ReleaseTypeAttr(value); }
    TypeAttribute(const TypeAttribute&) = delete;
    TypeAttribute& operator=(const TypeAttribute&) = delete;
};
struct FunctionDescription {
    ITypeInfo* info; FUNCDESC* value{};
    FunctionDescription(ITypeInfo* owner, UINT index) : info(owner) {
        require(info->GetFuncDesc(index, &value), "Read type method");
        if (!value) throw Failure("Null type method", E_UNEXPECTED);
    }
    ~FunctionDescription() { if (value) info->ReleaseFuncDesc(value); }
    FunctionDescription(const FunctionDescription&) = delete;
    FunctionDescription& operator=(const FunctionDescription&) = delete;
};


enum class Signature { boolean_in, boolean_out, bstr_in, no_arguments, property_in, property_out, close_out };
struct MethodSpec { const wchar_t* name; INVOKEKIND invocation; Signature signature; };

bool matches(std::wstring_view actual, INVOKEKIND invocation, const MethodSpec& wanted) {
    if (actual == wanted.name && invocation == wanted.invocation) return true;
    const std::wstring_view prefix = wanted.invocation == INVOKE_PROPERTYPUT ? L"put_" :
        wanted.invocation == INVOKE_PROPERTYGET ? L"get_" : L"";
    return !prefix.empty() && actual.substr(0, prefix.size()) == prefix && actual.substr(prefix.size()) == wanted.name &&
        (invocation == wanted.invocation || invocation == INVOKE_FUNC);
}
bool pointer_to(const TYPEDESC& type, VARTYPE expected) noexcept {
    return type.vt == VT_PTR && type.lptdesc && type.lptdesc->vt == expected;
}
bool in_parameter(const ELEMDESC& parameter, VARTYPE type) noexcept {
    const USHORT flags = parameter.paramdesc.wParamFlags;
    return parameter.tdesc.vt == type && (flags & PARAMFLAG_FIN) &&
        !(flags & (PARAMFLAG_FOUT | PARAMFLAG_FRETVAL | PARAMFLAG_FOPT));
}
bool out_parameter(const ELEMDESC& parameter, VARTYPE type, bool retval) noexcept {
    const USHORT flags = parameter.paramdesc.wParamFlags;
    return pointer_to(parameter.tdesc, type) && (flags & PARAMFLAG_FOUT) &&
        (!retval || (flags & PARAMFLAG_FRETVAL)) && !(flags & (PARAMFLAG_FIN | PARAMFLAG_FOPT));
}

bool close_enum(ITypeInfo* owner, const TYPEDESC& type) {
    if (type.vt != VT_PTR || !type.lptdesc || type.lptdesc->vt != VT_USERDEFINED) return false;
    ComPtr<ITypeInfo> reference;
    require(owner->GetRefTypeInfo(type.lptdesc->hreftype, reference.put()), "Read close enum type");
    if (!reference) throw Failure("Null close enum type", E_UNEXPECTED);
    ComPtr<ITypeInfo> information;
    {
        TypeAttribute attributes(reference.get());
        TextResult name; require(reference->GetDocumentation(MEMBERID_NIL, &name.value, nullptr, nullptr, nullptr), "Read close enum name");
        if (name.view() != L"ControlCloseStatus" || attributes.value->cbSizeInstance != sizeof(LONG)) return false;
        if (attributes.value->typekind == TKIND_ALIAS) {
            // The installed ARM64/x64 TLB exposes this public name as one
            // 32-bit alias. Resolve only that measured shape, without recursion.
            if (attributes.value->cVars != 0 || attributes.value->tdescAlias.vt != VT_USERDEFINED) return false;
            require(reference->GetRefTypeInfo(attributes.value->tdescAlias.hreftype, information.put()), "Read close enum alias target");
            if (!information) throw Failure("Null close enum alias target", E_UNEXPECTED);
        } else if (attributes.value->typekind == TKIND_ENUM) information.copy_from(reference.get());
        else return false;
    }
    TypeAttribute attributes(information.get());
    if (attributes.value->typekind != TKIND_ENUM || attributes.value->cVars != 2 || attributes.value->cbSizeInstance != sizeof(LONG)) return false;
    unsigned found{};
    for (UINT index = 0; index < attributes.value->cVars; ++index) {
        VARDESC* descriptor{}; require(information->GetVarDesc(index, &descriptor), "Read close enum constant");
        struct ReleaseVariable { ITypeInfo* owner; VARDESC* value; ~ReleaseVariable() { owner->ReleaseVarDesc(value); } } cleanup{information.get(), descriptor};
        TextResult member; require(information->GetDocumentation(descriptor->memid, &member.value, nullptr, nullptr, nullptr), "Read close enum member");
        if (descriptor->varkind != VAR_CONST || !descriptor->lpvarValue || descriptor->lpvarValue->vt != VT_I4) return false;
        if (member.view() == L"controlCloseCanProceed" && descriptor->lpvarValue->lVal == 0) found |= 1;
        else if (member.view() == L"controlCloseWaitForEvents" && descriptor->lpvarValue->lVal == 1) found |= 2;
        else return false;
    }
    return found == 3;
}

void validate_method(ITypeInfo* information, const TYPEATTR& type, const FUNCDESC& method, Signature signature) {
    const int count = signature == Signature::no_arguments ? 0 :
        signature == Signature::property_in || signature == Signature::property_out ? 2 : 1;
    if (method.cParams != count || method.cParamsOpt != 0 || method.elemdescFunc.tdesc.vt != VT_HRESULT ||
        method.callconv != CC_STDCALL || (method.funckind != FUNC_PUREVIRTUAL && method.funckind != FUNC_VIRTUAL) ||
        method.oVft < static_cast<SHORT>(3 * sizeof(void*)) || method.oVft % sizeof(void*) != 0 ||
        static_cast<std::size_t>(method.oVft) + sizeof(void*) > type.cbSizeVft || (count && !method.lprgelemdescParam))
        throw Failure("RDP native method ABI mismatch", TYPE_E_TYPEMISMATCH);
    if (!count) return;
    const ELEMDESC& first = method.lprgelemdescParam[0];
    bool valid{};
    switch (signature) {
    case Signature::boolean_in: valid = in_parameter(first, VT_BOOL); break;
    case Signature::boolean_out: valid = out_parameter(first, VT_BOOL, true); break;
    case Signature::bstr_in: valid = in_parameter(first, VT_BSTR); break;
    case Signature::property_in:
        valid = in_parameter(first, VT_BSTR) && pointer_to(method.lprgelemdescParam[1].tdesc, VT_VARIANT) &&
            (method.lprgelemdescParam[1].paramdesc.wParamFlags & PARAMFLAG_FIN) &&
            !(method.lprgelemdescParam[1].paramdesc.wParamFlags & (PARAMFLAG_FOUT | PARAMFLAG_FRETVAL | PARAMFLAG_FOPT)); break;
    case Signature::property_out: valid = in_parameter(first, VT_BSTR) && out_parameter(method.lprgelemdescParam[1], VT_VARIANT, false); break;
    case Signature::close_out:
        valid = (first.paramdesc.wParamFlags & PARAMFLAG_FOUT) &&
            !(first.paramdesc.wParamFlags & (PARAMFLAG_FIN | PARAMFLAG_FOPT)) && close_enum(information, first.tdesc); break;
    default: break;
    }
    if (!valid) throw Failure("RDP native parameter ABI mismatch", TYPE_E_TYPEMISMATCH);
}


} // namespace native_contract_probe
