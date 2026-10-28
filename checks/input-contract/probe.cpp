// An isolated installed-metadata probe. No connection or input method is called.
#include <windows.h>
#include <ole2.h>
#include <oleauto.h>
#include <ocidl.h>
#include <rdpencomapi.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

namespace {
constexpr IID InputId{0x4606850e,0x76a7,0x4e28,{0xa4,0x7e,0xc7,0x17,0x4f,0x61,0x93,0x51}};
constexpr CLSID ControlId{0xa0c63c30,0xf08d,0x4ab4,{0x90,0x7c,0x34,0x90,0x5d,0x77,0x0c,0x7d}};
struct Error { HRESULT value; const char* stage; };
void check(HRESULT value, const char* stage) { if(FAILED(value)) throw Error{value,stage}; }
void expect(bool value, const char* stage) { if(!value) throw Error{TYPE_E_TYPEMISMATCH,stage}; }
template<class T> struct Owner {
    T* value{};
    ~Owner(){reset();}
    Owner()=default; Owner(const Owner&)=delete; Owner& operator=(const Owner&)=delete;
    void reset() noexcept {if(auto* old=std::exchange(value,nullptr)) old->Release();}
    T* operator->()const noexcept{return value;}
};
struct Attributes {
    ITypeInfo* owner; TYPEATTR* value{};
    explicit Attributes(ITypeInfo* input):owner(input){check(owner->GetTypeAttr(&value),"type_attributes");expect(value!=nullptr,"null_type_attributes");}
    ~Attributes(){if(value)owner->ReleaseTypeAttr(value);}
};
struct Function {
    ITypeInfo* owner; FUNCDESC* value{};
    Function(ITypeInfo* input,UINT index):owner(input){check(owner->GetFuncDesc(index,&value),"function_description");expect(value!=nullptr,"null_function");}
    ~Function(){if(value)owner->ReleaseFuncDesc(value);}
};
struct Variable {
    ITypeInfo* owner; VARDESC* value{};
    Variable(ITypeInfo* input,UINT index):owner(input){check(owner->GetVarDesc(index,&value),"variable_description");expect(value!=nullptr,"null_variable");}
    ~Variable(){if(value)owner->ReleaseVarDesc(value);}
};
std::string name(ITypeInfo* info,MEMBERID member) {
    BSTR raw{};check(info->GetDocumentation(member,&raw,nullptr,nullptr,nullptr),"symbol_name");
    struct Free {BSTR value;~Free(){SysFreeString(value);}} release{raw};
    expect(raw&&SysStringLen(raw)>0&&SysStringLen(raw)<=96,"symbol_name_length");
    std::string result;result.reserve(SysStringLen(raw));
    for(UINT i=0;i<SysStringLen(raw);++i){
        const wchar_t c=raw[i];expect((c>=L'A'&&c<=L'Z')||(c>=L'a'&&c<=L'z')||(c>=L'0'&&c<=L'9')||c==L'_',"symbol_name_character");
        result.push_back(static_cast<char>(c));
    }
    return result;
}
struct Constant {std::string name;LONG value{};VARTYPE declared{},actual{};};
struct EnumInfo {
    std::string public_name,target_name;
    TYPEKIND public_kind{},target_kind{};
    ULONG public_size{},target_size{};
    UINT alias_depth{},count{};
    std::array<Constant,32> constants{};
};
struct MethodInfo {const char* name{};SHORT offset{-1};SHORT parameters{};};
struct ContractInfo {
    std::array<MethodInfo,3> methods{{{"SendKeyboardEvent",-1,5},{"SendMouseButtonEvent",-1,4},{"SendMouseMoveEvent",-1,2}}};
    std::array<EnumInfo,2> enums{};
    UINT found{};
    bool metadata{};
};
struct LibraryInfo {
    std::string guid;
    unsigned major{},minor{},count{};
    SYSKIND kind{};
    bool observed{};
};
struct TypePresence {
    const char* wanted{};
    bool found{};
    std::string guid;
    TYPEKIND kind{};
    UINT methods{},constants{};
};
struct ResourceInfo {
    WORD id{};
    HRESULT load_result{E_PENDING},input_type_result{E_PENDING},contract_result{E_PENDING};
    LibraryInfo library;
    ContractInfo contract;
};
struct Report : ContractInfo {
    bool sta{},qi{},qi_attempted{},cleanup{},ole_uninitialized{};
    bool sdk_qi_attempted{},sdk_qi{},control_class_verified{},diagnostics_complete{};
    HRESULT default_metadata_result{E_PENDING},input_qi_result{E_PENDING},sdk_qi_result{E_PENDING};
    HRESULT class_info_result{E_PENDING},diagnostics_result{E_PENDING};
    LibraryInfo default_library,class_library;
    std::array<TypePresence,9> types{{
        {"IMsRdpInputSink",false,{},TKIND_MAX,0,0},
        {"KbdCodeType",false,{},TKIND_MAX,0,0},
        {"MouseButtonType",false,{},TKIND_MAX,0,0},
        {"IRemoteDesktopClient",false,{},TKIND_MAX,0,0},
        {"IRemoteDesktopClientActions",false,{},TKIND_MAX,0,0},
        {"IMsRdpClient10",false,{},TKIND_MAX,0,0},
        {"IMsRdpExtendedSettings",false,{},TKIND_MAX,0,0},
        {"IMsRdpClientNonScriptable",false,{},TKIND_MAX,0,0},
        {"IMsTscAx",false,{},TKIND_MAX,0,0}
    }};
    std::array<ResourceInfo,8> resources{};
    unsigned resource_count{},named_resources{};
    DWORD resource_enumeration_error{};
    bool resource_enumeration_complete{},resource_overflow{},data_module_loaded{},data_module_freed{};
    LONG connected_before{-1},connected_after{-1};
    HRESULT error{S_OK},close{S_OK};const char* stage="none";
};
EnumInfo enum_info(ITypeInfo* owner,const ELEMDESC& parameter,const char* expected) {
    expect(parameter.tdesc.vt==VT_USERDEFINED,"enum_parameter_type");
    expect((parameter.paramdesc.wParamFlags&PARAMFLAG_FIN)!=0&&
        !(parameter.paramdesc.wParamFlags&(PARAMFLAG_FOUT|PARAMFLAG_FRETVAL|PARAMFLAG_FOPT)),"enum_parameter_direction");
    Owner<ITypeInfo> reference;check(owner->GetRefTypeInfo(parameter.tdesc.hreftype,&reference.value),"enum_reference");expect(reference.value!=nullptr,"null_enum_reference");
    EnumInfo result;result.public_name=name(reference.value,MEMBERID_NIL);expect(result.public_name==expected,"enum_public_name");
    Owner<ITypeInfo> target;
    {
        Attributes a(reference.value);result.public_kind=a.value->typekind;result.public_size=a.value->cbSizeInstance;
        expect(result.public_size==sizeof(LONG),"enum_public_width");
        if(a.value->typekind==TKIND_ALIAS){
            expect(a.value->cVars==0&&a.value->tdescAlias.vt==VT_USERDEFINED,"enum_alias_shape");
            check(reference->GetRefTypeInfo(a.value->tdescAlias.hreftype,&target.value),"enum_alias_target");result.alias_depth=1;
        }else{expect(a.value->typekind==TKIND_ENUM,"enum_kind");target.value=reference.value;target->AddRef();}
    }
    expect(target.value!=nullptr,"null_enum_target");
    Attributes a(target.value);result.target_kind=a.value->typekind;result.target_size=a.value->cbSizeInstance;
    expect(a.value->typekind==TKIND_ENUM&&a.value->cbSizeInstance==sizeof(LONG)&&a.value->cVars>0&&a.value->cVars<=result.constants.size(),"enum_target_shape");
    result.target_name=name(target.value,MEMBERID_NIL);result.count=a.value->cVars;
    for(UINT i=0;i<result.count;++i){
        Variable v(target.value,i);expect(v.value->varkind==VAR_CONST&&v.value->lpvarValue,"enum_constant_kind");
        auto& item=result.constants[i];item.name=name(target.value,v.value->memid);item.declared=v.value->elemdescVar.tdesc.vt;item.actual=v.value->lpvarValue->vt;
        expect(item.actual==VT_I4&&(item.declared==VT_INT||item.declared==VT_I4),"enum_constant_representation");item.value=v.value->lpvarValue->lVal;
        for(UINT j=0;j<i;++j)expect(result.constants[j].name!=item.name,"duplicate_enum_constant_name");
    }
    return result;
}
void scalar(const ELEMDESC& parameter,VARTYPE type){
    expect(parameter.tdesc.vt==type&&(parameter.paramdesc.wParamFlags&PARAMFLAG_FIN)!=0&&
        !(parameter.paramdesc.wParamFlags&(PARAMFLAG_FOUT|PARAMFLAG_FRETVAL|PARAMFLAG_FOPT)),"scalar_parameter_contract");
}
void metadata(ITypeLib* library,ContractInfo& report){
    Owner<ITypeInfo> info;check(library->GetTypeInfoOfGuid(InputId,&info.value),"input_type");expect(info.value!=nullptr,"null_input_type");
    Attributes a(info.value);const TYPEATTR& type=*a.value;
    expect(type.guid==InputId&&type.typekind==TKIND_INTERFACE&&type.cFuncs>=3&&type.cFuncs<=64&&type.cbSizeVft<=4096,"input_type_contract");
    for(UINT i=0;i<type.cFuncs;++i){
        Function f(info.value,i);const auto method_name=name(info.value,f.value->memid);
        for(std::size_t selected=0;selected<report.methods.size();++selected){
            auto& wanted=report.methods[selected];if(method_name!=wanted.name)continue;
            const FUNCDESC& method=*f.value;
            expect(wanted.offset<0&&method.cParams==wanted.parameters&&method.cParamsOpt==0&&method.invkind==INVOKE_FUNC&&
                method.elemdescFunc.tdesc.vt==VT_HRESULT&&method.callconv==CC_STDCALL&&
                (method.funckind==FUNC_PUREVIRTUAL||method.funckind==FUNC_VIRTUAL)&&
                method.oVft>=static_cast<SHORT>(3*sizeof(void*))&&method.oVft%sizeof(void*)==0&&
                static_cast<std::size_t>(method.oVft)+sizeof(void*)<=type.cbSizeVft&&method.lprgelemdescParam,"input_method_contract");
            if(selected==0){report.enums[0]=enum_info(info.value,method.lprgelemdescParam[0],"KbdCodeType");scalar(method.lprgelemdescParam[1],VT_UI2);for(int p=2;p<5;++p)scalar(method.lprgelemdescParam[p],VT_BOOL);}
            else if(selected==1){report.enums[1]=enum_info(info.value,method.lprgelemdescParam[0],"MouseButtonType");scalar(method.lprgelemdescParam[1],VT_BOOL);scalar(method.lprgelemdescParam[2],VT_UI4);scalar(method.lprgelemdescParam[3],VT_UI4);}
            else{scalar(method.lprgelemdescParam[0],VT_UI4);scalar(method.lprgelemdescParam[1],VT_UI4);}
            wanted.offset=method.oVft;++report.found;
        }
    }
    expect(report.found==report.methods.size(),"input_required_methods");
    for(std::size_t i=0;i<report.methods.size();++i)for(std::size_t j=0;j<i;++j)expect(report.methods[i].offset!=report.methods[j].offset,"duplicate_input_slot");
    report.metadata=true;
}
std::string guid_text(REFGUID value) {
    std::array<wchar_t, 40> raw{};
    const int count = StringFromGUID2(value, raw.data(), static_cast<int>(raw.size()));
    expect(count == 39, "guid_format");
    std::string result;
    result.reserve(38);
    for (int i = 0; i < count - 1; ++i) result.push_back(static_cast<char>(raw[static_cast<std::size_t>(i)]));
    return result;
}

LibraryInfo library_info(ITypeLib* library) {
    TLIBATTR* attributes{};
    check(library->GetLibAttr(&attributes), "library_attributes");
    expect(attributes != nullptr, "null_library_attributes");
    struct Release { ITypeLib* owner; TLIBATTR* value; ~Release() { owner->ReleaseTLibAttr(value); } } release{library, attributes};
    LibraryInfo result;
    result.guid = guid_text(attributes->guid);
    result.major = attributes->wMajorVerNum;
    result.minor = attributes->wMinorVerNum;
    result.kind = attributes->syskind;
    result.count = library->GetTypeInfoCount();
    expect(result.count > 0 && result.count <= 4096, "library_type_count");
    result.observed = true;
    return result;
}

void whitelisted_types(ITypeLib* library, Report& report) {
    const UINT count = library->GetTypeInfoCount();
    expect(count > 0 && count <= 4096, "inventory_type_count");
    for (UINT i = 0; i < count; ++i) {
        Owner<ITypeInfo> info;
        check(library->GetTypeInfo(i, &info.value), "inventory_type_info");
        expect(info.value != nullptr, "inventory_null_type");
        BSTR raw{};
        check(info->GetDocumentation(MEMBERID_NIL, &raw, nullptr, nullptr, nullptr), "inventory_type_name");
        struct Free { BSTR value; ~Free() { SysFreeString(value); } } release{raw};
        if (!raw || SysStringLen(raw) > 96) continue;
        std::string symbol;
        bool ascii = true;
        for (UINT character = 0; character < SysStringLen(raw); ++character) {
            if (raw[character] < 32 || raw[character] > 126) { ascii = false; break; }
            symbol.push_back(static_cast<char>(raw[character]));
        }
        if (!ascii) continue;
        for (auto& target : report.types) {
            if (symbol != target.wanted) continue;
            expect(!target.found, "inventory_duplicate_type");
            Attributes attributes(info.value);
            target.guid = guid_text(attributes.value->guid);
            target.kind = attributes.value->typekind;
            target.methods = attributes.value->cFuncs;
            target.constants = attributes.value->cVars;
            target.found = true;
        }
    }
}

BOOL CALLBACK resource_name(HMODULE, LPCWSTR, LPWSTR resource, LONG_PTR context) noexcept {
    auto& report = *reinterpret_cast<Report*>(context);
    if (!IS_INTRESOURCE(resource)) {
        ++report.named_resources;
        if (report.named_resources > report.resources.size()) {
            report.resource_overflow = true;
            return FALSE;
        }
        return TRUE;
    }
    if (report.resource_count >= report.resources.size()) {
        report.resource_overflow = true;
        return FALSE;
    }
    report.resources[report.resource_count++].id = static_cast<WORD>(reinterpret_cast<ULONG_PTR>(resource));
    return TRUE;
}

void resource_libraries(const wchar_t* path, Report& report) {
    const HMODULE module = LoadLibraryExW(path, nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!module) throw Error{HRESULT_FROM_WIN32(GetLastError()), "type_resource_module"};
    report.data_module_loaded = true;
    struct Release {
        HMODULE module;
        Report& report;
        ~Release() { report.data_module_freed = FreeLibrary(module) != FALSE; }
    } release{module, report};
    SetLastError(ERROR_SUCCESS);
    const BOOL enumerated = EnumResourceNamesW(module, L"TYPELIB", resource_name, reinterpret_cast<LONG_PTR>(&report));
    report.resource_enumeration_error = enumerated ? ERROR_SUCCESS : GetLastError();
    report.resource_enumeration_complete = enumerated != FALSE && !report.resource_overflow;
    if (!enumerated || report.resource_overflow) return;

    // Only IDs actually returned by the system are used. The documented
    // DLL\integer resource syntax is read with REGKIND_NONE, never registered.
    for (unsigned i = 0; i < report.resource_count; ++i) {
        ResourceInfo& resource = report.resources[i];
        const std::wstring resource_path = std::wstring(path) + L"\\" + std::to_wstring(resource.id);
        Owner<ITypeLib> library;
        resource.load_result = LoadTypeLibEx(resource_path.c_str(), REGKIND_NONE, &library.value);
        if (FAILED(resource.load_result) || !library.value) continue;
        resource.library = library_info(library.value);
        Owner<ITypeInfo> input;
        resource.input_type_result = library->GetTypeInfoOfGuid(InputId, &input.value);
        if (FAILED(resource.input_type_result) || !input.value) continue;
        try {
            metadata(library.value, resource.contract);
            resource.contract_result = S_OK;
        } catch (const Error& error) { resource.contract_result = error.value; }
    }
}

void control_library(IUnknown* control, Report& report) {
    Owner<IProvideClassInfo> provider;
    report.class_info_result = control->QueryInterface(IID_IProvideClassInfo,
        reinterpret_cast<void**>(&provider.value));
    if (FAILED(report.class_info_result) || !provider.value) return;
    Owner<ITypeInfo> info;
    report.class_info_result = provider->GetClassInfo(&info.value);
    if (FAILED(report.class_info_result) || !info.value) return;
    Attributes attributes(info.value);
    report.control_class_verified = attributes.value->guid == ControlId && attributes.value->typekind == TKIND_COCLASS;
    Owner<ITypeLib> library;
    UINT index{};
    report.class_info_result = info->GetContainingTypeLib(&library.value, &index);
    if (FAILED(report.class_info_result) || !library.value) return;
    report.class_library = library_info(library.value);
}

LONG connected(IDispatch* dispatch){
    LPOLESTR symbol=const_cast<LPOLESTR>(L"Connected");DISPID id{};
    check(dispatch->GetIDsOfNames(IID_NULL,&symbol,1,LOCALE_INVARIANT,&id),"connected_identifier");
    DISPPARAMS parameters{};VARIANT result{};VariantInit(&result);
    struct Clear {VARIANT* value;~Clear(){VariantClear(value);}} clear{&result};
    check(dispatch->Invoke(id,IID_NULL,LOCALE_INVARIANT,DISPATCH_PROPERTYGET,&parameters,&result,nullptr,nullptr),"connected_get");
    expect(result.vt==VT_I2||result.vt==VT_I4,"connected_type");return result.vt==VT_I2?result.iVal:result.lVal;
}
void print_library(const LibraryInfo& library) {
    std::printf("{\"observed\":%s,\"guid\":\"%s\",\"major\":%u,\"minor\":%u,\"syskind\":%d,\"type_count\":%u}",
        library.observed ? "true" : "false", library.guid.c_str(), library.major,
        library.minor, static_cast<int>(library.kind), library.count);
}

void print_contract(const ContractInfo& contract) {
    std::printf("{\"metadata_verified\":%s,\"methods\":[", contract.metadata ? "true" : "false");
    for (std::size_t i = 0; i < contract.methods.size(); ++i) {
        const auto& method = contract.methods[i];
        std::printf("%s{\"name\":\"%s\",\"offset\":%d,\"parameters\":%d}",
            i ? "," : "", method.name, method.offset, method.parameters);
    }
    std::printf("],\"enums\":[");
    for (std::size_t i = 0; i < contract.enums.size(); ++i) {
        const auto& type = contract.enums[i];
        std::printf("%s{\"public_name\":\"%s\",\"public_kind\":%d,\"public_size\":%lu,\"alias_depth\":%u,\"target_name\":\"%s\",\"target_kind\":%d,\"target_size\":%lu,\"constants\":[",
            i ? "," : "", type.public_name.c_str(), static_cast<int>(type.public_kind),
            static_cast<unsigned long>(type.public_size), type.alias_depth,
            type.target_name.c_str(), static_cast<int>(type.target_kind),
            static_cast<unsigned long>(type.target_size));
        for (UINT j = 0; j < type.count; ++j) {
            const auto& value = type.constants[j];
            std::printf("%s{\"name\":\"%s\",\"value\":%ld,\"declared_type\":%u,\"variant_type\":%u}",
                j ? "," : "", value.name.c_str(), static_cast<long>(value.value),
                static_cast<unsigned>(value.declared), static_cast<unsigned>(value.actual));
        }
        std::printf("]}");
    }
    std::printf("]}");
}

void print(const Report& report) {
    const bool verified = report.cleanup && report.metadata && report.qi && report.error == S_OK;
    std::printf("{\"schema\":\"native-input-contract/v2\",\"status\":\"%s\",\"error_hresult\":%ld,\"error_stage\":\"%s\",\"close_hresult\":%ld,",
        verified ? "verified" : "failed", static_cast<long>(report.error), report.stage,
        static_cast<long>(report.close));
    std::printf("\"sta_verified\":%s,\"metadata_verified\":%s,\"default_metadata_hresult\":%ld,\"qi_attempted\":%s,\"qi_verified\":%s,\"input_qi_hresult\":%ld,",
        report.sta ? "true" : "false", report.metadata ? "true" : "false",
        static_cast<long>(report.default_metadata_result), report.qi_attempted ? "true" : "false",
        report.qi ? "true" : "false", static_cast<long>(report.input_qi_result));
    std::printf("\"sdk_input_qi_attempted\":%s,\"sdk_input_qi_verified\":%s,\"sdk_input_qi_hresult\":%ld,\"connected_before\":%ld,\"connected_after\":%ld,",
        report.sdk_qi_attempted ? "true" : "false", report.sdk_qi ? "true" : "false",
        static_cast<long>(report.sdk_qi_result), static_cast<long>(report.connected_before),
        static_cast<long>(report.connected_after));
    std::printf("\"cleanup_verified\":%s,\"ole_uninitialized\":%s,\"control_class_verified\":%s,\"class_info_hresult\":%ld,\"diagnostics_complete\":%s,\"diagnostics_hresult\":%ld,",
        report.cleanup ? "true" : "false", report.ole_uninitialized ? "true" : "false",
        report.control_class_verified ? "true" : "false", static_cast<long>(report.class_info_result),
        report.diagnostics_complete ? "true" : "false", static_cast<long>(report.diagnostics_result));
    std::printf("\"rdp_connect_called\":false,\"input_methods_called\":false,\"credentials_used\":false,\"remote_frame_verified\":false,\"input_delivery_verified\":false,\"physical_multiseat_verified\":false,");
    std::printf("\"default_library\":");
    print_library(report.default_library);
    std::printf(",\"class_library\":");
    print_library(report.class_library);
    std::printf(",\"default_contract\":");
    print_contract(report);
    std::printf(",\"whitelisted_types\":[");
    for (std::size_t i = 0; i < report.types.size(); ++i) {
        const auto& type = report.types[i];
        std::printf("%s{\"name\":\"%s\",\"found\":%s,\"guid\":\"%s\",\"kind\":%d,\"methods\":%u,\"constants\":%u}",
            i ? "," : "", type.wanted, type.found ? "true" : "false", type.guid.c_str(),
            static_cast<int>(type.kind), type.methods, type.constants);
    }
    std::printf("],\"resource_enumeration_complete\":%s,\"resource_enumeration_error\":%lu,\"resource_overflow\":%s,\"named_resources_not_loaded\":%u,\"data_module_freed\":%s,\"typelib_resources\":[",
        report.resource_enumeration_complete ? "true" : "false",
        static_cast<unsigned long>(report.resource_enumeration_error),
        report.resource_overflow ? "true" : "false", report.named_resources,
        report.data_module_freed ? "true" : "false");
    for (unsigned i = 0; i < report.resource_count; ++i) {
        const auto& resource = report.resources[i];
        std::printf("%s{\"id\":%u,\"load_hresult\":%ld,\"input_type_hresult\":%ld,\"contract_hresult\":%ld,\"library\":",
            i ? "," : "", static_cast<unsigned>(resource.id), static_cast<long>(resource.load_result),
            static_cast<long>(resource.input_type_result), static_cast<long>(resource.contract_result));
        print_library(resource.library);
        std::printf(",\"contract\":");
        print_contract(resource.contract);
        std::printf("}");
    }
    std::printf("]}\n");
}
}
int main() {
    Report report;
    const HRESULT initialized = OleInitialize(nullptr);
    if (FAILED(initialized)) {
        report.error = initialized;
        report.stage = "ole_initialize";
        print(report);
        return 1;
    }
    Owner<IUnknown> control;
    Owner<IOleObject> ole;
    Owner<IDispatch> dispatch;
    Owner<IUnknown> sink;
    Owner<IRDPViewerInputSink> sdk_sink;
    try {
        APTTYPE apartment{};
        APTTYPEQUALIFIER qualifier{};
        check(CoGetApartmentType(&apartment, &qualifier), "apartment_query");
        expect(apartment == APTTYPE_STA || apartment == APTTYPE_MAINSTA, "sta_required");
        report.sta = true;
        std::array<wchar_t, 32768> path{};
        const UINT length = GetSystemDirectoryW(path.data(), static_cast<UINT>(path.size()));
        constexpr wchar_t suffix[] = L"\\mstscax.dll";
        expect(length > 0 && length < path.size() && length + std::size(suffix) <= path.size(), "system_path_length");
        std::memcpy(path.data() + length, suffix, sizeof(suffix));
        Owner<ITypeLib> library;
        check(LoadTypeLibEx(path.data(), REGKIND_NONE, &library.value), "type_library");
        expect(library.value != nullptr, "null_type_library");
        report.default_library = library_info(library.value);
        try {
            metadata(library.value, report);
            report.default_metadata_result = S_OK;
        } catch (const Error& error) {
            report.default_metadata_result = error.value;
            report.error = error.value;
            report.stage = error.stage;
        }
        try {
            whitelisted_types(library.value, report);
            resource_libraries(path.data(), report);
            report.diagnostics_result = S_OK;
            report.diagnostics_complete = report.resource_enumeration_complete && report.data_module_freed;
        } catch (const Error& error) { report.diagnostics_result = error.value; }

        // These queries are independent of type-library lookup. A missing
        // typelib entry must not suppress an actual interface availability test.
        check(CoCreateInstance(ControlId, nullptr, CLSCTX_INPROC_SERVER, IID_IUnknown,
            reinterpret_cast<void**>(&control.value)), "control_create");
        expect(control.value != nullptr, "null_control");
        check(control->QueryInterface(IID_IOleObject, reinterpret_cast<void**>(&ole.value)), "ole_query");
        expect(ole.value != nullptr, "null_ole");
        check(control->QueryInterface(IID_IDispatch, reinterpret_cast<void**>(&dispatch.value)), "dispatch_query");
        expect(dispatch.value != nullptr, "null_dispatch");
        report.connected_before = connected(dispatch.value);
        expect(report.connected_before == 0, "fresh_control_disconnected");
        report.qi_attempted = true;
        report.input_qi_result = control->QueryInterface(InputId, reinterpret_cast<void**>(&sink.value));
        report.qi = report.input_qi_result == S_OK && sink.value;
        report.sdk_qi_attempted = true;
        report.sdk_qi_result = control->QueryInterface(__uuidof(IRDPViewerInputSink), reinterpret_cast<void**>(&sdk_sink.value));
        report.sdk_qi = report.sdk_qi_result == S_OK && sdk_sink.value;
        try { control_library(control.value, report); }
        catch (const Error& error) { report.class_info_result = error.value; }
        report.connected_after = connected(dispatch.value);
        expect(report.connected_after == 0, "control_remains_disconnected");
        if (!report.qi && report.error == S_OK) {
            report.error = FAILED(report.input_qi_result) ? report.input_qi_result : E_UNEXPECTED;
            report.stage = "input_query";
        }
    } catch (const Error& error) {
        report.error = error.value;
        report.stage = error.stage;
    } catch (...) {
        report.error = E_UNEXPECTED;
        report.stage = "native_exception";
    }
    sdk_sink.reset();
    sink.reset();
    dispatch.reset();
    if (ole.value) report.close = ole->Close(OLECLOSE_NOSAVE);
    ole.reset();
    control.reset();
    OleUninitialize();
    report.ole_uninitialized = true;
    report.cleanup = SUCCEEDED(report.close) && (!report.data_module_loaded || report.data_module_freed);
    print(report);
    return report.metadata && report.qi && report.cleanup && SUCCEEDED(report.error) ? 0 : 1;
}
