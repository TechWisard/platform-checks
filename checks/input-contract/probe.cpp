// An isolated installed-metadata probe. No connection or input method is called.
#include <windows.h>
#include <ole2.h>
#include <oleauto.h>
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
struct Report {
    std::array<MethodInfo,3> methods{{{"SendKeyboardEvent",-1,5},{"SendMouseButtonEvent",-1,4},{"SendMouseMoveEvent",-1,2}}};
    std::array<EnumInfo,2> enums{};
    UINT found{};
    bool sta{},metadata{},qi{},cleanup{},ole_uninitialized{};
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
void metadata(ITypeLib* library,Report& report){
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
LONG connected(IDispatch* dispatch){
    LPOLESTR symbol=const_cast<LPOLESTR>(L"Connected");DISPID id{};
    check(dispatch->GetIDsOfNames(IID_NULL,&symbol,1,LOCALE_INVARIANT,&id),"connected_identifier");
    DISPPARAMS parameters{};VARIANT result{};VariantInit(&result);
    struct Clear {VARIANT* value;~Clear(){VariantClear(value);}} clear{&result};
    check(dispatch->Invoke(id,IID_NULL,LOCALE_INVARIANT,DISPATCH_PROPERTYGET,&parameters,&result,nullptr,nullptr),"connected_get");
    expect(result.vt==VT_I2||result.vt==VT_I4,"connected_type");return result.vt==VT_I2?result.iVal:result.lVal;
}
void print(const Report& r){
    std::printf("{\"schema\":\"native-input-contract/v1\",\"status\":\"%s\",\"error_hresult\":%ld,\"error_stage\":\"%s\",\"close_hresult\":%ld,",r.cleanup&&r.metadata&&r.qi&&r.error==S_OK?"verified":"failed",static_cast<long>(r.error),r.stage,static_cast<long>(r.close));
    std::printf("\"sta_verified\":%s,\"metadata_verified\":%s,\"qi_verified\":%s,\"connected_before\":%ld,\"connected_after\":%ld,\"cleanup_verified\":%s,\"ole_uninitialized\":%s,",r.sta?"true":"false",r.metadata?"true":"false",r.qi?"true":"false",static_cast<long>(r.connected_before),static_cast<long>(r.connected_after),r.cleanup?"true":"false",r.ole_uninitialized?"true":"false");
    std::printf("\"rdp_connect_called\":false,\"input_methods_called\":false,\"credentials_used\":false,\"remote_frame_verified\":false,\"input_delivery_verified\":false,\"physical_multiseat_verified\":false,\"methods\":[");
    for(std::size_t i=0;i<r.methods.size();++i){const auto& m=r.methods[i];std::printf("%s{\"name\":\"%s\",\"offset\":%d,\"parameters\":%d}",i?",":"",m.name,m.offset,m.parameters);}
    std::printf("],\"enums\":[");
    for(std::size_t i=0;i<r.enums.size();++i){const auto& e=r.enums[i];std::printf("%s{\"public_name\":\"%s\",\"public_kind\":%d,\"public_size\":%lu,\"alias_depth\":%u,\"target_name\":\"%s\",\"target_kind\":%d,\"target_size\":%lu,\"constants\":[",i?",":"",e.public_name.c_str(),static_cast<int>(e.public_kind),static_cast<unsigned long>(e.public_size),e.alias_depth,e.target_name.c_str(),static_cast<int>(e.target_kind),static_cast<unsigned long>(e.target_size));
        for(UINT j=0;j<e.count;++j){const auto& c=e.constants[j];std::printf("%s{\"name\":\"%s\",\"value\":%ld,\"declared_type\":%u,\"variant_type\":%u}",j?",":"",c.name.c_str(),static_cast<long>(c.value),static_cast<unsigned>(c.declared),static_cast<unsigned>(c.actual));}std::printf("]}");}
    std::printf("]}\n");
}
}
int main(){
    Report report;const HRESULT initialized=OleInitialize(nullptr);
    if(FAILED(initialized)){report.error=initialized;report.stage="ole_initialize";print(report);return 1;}
    Owner<IUnknown> control;Owner<IOleObject> ole;Owner<IDispatch> dispatch;Owner<IUnknown> sink;
    try{
        APTTYPE apartment{};APTTYPEQUALIFIER qualifier{};check(CoGetApartmentType(&apartment,&qualifier),"apartment_query");
        expect(apartment==APTTYPE_STA||apartment==APTTYPE_MAINSTA,"sta_required");report.sta=true;
        std::array<wchar_t,32768> path{};const UINT length=GetSystemDirectoryW(path.data(),static_cast<UINT>(path.size()));
        constexpr wchar_t suffix[]=L"\\mstscax.dll";expect(length>0&&length<path.size()&&length+std::size(suffix)<=path.size(),"system_path_length");
        std::memcpy(path.data()+length,suffix,sizeof(suffix));
        Owner<ITypeLib> library;check(LoadTypeLibEx(path.data(),REGKIND_NONE,&library.value),"type_library");expect(library.value!=nullptr,"null_type_library");
        metadata(library.value,report);
        check(CoCreateInstance(ControlId,nullptr,CLSCTX_INPROC_SERVER,IID_IUnknown,reinterpret_cast<void**>(&control.value)),"control_create");expect(control.value!=nullptr,"null_control");
        check(control->QueryInterface(IID_IOleObject,reinterpret_cast<void**>(&ole.value)),"ole_query");expect(ole.value!=nullptr,"null_ole");
        check(control->QueryInterface(IID_IDispatch,reinterpret_cast<void**>(&dispatch.value)),"dispatch_query");expect(dispatch.value!=nullptr,"null_dispatch");
        report.connected_before=connected(dispatch.value);expect(report.connected_before==0,"fresh_control_disconnected");
        check(control->QueryInterface(InputId,reinterpret_cast<void**>(&sink.value)),"input_query");expect(sink.value!=nullptr,"null_input");report.qi=true;
        report.connected_after=connected(dispatch.value);expect(report.connected_after==0,"control_remains_disconnected");
    }catch(const Error& e){report.error=e.value;report.stage=e.stage;}catch(...){report.error=E_UNEXPECTED;report.stage="native_exception";}
    sink.reset();dispatch.reset();if(ole.value)report.close=ole->Close(OLECLOSE_NOSAVE);ole.reset();control.reset();
    OleUninitialize();report.ole_uninitialized=true;report.cleanup=SUCCEEDED(report.close);
    print(report);return report.metadata&&report.qi&&report.cleanup&&SUCCEEDED(report.error)?0:1;
}
