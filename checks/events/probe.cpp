#include <winsock2.h>
#include <ws2tcpip.h>
#include "ole_host.hpp"
#include "event_sink.hpp"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <memory>

using namespace native_contract_probe;
using native_event_probe::EventSink;
using native_event_probe::RdpEvent;
using native_event_probe::RdpEventKind;
namespace {
constexpr CLSID ControlClass{0xa0c63c30,0xf08d,0x4ab4,{0x90,0x7c,0x34,0x90,0x5d,0x77,0x0c,0x7d}};
constexpr IID ExtendedId{0x302d8188,0x0052,0x4807,{0x80,0x6a,0x36,0x2b,0x62,0x8f,0x9a,0xc5}};
constexpr IID PromptId{0x4f6996d5,0xd7b1,0x412c,{0xb0,0xff,0x06,0x37,0x18,0x56,0x69,0x07}};
constexpr IID ClientId{0x92b4a539,0x7115,0x4b7c,{0xa5,0xa9,0xe5,0xd9,0xef,0xc2,0x78,0x0a}};
constexpr wchar_t WindowClass[] = L"NativeEventDeliveryProbeWindow";
constexpr ULONGLONG EventBudgetMs = 20000;
constexpr DWORD WatchdogMs = 45000;
struct EventRecord { unsigned kind{}; LONG code{}; ULONGLONG at{}; };
struct Result {
    const char* stage{"preflight"}; const char* operation{""}; HRESULT error{S_OK}, cleanup_error{S_OK};
    HRESULT advise_hresult{E_PENDING}, connect_hresult{E_PENDING}, request_close_hresult{E_PENDING}, unadvise_hresult{E_PENDING}, host_close_hresult{E_PENDING};
    int connected_before{-1}, connected_after{-1}, close_status{-1};
    unsigned event_count{}, connecting_sequence{}, disconnected_sequence{}, architecture{}, pointer_bits{sizeof(void*)*8};
    bool unavailable{}, environment_verified{}, non_system_verified{}, sta_verified{}, system_control_verified{};
    bool host_verified{}, parent_hidden{}, child_mode_disabled{}, credential_prompt_disabled{}, gateway_direct{}, reconnect_disabled{};
    bool listener_bound{}, listener_exclusive{}, listener_address_verified{}, listener_started{}, socket_accepted{}, peer_loopback{}, accepted_socket_closed{};
    bool advised{}, advise_cookie_nonzero{}, connect_called{}, connect_returned{}, event_overflow{}, callbacks_on_owner_thread{true};
    bool connecting_seen{}, disconnected_seen{}, login_seen{}, authentication_warning_seen{}, fatal_seen{}, event_contract_failed{};
    bool native_event_delivery_verified{}, request_close_called{}, request_close_verified{};
    bool disconnected_for_cleanup{}, sink_detached{true}, unadvised{true}, advise_cookie_cleared{true};
    bool references_released{true}, host_closed{true}, parent_destroyed{true}, class_unregistered{true};
    bool listener_thread_joined{true}, listener_socket_closed{true}, winsock_cleaned{true}, ole_uninitialized{true};
    bool watchdog_stopped{true}, watchdog_handles_closed{true}, cleanup_verified{};
    int socket_error{}, shutdown_error{};
    ULONGLONG accept_at{};
    std::array<EventRecord,64> events{};
};
void win32(bool ok, const char* stage) { if (!ok) throw Failure(stage, last_win32_error()); }
void socket_check(bool ok, const char* stage) { if (!ok) throw Failure(stage, HRESULT_FROM_WIN32(static_cast<DWORD>(WSAGetLastError()))); }
template<std::size_t N> [[noreturn]] void terminate_unverified(const char (&reason)[N], HRESULT error, DWORD wait) noexcept {
    static_assert(N <= 64);
    // A worker that did not join may still use its Probe/event handle. Keep all
    // contexts alive and stop only this disposable process, without unwinding.
    char record[384]{};
    const int length = std::snprintf(record, sizeof(record),
        "{\"schema\":\"native-event-delivery-termination/v1\",\"status\":\"cleanup_unverified\",\"reason\":\"%s\",\"cleanup_hresult\":%u,\"wait_result\":%u,\"cleanup_verified\":false,\"exit_code\":125}\n",
        reason, static_cast<unsigned>(static_cast<std::uint32_t>(error)), static_cast<unsigned>(wait));
    if (length > 0 && static_cast<std::size_t>(length) < sizeof(record)) {
        DWORD written{};
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), record, static_cast<DWORD>(length), &written, nullptr);
    }
    TerminateProcess(GetCurrentProcess(), 125);
    std::_Exit(125); // Also skips local destructors if the Win32 call returns.
}
bool environment_equals(const wchar_t* name, const wchar_t* value) {
    std::array<wchar_t,64> actual{};
    const DWORD size=GetEnvironmentVariableW(name,actual.data(),static_cast<DWORD>(actual.size()));
    return size>0 && size<actual.size() && std::wstring_view(actual.data(),size)==value;
}
HRESULT dispatch(IDispatch* object,const wchar_t* name,WORD flags,VARIANT* argument,VARIANT* result) {
    LPOLESTR member=const_cast<LPOLESTR>(name); DISPID id{};
    require(object->GetIDsOfNames(IID_NULL,&member,1,LOCALE_INVARIANT,&id),"dispatch_member");
    DISPPARAMS parameters{}; DISPID named=DISPID_PROPERTYPUT;
    parameters.rgvarg=argument; parameters.cArgs=argument?1U:0U;
    if(flags==DISPATCH_PROPERTYPUT){parameters.rgdispidNamedArgs=&named;parameters.cNamedArgs=1;}
    struct Exception {EXCEPINFO value{};~Exception(){erase_bstr(value.bstrSource);erase_bstr(value.bstrDescription);erase_bstr(value.bstrHelpFile);}} exception;
    UINT bad{}; const HRESULT status=object->Invoke(id,IID_NULL,LOCALE_INVARIANT,flags,&parameters,result,&exception.value,&bad);
    if(exception.value.pfnDeferredFillIn)exception.value.pfnDeferredFillIn(&exception.value);
    require(status,"dispatch_invocation");
    return status;
}
LONG number(const VARIANT& value) {
    if(value.vt==VT_I4)return value.lVal;
    if(value.vt==VT_I2)return value.iVal;
    if(value.vt==VT_UI4 && value.ulVal<=static_cast<ULONG>((std::numeric_limits<LONG>::max)()))return static_cast<LONG>(value.ulVal);
    throw Failure("numeric_property_type",DISP_E_TYPEMISMATCH);
}
int connected(IDispatch* object) {Value value;dispatch(object,L"Connected",DISPATCH_PROPERTYGET,nullptr,&value.value);const LONG state=number(value.value);check(state>=0&&state<=2,"connected_range");return static_cast<int>(state);}
void set_number(IDispatch* object,const wchar_t* name,LONG wanted,VARTYPE type=VT_I4) {
    Value value;value.value.vt=type;
    if(type==VT_BOOL)value.value.boolVal=static_cast<VARIANT_BOOL>(wanted);
    else if(type==VT_UI4)value.value.ulVal=static_cast<ULONG>(wanted);
    else value.value.lVal=wanted;
    Value ignored;dispatch(object,name,DISPATCH_PROPERTYPUT,&value.value,&ignored.value);
    Value actual;dispatch(object,name,DISPATCH_PROPERTYGET,nullptr,&actual.value);
    if(type==VT_BOOL)check(actual.value.vt==VT_BOOL&&actual.value.boolVal==value.value.boolVal,"boolean_property_readback");
    else check(number(actual.value)==wanted,"numeric_property_readback");
}
void set_string(IDispatch* object,const wchar_t* name,const wchar_t* wanted) {
    Value value;value.value.vt=VT_BSTR;value.value.bstrVal=SysAllocString(wanted);check(value.value.bstrVal!=nullptr,"literal_allocation",E_OUTOFMEMORY);
    Value ignored;dispatch(object,name,DISPATCH_PROPERTYPUT,&value.value,&ignored.value);
    Value actual;dispatch(object,name,DISPATCH_PROPERTYGET,nullptr,&actual.value);
    check(actual.value.vt==VT_BSTR && std::wstring_view(actual.value.bstrVal?actual.value.bstrVal:L"",actual.value.bstrVal?SysStringLen(actual.value.bstrVal):0)==wanted,"literal_property_readback");
}
ComPtr<IDispatch> child_object(IDispatch* object,const wchar_t* name) {
    Value value;dispatch(object,name,DISPATCH_PROPERTYGET,nullptr,&value.value);
    check(value.value.vt==VT_DISPATCH&&value.value.pdispVal,"property_dispatch_object",E_NOINTERFACE);
    ComPtr<IDispatch> result;result.copy_from(value.value.pdispVal);return result;
}
class VerifiedMethods final {
public:
    void create(IUnknown* control,ITypeLib* library,REFIID iid,std::initializer_list<MethodSpec> specs) {
        check(specs.size()>0&&specs.size()<=offsets_.size(),"native_specification_count");count_=specs.size();offsets_.fill(-1);
        ComPtr<ITypeInfo> info;require(library->GetTypeInfoOfGuid(iid,info.put()),"native_type_information");check(info.get()!=nullptr,"native_type_missing");
        bool dual{};{TypeAttribute type(info.get());dual=type.value->typekind==TKIND_DISPATCH&&(type.value->wTypeFlags&TYPEFLAG_FDUAL);}
        if(dual){HREFTYPE reference{};require(info->GetRefTypeOfImplType(static_cast<UINT>(-1),&reference),"resolve_dual_type");ComPtr<ITypeInfo> native;require(info->GetRefTypeInfo(reference,native.put()),"read_native_type");info=std::move(native);}
        check(info.get()!=nullptr,"native_type_missing");TypeAttribute type(info.get());
        check(type.value->guid==iid&&type.value->typekind==TKIND_INTERFACE&&type.value->cFuncs<=512&&type.value->cbSizeVft<=16384,"native_interface_shape",TYPE_E_TYPEMISMATCH);
        for(UINT i=0;i<type.value->cFuncs;++i){FunctionDescription method(info.get(),i);TextResult name;require(info->GetDocumentation(method.value->memid,&name.value,nullptr,nullptr,nullptr),"native_member_name");std::size_t n{};
            for(const auto& spec:specs){if(matches(name.view(),method.value->invkind,spec)){check(offsets_[n]<0,"duplicate_native_member",TYPE_E_AMBIGUOUSNAME);validate_method(info.get(),*type.value,*method.value,spec.signature);offsets_[n]=method.value->oVft;}++n;}}
        for(std::size_t i=0;i<count_;++i){check(offsets_[i]>=0,"native_member_missing",DISP_E_MEMBERNOTFOUND);for(std::size_t j=0;j<i;++j)check(offsets_[i]!=offsets_[j],"duplicate_native_offset",TYPE_E_TYPEMISMATCH);}
        object_=query<IUnknown>(control,iid,"verified_native_interface");
    }
    template<class Call>Call bind(std::size_t index)const{
        check(object_&&index<count_&&offsets_[index]>=0,"unverified_native_call");
        const auto table=*reinterpret_cast<void*const*const*>(object_.get());void* address=table[static_cast<std::size_t>(offsets_[index])/sizeof(void*)];check(address!=nullptr,"null_native_method");
        static_assert(sizeof(Call)==sizeof(address));Call result{};std::memcpy(&result,&address,sizeof(result));return result;
    }
    void* instance()const noexcept{return object_.get();}
    void reset()noexcept{object_.reset();count_=0;offsets_.fill(-1);}
private:ComPtr<IUnknown> object_;std::array<int,2>offsets_{{-1,-1}};std::size_t count_{};
};
class Probe final:public native_event_probe::RdpObserver {
public:
    explicit Probe(Result& result)noexcept:result_(result),owner_thread_(GetCurrentThreadId()),instance_(GetModuleHandleW(nullptr)){}
    ~Probe(){cleanup();}
    void on_rdp_event(RdpEvent event)noexcept override{
        if(GetCurrentThreadId()!=owner_thread_){result_.callbacks_on_owner_thread=false;return;}
        if(result_.event_count==result_.events.size()){result_.event_overflow=true;return;}
        const unsigned sequence=++result_.event_count;
        result_.events[sequence-1]={static_cast<unsigned>(event.kind),event.code,GetTickCount64()};
        switch(event.kind){
        case RdpEventKind::connecting:if(!result_.connecting_seen)result_.connecting_sequence=sequence;result_.connecting_seen=true;break;
        case RdpEventKind::disconnected:if(!result_.disconnected_seen)result_.disconnected_sequence=sequence;result_.disconnected_seen=true;break;
        case RdpEventKind::login_complete:result_.login_seen=true;break;
        case RdpEventKind::authentication_warning:result_.authentication_warning_seen=true;break;
        case RdpEventKind::fatal_error:result_.fatal_seen=true;break;
        case RdpEventKind::event_contract_failure:result_.event_contract_failed=true;break;
        default:break;}
    }
    bool allow_rdp_close()noexcept override{return close_allowed_;}
    void run(){
        SYSTEM_INFO system{};GetNativeSystemInfo(&system);result_.architecture=system.wProcessorArchitecture;
        result_.environment_verified=environment_equals(L"GITHUB_ACTIONS",L"true")&&environment_equals(L"RUNNER_ENVIRONMENT",L"github-hosted")&&environment_equals(L"RUNNER_OS",L"Windows");
        if(!result_.environment_verified){result_.unavailable=true;throw Failure("disposable_hosted_runner_required",E_ACCESSDENIED);}
        DWORD session{};win32(ProcessIdToSessionId(GetCurrentProcessId(),&session)!=FALSE,"process_session");
        if(!session){result_.unavailable=true;throw Failure("session_zero_unsupported",E_ACCESSDENIED);}
        HANDLE token{};win32(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=FALSE,"open_current_process_token");
        struct Token{HANDLE value;~Token(){CloseHandle(value);}}owned_token{token};
        alignas(TOKEN_USER)std::array<BYTE,sizeof(TOKEN_USER)+SECURITY_MAX_SID_SIZE> user{};DWORD needed{};
        win32(GetTokenInformation(token,TokenUser,user.data(),static_cast<DWORD>(user.size()),&needed)!=FALSE,"current_token_user");
        result_.non_system_verified=IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,WinLocalSystemSid)==FALSE;
        check(result_.non_system_verified,"system_identity_unsupported",E_ACCESSDENIED);
        start_watchdog();result_.stage="ole_initialize";require(OleInitialize(nullptr),"ole_initialize");ole_started_=true;result_.ole_uninitialized=false;
        APTTYPE apartment{};APTTYPEQUALIFIER qualifier{};require(CoGetApartmentType(&apartment,&qualifier),"apartment_type");result_.sta_verified=apartment==APTTYPE_STA||apartment==APTTYPE_MAINSTA;check(result_.sta_verified,"sta_required");
        create_listener();create_host();configure();subscribe();
        check(result_.event_count==0,"unexpected_preconnect_event");
        result_.stage="connect_owned_loopback";connect_at_=GetTickCount64();
        listener_thread_=CreateThread(nullptr,0,&listener_entry,this,0,nullptr);win32(listener_thread_!=nullptr,"listener_thread");result_.listener_started=true;result_.listener_thread_joined=false;
        result_.connect_called=true;
        try{Value ignored;result_.connect_hresult=dispatch(automation_.get(),L"Connect",DISPATCH_METHOD,nullptr,&ignored.value);result_.connect_returned=true;}
        catch(const Failure& error){result_.connect_hresult=error.result();throw;}
        check(result_.connect_hresult==S_OK,"connect_noncanonical_success");
        const ULONGLONG end=GetTickCount64()+EventBudgetMs;
        while(GetTickCount64()<end){
            pump(50);snapshot_socket();
            check(!result_.event_overflow&&result_.callbacks_on_owner_thread&&!result_.event_contract_failed,"event_contract_failure");
            check(!result_.login_seen&&!result_.authentication_warning_seen&&!result_.fatal_seen,"unexpected_protocol_progress");
            check(visible_thread_windows()==0,"unexpected_visible_own_thread_window");
            if(socket_finished_.load(std::memory_order_acquire)&&result_.socket_error)throw Failure("owned_listener_failed",HRESULT_FROM_WIN32(static_cast<DWORD>(result_.socket_error)));
            if(result_.connecting_seen&&result_.disconnected_seen&&socket_finished_.load(std::memory_order_acquire)&&connected(automation_.get())==0)break;
        }
        snapshot_socket();result_.connected_after=connected(automation_.get());
        check(result_.socket_accepted&&result_.peer_loopback&&result_.accepted_socket_closed&&result_.socket_error==0&&result_.shutdown_error==0,"owned_socket_evidence_missing");
        check(result_.connecting_seen&&result_.disconnected_seen&&result_.connecting_sequence<result_.disconnected_sequence&&result_.connected_after==0,"native_event_deadline_or_order",HRESULT_FROM_WIN32(WAIT_TIMEOUT));
        const auto& last=result_.events[result_.disconnected_sequence-1];
        check(result_.accept_at>=connect_at_&&result_.accept_at<=last.at,"socket_event_order");
        result_.native_event_delivery_verified=true;
        result_.stage="request_close_after_disconnected";
        // This call is never used to force an unknown or active state closed.
        check(connected(automation_.get())==0,"request_close_requires_disconnected");close_allowed_=true;
        using Close=HRESULT(STDMETHODCALLTYPE*)(void*,LONG*);LONG status=-1;
        result_.request_close_called=true;result_.request_close_hresult=close_.bind<Close>(0)(close_.instance(),&status);result_.close_status=status;
        require(result_.request_close_hresult,"request_close_call");check(result_.request_close_hresult==S_OK&&status==0,"request_close_not_can_proceed");result_.request_close_verified=true;
        result_.stage="completed";
    }
    void cleanup()noexcept{
        if(cleaned_)return;
        cleaned_=true;
        auto attempt=[&](auto action){try{action();}catch(const Failure& error){cleanup_failure(error.result());}catch(const native_ole_probe::Failure& error){cleanup_failure(error.result());}catch(...){cleanup_failure(E_UNEXPECTED);}};
        stop_listener_.store(true,std::memory_order_release);
        bool safe_host_close=!automation_;
        if(automation_)attempt([&]{
            if(connected(automation_.get())!=0){Value ignored;dispatch(automation_.get(),L"Disconnect",DISPATCH_METHOD,nullptr,&ignored.value);const ULONGLONG end=GetTickCount64()+5000;while(GetTickCount64()<end&&connected(automation_.get())!=0)pump(50);}
            safe_host_close=connected(automation_.get())==0;result_.disconnected_for_cleanup=safe_host_close;check(safe_host_close,"cleanup_connected_state_unknown",E_PENDING);
        });
        close_allowed_=safe_host_close;
        if(sink_){sink_->detach();result_.sink_detached=true;}
        if(cookie_&&point_){result_.unadvise_hresult=point_->Unadvise(cookie_);result_.unadvised=result_.unadvise_hresult==S_OK;if(result_.unadvised){cookie_=0;result_.advise_cookie_cleared=true;}else cleanup_failure(result_.unadvise_hresult);}
        point_.reset();sink_.reset();extended_.reset();prompt_.reset();close_.reset();automation_.reset();library_.reset();
        if(safe_host_close){
            if(host_){result_.host_close_hresult=host_->close();result_.host_closed=result_.host_close_hresult==S_OK;if(!result_.host_closed)cleanup_failure(result_.host_close_hresult);host_.reset();}
            result_.references_released=true;
            if(window_){const HWND original=window_;const BOOL removed=DestroyWindow(window_);result_.parent_destroyed=removed&&!IsWindow(original);if(!result_.parent_destroyed)cleanup_failure(last_win32_error());}
            if(registered_){result_.class_unregistered=UnregisterClassW(WindowClass,instance_)!=FALSE;if(!result_.class_unregistered)cleanup_failure(last_win32_error());registered_=0;}
            if(ole_started_){OleUninitialize();ole_started_=false;result_.ole_uninitialized=true;}
        }else{
            // A failed/cancelled test cannot claim a completed protocol teardown.
            // Leave the still-owned host/HWND to this disposable process's exit;
            // do not call RequestClose or an OLE close on an unknown state.
            (void)host_.release();result_.references_released=false;cleanup_failure(E_PENDING);
        }
        if(listener_thread_){
            const DWORD wait=WaitForSingleObject(listener_thread_,5000);result_.listener_thread_joined=wait==WAIT_OBJECT_0;
            if(!result_.listener_thread_joined){
                const HRESULT error=wait==WAIT_FAILED?last_win32_error():HRESULT_FROM_WIN32(WAIT_TIMEOUT);
                cleanup_failure(error);terminate_unverified("listener_join_unverified",error,wait);
            }
            if(!CloseHandle(listener_thread_))cleanup_failure(last_win32_error());
            listener_thread_=nullptr;
        }
        snapshot_socket();
        if(result_.listener_thread_joined&&listener_!=INVALID_SOCKET){result_.listener_socket_closed=closesocket(listener_)==0;if(!result_.listener_socket_closed)cleanup_failure(HRESULT_FROM_WIN32(static_cast<DWORD>(WSAGetLastError())));listener_=INVALID_SOCKET;}
        if(wsa_started_&&result_.listener_thread_joined&&result_.listener_socket_closed){result_.winsock_cleaned=WSACleanup()==0;if(!result_.winsock_cleaned)cleanup_failure(HRESULT_FROM_WIN32(static_cast<DWORD>(WSAGetLastError())));wsa_started_=false;}
        stop_watchdog();
        result_.cleanup_verified=SUCCEEDED(result_.cleanup_error)&&result_.sink_detached&&result_.unadvised&&result_.advise_cookie_cleared&&result_.references_released&&result_.host_closed&&result_.parent_destroyed&&result_.class_unregistered&&result_.listener_thread_joined&&result_.listener_socket_closed&&result_.winsock_cleaned&&result_.ole_uninitialized&&result_.watchdog_stopped&&result_.watchdog_handles_closed&&(!result_.socket_accepted||result_.accepted_socket_closed)&&(!result_.connect_called||result_.disconnected_for_cleanup);
    }
private:
    void cleanup_failure(HRESULT value)noexcept{if(SUCCEEDED(result_.cleanup_error))result_.cleanup_error=FAILED(value)?value:E_FAIL;}
    static DWORD WINAPI watchdog_entry(void* event)noexcept{
        const DWORD wait=WaitForSingleObject(static_cast<HANDLE>(event),WatchdogMs);
        if(wait==WAIT_OBJECT_0)return 0;
        const HRESULT error=wait==WAIT_FAILED?last_win32_error():HRESULT_FROM_WIN32(WAIT_TIMEOUT);
        terminate_unverified("watchdog_deadline_or_wait",error,wait);
    }
    void start_watchdog(){watchdog_stop_=CreateEventW(nullptr,TRUE,FALSE,nullptr);win32(watchdog_stop_!=nullptr,"watchdog_event");result_.watchdog_handles_closed=false;watchdog_thread_=CreateThread(nullptr,0,&watchdog_entry,watchdog_stop_,0,nullptr);win32(watchdog_thread_!=nullptr,"watchdog_thread");result_.watchdog_stopped=false;}
    void stop_watchdog()noexcept{
        bool handles=true;
        if(watchdog_thread_){
            if(!SetEvent(watchdog_stop_)){
                const HRESULT error=last_win32_error();result_.watchdog_stopped=false;cleanup_failure(error);
                terminate_unverified("watchdog_signal_failed",error,WAIT_FAILED);
            }
            const DWORD wait=WaitForSingleObject(watchdog_thread_,5000);result_.watchdog_stopped=wait==WAIT_OBJECT_0;
            if(!result_.watchdog_stopped){
                const HRESULT error=wait==WAIT_FAILED?last_win32_error():HRESULT_FROM_WIN32(WAIT_TIMEOUT);
                cleanup_failure(error);terminate_unverified("watchdog_join_unverified",error,wait);
            }
            handles=CloseHandle(watchdog_thread_)!=FALSE;watchdog_thread_=nullptr;
        }
        if(watchdog_stop_){handles=(CloseHandle(watchdog_stop_)!=FALSE)&&handles;watchdog_stop_=nullptr;}
        result_.watchdog_handles_closed=handles;if(!handles)cleanup_failure(last_win32_error());
    }
    void create_listener(){
        result_.stage="owned_loopback_listener";WSADATA data{};const int start=WSAStartup(MAKEWORD(2,2),&data);check(start==0,"winsock_start",HRESULT_FROM_WIN32(static_cast<DWORD>(start)));wsa_started_=true;result_.winsock_cleaned=false;
        listener_=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);socket_check(listener_!=INVALID_SOCKET,"listener_socket");result_.listener_socket_closed=false;
        BOOL exclusive=TRUE;socket_check(setsockopt(listener_,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))==0,"exclusive_listener");
        BOOL actual=FALSE;int length=sizeof(actual);socket_check(getsockopt(listener_,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<char*>(&actual),&length)==0,"exclusive_readback");result_.listener_exclusive=length==sizeof(actual)&&actual!=FALSE;check(result_.listener_exclusive,"exclusive_listener_not_observed");
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=0;
        socket_check(bind(listener_,reinterpret_cast<const sockaddr*>(&address),sizeof(address))==0,"bind_owned_loopback");result_.listener_bound=true;
        length=sizeof(address);socket_check(getsockname(listener_,reinterpret_cast<sockaddr*>(&address),&length)==0,"owned_listener_address");port_=ntohs(address.sin_port);result_.listener_address_verified=length==sizeof(address)&&address.sin_family==AF_INET&&address.sin_addr.s_addr==htonl(INADDR_LOOPBACK)&&port_>0;check(result_.listener_address_verified,"owned_loopback_address_mismatch");
        u_long nonblocking=1;socket_check(ioctlsocket(listener_,FIONBIO,&nonblocking)==0,"listener_nonblocking");socket_check(listen(listener_,1)==0,"owned_listener_listen");
    }
    static DWORD WINAPI listener_entry(void* context)noexcept{return static_cast<Probe*>(context)->accept_once();}
    DWORD accept_once()noexcept{
        const ULONGLONG end=GetTickCount64()+EventBudgetMs;
        while(!stop_listener_.load(std::memory_order_acquire)&&GetTickCount64()<end){
            fd_set descriptors;FD_ZERO(&descriptors);FD_SET(listener_,&descriptors);timeval timeout{0,100000};
            const int ready=select(0,&descriptors,nullptr,nullptr,&timeout);
            if(ready==SOCKET_ERROR){socket_error_.store(WSAGetLastError());break;}
            if(!ready||stop_listener_.load(std::memory_order_acquire))continue;
            sockaddr_in peer{};int length=sizeof(peer);const SOCKET accepted=accept(listener_,reinterpret_cast<sockaddr*>(&peer),&length);
            if(accepted==INVALID_SOCKET){const int error=WSAGetLastError();if(error==WSAEWOULDBLOCK)continue;socket_error_.store(error);break;}
            accept_at_.store(GetTickCount64());accepted_.store(true);peer_loopback_.store(length==sizeof(peer)&&peer.sin_family==AF_INET&&peer.sin_addr.s_addr==htonl(INADDR_LOOPBACK));
            // No recv/send, no protocol parser, no RDP/TLS/authentication reply.
            // The client's initial negotiation may already exist in the kernel queue.
            if(shutdown(accepted,SD_BOTH)==SOCKET_ERROR)shutdown_error_.store(WSAGetLastError());
            const bool closed=closesocket(accepted)==0;accepted_closed_.store(closed);
            if(!closed)socket_error_.store(WSAGetLastError());
            break;
        }
        socket_finished_.store(true,std::memory_order_release);return 0;
    }
    void snapshot_socket()noexcept{
        result_.socket_accepted=accepted_.load();result_.peer_loopback=peer_loopback_.load();result_.accepted_socket_closed=accepted_closed_.load();result_.accept_at=accept_at_.load();result_.socket_error=socket_error_.load();result_.shutdown_error=shutdown_error_.load();
    }
    static LRESULT CALLBACK window_proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam)noexcept{
        if(message==WM_CLOSE)return 0;
        return DefWindowProcW(window,message,wparam,lparam);
    }
    void create_host(){
        result_.stage="hidden_ole_host";WNDCLASSEXW type{};type.cbSize=sizeof(type);type.hInstance=instance_;type.lpfnWndProc=&window_proc;type.lpszClassName=WindowClass;
        registered_=RegisterClassExW(&type);win32(registered_!=0,"register_owned_window_class");result_.class_unregistered=false;
        window_=CreateWindowExW(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE,WindowClass,L"Native event delivery check",WS_POPUP|WS_CLIPCHILDREN,0,0,1024,768,nullptr,nullptr,instance_,nullptr);win32(window_!=nullptr,"create_hidden_parent");result_.parent_destroyed=false;
        host_=std::make_unique<native_ole_probe::OleControlHost>(window_);result_.host_closed=false;result_.references_released=false;
        const RECT bounds{0,0,1024,768};host_->create(ControlClass,bounds,L"Native event delivery check");
        auto ole=query<IOleObject>(host_->object(),IID_IOleObject,"control_ole_identity");CLSID clsid{};require(ole->GetUserClassID(&clsid),"control_class");check(clsid==ControlClass,"control_class_mismatch");
        auto in_place=query<IOleInPlaceObject>(host_->object(),IID_IOleInPlaceObject,"control_in_place");HWND child{};require(in_place->GetWindow(&child),"control_native_window");
        result_.host_verified=child&&IsWindow(child)&&IsChild(window_,child)&&host_->observation().in_place_active;
        result_.parent_hidden=IsWindowVisible(window_)==FALSE;check(result_.host_verified&&result_.parent_hidden,"hidden_host_not_verified");
        std::array<wchar_t,32768> expected{},loaded{};const UINT length=GetSystemDirectoryW(expected.data(),static_cast<UINT>(expected.size()));constexpr wchar_t suffix[]=L"\\mstscax.dll";
        check(length&&length+std::size(suffix)<=expected.size(),"system_control_path");std::memcpy(expected.data()+length,suffix,sizeof(suffix));
        const HMODULE module=GetModuleHandleW(L"mstscax.dll");check(module!=nullptr,"system_control_module_not_loaded");const DWORD count=GetModuleFileNameW(module,loaded.data(),static_cast<DWORD>(loaded.size()));
        result_.system_control_verified=count>0&&count<loaded.size()&&CompareStringOrdinal(loaded.data(),static_cast<int>(count),expected.data(),-1,TRUE)==CSTR_EQUAL;check(result_.system_control_verified,"system_control_module_mismatch");
        require(LoadTypeLibEx(expected.data(),REGKIND_NONE,library_.put()),"load_same_system_typelib");check(library_.get()!=nullptr,"system_typelib_missing");
        automation_=query<IDispatch>(host_->object(),IID_IDispatch,"control_automation");result_.connected_before=connected(automation_.get());check(result_.connected_before==0,"fresh_control_not_disconnected");
    }
    void configure(){
        result_.stage="configure_exact_loopback";
        extended_.create(host_->object(),library_.get(),ExtendedId,{{L"Property",INVOKE_PROPERTYPUT,Signature::property_in},{L"Property",INVOKE_PROPERTYGET,Signature::property_out}});
        prompt_.create(host_->object(),library_.get(),PromptId,{{L"AllowPromptingForCredentials",INVOKE_PROPERTYPUT,Signature::boolean_in},{L"AllowPromptingForCredentials",INVOKE_PROPERTYGET,Signature::boolean_out}});
        close_.create(host_->object(),library_.get(),ClientId,{{L"RequestClose",INVOKE_FUNC,Signature::close_out}});
        using Property=HRESULT(STDMETHODCALLTYPE*)(void*,BSTR,VARIANT*);String name(L"ConnectToChildSession");Value desired;desired.value.vt=VT_BOOL;desired.value.boolVal=VARIANT_FALSE;
        require(extended_.bind<Property>(0)(extended_.instance(),name.value,&desired.value),"disable_child_connection");Value actual;require(extended_.bind<Property>(1)(extended_.instance(),name.value,&actual.value),"read_child_connection");result_.child_mode_disabled=actual.value.vt==VT_BOOL&&actual.value.boolVal==VARIANT_FALSE;check(result_.child_mode_disabled,"child_connection_not_disabled");
        using Put=HRESULT(STDMETHODCALLTYPE*)(void*,VARIANT_BOOL);using Get=HRESULT(STDMETHODCALLTYPE*)(void*,VARIANT_BOOL*);
        require(prompt_.bind<Put>(0)(prompt_.instance(),VARIANT_FALSE),"disable_credentials_prompt");VARIANT_BOOL prompt=VARIANT_TRUE;require(prompt_.bind<Get>(1)(prompt_.instance(),&prompt),"read_credentials_prompt");result_.credential_prompt_disabled=prompt==VARIANT_FALSE;check(result_.credential_prompt_disabled,"credentials_prompt_not_disabled");
        set_string(automation_.get(),L"Server",L"127.0.0.1");set_number(automation_.get(),L"DesktopWidth",1024);set_number(automation_.get(),L"DesktopHeight",768);set_number(automation_.get(),L"ColorDepth",32);
        auto advanced=child_object(automation_.get(),L"AdvancedSettings9");set_number(advanced.get(),L"RDPPort",port_);set_number(advanced.get(),L"EnableAutoReconnect",VARIANT_FALSE,VT_BOOL);result_.reconnect_disabled=true;
        // Only this fresh control's routing changes; no auth/trust/policy edits.
        auto transport=child_object(automation_.get(),L"TransportSettings2");set_number(transport.get(),L"GatewayUsageMethod",0,VT_UI4);result_.gateway_direct=true;
        check(connected(automation_.get())==0,"configuration_connected_control");
    }
    void subscribe(){
        result_.stage="subscribe_exact_event_sink";sink_.attach(new EventSink(library_.get(),*this));result_.sink_detached=false;
        auto container=query<IConnectionPointContainer>(host_->object(),IID_IConnectionPointContainer,"connection_point_container");require(container->FindConnectionPoint(native_event_probe::EventsInterface,point_.put()),"find_events_connection_point");check(point_.get()!=nullptr,"events_connection_point_missing");
        IID iid{};require(point_->GetConnectionInterface(&iid),"connection_interface");check(iid==native_event_probe::EventsInterface,"connection_interface_mismatch");
        result_.advise_hresult=point_->Advise(static_cast<IDispatch*>(sink_.get()),&cookie_);
        if(cookie_){result_.unadvised=false;result_.advise_cookie_cleared=false;}
        require(result_.advise_hresult,"advise_events");check(result_.advise_hresult==S_OK,"advise_noncanonical_success");
        result_.advised=true;result_.advise_cookie_nonzero=cookie_!=0;check(result_.advise_cookie_nonzero,"advise_cookie_missing");
    }
    void pump(DWORD wait){
        const DWORD state=MsgWaitForMultipleObjectsEx(0,nullptr,wait,QS_ALLINPUT,MWMO_INPUTAVAILABLE);if(state==WAIT_FAILED)throw Failure("message_wait",last_win32_error());
        MSG message{};unsigned count{};while(count++<256&&PeekMessageW(&message,nullptr,0,0,PM_REMOVE)){if(message.message==WM_QUIT)throw Failure("unexpected_thread_quit",E_ABORT);TranslateMessage(&message);DispatchMessageW(&message);}
    }
    static BOOL CALLBACK count_visible(HWND window,LPARAM parameter)noexcept{if(IsWindowVisible(window))++*reinterpret_cast<unsigned*>(parameter);return TRUE;}
    unsigned visible_thread_windows(){unsigned count{};win32(EnumThreadWindows(owner_thread_,&count_visible,reinterpret_cast<LPARAM>(&count))!=FALSE,"own_thread_window_observation");return count;}
    Result& result_;DWORD owner_thread_{};HINSTANCE instance_{};HWND window_{};ATOM registered_{};bool cleaned_{},ole_started_{},wsa_started_{},close_allowed_{};DWORD cookie_{};USHORT port_{};ULONGLONG connect_at_{};
    HANDLE watchdog_stop_{},watchdog_thread_{},listener_thread_{};SOCKET listener_{INVALID_SOCKET};
    std::atomic<bool>stop_listener_{false},socket_finished_{false},accepted_{false},peer_loopback_{false},accepted_closed_{false};std::atomic<int>socket_error_{0},shutdown_error_{0};std::atomic<ULONGLONG>accept_at_{0};
    std::unique_ptr<native_ole_probe::OleControlHost>host_;ComPtr<ITypeLib>library_;ComPtr<IDispatch>automation_;ComPtr<IConnectionPoint>point_;ComPtr<EventSink>sink_;VerifiedMethods extended_,prompt_,close_;
};
int report(const Result& r,ULONGLONG elapsed){
    const bool passed=SUCCEEDED(r.error)&&r.environment_verified&&r.non_system_verified&&r.sta_verified&&r.system_control_verified&&r.host_verified&&r.parent_hidden&&r.child_mode_disabled&&r.credential_prompt_disabled&&r.gateway_direct&&r.reconnect_disabled&&r.listener_bound&&r.listener_exclusive&&r.listener_address_verified&&r.listener_started&&r.advised&&r.advise_cookie_nonzero&&r.connect_called&&r.connect_returned&&r.connect_hresult==S_OK&&r.native_event_delivery_verified&&r.request_close_verified&&r.callbacks_on_owner_thread&&!r.event_overflow&&!r.event_contract_failed&&!r.login_seen&&!r.authentication_warning_seen&&!r.fatal_seen&&r.cleanup_verified;
    std::cout<<std::boolalpha<<"{\"schema\":\"native-event-delivery/v1\",\"status\":\""<<(passed?"verified":r.unavailable&&r.cleanup_verified?"unavailable":"failed")<<"\",\"stage\":\""<<r.stage<<"\",\"operation\":\""<<r.operation<<"\",\"error_hresult\":"<<static_cast<std::int32_t>(r.error)<<",\"cleanup_hresult\":"<<static_cast<std::int32_t>(r.cleanup_error)<<",\"elapsed_ms\":"<<elapsed;
#define FIELD(name) std::cout<<",\"" #name "\":"<<r.name
    FIELD(architecture);FIELD(pointer_bits);FIELD(environment_verified);FIELD(non_system_verified);FIELD(sta_verified);FIELD(system_control_verified);FIELD(host_verified);FIELD(parent_hidden);FIELD(child_mode_disabled);FIELD(credential_prompt_disabled);FIELD(gateway_direct);FIELD(reconnect_disabled);FIELD(listener_bound);FIELD(listener_exclusive);FIELD(listener_address_verified);FIELD(listener_started);FIELD(socket_accepted);FIELD(peer_loopback);FIELD(accepted_socket_closed);FIELD(socket_error);FIELD(shutdown_error);FIELD(advised);FIELD(advise_cookie_nonzero);FIELD(connect_called);FIELD(connect_returned);FIELD(connected_before);FIELD(connected_after);FIELD(event_count);FIELD(connecting_sequence);FIELD(disconnected_sequence);FIELD(callbacks_on_owner_thread);FIELD(event_overflow);FIELD(event_contract_failed);FIELD(connecting_seen);FIELD(disconnected_seen);FIELD(login_seen);FIELD(authentication_warning_seen);FIELD(fatal_seen);FIELD(native_event_delivery_verified);FIELD(request_close_called);FIELD(request_close_verified);FIELD(close_status);FIELD(disconnected_for_cleanup);FIELD(sink_detached);FIELD(unadvised);FIELD(advise_cookie_cleared);FIELD(references_released);FIELD(host_closed);FIELD(parent_destroyed);FIELD(class_unregistered);FIELD(listener_thread_joined);FIELD(listener_socket_closed);FIELD(winsock_cleaned);FIELD(ole_uninitialized);FIELD(watchdog_stopped);FIELD(watchdog_handles_closed);FIELD(cleanup_verified);
#undef FIELD
    std::cout<<",\"advise_hresult\":"<<static_cast<std::int32_t>(r.advise_hresult)<<",\"connect_hresult\":"<<static_cast<std::int32_t>(r.connect_hresult)<<",\"request_close_hresult\":"<<static_cast<std::int32_t>(r.request_close_hresult)<<",\"unadvise_hresult\":"<<static_cast<std::int32_t>(r.unadvise_hresult)<<",\"host_close_hresult\":"<<static_cast<std::int32_t>(r.host_close_hresult)<<",\"events\":[";
    for(unsigned i=0;i<r.event_count;++i){if(i)std::cout<<',';std::cout<<"{\"sequence\":"<<i+1<<",\"kind\":"<<r.events[i].kind<<",\"code\":"<<r.events[i].code<<'}';}
    std::cout<<"],\"synthetic_invoke_called\":false,\"listener_recv_called\":false,\"listener_send_called\":false,\"server_protocol_reply_sent\":false,\"credentials_provided\":false,\"password_methods_called\":false,\"child_feature_changed\":false,\"accounts_created\":false,\"session_creation_verified\":false,\"remote_frame_verified\":false,\"input_channel_verified\":false,\"physical_multiseat_verified\":false}"<<std::endl;
    return passed?0:r.unavailable&&r.cleanup_verified?77:1;
}
} // namespace
int main(){const ULONGLONG started=GetTickCount64();Result result;Probe probe(result);
    try{probe.run();}catch(const Failure& error){result.operation=error.what();result.error=error.result();}catch(const native_ole_probe::Failure& error){result.operation=error.what();result.error=error.result();}catch(...){result.operation="unexpected_cpp_exception";result.error=E_UNEXPECTED;}
    probe.cleanup();return report(result,GetTickCount64()-started);
}
