#include "bridge.hpp"
#include "ole_host.hpp"
#include "event_sink.hpp"
#include <array>
#include <algorithm>
#include <memory>
#include <new>

namespace {
using native_contract_probe::ComPtr;
using native_contract_probe::Failure;
using native_contract_probe::require;
using native_contract_probe::query;
constexpr CLSID ControlClass{0xa0c63c30,0xf08d,0x4ab4,{0x90,0x7c,0x34,0x90,0x5d,0x77,0x0c,0x7d}};

struct State final : native_event_probe::RdpObserver {
    DWORD owner{GetCurrentThreadId()};
    HWND parent{}, control_window{};
    bool ole_initialized{}, abandoned{};
    unsigned external_depth{};
    std::unique_ptr<native_ole_probe::OleControlHost> host;
    ComPtr<ITypeLib> library;
    ComPtr<IConnectionPoint> point;
    ComPtr<native_event_probe::EventSink> sink;
    DWORD cookie{};
    NativeHostSnapshot record{};
    std::array<NativeHostEvent,256> events{};

    void on_rdp_event(native_event_probe::RdpEvent event) noexcept override {
        if (record.event_count == events.size()) { record.event_overflow = 1; return; }
        const auto sequence = ++record.event_count;
        events[sequence - 1] = {sequence, static_cast<std::uint32_t>(event.kind), event.code};
        using Kind = native_event_probe::RdpEventKind;
        if (event.kind == Kind::connecting && !record.connecting_sequence) record.connecting_sequence = sequence;
        if (event.kind == Kind::connected && !record.connected_sequence) record.connected_sequence = sequence;
        if (event.kind == Kind::login_complete && !record.login_sequence) record.login_sequence = sequence;
        if (event.kind == Kind::disconnected && !record.disconnected_sequence) record.disconnected_sequence = sequence;
        if (event.kind == Kind::event_contract_failure) record.event_contract_failed = 1;
    }
    bool allow_rdp_close() noexcept override { return record.cleanup_started != 0; }
};

State& checked(void* context) {
    if (!context) throw Failure("native_host_context_missing", E_POINTER);
    auto& state = *static_cast<State*>(context);
    if (state.owner != GetCurrentThreadId()) throw Failure("native_host_wrong_thread", RPC_E_WRONG_THREAD);
    if (state.abandoned) throw Failure("native_host_abandoned", E_UNEXPECTED);
    return state;
}
struct ExternalCall final {
    State& state;
    explicit ExternalCall(State& value) : state(value) { ++state.external_depth; }
    ~ExternalCall() { --state.external_depth; }
};

template<class Function> HRESULT guarded(Function function) noexcept {
    try { return function(); }
    catch (const Failure& failure) { return failure.result(); }
    catch (const native_ole_probe::Failure& failure) { return failure.result(); }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}

void snapshot(State& state, NativeHostSnapshot& out) {
    const auto observation = state.host->observation();
    state.record.client_site_attached = observation.client_site_attached;
    state.record.in_place_active = observation.in_place_active;
    state.record.ui_active = observation.ui_active;
    state.record.control_window_is_child = observation.control_window_is_child;
    state.record.activation_count = observation.in_place_activation_count;
    out = state.record;
}

ComPtr<ITypeLib> load_system_library() {
    std::array<wchar_t,32768> path{};
    const UINT count = GetSystemDirectoryW(path.data(), static_cast<UINT>(path.size()));
    constexpr wchar_t suffix[] = L"\\mstscax.dll";
    if (!count || count >= path.size() || count + std::size(suffix) > path.size())
        throw Failure("native_host_system_library_path", E_UNEXPECTED);
    std::copy(std::begin(suffix), std::end(suffix), path.begin() + count);
    ComPtr<ITypeLib> library;
    require(LoadTypeLibEx(path.data(), REGKIND_NONE, library.put()), "native_host_system_library");
    if (!library) throw Failure("native_host_system_library_missing", E_UNEXPECTED);
    return library;
}

bool disconnected(State& state) {
    // Independent read-only close precondition, not the product Dispatch class.
    auto dispatch = query<IDispatch>(state.host->object(), IID_IDispatch, "native_host_state_dispatch");
    wchar_t name[] = L"Connected"; LPOLESTR names[] = {name}; DISPID id{};
    require(dispatch->GetIDsOfNames(IID_NULL,names,1,LOCALE_INVARIANT,&id), "native_host_state_identifier");
    DISPPARAMS parameters{}; native_contract_probe::Value value;
    struct Exception final {
        EXCEPINFO info{};
        ~Exception() {
            native_contract_probe::erase_bstr(info.bstrSource);
            native_contract_probe::erase_bstr(info.bstrDescription);
            native_contract_probe::erase_bstr(info.bstrHelpFile);
        }
    } error;
    const HRESULT result = dispatch->Invoke(id,IID_NULL,LOCALE_INVARIANT,DISPATCH_PROPERTYGET,
        &parameters,&value.value,&error.info,nullptr);
    if (error.info.pfnDeferredFillIn) error.info.pfnDeferredFillIn(&error.info);
    require(result,"native_host_state_read");
    if (value.value.vt == VT_I2) return value.value.iVal == 0;
    if (value.value.vt == VT_I4) return value.value.lVal == 0;
    throw Failure("native_host_state_type", DISP_E_TYPEMISMATCH);
}

HRESULT release_state(State* state, NativeHostSnapshot* out) noexcept {
    HRESULT first = S_OK;
    auto remember = [&first](HRESULT value) { if (FAILED(value) && SUCCEEDED(first)) first = value; };
    state->record.cleanup_started = 1;
    if (state->sink) state->sink->detach();
    state->record.sink_detached = 1;
    if (state->point && state->cookie) {
        state->record.unadvise_hresult = state->point->Unadvise(state->cookie);
        remember(state->record.unadvise_hresult);
        state->record.unadvised = SUCCEEDED(state->record.unadvise_hresult);
        if (state->record.unadvised) state->cookie = 0;
    } else state->record.unadvised = 1;
    state->point.reset(); state->sink.reset(); state->library.reset();
    if (state->host) {
        state->record.host_close_hresult = state->host->close();
        remember(state->record.host_close_hresult);
        state->record.host_closed = SUCCEEDED(state->record.host_close_hresult);
        state->host.reset();
    }
    state->record.control_window_destroyed = !state->control_window || !IsWindow(state->control_window);
    if (!state->record.control_window_destroyed) remember(E_FAIL);
    state->record.references_released = 1;
    const bool uninitialize = state->ole_initialized;
    NativeHostSnapshot final = state->record;
    delete state;
    if (uninitialize) { OleUninitialize(); final.ole_balanced = 1; }
    if (out) *out = final;
    return first;
}
} // namespace

NATIVE_HOST_API native_host_create(HWND parent, int width, int height, void** context, IUnknown** object) {
    if (!context || !object) return E_POINTER;
    *context = nullptr; *object = nullptr;
    return guarded([&]() -> HRESULT {
        DWORD process{};
        if (width <= 0 || height <= 0 || width > 8192 || height > 8192 ||
            GetWindowThreadProcessId(parent,&process) != GetCurrentThreadId() || process != GetCurrentProcessId())
            return E_INVALIDARG;
        auto* state = new State;
        struct Rollback final { State* state; ~Rollback() { if (state) release_state(state,nullptr); } } rollback{state};
        state->parent = parent;
        state->record.size = static_cast<std::uint32_t>(sizeof(NativeHostSnapshot)); state->record.version = 1; state->record.parent_owned = 1;
        require(OleInitialize(nullptr), "native_host_ole_initialize");
        state->ole_initialized = true;
        APTTYPE apartment{}; APTTYPEQUALIFIER qualifier{};
        require(CoGetApartmentType(&apartment,&qualifier), "native_host_apartment");
        if (apartment != APTTYPE_STA && apartment != APTTYPE_MAINSTA) return RPC_E_WRONG_THREAD;
        state->record.sta_verified = 1;
        state->host = std::make_unique<native_ole_probe::OleControlHost>(parent);
        state->host->create(ControlClass,RECT{0,0,width,height},L"Independent native host acceptance");
        auto window = query<IOleInPlaceObject>(state->host->object(),IID_IOleInPlaceObject,"native_host_ole_window");
        require(window->GetWindow(&state->control_window),"native_host_control_window");
        if (!state->control_window || !IsChild(parent,state->control_window)) return E_UNEXPECTED;
        state->library = load_system_library();
        state->sink.attach(new native_event_probe::EventSink(state->library.get(),*state));
        auto container = query<IConnectionPointContainer>(state->host->object(),IID_IConnectionPointContainer,"native_host_connection_container");
        require(container->FindConnectionPoint(native_event_probe::EventsInterface,state->point.put()),"native_host_connection_point");
        if (!state->point) return E_UNEXPECTED;
        IID actual{}; require(state->point->GetConnectionInterface(&actual),"native_host_connection_interface");
        if (actual != native_event_probe::EventsInterface) return E_NOINTERFACE;
        require(state->point->Advise(static_cast<IDispatch*>(state->sink.get()),&state->cookie),"native_host_advise");
        if (!state->cookie) return E_UNEXPECTED;
        state->host->object()->AddRef(); // One explicit transfer; caller releases after constructing its unique RCW.
        *object = state->host->object(); *context = state; rollback.state = nullptr;
        return S_OK;
    });
}
NATIVE_HOST_API native_host_snapshot(void* context, NativeHostSnapshot* out) {
    if (!out || out->size != sizeof(*out)) return E_INVALIDARG;
    return guarded([&]() -> HRESULT { auto& state=checked(context); ExternalCall call(state); snapshot(state,*out); return S_OK; });
}
NATIVE_HOST_API native_host_event(void* context, unsigned index, NativeHostEvent* event) {
    if (!event) return E_POINTER;
    return guarded([&]() -> HRESULT { auto& state=checked(context); if(index>=state.record.event_count)return E_INVALIDARG; *event=state.events[index]; return S_OK; });
}
NATIVE_HOST_API native_host_resize(void* context, int width, int height) {
    return guarded([&]() -> HRESULT {
        auto& state=checked(context); if(state.external_depth)return RPC_E_CANTCALLOUT_ININPUTSYNCCALL;
        if(width<=0 || height<=0 || width>8192 || height>8192)return E_INVALIDARG;
        ExternalCall call(state); const HRESULT result=state.host->resize(RECT{0,0,width,height});
        if(SUCCEEDED(result))++state.record.resize_calls;
        return result;
    });
}
NATIVE_HOST_API native_host_focus(void* context) {
    return guarded([&]() -> HRESULT {
        auto& state=checked(context); if(state.external_depth)return RPC_E_CANTCALLOUT_ININPUTSYNCCALL;
        ExternalCall call(state); const HRESULT result=state.host->focus();
        if(SUCCEEDED(result))++state.record.focus_calls;
        return result;
    });
}
NATIVE_HOST_API native_host_translate(void* context, HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    return guarded([&]() -> HRESULT {
        auto& state=checked(context);
        if(state.external_depth)return RPC_E_CANTCALLOUT_ININPUTSYNCCALL;
        if(message<WM_KEYFIRST || message>WM_KEYLAST ||
            (window!=state.control_window && !IsChild(state.control_window,window)))return E_INVALIDARG;
        MSG item{}; item.hwnd=window; item.message=message; item.wParam=wparam; item.lParam=lparam;
        item.time=static_cast<DWORD>(GetMessageTime()); const DWORD position=GetMessagePos();
        item.pt.x=static_cast<short>(LOWORD(position)); item.pt.y=static_cast<short>(HIWORD(position));
        ExternalCall call(state); const HRESULT result=state.host->translate(item);
        if(message==WM_KEYDOWN)++state.record.key_down_translated;
        else if(message==WM_KEYUP)++state.record.key_up_translated;
        else ++state.record.other_key_translated;
        if(result==S_OK)++state.record.translation_handled;
        else if(result==S_FALSE)++state.record.translation_declined;
        else ++state.record.translation_failed;
        return result;
    });
}
NATIVE_HOST_API native_host_begin_cleanup(void* context) {
    return guarded([&]() -> HRESULT { auto& state=checked(context); state.record.cleanup_started=1; return S_OK; });
}
NATIVE_HOST_API native_host_close(void* context, NativeHostSnapshot* out, int* consumed) {
    if(!consumed)return E_POINTER;
    *consumed=0;
    if(!out || out->size!=sizeof(*out))return E_INVALIDARG;
    return guarded([&]() -> HRESULT {
        auto& state=checked(context); if(state.external_depth)return RPC_E_CANTCALLOUT_ININPUTSYNCCALL;
        { ExternalCall call(state); if(!disconnected(state))return E_PENDING; snapshot(state,*out); }
        *consumed=1; return release_state(&state,out);
    });
}
NATIVE_HOST_API native_host_abandon(void* context) {
    return guarded([&]() -> HRESULT {
        auto& state=checked(context); if(state.sink)state.sink->detach();
        state.abandoned=true; return S_OK;
    });
}
