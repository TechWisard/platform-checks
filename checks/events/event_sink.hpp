#pragma once
#include "abi_contract.hpp"
#include <array>

namespace native_event_probe {
using namespace native_contract_probe;
constexpr IID EventsInterface{0x336d5562,0xefa8,0x482e,{0x8c,0xb3,0xc5,0xc0,0xfc,0x7a,0x7d,0xb6}};

enum class RdpEventKind {
    connecting, connected, login_complete, disconnected, fatal_error, warning,
    logon_error, authentication_warning, authentication_warning_dismissed,
    close_confirmation, event_contract_failure
};
struct RdpEvent { RdpEventKind kind{}; LONG code{}; };

class RdpObserver {
public:
    virtual ~RdpObserver() = default;
    // The callback must not make a reentrant call to the control or throw.
    virtual void on_rdp_event(RdpEvent event) noexcept = 0;
    virtual bool allow_rdp_close() noexcept = 0;
};

enum class EventShape { empty, integer, close_boolean };
struct EventSpec { const wchar_t* name; RdpEventKind kind; EventShape shape; DISPID identifier{DISPID_UNKNOWN}; };

class EventSink final : public IDispatch {
public:
    EventSink(ITypeLib* library, RdpObserver& observer) : observer_(&observer), owner_thread_(GetCurrentThreadId()) {
        events_ = {{
            {L"OnConnecting", RdpEventKind::connecting, EventShape::empty},
            {L"OnConnected", RdpEventKind::connected, EventShape::empty},
            {L"OnLoginComplete", RdpEventKind::login_complete, EventShape::empty},
            {L"OnDisconnected", RdpEventKind::disconnected, EventShape::integer},
            {L"OnFatalError", RdpEventKind::fatal_error, EventShape::integer},
            {L"OnWarning", RdpEventKind::warning, EventShape::integer},
            {L"OnLogonError", RdpEventKind::logon_error, EventShape::integer},
            {L"OnAuthenticationWarningDisplayed", RdpEventKind::authentication_warning, EventShape::empty},
            {L"OnAuthenticationWarningDismissed", RdpEventKind::authentication_warning_dismissed, EventShape::empty},
            {L"OnConfirmClose", RdpEventKind::close_confirmation, EventShape::close_boolean}
        }};
        ComPtr<ITypeInfo> information;
        require(library->GetTypeInfoOfGuid(EventsInterface, information.put()), "Find RDP event type");
        TypeAttribute attributes(information.get());
        if (attributes.value->guid != EventsInterface || attributes.value->typekind != TKIND_DISPATCH || attributes.value->cFuncs > 256)
            throw Failure("RDP event interface mismatch", TYPE_E_TYPEMISMATCH);
        for (UINT index = 0; index < attributes.value->cFuncs; ++index) {
            FunctionDescription descriptor(information.get(), index); const FUNCDESC& method = *descriptor.value;
            TextResult name; require(information->GetDocumentation(method.memid, &name.value, nullptr, nullptr, nullptr), "Read RDP event name");
            for (EventSpec& event : events_) {
                if (name.view() != event.name) continue;
                if (event.identifier != DISPID_UNKNOWN || method.memid < 1 || method.cParamsOpt ||
                    method.invkind != INVOKE_FUNC || method.funckind != FUNC_DISPATCH || method.elemdescFunc.tdesc.vt != VT_VOID ||
                    method.cParams != (event.shape == EventShape::empty ? 0 : 1))
                    throw Failure("RDP event ABI mismatch", TYPE_E_TYPEMISMATCH);
                if (event.shape != EventShape::empty && !method.lprgelemdescParam) throw Failure("RDP event parameter missing", TYPE_E_TYPEMISMATCH);
                if (event.shape == EventShape::integer && !in_parameter(method.lprgelemdescParam[0], VT_I4)) throw Failure("RDP event integer mismatch", TYPE_E_TYPEMISMATCH);
                if (event.shape == EventShape::close_boolean && !out_parameter(method.lprgelemdescParam[0], VT_BOOL, false)) throw Failure("RDP close event mismatch", TYPE_E_TYPEMISMATCH);
                event.identifier = method.memid;
            }
        }
        for (std::size_t i = 0; i < events_.size(); ++i) {
            if (events_[i].identifier == DISPID_UNKNOWN) throw Failure("Required RDP event unavailable", DISP_E_MEMBERNOTFOUND);
            for (std::size_t j = 0; j < i; ++j) if (events_[i].identifier == events_[j].identifier) throw Failure("Duplicate RDP event ID", TYPE_E_TYPEMISMATCH);
        }
    }
    void detach() noexcept { observer_ = nullptr; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) override {
        if (!result) return E_POINTER;
        *result = nullptr;
        if (iid != IID_IUnknown && iid != IID_IDispatch && iid != EventsInterface) return E_NOINTERFACE;
        *result = static_cast<IDispatch*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&references_)); }
    ULONG STDMETHODCALLTYPE Release() override { const ULONG count = static_cast<ULONG>(InterlockedDecrement(&references_)); if (!count) delete this; return count; }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override { if (!count) return E_POINTER; *count = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo** result) override { if (!result) return E_POINTER; *result = nullptr; return DISP_E_BADINDEX; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID iid, LPOLESTR* names, UINT count, LCID, DISPID* ids) override {
        if (iid != IID_NULL) return DISP_E_UNKNOWNINTERFACE;
        if (!names || !ids) return E_POINTER;
        HRESULT result = S_OK;
        for (UINT i = 0; i < count; ++i) {
            ids[i] = DISPID_UNKNOWN;
            if (!names[i]) return E_POINTER;
            for (const EventSpec& event : events_) if (CompareStringOrdinal(names[i], -1, event.name, -1, TRUE) == CSTR_EQUAL) ids[i] = event.identifier;
            if (ids[i] == DISPID_UNKNOWN) result = DISP_E_UNKNOWNNAME;
        }
        return result;
    }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID id, REFIID iid, LCID, WORD flags, DISPPARAMS* parameters,
        VARIANT* result, EXCEPINFO*, UINT* argument_error) override {
        if (iid != IID_NULL) return DISP_E_UNKNOWNINTERFACE;
        if (flags != DISPATCH_METHOD) return DISP_E_MEMBERNOTFOUND;
        if (!parameters) return E_POINTER;
        if (result) VariantInit(result);
        const EventSpec* selected{};
        for (const EventSpec& event : events_) if (event.identifier == id) { selected = &event; break; }
        if (!selected) return DISP_E_MEMBERNOTFOUND;
        if (parameters->cNamedArgs || parameters->cArgs != (selected->shape == EventShape::empty ? 0U : 1U)) return contract_failure(DISP_E_BADPARAMCOUNT);
        if (parameters->cArgs && !parameters->rgvarg) return contract_failure(E_POINTER);
        if (GetCurrentThreadId() != owner_thread_) return RPC_E_WRONG_THREAD;
        LONG code{};
        if (selected->shape == EventShape::integer) {
            if (parameters->rgvarg[0].vt != VT_I4) { if (argument_error) *argument_error = 0; return contract_failure(DISP_E_TYPEMISMATCH); }
            code = parameters->rgvarg[0].lVal;
        } else if (selected->shape == EventShape::close_boolean) {
            if (parameters->rgvarg[0].vt != (VT_BOOL | VT_BYREF) || !parameters->rgvarg[0].pboolVal)
                return contract_failure(DISP_E_TYPEMISMATCH);
            *parameters->rgvarg[0].pboolVal = observer_ && observer_->allow_rdp_close() ? VARIANT_TRUE : VARIANT_FALSE;
        }
        if (observer_) observer_->on_rdp_event({selected->kind, code});
        return S_OK;
    }
private:
    HRESULT contract_failure(HRESULT result) noexcept {
        if (observer_ && GetCurrentThreadId() == owner_thread_) observer_->on_rdp_event({RdpEventKind::event_contract_failure, result});
        return result;
    }
    LONG references_{1};
    RdpObserver* observer_{};
    DWORD owner_thread_{};
    std::array<EventSpec, 10> events_{};
};


} // namespace native_event_probe
