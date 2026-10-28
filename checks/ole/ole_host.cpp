#include "ole_host.hpp"
#include <olectl.h>
#include <algorithm>
#include <cmath>
#include <limits>
#include <new>

namespace native_ole_probe {
namespace {

class SingleObjectEnumerator final : public IEnumUnknown {
public:
    explicit SingleObjectEnumerator(IUnknown* object, bool consumed = false) noexcept : consumed_(consumed) {
        object_.copy_from(object);
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) override {
        if (!result) return E_POINTER;
        *result = nullptr;
        if (iid != IID_IUnknown && iid != IID_IEnumUnknown) return E_NOINTERFACE;
        *result = static_cast<IEnumUnknown*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&references_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG count = static_cast<ULONG>(InterlockedDecrement(&references_));
        if (!count) delete this;
        return count;
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG count, IUnknown** items, ULONG* fetched) override {
        if (!items || (!fetched && count != 1)) return E_POINTER;
        if (fetched) *fetched = 0;
        if (!count) return S_OK;
        items[0] = nullptr;
        if (consumed_ || !object_) return S_FALSE;
        items[0] = object_.get(); items[0]->AddRef(); consumed_ = true;
        if (fetched) *fetched = 1;
        return count == 1 ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG count) override {
        if (!count) return S_OK;
        const bool available = !consumed_ && static_cast<bool>(object_);
        consumed_ = true; return available && count == 1 ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Reset() override { consumed_ = false; return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumUnknown** result) override {
        if (!result) return E_POINTER;
        *result = new(std::nothrow) SingleObjectEnumerator(object_.get(), consumed_);
        return *result ? S_OK : E_OUTOFMEMORY;
    }
private:
    LONG references_{1};
    ComPtr<IUnknown> object_;
    bool consumed_{};
};

bool rectangle_valid(const RECT& r) noexcept {
    return r.left >= 0 && r.top >= 0 && r.right > r.left && r.bottom > r.top;
}

} // namespace

class OleControlHost::Site final : public IOleClientSite, public IOleInPlaceSite,
    public IOleInPlaceFrame, public IOleControlSite, public IOleContainer, public IDispatch {
public:
    explicit Site(OleControlHost* host) noexcept : host_(host) {}
    void orphan() noexcept {
        host_ = nullptr; active_.reset();
        in_place_active_ = ui_active_ = show_notified_ = in_place_locked_ = control_has_focus_ = false;
        control_info_ = {};
    }
    HRESULT translate(MSG& message) noexcept {
        return active_ ? active_->TranslateAccelerator(&message) : S_FALSE;
    }
    OleHostObservation observe() const noexcept {
        return {host_ && host_->client_site_attached_, in_place_active_, ui_active_, show_notified_, false, activation_count_};
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) override {
        if (!result) return E_POINTER;
        *result = nullptr;
        if (iid == IID_IUnknown || iid == IID_IOleClientSite) *result = static_cast<IOleClientSite*>(this);
        else if (iid == IID_IOleWindow || iid == IID_IOleInPlaceSite) *result = static_cast<IOleInPlaceSite*>(this);
        else if (iid == IID_IOleInPlaceUIWindow || iid == IID_IOleInPlaceFrame) *result = static_cast<IOleInPlaceFrame*>(this);
        else if (iid == IID_IOleControlSite) *result = static_cast<IOleControlSite*>(this);
        else if (iid == IID_IParseDisplayName || iid == IID_IOleContainer) *result = static_cast<IOleContainer*>(this);
        else if (iid == IID_IDispatch) *result = static_cast<IDispatch*>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&references_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG count = static_cast<ULONG>(InterlockedDecrement(&references_));
        if (!count) delete this;
        return count;
    }

    HRESULT STDMETHODCALLTYPE SaveObject() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetMoniker(DWORD, DWORD, IMoniker** result) override {
        if (!result) return E_POINTER;
        *result = nullptr; return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetContainer(IOleContainer** result) override {
        if (!result) return E_POINTER;
        *result = static_cast<IOleContainer*>(this); AddRef(); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ShowObject() override {
        if (!host_ || !IsWindow(host_->parent_)) return E_UNEXPECTED;
        return InvalidateRect(host_->parent_, &host_->rectangle_, FALSE) ? S_OK : last_win32_error();
    }
    HRESULT STDMETHODCALLTYPE OnShowWindow(BOOL show) override { show_notified_ = show != FALSE; return S_OK; }
    HRESULT STDMETHODCALLTYPE RequestNewObjectLayout() override { return E_NOTIMPL; }

    HRESULT STDMETHODCALLTYPE GetWindow(HWND* result) override {
        if (!result) return E_POINTER;
        *result = host_ ? host_->parent_ : nullptr;
        return *result && IsWindow(*result) ? S_OK : E_UNEXPECTED;
    }
    HRESULT STDMETHODCALLTYPE ContextSensitiveHelp(BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CanInPlaceActivate() override { return host_ && IsWindow(host_->parent_) ? S_OK : E_UNEXPECTED; }
    HRESULT STDMETHODCALLTYPE OnInPlaceActivate() override {
        if (!host_) return E_UNEXPECTED;
        in_place_active_ = true; ++activation_count_; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE OnUIActivate() override { if (!host_) return E_UNEXPECTED; ui_active_ = true; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetWindowContext(IOleInPlaceFrame** frame, IOleInPlaceUIWindow** document,
        RECT* position, RECT* clip, OLEINPLACEFRAMEINFO* information) override {
        if (!frame || !document || !position || !clip || !information) return E_POINTER;
        *frame = nullptr; *document = nullptr;
        if (!host_ || information->cb < sizeof(OLEINPLACEFRAMEINFO)) return E_INVALIDARG;
        RECT client{};
        if (!GetClientRect(host_->parent_, &client)) return last_win32_error();
        *position = host_->rectangle_;
        if (!IntersectRect(clip, position, &client)) SetRectEmpty(clip);
        information->cb = sizeof(OLEINPLACEFRAMEINFO); information->fMDIApp = FALSE;
        information->hwndFrame = host_->parent_; information->haccel = nullptr; information->cAccelEntries = 0;
        *frame = static_cast<IOleInPlaceFrame*>(this); AddRef(); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Scroll(SIZE) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE OnUIDeactivate(BOOL) override { ui_active_ = false; active_.reset(); return S_OK; }
    HRESULT STDMETHODCALLTYPE OnInPlaceDeactivate() override { in_place_active_ = false; ui_active_ = false; active_.reset(); return S_OK; }
    HRESULT STDMETHODCALLTYPE DiscardUndoState() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DeactivateAndUndo() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE OnPosRectChange(const RECT* rectangle) override {
        if (!rectangle) return E_POINTER;
        // The container owns its viewport; a control cannot resize the outer UI.
        return host_ && host_->in_place_ ?
            host_->in_place_->SetObjectRects(&host_->rectangle_, &host_->rectangle_) : E_UNEXPECTED;
    }
    HRESULT STDMETHODCALLTYPE GetBorder(RECT* border) override {
        if (!border) return E_POINTER;
        if (!host_) return E_UNEXPECTED;
        *border = host_->rectangle_; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE RequestBorderSpace(const BORDERWIDTHS* widths) override {
        if (!widths) return E_POINTER;
        return widths->left || widths->top || widths->right || widths->bottom ? INPLACE_E_NOTOOLSPACE : S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetBorderSpace(const BORDERWIDTHS* widths) override {
        return !widths || (!widths->left && !widths->top && !widths->right && !widths->bottom) ? S_OK : INPLACE_E_NOTOOLSPACE;
    }
    HRESULT STDMETHODCALLTYPE SetActiveObject(IOleInPlaceActiveObject* active, LPCOLESTR) override {
        if (!host_) return E_UNEXPECTED;
        active_.copy_from(active); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE InsertMenus(HMENU, OLEMENUGROUPWIDTHS*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetMenu(HMENU shared, HOLEMENU descriptor, HWND) override {
        return !shared && !descriptor ? S_OK : E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE RemoveMenus(HMENU) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetStatusText(LPCOLESTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EnableModeless(BOOL enable) override {
        if (!host_ || !IsWindow(host_->parent_)) return E_UNEXPECTED;
        EnableWindow(host_->parent_, enable);
        return (IsWindowEnabled(host_->parent_) != FALSE) == (enable != FALSE) ? S_OK : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE TranslateAccelerator(MSG*, WORD) override { return S_FALSE; }

    HRESULT STDMETHODCALLTYPE OnControlInfoChanged() override {
        if (!host_ || !host_->object_) return E_UNEXPECTED;
        ComPtr<IOleControl> control;
        const HRESULT queried = host_->object_->QueryInterface(IID_IOleControl, reinterpret_cast<void**>(control.put()));
        if (FAILED(queried)) return queried;
        CONTROLINFO information{}; information.cb = sizeof(information);
        const HRESULT result = control->GetControlInfo(&information);
        if (SUCCEEDED(result)) control_info_ = information;
        return result;
    }
    HRESULT STDMETHODCALLTYPE LockInPlaceActive(BOOL lock) override { in_place_locked_ = lock != FALSE; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetExtendedControl(IDispatch** result) override {
        if (!result) return E_POINTER;
        *result = nullptr; return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE TransformCoords(POINTL* metric, POINTF* pixels, DWORD flags) override {
        if (!metric || !pixels) return E_POINTER;
        const DWORD kind = flags & (XFORMCOORDS_POSITION | XFORMCOORDS_SIZE);
        const DWORD direction = flags & (XFORMCOORDS_HIMETRICTOCONTAINER | XFORMCOORDS_CONTAINERTOHIMETRIC);
        // The container uses the same client-pixel units for events and other
        // coordinates; EVENTCOMPAT therefore does not select a different scale.
        if ((kind != XFORMCOORDS_POSITION && kind != XFORMCOORDS_SIZE) ||
            (direction != XFORMCOORDS_HIMETRICTOCONTAINER && direction != XFORMCOORDS_CONTAINERTOHIMETRIC) ||
            (flags & ~(XFORMCOORDS_POSITION | XFORMCOORDS_SIZE | XFORMCOORDS_HIMETRICTOCONTAINER | XFORMCOORDS_CONTAINERTOHIMETRIC | XFORMCOORDS_EVENTCOMPAT))) return E_INVALIDARG;
        if (!host_) return E_UNEXPECTED;
        const UINT dpi = GetDpiForWindow(host_->parent_);
        if (!dpi) return E_UNEXPECTED;
        if (direction == XFORMCOORDS_HIMETRICTOCONTAINER) {
            pixels->x = static_cast<float>(static_cast<double>(metric->x) * dpi / 2540.0);
            pixels->y = static_cast<float>(static_cast<double>(metric->y) * dpi / 2540.0);
        } else {
            const double x = std::round(static_cast<double>(pixels->x) * 2540.0 / dpi);
            const double y = std::round(static_cast<double>(pixels->y) * 2540.0 / dpi);
            if (!std::isfinite(x) || !std::isfinite(y) || x < (std::numeric_limits<LONG>::min)() ||
                x > (std::numeric_limits<LONG>::max)() || y < (std::numeric_limits<LONG>::min)() || y > (std::numeric_limits<LONG>::max)()) return E_INVALIDARG;
            metric->x = static_cast<LONG>(x); metric->y = static_cast<LONG>(y);
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE TranslateAccelerator(MSG*, DWORD) override { return S_FALSE; }
    HRESULT STDMETHODCALLTYPE OnFocus(BOOL focus) override { control_has_focus_ = focus != FALSE; return S_OK; }
    HRESULT STDMETHODCALLTYPE ShowPropertyFrame() override { return E_NOTIMPL; }

    HRESULT STDMETHODCALLTYPE ParseDisplayName(IBindCtx*, LPOLESTR, ULONG* eaten, IMoniker** result) override {
        if (!eaten || !result) return E_POINTER;
        *eaten = 0; *result = nullptr; return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE EnumObjects(DWORD flags, IEnumUnknown** result) override {
        if (!result) return E_POINTER;
        *result = nullptr;
        if (!host_) return E_UNEXPECTED;
        IUnknown* included = host_->object_ && (flags & OLECONTF_EMBEDDINGS) &&
            (!(flags & OLECONTF_ONLYIFRUNNING) || (host_->ole_ && OleIsRunning(host_->ole_.get()))) ? host_->object_.get() : nullptr;
        *result = new(std::nothrow) SingleObjectEnumerator(included);
        return *result ? S_OK : E_OUTOFMEMORY;
    }
    HRESULT STDMETHODCALLTYPE LockContainer(BOOL lock) override {
        if (lock) {
            if (container_locks_ == (std::numeric_limits<ULONG>::max)()) return E_UNEXPECTED;
            ++container_locks_; AddRef();
        } else {
            if (!container_locks_) return E_UNEXPECTED;
            --container_locks_; Release();
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override { if (!count) return E_POINTER; *count = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo** result) override {
        if (!result) return E_POINTER;
        *result = nullptr; return DISP_E_BADINDEX;
    }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR*, UINT count, LCID, DISPID* ids) override {
        if (!ids) return E_POINTER;
        for (UINT i = 0; i < count; ++i) ids[i] = DISPID_UNKNOWN;
        return DISP_E_UNKNOWNNAME;
    }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID id, REFIID iid, LCID, WORD flags, DISPPARAMS* parameters,
        VARIANT* result, EXCEPINFO*, UINT*) override {
        if (iid != IID_NULL) return DISP_E_UNKNOWNINTERFACE;
        if (flags != DISPATCH_PROPERTYGET) return DISP_E_MEMBERNOTFOUND;
        if (!parameters || !result) return E_POINTER;
        if (parameters->cArgs || parameters->cNamedArgs) return DISP_E_BADPARAMCOUNT;
        VariantInit(result);
        switch (id) {
        case DISPID_AMBIENT_USERMODE: result->vt = VT_BOOL; result->boolVal = VARIANT_TRUE; break;
        case DISPID_AMBIENT_UIDEAD: result->vt = VT_BOOL; result->boolVal = host_ ? VARIANT_FALSE : VARIANT_TRUE; break;
        case DISPID_AMBIENT_SHOWGRABHANDLES: case DISPID_AMBIENT_SHOWHATCHING:
        case DISPID_AMBIENT_DISPLAYASDEFAULT: case DISPID_AMBIENT_SUPPORTSMNEMONICS:
        case DISPID_AMBIENT_MESSAGEREFLECT: result->vt = VT_BOOL; result->boolVal = VARIANT_FALSE; break;
        case DISPID_AMBIENT_LOCALEID: result->vt = VT_I4; result->lVal = static_cast<LONG>(GetUserDefaultLCID()); break;
        case DISPID_AMBIENT_BACKCOLOR: result->vt = VT_I4; result->lVal = static_cast<LONG>(GetSysColor(COLOR_WINDOW)); break;
        case DISPID_AMBIENT_FORECOLOR: result->vt = VT_I4; result->lVal = static_cast<LONG>(GetSysColor(COLOR_WINDOWTEXT)); break;
        case DISPID_AMBIENT_AUTOCLIP: result->vt = VT_BOOL; result->boolVal = VARIANT_TRUE; break;
        default: return DISP_E_MEMBERNOTFOUND;
        }
        return S_OK;
    }
private:
    LONG references_{1};
    OleControlHost* host_{};
    ComPtr<IOleInPlaceActiveObject> active_;
    CONTROLINFO control_info_{};
    ULONG container_locks_{};
    unsigned activation_count_{};
    bool in_place_active_{}, ui_active_{}, show_notified_{}, in_place_locked_{}, control_has_focus_{};
};

OleControlHost::OleControlHost(HWND parent) : parent_(parent) {
    if (!IsWindow(parent_)) throw Failure("OLE parent window", E_INVALIDARG);
    site_ = new Site(this);
}
OleControlHost::~OleControlHost() { close(); if (site_) { site_->orphan(); site_->Release(); } }
IUnknown* OleControlHost::object() const noexcept { return object_.get(); }

void OleControlHost::create(REFCLSID clsid, const RECT& rectangle, const wchar_t* application_name) {
    if (creation_started_ || closed_) throw Failure("OLE host is single-use", E_UNEXPECTED);
    if (!rectangle_valid(rectangle) || !application_name) throw Failure("OLE creation arguments", E_INVALIDARG);
    creation_started_ = true;
    rectangle_ = rectangle;
    require(CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER, IID_IUnknown,
        reinterpret_cast<void**>(object_.put())), "Create OLE control");
    ole_ = query<IOleObject>(object_.get(), IID_IOleObject, "OLE object interface");
    DWORD misc{}; require(ole_->GetMiscStatus(DVASPECT_CONTENT, &misc), "OLE misc status");
    auto attach_site = [this]() {
        require(ole_->SetClientSite(static_cast<IOleClientSite*>(site_)), "Attach OLE site");
        client_site_attached_ = true;
    };
    if (misc & OLEMISC_SETCLIENTSITEFIRST) attach_site();
    auto persistence = query<IPersistStreamInit>(object_.get(), IID_IPersistStreamInit, "OLE persistence interface");
    require(persistence->InitNew(), "Initialize OLE control");
    if (!client_site_attached_) attach_site();
    require(ole_->SetHostNames(application_name, L""), "OLE host name");
    require(OleSetContainedObject(object_.get(), TRUE), "Mark contained OLE control");
    in_place_ = query<IOleInPlaceObject>(object_.get(), IID_IOleInPlaceObject, "OLE in-place interface");
    require(ole_->DoVerb(OLEIVERB_INPLACEACTIVATE, nullptr, static_cast<IOleClientSite*>(site_), 0,
        parent_, &rectangle_), "Activate OLE control");
    require(resize(rectangle_), "Place OLE control");
    HWND window{}; require(in_place_->GetWindow(&window), "OLE control window");
    if (!window || !IsChild(parent_, window)) throw Failure("OLE control window ancestry", E_UNEXPECTED);
}

HRESULT OleControlHost::resize(const RECT& rectangle) noexcept {
    if (!in_place_ || !rectangle_valid(rectangle)) return E_INVALIDARG;
    rectangle_ = rectangle;
    RECT client{}, clip{};
    if (!GetClientRect(parent_, &client)) return last_win32_error();
    if (!IntersectRect(&clip, &rectangle_, &client)) SetRectEmpty(&clip);
    return in_place_->SetObjectRects(&rectangle_, &clip);
}
HRESULT OleControlHost::focus() noexcept {
    if (!ole_ || !in_place_) return E_UNEXPECTED;
    const HRESULT result = ole_->DoVerb(OLEIVERB_UIACTIVATE, nullptr, static_cast<IOleClientSite*>(site_), 0, parent_, &rectangle_);
    if (FAILED(result)) return result;
    HWND window{}; const HRESULT queried = in_place_->GetWindow(&window);
    if (FAILED(queried)) return queried;
    if (!window || !IsChild(parent_, window)) return E_UNEXPECTED;
    SetFocus(window);
    const HWND actual = GetFocus();
    return actual == window || IsChild(window, actual) ? S_OK : E_FAIL;
}
HRESULT OleControlHost::translate(MSG& message) noexcept { return site_ ? site_->translate(message) : S_FALSE; }
OleHostObservation OleControlHost::observation() const noexcept {
    OleHostObservation result = site_ ? site_->observe() : OleHostObservation{};
    HWND window{};
    result.control_window_is_child = in_place_ && SUCCEEDED(in_place_->GetWindow(&window)) && window && IsChild(parent_, window);
    return result;
}
HRESULT OleControlHost::close() noexcept {
    closed_ = true;
    HRESULT first = S_OK;
    auto record = [&first](HRESULT result) { if (FAILED(result) && SUCCEEDED(first)) first = result; };
    if (in_place_) { record(in_place_->UIDeactivate()); record(in_place_->InPlaceDeactivate()); }
    if (ole_) {
        record(ole_->Close(OLECLOSE_NOSAVE));
        if (client_site_attached_) record(ole_->SetClientSite(nullptr));
    }
    client_site_attached_ = false;
    if (object_) record(OleSetContainedObject(object_.get(), FALSE));
    if (site_) site_->orphan();
    in_place_.reset(); ole_.reset(); object_.reset();
    return first;
}

} // namespace native_ole_probe
