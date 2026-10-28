#pragma once
#include "com_raii.hpp"
#include <ocidl.h>
#include <memory>

namespace native_ole_probe {

struct OleHostObservation {
    bool client_site_attached{};
    bool in_place_active{};
    bool ui_active{};
    bool show_notified{};
    bool control_window_is_child{};
    unsigned in_place_activation_count{};
};

// Generic single-control, single-use OLE container; create() is attempted once.
// It knows nothing about RDP, credentials, account creation or Windows sessions.
class OleControlHost final {
public:
    explicit OleControlHost(HWND parent);
    ~OleControlHost();
    OleControlHost(const OleControlHost&) = delete;
    OleControlHost& operator=(const OleControlHost&) = delete;
    void create(REFCLSID clsid, const RECT& rectangle, const wchar_t* application_name);
    IUnknown* object() const noexcept;
    HRESULT resize(const RECT& rectangle) noexcept;
    HRESULT focus() noexcept;
    HRESULT translate(MSG& message) noexcept;
    OleHostObservation observation() const noexcept;
    // Call after the hosted protocol has completed its own close handshake.
    // Returns the first actual COM cleanup failure; destructor remains fallback.
    HRESULT close() noexcept;
private:
    class Site;
    friend class Site;
    HWND parent_{};
    RECT rectangle_{};
    Site* site_{};
    ComPtr<IUnknown> object_;
    ComPtr<IOleObject> ole_;
    ComPtr<IOleInPlaceObject> in_place_;
    bool client_site_attached_{};
    bool creation_started_{}, closed_{};
};

} // namespace native_ole_probe
