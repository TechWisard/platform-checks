#include "ole_host.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>

using namespace native_ole_probe;
namespace {
constexpr CLSID ControlClass{0xa0c63c30, 0xf08d, 0x4ab4, {0x90,0x7c,0x34,0x90,0x5d,0x77,0x0c,0x7d}};
constexpr wchar_t WindowClass[] = L"NativeOleHostProbeWindow";
constexpr UINT_PTR TimerId = 1;
constexpr ULONGLONG PumpBudgetMs = 10000;

struct Result {
    const char* stage{"preflight"};
    const char* operation{""};
    HRESULT error{S_OK}, cleanup_error{S_OK}, close_result{S_OK};
    DWORD session{};
    unsigned architecture{}, dpi{}, ticks{}, activation_count{};
    int apartment{-1}, apartment_qualifier{-1};
    bool unavailable{}, observations_complete{}, ole_initialized{}, sta_verified{};
    bool input_desktop{}, dpi_context_verified{}, parent_created{}, parent_visible{};
    bool control_class_verified{}, control_identity_verified{}, site_verified{};
    bool in_place_active{}, control_owned{}, control_visible{}, initial_geometry_verified{};
    bool resize_requested{}, resized_geometry_verified{}, message_pump_verified{};
    bool timer_removed{true}, host_closed{true}, owned_com_references_released{true};
    bool control_window_destroyed{}, parent_destroyed{}, class_unregistered{true};
    bool ole_uninitialized{}, cleanup_verified{};
    RECT initial_expected{}, initial_actual{}, resized_expected{}, resized_actual{};
};

void check(bool value) { if (!value) throw Failure("Probe invariant", E_UNEXPECTED); }
void win32(bool value) { if (!value) throw Failure("Windows API", last_win32_error()); }
bool equal(const RECT& a, const RECT& b) noexcept {
    return a.left == b.left && a.top == b.top && a.right == b.right && a.bottom == b.bottom;
}

class Probe final {
public:
    explicit Probe(Result& result) noexcept : result_(result), instance_(GetModuleHandleW(nullptr)) {}
    ~Probe() { cleanup(); }
    void run() {
        SYSTEM_INFO system{}; GetNativeSystemInfo(&system);
        result_.architecture = system.wProcessorArchitecture;
        win32(ProcessIdToSessionId(GetCurrentProcessId(), &result_.session) != FALSE);
        if (!result_.session) {
            result_.stage = "session_zero_unavailable"; result_.unavailable = true;
            throw Failure("Noninteractive session", E_UNEXPECTED);
        }
        result_.stage = "input_desktop";
        BOOL input{}; DWORD needed{};
        win32(GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()), UOI_IO,
            &input, sizeof(input), &needed) != FALSE);
        result_.input_desktop = input != FALSE;
        if (!result_.input_desktop) {
            result_.unavailable = true; throw Failure("Input desktop unavailable", E_UNEXPECTED);
        }
        result_.stage = "dpi_context";
        // This new process changes only its own awareness, before creating HWNDs.
        const BOOL dpi_set = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        const HRESULT dpi_error = dpi_set ? S_OK : last_win32_error();
        result_.dpi_context_verified = AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(),
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) != FALSE;
        if (!result_.dpi_context_verified) throw Failure("DPI context", dpi_error == S_OK ? E_UNEXPECTED : dpi_error);
        result_.stage = "ole_initialize";
        require(OleInitialize(nullptr), "OLE STA initialization");
        result_.ole_initialized = true;
        APTTYPE apartment{}; APTTYPEQUALIFIER qualifier{};
        require(CoGetApartmentType(&apartment, &qualifier), "Query apartment");
        result_.apartment = static_cast<int>(apartment); result_.apartment_qualifier = static_cast<int>(qualifier);
        result_.sta_verified = apartment == APTTYPE_STA || apartment == APTTYPE_MAINSTA;
        check(result_.sta_verified);
        result_.stage = "create_parent";
        WNDCLASSEXW definition{}; definition.cbSize = sizeof(definition);
        definition.hInstance = instance_; definition.lpfnWndProc = procedure;
        definition.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        definition.hbrBackground = reinterpret_cast<HBRUSH>(static_cast<INT_PTR>(COLOR_WINDOW + 1));
        definition.lpszClassName = WindowClass;
        registered_ = RegisterClassExW(&definition); win32(registered_ != 0);
        result_.class_unregistered = false;
        HWND created = CreateWindowExW(0, WindowClass, L"Native OLE hosting check",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 850, 650,
            nullptr, nullptr, instance_, this);
        win32(created != nullptr); original_window_ = created; result_.parent_created = true;
        ShowWindow(window_, SW_SHOWNOACTIVATE); UpdateWindow(window_);
        result_.parent_visible = IsWindowVisible(window_) != FALSE; check(result_.parent_visible);
        result_.dpi = GetDpiForWindow(window_); check(result_.dpi != 0);
        RECT client{}; win32(GetClientRect(window_, &client) != FALSE);
        check(client.right >= 400 && client.bottom >= 300);
        result_.initial_expected = {16, 16, client.right - 16, client.bottom - 16};
        result_.resized_expected = {32, 24, client.right - 72, client.bottom - 88};
        check(!equal(result_.initial_expected, result_.resized_expected));
        expected_ = result_.initial_expected;
        result_.stage = "activate_control";
        host_ = std::make_unique<OleControlHost>(window_);
        result_.host_closed = false; result_.owned_com_references_released = false;
        host_->create(ControlClass, expected_, L"Native OLE hosting check");
        verify_site();
        result_.stage = "initial_geometry";
        deadline_ = GetTickCount64() + PumpBudgetMs;
        win32(SetTimer(window_, TimerId, 100, nullptr) != 0); timer_ = true; result_.timer_removed = false;
        while (!done_) {
            MSG message{};
            const BOOL received = GetMessageW(&message, nullptr, 0, 0);
            if (received == -1) throw Failure("Message pump", last_win32_error());
            if (!received) throw Failure("Unexpected quit", E_ABORT);
            TranslateMessage(&message); DispatchMessageW(&message);
        }
    }
private:
    static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept {
        auto* self = reinterpret_cast<Probe*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
            self = static_cast<Probe*>(create->lpCreateParams);
            if (!self) return FALSE;
            self->window_ = window;
            SetLastError(ERROR_SUCCESS);
            if (!SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self)) && GetLastError()) return FALSE;
        }
        if (self) {
            if (message == WM_TIMER && wparam == TimerId) {
                try { if (!self->done_ && !self->cleaning_) self->tick(); }
                catch (const Failure& failure) { self->result_.operation = failure.what(); self->fail(failure.result()); }
                catch (...) { self->result_.operation = "unknown_cpp_exception"; self->fail(E_UNEXPECTED); }
                return 0;
            }
            if (message == WM_CLOSE) { self->fail(HRESULT_FROM_WIN32(ERROR_CANCELLED)); return 0; }
            if (message == WM_DESTROY && !self->cleaning_) self->fail(E_ABORT);
            if (message == WM_NCDESTROY) {
                SetWindowLongPtrW(window, GWLP_USERDATA, 0); self->window_ = nullptr;
            }
        }
        return DefWindowProcW(window, message, wparam, lparam);
    }
    void fail(HRESULT error) noexcept { result_.error = error; done_ = true; }
    void verify_site() {
        auto object = query<IOleObject>(host_->object(), IID_IOleObject, "OLE object");
        CLSID actual{}; require(object->GetUserClassID(&actual), "OLE class");
        result_.control_class_verified = IsEqualCLSID(actual, ControlClass) != FALSE;
        check(result_.control_class_verified);
        auto first = query<IUnknown>(host_->object(), IID_IUnknown, "Control identity");
        auto second = query<IUnknown>(object.get(), IID_IUnknown, "OLE identity");
        result_.control_identity_verified = first.get() == second.get(); check(result_.control_identity_verified);
        ComPtr<IOleClientSite> client;
        require(object->GetClientSite(client.put()), "Actual client site"); check(static_cast<bool>(client));
        auto site = query<IOleInPlaceSite>(client.get(), IID_IOleInPlaceSite, "Actual in-place site");
        HWND site_window{}; require(site->GetWindow(&site_window), "Site parent window"); check(site_window == window_);
        ComPtr<IOleInPlaceFrame> frame; ComPtr<IOleInPlaceUIWindow> document;
        RECT position{}, clip{}; OLEINPLACEFRAMEINFO information{}; information.cb = sizeof(information);
        require(site->GetWindowContext(frame.put(), document.put(), &position, &clip, &information), "Site context");
        check(frame && !document && information.hwndFrame == window_ && !information.fMDIApp);
        HWND frame_window{}; require(frame->GetWindow(&frame_window), "Frame window"); check(frame_window == window_);
        check(equal(position, expected_) && equal(clip, expected_));
        auto site_identity = query<IUnknown>(client.get(), IID_IUnknown, "Client site identity");
        auto frame_identity = query<IUnknown>(frame.get(), IID_IUnknown, "Frame identity");
        check(site_identity.get() == frame_identity.get());
        result_.site_verified = true;
        const OleHostObservation observed = host_->observation();
        result_.in_place_active = observed.in_place_active;
        result_.activation_count = observed.in_place_activation_count;
        check(observed.client_site_attached && observed.in_place_active && observed.control_window_is_child &&
            observed.in_place_activation_count > 0);
    }
    RECT observe_geometry() {
        auto in_place = query<IOleInPlaceObject>(host_->object(), IID_IOleInPlaceObject, "In-place window");
        HWND control{}; require(in_place->GetWindow(&control), "Native control window");
        check(control && IsWindow(control) && IsChild(window_, control) && GetAncestor(control, GA_ROOT) == window_);
        DWORD pid{}; const DWORD thread = GetWindowThreadProcessId(control, &pid); check(thread != 0);
        DWORD session{}; win32(ProcessIdToSessionId(pid, &session) != FALSE);
        result_.control_owned = pid == GetCurrentProcessId() && thread == GetCurrentThreadId() && session == result_.session;
        check(result_.control_owned); control_ = control;
        result_.control_visible = IsWindowVisible(control) != FALSE; check(result_.control_visible);
        RECT rectangle{}; win32(GetWindowRect(control, &rectangle) != FALSE);
        POINT points[2]{{rectangle.left, rectangle.top}, {rectangle.right, rectangle.bottom}};
        win32(ScreenToClient(window_, &points[0]) != FALSE); win32(ScreenToClient(window_, &points[1]) != FALSE);
        return {points[0].x, points[0].y, points[1].x, points[1].y};
    }
    void tick() {
        ++result_.ticks;
        if (GetTickCount64() >= deadline_) {
            result_.stage = "geometry_timeout"; throw Failure("Geometry deadline", HRESULT_FROM_WIN32(WAIT_TIMEOUT));
        }
        const RECT actual = observe_geometry();
        if (resized_) result_.resized_actual = actual; else result_.initial_actual = actual;
        consecutive_ = equal(actual, expected_) ? consecutive_ + 1 : 0;
        if (consecutive_ < 3) return;
        if (!resized_) {
            result_.initial_geometry_verified = true; result_.stage = "resize_geometry";
            expected_ = result_.resized_expected;
            require(host_->resize(expected_), "Resize hosted control");
            result_.resize_requested = true; resized_ = true; consecutive_ = 0;
        } else if (result_.ticks >= 10) {
            result_.resized_geometry_verified = true; result_.message_pump_verified = true;
            result_.observations_complete = true; result_.stage = "observations_complete"; done_ = true;
        }
    }
    void cleanup() noexcept {
        cleaning_ = true;
        auto record = [this](HRESULT error) {
            if (FAILED(error) && SUCCEEDED(result_.cleanup_error)) result_.cleanup_error = error;
        };
        if (timer_) {
            result_.timer_removed = !window_ || KillTimer(window_, TimerId) != FALSE;
            if (!result_.timer_removed) record(last_win32_error());
        }
        if (host_) {
            result_.close_result = host_->close(); result_.host_closed = SUCCEEDED(result_.close_result);
            record(result_.close_result); host_.reset();
        }
        result_.owned_com_references_released = true;
        result_.control_window_destroyed = control_ && !IsWindow(control_);
        if (control_ && !result_.control_window_destroyed) record(E_UNEXPECTED);
        if (window_) {
            // The stored HWND must still identify this object's own parent.
            if (reinterpret_cast<Probe*>(GetWindowLongPtrW(window_, GWLP_USERDATA)) != this) record(E_UNEXPECTED);
            else if (!DestroyWindow(window_)) record(last_win32_error());
        }
        result_.parent_destroyed = original_window_ && !IsWindow(original_window_);
        if (original_window_ && !result_.parent_destroyed) record(E_UNEXPECTED);
        if (registered_) {
            result_.class_unregistered = UnregisterClassW(WindowClass, instance_) != FALSE;
            if (!result_.class_unregistered) record(last_win32_error());
        }
        if (result_.ole_initialized) { OleUninitialize(); result_.ole_uninitialized = true; }
        result_.cleanup_verified = SUCCEEDED(result_.cleanup_error) && result_.timer_removed && result_.host_closed &&
            result_.owned_com_references_released && (!original_window_ || result_.parent_destroyed) &&
            result_.class_unregistered && (!result_.ole_initialized || result_.ole_uninitialized);
    }
    Result& result_;
    HINSTANCE instance_{};
    HWND window_{}, original_window_{}, control_{};
    ATOM registered_{};
    std::unique_ptr<OleControlHost> host_;
    RECT expected_{};
    ULONGLONG deadline_{};
    unsigned consecutive_{};
    bool timer_{}, done_{}, resized_{}, cleaning_{};
};

void rectangle(const char* name, const RECT& value) {
    std::cout << ",\"" << name << "\":[" << value.left << ',' << value.top << ',' << value.right << ',' << value.bottom << ']';
}
void report(const Result& r, const char* status, ULONGLONG elapsed) {
    std::cout << std::boolalpha << "{\"schema\":\"native-ole-host-probe/v1\",\"status\":\"" << status
        << "\",\"stage\":\"" << r.stage << "\",\"failure_operation\":\"";
    // Failure stages are source literals, never COM/server-provided text.
    for (const char* item = r.operation; *item; ++item) {
        const unsigned char value = static_cast<unsigned char>(*item);
        std::cout << ((value >= 32 && value <= 126 && value != '"' && value != '\\') ? *item : '_');
    }
    std::cout << "\",\"error_hresult\":" << static_cast<std::uint32_t>(r.error)
        << ",\"cleanup_hresult\":" << static_cast<std::uint32_t>(r.cleanup_error)
        << ",\"host_close_hresult\":" << static_cast<std::uint32_t>(r.close_result)
        << ",\"session_id\":" << r.session << ",\"native_architecture\":" << r.architecture
        << ",\"dpi\":" << r.dpi << ",\"apartment_type\":" << r.apartment
        << ",\"apartment_qualifier\":" << r.apartment_qualifier << ",\"timer_ticks\":" << r.ticks
        << ",\"in_place_activation_count\":" << r.activation_count << ",\"elapsed_ms\":" << elapsed;
#define FIELD(name) std::cout << ",\"" #name "\":" << r.name
    FIELD(observations_complete); FIELD(ole_initialized); FIELD(sta_verified); FIELD(input_desktop);
    FIELD(dpi_context_verified); FIELD(parent_created); FIELD(parent_visible); FIELD(control_class_verified);
    FIELD(control_identity_verified); FIELD(site_verified); FIELD(in_place_active); FIELD(control_owned);
    FIELD(control_visible); FIELD(initial_geometry_verified); FIELD(resize_requested); FIELD(resized_geometry_verified);
    FIELD(message_pump_verified); FIELD(timer_removed); FIELD(host_closed); FIELD(owned_com_references_released);
    FIELD(control_window_destroyed); FIELD(parent_destroyed); FIELD(class_unregistered); FIELD(ole_uninitialized);
    FIELD(cleanup_verified);
#undef FIELD
    rectangle("initial_expected", r.initial_expected); rectangle("initial_actual", r.initial_actual);
    rectangle("resized_expected", r.resized_expected); rectangle("resized_actual", r.resized_actual);
    std::cout << ",\"rdp_connect_called\":false,\"session_creation_verified\":false,\"remote_frame_verified\":false,"
        "\"input_channel_verified\":false,\"physical_multiseat_verified\":false,\"screen_presentation_verified\":false}\n";
}
} // namespace

int main() {
    const ULONGLONG started = GetTickCount64(); Result result;
    try { Probe probe(result); probe.run(); }
    catch (const Failure& failure) {
        result.error = failure.result(); result.operation = failure.what();
        if (failure.result() == REGDB_E_CLASSNOTREG || failure.result() == HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND)) result.unavailable = true;
    }
    catch (...) { result.error = E_UNEXPECTED; result.operation = "unknown_cpp_exception"; }
    const bool passed = result.observations_complete && SUCCEEDED(result.error) && result.cleanup_verified &&
        result.control_window_destroyed && result.parent_destroyed;
    const bool unavailable = !passed && result.unavailable && result.cleanup_verified;
    if (!passed && !unavailable && SUCCEEDED(result.error) && FAILED(result.cleanup_error)) result.stage = "cleanup_failed";
    report(result, passed ? "verified" : unavailable ? "unavailable" : "failed", GetTickCount64() - started);
    return passed ? 0 : unavailable ? 77 : 1;
}
