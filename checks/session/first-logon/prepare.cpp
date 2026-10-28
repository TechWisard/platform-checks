#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <ole2.h>
#include <appmodel.h>
#include <dwmapi.h>
#include <wtsapi32.h>
#include <uiautomation.h>
#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <string_view>
#include <utility>

namespace {
constexpr wchar_t TargetFamily[] = L"Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy";
constexpr wchar_t TargetApplication[] = L"Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy!App";
constexpr wchar_t SearchFamily[] = L"MicrosoftWindows.Client.CBS_cw5n1h2txyewy";
constexpr wchar_t SearchApplication[] = L"MicrosoftWindows.Client.CBS_cw5n1h2txyewy!CortanaUI";
constexpr wchar_t TargetClass[] = L"Windows.UI.Core.CoreWindow";
constexpr wchar_t PrivacyHeading[] = L"Choose privacy settings for your device";
constexpr wchar_t AcceptId[] = L"OobeSettingsAcceptButton";
constexpr char ObservedAcceptLabel[] = "Accept these privacy settings";
constexpr ULONGLONG TotalBudgetMs = 32000;
constexpr ULONGLONG PostReadBudgetMs = 3000;
constexpr ULONGLONG AcceptTransitionBudgetMs = 6000;
// These exact fixed OS headings are also used by the read-only presentation probe.
constexpr const wchar_t* KnownHeadings[]{PrivacyHeading, L"Privacy settings", L"Hi", L"Just a moment...",
    L"Just a moment", L"Getting things ready", L"We're getting things ready for you",
    L"This might take a few minutes", L"Let's finish setting up your device", L"Something went wrong",
    L"Microsoft account"};
constexpr const wchar_t* KnownButtonLabels[]{L"Accept", L"Next", L"Back", L"Yes", L"No", L"More", L"Continue",
    L"Done", L"OK", L"Cancel", L"Learn more", L"Save", L"Try again", L"Retry", L"Skip for now", L"Sign in",
    L"Use recommended settings"};
constexpr const wchar_t* SearchNames[]{L"Search", L"Type here to search", L"Type to search", L"Search highlights",
    L"All", L"Apps", L"Documents", L"Settings"};
constexpr const wchar_t* DismissNames[]{L"Close", L"Back", L"Cancel"};
struct ButtonLabel {
    const char* status{"not_read"};
    HRESULT error{S_OK};
    unsigned category{}; // 1 More, 2 Next, 3 Accept, 4 Continue, 5 Done, 255 other safe label.
    std::array<char, 129> ascii{};
};
struct PostPage {
    const char* stage{"not_attempted"};
    HRESULT error{S_OK}, invoke_pattern_error{S_OK};
    bool attempted{}, owner_verified{}, owner_stable{}, root_verified{}, completed{}, button_verified{};
    bool enabled{}, offscreen{true}, invoke_available{};
    int button_count{-1};
    std::array<int, sizeof(KnownHeadings) / sizeof(KnownHeadings[0])> headings{};
    std::array<int, sizeof(KnownButtonLabels) / sizeof(KnownButtonLabels[0])> known_buttons{};
    ButtonLabel label;
    PostPage() { headings.fill(-1); known_buttons.fill(-1); }
};
struct DismissButton {
    int count{-1};
    bool identity_verified{}, enabled{}, offscreen{true}, invoke_available{}, id_read{}, id_safe{};
    HRESULT invoke_error{S_OK}, id_error{S_OK};
    std::array<char, 129> automation_id{};
};
struct SearchPage {
    const char* stage{"not_attempted"};
    HRESULT error{S_OK}, window_pattern_error{S_OK}, interaction_error{S_OK}, modal_error{S_OK}, topmost_error{S_OK};
    bool attempted{}, owner_verified{}, owner_stable{}, root_verified{}, completed{}, window_pattern_available{};
    bool modal{}, topmost{};
    int root_control_type{}, interaction_state{-1};
    std::array<int, sizeof(SearchNames) / sizeof(SearchNames[0])> name_counts{};
    std::array<DismissButton, sizeof(DismissNames) / sizeof(DismissNames[0])> buttons;
    SearchPage() { name_counts.fill(-1); }
};
struct FreshForeground {
    const char* stage{"not_attempted"};
    HRESULT error{S_OK}, class_error{S_OK}, package_error{S_OK}, application_error{S_OK};
    ULONGLONG after_second_ms{}, elapsed_ms{};
    bool attempted{}, active_desktop_verified{}, original_target_destroyed{}, owner_verified{}, owner_stable{};
    bool class_read{}, package_read{}, application_read{}, class_safe{}, package_safe{}, application_safe{};
    bool exact_cloud_identity{}, exact_search_identity{}, content_attempted{};
    unsigned class_category{}, package_category{}, application_category{};
    std::array<char, 129> class_identifier{};
    std::array<char, 257> package_identifier{}, application_identifier{};
    PostPage page;
    SearchPage search_page;
};
struct SecondAction {
    const char* stage{"not_attempted"};
    HRESULT invoke_error{S_OK};
    ULONGLONG delay_ms{};
    ULONGLONG completed_tick{}; // Internal scheduling only; never a window/process identifier.
    unsigned initial_heading_count{}, recheck_heading_count{}, initial_button_count{}, recheck_button_count{};
    bool checked{}, first_page_verified{}, recheck_page_verified{}, owner_verified{}, owner_reverified{}, same_button_reverified{};
    bool invoke_attempted{}, invoke_succeeded{};
    ButtonLabel first_label, recheck_label;
};
struct SearchEscape {
    const char* stage{"not_attempted"};
    HRESULT error{S_OK}, target_observation_error{S_OK};
    ULONGLONG after_second_ms{}, elapsed_ms{};
    unsigned initial_search_count{}, recheck_search_count{}, async_down_mask{}, queue_down_mask{};
    unsigned send_call_count{}, requested_input_count{}, inserted_input_count{}, send_last_error{};
    unsigned cleanup_call_count{}, cleanup_inserted_count{}, cleanup_last_error{}, release_observations{}, target_observations{};
    bool checked{}, first_snapshot_verified{}, original_target_destroyed{}, owner_verified{}, owner_reverified{};
    bool first_page_verified{}, recheck_page_verified{}, same_root_reverified{}, key_state_checked{};
    bool keyboard_state_query_succeeded{}, async_highbits_up{}, queue_highbits_up{}, send_attempted{}, pair_inserted{};
    bool release_cleanup_attempted{}, release_event_inserted{}, escape_up_observed{}, key_cleanup_verified{true};
    bool target_observation_valid{}, target_exists{}, target_visible{}, target_foreground{}, target_hidden_or_destroyed{};
};
struct Failure { const char* stage; HRESULT result; };
void need(bool value, const char* stage, HRESULT error = E_UNEXPECTED) {
    if (!value) throw Failure{stage, error};
}
void hr(HRESULT value, const char* stage) { need(SUCCEEDED(value), stage, value); }
HRESULT last_error() noexcept {
    const DWORD error = GetLastError(); return HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE);
}
void win32(BOOL value, const char* stage) { if (!value) throw Failure{stage, last_error()}; }
template<class T> class Com final {
    T* value_{};
public:
    Com() = default;
    ~Com() { if (value_) value_->Release(); }
    Com(const Com&) = delete;
    Com& operator=(const Com&) = delete;
    Com(Com&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    T* get() const noexcept { return value_; }
    T* operator->() const noexcept { return value_; }
    T** put() noexcept { if (value_) value_->Release(); value_ = nullptr; return &value_; }
};
struct Result {
    const char* status{"failed"};
    const char* stage{"start"};
    HRESULT error{S_OK}, invoke_error{S_OK}, cleanup_error{S_OK};
    HRESULT foreground_class_hresult{S_OK}, observed_target_cloak_hresult{S_OK};
    DWORD session{};
    unsigned initial_heading_count{}, recheck_heading_count{}, initial_button_count{}, recheck_button_count{};
    unsigned invoke_count{}, wait_observations{}, stable_observations{}, foreground_kind{};
    unsigned wait_guard{}, foreground_class_category{};
    DWORD observed_target_cloak_flags{};
    bool opted_in{}, disposable_environment_verified{}, input_default_desktop_verified{}, target_initially_foreground{};
    bool target_owner_verified{}, target_owner_reverified{}, root_handle_verified{}, same_button_reverified{};
    bool invoke_attempted{}, invoke_succeeded{}, observed_page_hidden_or_destroyed{};
    bool explorer_shell_verified{}, ordinary_desktop_verified{}, com_uninitialized{}, cleanup_verified{true};
    bool shell_handle_present{}, shell_window_exists{}, shell_identity_checked{};
    bool foreground_present{}, foreground_class_read{}, associated_console_present{};
    bool foreground_is_shell{}, foreground_matches_associated_console{}, foreground_shares_shell_process{};
    bool foreground_is_observed_target{}, observed_target_sampled{}, observed_target_exists{}, observed_target_visible{};
    bool observed_target_cloak_query_attempted{};
    bool final_active_input_desktop_verified{};
    bool first_label_is_known_accept{};
    ButtonLabel button_before;
    PostPage post;
    SecondAction second;
    std::array<FreshForeground, 2> fresh_foreground;
    SearchEscape search_escape;
};
struct Handle final {
    HANDLE value{};
    Result* result{};
    Handle(HANDLE handle, Result& out) noexcept : value(handle), result(&out) {}
    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE && !CloseHandle(value)) {
            result->cleanup_verified = false; result->cleanup_error = last_error();
        }
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct SearchEscapeTarget {
    HWND window{};
    DWORD owner{}, thread{};
    Handle process;
    explicit SearchEscapeTarget(Result& out) : process(nullptr, out) {}
};
struct Apartment final {
    Result& result;
    explicit Apartment(Result& out) : result(out) { hr(CoInitializeEx(nullptr, COINIT_MULTITHREADED), "com_initialize"); }
    ~Apartment() { CoUninitialize(); result.com_uninitialized = true; }
};
struct Text final {
    BSTR value{};
    ~Text() { if (value) { SecureZeroMemory(value, SysStringByteLen(value)); SysFreeString(value); } }
};
bool environment_equals(const wchar_t* name, const wchar_t* expected) {
    std::array<wchar_t, 64> value{};
    const DWORD size = GetEnvironmentVariableW(name, value.data(), static_cast<DWORD>(value.size()));
    return size > 0 && size < value.size() && std::wcscmp(value.data(), expected) == 0;
}
bool text_equals(BSTR value, const wchar_t* expected) noexcept {
    const auto expected_size = std::wcslen(expected);
    return value && SysStringLen(value) == expected_size && std::wcscmp(value, expected) == 0;
}
bool unicode_space(std::uint32_t c) noexcept {
    // Unicode 16.0 White_Space; collapse to one ASCII space and trim.
    return (c >= 9 && c <= 13) || c == 0x20 || c == 0x85 || c == 0xA0 || c == 0x1680 ||
        (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029 || c == 0x202F || c == 0x205F || c == 0x3000;
}
bool unicode_format(std::uint32_t c) noexcept {
    // Unicode 16.0 General_Category=Cf, used only to normalize this fixed button's label.
    constexpr std::uint32_t ranges[][2]{{0xAD,0xAD},{0x600,0x605},{0x61C,0x61C},{0x6DD,0x6DD},
        {0x70F,0x70F},{0x890,0x891},{0x8E2,0x8E2},{0x180E,0x180E},{0x200B,0x200F},
        {0x202A,0x202E},{0x2060,0x2064},{0x2066,0x206F},{0xFEFF,0xFEFF},{0xFFF9,0xFFFB},
        {0x110BD,0x110BD},{0x110CD,0x110CD},{0x13430,0x1343F},{0x1BCA0,0x1BCA3},
        {0x1D173,0x1D17A},{0xE0001,0xE0001},{0xE0020,0xE007F}};
    for (const auto& range : ranges) if (c >= range[0] && c <= range[1]) return true;
    return false;
}
void normalize_button_label(BSTR value, ButtonLabel& out) {
    const UINT length = value ? SysStringLen(value) : 0;
    if (!length || length > 128) { out.status = length ? "oversized" : "empty"; return; }
    std::array<char, 129> normalized{}; std::size_t used{}; bool space{};
    for (UINT index = 0; index < length; ++index) {
        std::uint32_t c = static_cast<std::uint16_t>(value[index]);
        if (c >= 0xD800 && c <= 0xDBFF && index + 1 < length) {
            const auto low = static_cast<std::uint16_t>(value[index + 1]);
            if (low >= 0xDC00 && low <= 0xDFFF) { c = 0x10000 + ((c - 0xD800) << 10) + low - 0xDC00; ++index; }
        }
        if (unicode_format(c)) continue;
        if (unicode_space(c)) { space = used != 0; continue; }
        // No controls, non-ASCII text, quotes, slash, backslash, colon, dot or @.
        // Consequently the fallback cannot contain a URL, email or path.
        const bool safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '\'' || c == '(' || c == ')' || c == '?' || c == '!';
        if (!safe) { out.status = "unsafe_or_non_ascii"; return; }
        if (space) normalized[used++] = ' ';
        space = false; normalized[used++] = static_cast<char>(c);
    }
    if (!used) { out.status = "empty_after_normalization"; return; }
    out.ascii = normalized; out.category = 255; out.status = "safe_ascii";
    for (std::size_t index = 0; index < used; ++index)
        if (normalized[index] >= 'A' && normalized[index] <= 'Z')
            normalized[index] = static_cast<char>(normalized[index] + ('a' - 'A'));
    constexpr const char* labels[]{"more", "next", "accept", "continue", "done"};
    for (unsigned index = 0; index < sizeof(labels) / sizeof(labels[0]); ++index)
        if (std::strcmp(normalized.data(), labels[index]) == 0) { out.category = index + 1; out.status = "classified"; break; }
}
void budget(ULONGLONG end) { need(GetTickCount64() < end, "preparation_deadline", HRESULT_FROM_WIN32(WAIT_TIMEOUT)); }
void read_button_label(IUIAutomationElement* button, ButtonLabel& out, ULONGLONG end) {
    Text name; budget(end); out.error = button->get_CurrentName(&name.value);
    if (FAILED(out.error)) { out.status = "name_unavailable"; return; }
    normalize_button_label(name.value, out);
}
bool exact_observed_accept(const ButtonLabel& label) noexcept {
    return SUCCEEDED(label.error) && std::strcmp(label.ascii.data(), ObservedAcceptLabel) == 0;
}
void verify_desktop(Result& out) {
    DWORD session{};
    win32(ProcessIdToSessionId(GetCurrentProcessId(), &session), "current_session");
    need(session && session == WTSGetActiveConsoleSessionId() && (!out.session || session == out.session), "active_own_console_required");
    out.session = session;
    LPWSTR state{}; DWORD state_bytes{};
    win32(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSConnectState, &state, &state_bytes),
        "current_session_state");
    const bool active = state && state_bytes == sizeof(WTS_CONNECTSTATE_CLASS) &&
        *reinterpret_cast<WTS_CONNECTSTATE_CLASS*>(state) == WTSActive;
    if (state) WTSFreeMemory(state);
    need(active, "current_session_not_active");
    const HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
    BOOL input{}; DWORD needed{}; std::array<wchar_t, 128> name{};
    win32(GetUserObjectInformationW(desktop, UOI_IO, &input, sizeof(input), &needed), "input_desktop_query");
    win32(GetUserObjectInformationW(desktop, UOI_NAME, name.data(), static_cast<DWORD>(sizeof(name)), &needed), "desktop_name_query");
    need(input && needed > 0 && needed <= sizeof(name) && name.back() == L'\0' &&
        std::wcscmp(name.data(), L"Default") == 0, "default_input_desktop_required");
    out.input_default_desktop_verified = true;
}
DWORD window_owner(HWND window, DWORD session, DWORD* thread_out = nullptr) {
    DWORD owner{}, actual_session{};
    const DWORD thread = GetWindowThreadProcessId(window, &owner);
    need(thread && owner && ProcessIdToSessionId(owner, &actual_session) != FALSE && actual_session == session,
        "same_session_window_required");
    if (thread_out) *thread_out = thread;
    return owner;
}
bool target_package(HANDLE process) {
    std::array<wchar_t, 257> family{}; UINT32 size = static_cast<UINT32>(family.size());
    const LONG result = GetPackageFamilyName(process, &size, family.data());
    if (result == APPMODEL_ERROR_NO_PACKAGE) return false;
    need(result == ERROR_SUCCESS && size > 1 && size <= family.size() && family[size - 1] == L'\0',
        "package_identity_query", result == ERROR_SUCCESS ? E_UNEXPECTED : HRESULT_FROM_WIN32(result));
    return std::wcscmp(family.data(), TargetFamily) == 0;
}
bool class_equals(HWND window, const wchar_t* expected) {
    std::array<wchar_t, 128> name{};
    const int count = GetClassNameW(window, name.data(), static_cast<int>(name.size()));
    need(count > 0 && count < static_cast<int>(name.size() - 1), "window_class_query", last_error());
    return std::wcscmp(name.data(), expected) == 0;
}
void verify_target(HWND root, DWORD owner, DWORD thread, HANDLE process, Result& out) {
    verify_desktop(out);
    DWORD actual_thread{};
    need(IsWindow(root) && IsWindowVisible(root) && GetAncestor(GetForegroundWindow(), GA_ROOT) == root &&
        window_owner(root, out.session, &actual_thread) == owner && actual_thread == thread,
        "target_foreground_owner_changed");
    DWORD exit_code{};
    need(GetProcessId(process) == owner && GetExitCodeProcess(process, &exit_code) != FALSE && exit_code == STILL_ACTIVE,
        "pinned_target_process_not_active");
    need(class_equals(root, TargetClass) && target_package(process), "target_class_or_package_changed");
    std::array<wchar_t, 257> app{}; UINT32 size = static_cast<UINT32>(app.size());
    const LONG result = GetApplicationUserModelId(process, &size, app.data());
    need(result == ERROR_SUCCESS && size > 1 && size <= app.size() && app[size - 1] == L'\0' &&
        std::wcscmp(app.data(), TargetApplication) == 0, "target_application_mismatch",
        result == ERROR_SUCCESS ? E_UNEXPECTED : HRESULT_FROM_WIN32(result));
}
bool explorer_image(HANDLE process) {
    struct Buffer { std::array<wchar_t, 1024> value{}; ~Buffer() { SecureZeroMemory(value.data(), sizeof(value)); } } path;
    DWORD size = static_cast<DWORD>(path.value.size());
    win32(QueryFullProcessImageNameW(process, 0, path.value.data(), &size), "shell_image_query");
    need(size && size < path.value.size(), "shell_image_size");
    const wchar_t* last = std::wcsrchr(path.value.data(), L'\\');
    const wchar_t* basename = last ? last + 1 : path.value.data();
    return CompareStringOrdinal(basename, -1, L"explorer.exe", -1, TRUE) == CSTR_EQUAL;
}
template<std::size_t Size> bool safe_identifier(const wchar_t* value, std::size_t length,
    std::array<char, Size>& output, bool allow_bang) noexcept {
    if (!length || length >= Size) return false;
    std::array<char, Size> candidate{};
    for (std::size_t index = 0; index < length; ++index) {
        const auto c = static_cast<std::uint16_t>(value[index]);
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '_' || c == '.' || (allow_bang && c == '!'))) return false;
        candidate[index] = static_cast<char>(c);
    }
    output = candidate; return true; // No prefix is retained on rejection.
}
unsigned foreground_class(HWND window, bool& read, HRESULT& error, std::array<char, 129>* identifier = nullptr,
    bool* identifier_safe = nullptr) {
    std::array<wchar_t, 130> value{};
    const int size = GetClassNameW(window, value.data(), static_cast<int>(value.size()));
    if (size <= 0 || size > 128) {
        error = size <= 0 ? last_error() : HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    read = true;
    if (identifier && identifier_safe) *identifier_safe = safe_identifier(value.data(), static_cast<std::size_t>(size), *identifier, false);
    constexpr const wchar_t* classes[]{L"Progman", L"WorkerW", L"CabinetWClass", L"ConsoleWindowClass",
        L"CASCADIA_HOSTING_WINDOW_CLASS", L"Windows.UI.Core.CoreWindow", L"ApplicationFrameWindow"};
    for (unsigned index = 0; index < sizeof(classes) / sizeof(classes[0]); ++index)
        if (std::wcscmp(value.data(), classes[index]) == 0) return index + 1;
    return 255; // Classification never widens readiness; a fresh snapshot may emit a separately filtered OS identifier.
}
bool ordinary_desktop(HWND original_target, Result& out) {
    verify_desktop(out);
    out.wait_guard = 0; out.foreground_kind = 0; out.explorer_shell_verified = false; out.shell_identity_checked = false;
    out.foreground_class_category = 0; out.foreground_class_read = false; out.foreground_class_hresult = S_OK;
    out.foreground_shares_shell_process = false;
    // Every directly readable observation is refreshed before an early return.
    // DWM cloak state is diagnostic only; all existing readiness gates stay.
    out.observed_target_sampled = original_target != nullptr;
    out.observed_target_exists = original_target && IsWindow(original_target);
    out.observed_target_visible = out.observed_target_exists && IsWindowVisible(original_target);
    out.observed_page_hidden_or_destroyed = original_target && (!out.observed_target_exists || !out.observed_target_visible);
    out.observed_target_cloak_query_attempted = out.observed_target_exists;
    out.observed_target_cloak_flags = 0; out.observed_target_cloak_hresult = S_OK;
    if (out.observed_target_exists) {
        out.observed_target_cloak_hresult = DwmGetWindowAttribute(original_target, DWMWA_CLOAKED,
            &out.observed_target_cloak_flags, sizeof(out.observed_target_cloak_flags));
    }
    const HWND shell = GetShellWindow();
    out.shell_handle_present = shell != nullptr; out.shell_window_exists = shell && IsWindow(shell);
    const HWND foreground = GetAncestor(GetForegroundWindow(), GA_ROOT);
    const HWND console = GetConsoleWindow();
    out.foreground_present = foreground != nullptr; out.associated_console_present = console != nullptr;
    out.foreground_is_shell = foreground && foreground == shell;
    out.foreground_matches_associated_console = foreground && console && foreground == GetAncestor(console, GA_ROOT);
    out.foreground_is_observed_target = foreground && original_target && foreground == original_target;
    if (foreground) out.foreground_class_category = foreground_class(foreground, out.foreground_class_read, out.foreground_class_hresult);
    if (!shell || !IsWindow(shell)) { out.wait_guard = 1; return false; }
    const DWORD shell_owner = window_owner(shell, out.session);
    Handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, shell_owner), out};
    need(process.value != nullptr, "shell_process_open", last_error());
    out.explorer_shell_verified = explorer_image(process.value); out.shell_identity_checked = true;
    need(out.explorer_shell_verified, "shell_process_not_explorer");
    if (!foreground) { out.wait_guard = 2; return false; }
    const DWORD foreground_owner = window_owner(foreground, out.session);
    out.foreground_shares_shell_process = foreground_owner == shell_owner;
    unsigned kind{};
    if (foreground == shell) kind = 1;
    else if (foreground == GetAncestor(GetConsoleWindow(), GA_ROOT)) kind = 2;
    else if (foreground_owner == shell_owner &&
        (class_equals(foreground, L"Progman") || class_equals(foreground, L"WorkerW") || class_equals(foreground, L"CabinetWClass"))) kind = 3;
    out.foreground_kind = kind;
    if (!kind) { out.wait_guard = 3; return false; }
    const bool absent = !original_target || !IsWindow(original_target) || !IsWindowVisible(original_target);
    if (!absent) { out.wait_guard = 4; return false; }
    // Recheck the exact observed shell/foreground before reporting a stable poll.
    if (GetShellWindow() != shell || GetAncestor(GetForegroundWindow(), GA_ROOT) != foreground ||
        window_owner(shell, out.session) != shell_owner || window_owner(foreground, out.session) != foreground_owner) {
        out.wait_guard = 5; return false;
    }
    out.explorer_shell_verified = true; out.foreground_kind = kind;
    if (original_target) out.observed_page_hidden_or_destroyed = true;
    out.wait_guard = 6;
    return true;
}
Com<IUIAutomationCondition> property(IUIAutomation2* automation, PROPERTYID id, VARIANT value, ULONGLONG end) {
    budget(end); Com<IUIAutomationCondition> condition;
    hr(automation->CreatePropertyCondition(id, value, condition.put()), "automation_condition");
    need(condition.get() != nullptr, "automation_null_condition"); return condition;
}
Com<IUIAutomationCondition> number_property(IUIAutomation2* automation, PROPERTYID id, int number, ULONGLONG end) {
    VARIANT value{}; value.vt = VT_I4; value.lVal = number; return property(automation, id, value, end);
}
Com<IUIAutomationCondition> bool_property(IUIAutomation2* automation, PROPERTYID id, bool boolean, ULONGLONG end) {
    VARIANT value{}; value.vt = VT_BOOL; value.boolVal = boolean ? VARIANT_TRUE : VARIANT_FALSE; return property(automation, id, value, end);
}
Com<IUIAutomationCondition> text_property(IUIAutomation2* automation, PROPERTYID id, const wchar_t* text, ULONGLONG end) {
    Text stored; stored.value = SysAllocString(text); need(stored.value != nullptr, "condition_allocation", E_OUTOFMEMORY);
    VARIANT value{}; value.vt = VT_BSTR; value.bstrVal = stored.value; return property(automation, id, value, end);
}
Com<IUIAutomationElementArray> matches(IUIAutomation2* automation, IUIAutomationElement* root, DWORD owner,
    bool button, ULONGLONG end, const wchar_t* heading = PrivacyHeading) {
    need(owner <= static_cast<DWORD>(INT_MAX), "automation_process_id_range");
    std::array<Com<IUIAutomationCondition>, 6> conditions{
        number_property(automation, UIA_ProcessIdPropertyId, static_cast<int>(owner), end),
        bool_property(automation, UIA_IsPasswordPropertyId, false, end),
        bool_property(automation, UIA_IsOffscreenPropertyId, false, end),
        number_property(automation, UIA_ControlTypePropertyId, button ? UIA_ButtonControlTypeId : UIA_TextControlTypeId, end),
        text_property(automation, button ? UIA_AutomationIdPropertyId : UIA_NamePropertyId, button ? AcceptId : heading, end),
        bool_property(automation, UIA_IsEnabledPropertyId, true, end)
    };
    std::array<IUIAutomationCondition*, 6> raw{};
    for (std::size_t i = 0; i < conditions.size(); ++i) raw[i] = conditions[i].get();
    Com<IUIAutomationCondition> combined;
    budget(end); hr(automation->CreateAndConditionFromNativeArray(raw.data(), button ? 6 : 5, combined.put()), "automation_conditions");
    Com<IUIAutomationElementArray> elements;
    budget(end); hr(root->FindAll(TreeScope_Descendants, combined.get(), elements.put()), "targeted_page_search");
    need(elements.get() != nullptr, "automation_null_elements"); return elements;
}
int fixed_button_label_count(IUIAutomation2* automation, IUIAutomationElement* root, DWORD owner,
    const wchar_t* label, ULONGLONG end) {
    need(owner <= static_cast<DWORD>(INT_MAX), "fixed_button_process_range");
    std::array<Com<IUIAutomationCondition>, 5> conditions{
        number_property(automation, UIA_ProcessIdPropertyId, static_cast<int>(owner), end),
        bool_property(automation, UIA_IsPasswordPropertyId, false, end),
        bool_property(automation, UIA_IsOffscreenPropertyId, false, end),
        number_property(automation, UIA_ControlTypePropertyId, UIA_ButtonControlTypeId, end),
        text_property(automation, UIA_NamePropertyId, label, end)};
    std::array<IUIAutomationCondition*, 5> raw{};
    for (std::size_t index = 0; index < raw.size(); ++index) raw[index] = conditions[index].get();
    Com<IUIAutomationCondition> combined; Com<IUIAutomationElementArray> elements;
    budget(end); hr(automation->CreateAndConditionFromNativeArray(raw.data(), static_cast<int>(raw.size()), combined.put()), "fixed_button_condition");
    budget(end); hr(root->FindAll(TreeScope_Descendants, combined.get(), elements.put()), "fixed_button_search");
    need(elements.get() != nullptr, "fixed_button_null_elements");
    int count{}; budget(end); hr(elements->get_Length(&count), "fixed_button_count");
    need(count >= 0 && count <= 8, "fixed_button_count_bound"); return count;
}
struct Page {
    Com<IUIAutomationElement> root, button;
    Com<IUIAutomationInvokePattern> invoke;
    unsigned headings{}, buttons{};
};
Page read_page(IUIAutomation2* automation, HWND window, DWORD owner, ULONGLONG end, Result& out) {
    Page page;
    budget(end); hr(automation->ElementFromHandle(window, page.root.put()), "automation_root");
    need(page.root.get() != nullptr, "automation_null_root");
    UIA_HWND native{}; int root_owner{};
    budget(end); hr(page.root->get_CurrentNativeWindowHandle(&native), "automation_root_handle");
    budget(end); hr(page.root->get_CurrentProcessId(&root_owner), "automation_root_process");
    need(native == window && root_owner > 0 && static_cast<DWORD>(root_owner) == owner, "automation_root_identity_mismatch");
    out.root_handle_verified = true;
    auto headings = matches(automation, page.root.get(), owner, false, end);
    int count{}; budget(end); hr(headings->get_Length(&count), "privacy_heading_count");
    need(count > 0 && count <= 8, "exact_visible_privacy_heading_required"); page.headings = static_cast<unsigned>(count);
    auto buttons = matches(automation, page.root.get(), owner, true, end);
    budget(end); hr(buttons->get_Length(&count), "accept_button_count");
    need(count == 1, "unique_visible_enabled_accept_button_required"); page.buttons = static_cast<unsigned>(count);
    budget(end); hr(buttons->GetElement(0, page.button.put()), "accept_button_element"); need(page.button.get() != nullptr, "null_accept_button");
    // Read back only the fixed candidate's identity. No arbitrary names/values.
    int process_id{}, type{}; BOOL password = TRUE, offscreen = TRUE, enabled = FALSE;
    budget(end); hr(page.button->get_CurrentProcessId(&process_id), "button_process");
    budget(end); hr(page.button->get_CurrentControlType(&type), "button_type");
    budget(end); hr(page.button->get_CurrentIsPassword(&password), "button_password_flag");
    budget(end); hr(page.button->get_CurrentIsOffscreen(&offscreen), "button_visibility");
    budget(end); hr(page.button->get_CurrentIsEnabled(&enabled), "button_enabled");
    Text id; budget(end); hr(page.button->get_CurrentAutomationId(&id.value), "button_id");
    need(process_id > 0 && static_cast<DWORD>(process_id) == owner && type == UIA_ButtonControlTypeId &&
        !password && !offscreen && enabled && text_equals(id.value, AcceptId), "accept_button_changed");
    budget(end); hr(page.button->GetCurrentPatternAs(UIA_InvokePatternId, __uuidof(IUIAutomationInvokePattern),
        reinterpret_cast<void**>(page.invoke.put())), "button_invoke_pattern");
    need(page.invoke.get() != nullptr, "invoke_pattern_unavailable"); return page;
}
void consider_observed_accept(IUIAutomation2* automation, HWND window, DWORD owner, DWORD thread, HANDLE process,
    ULONGLONG first_completed, ULONGLONG wait_end, Result& out) {
    auto& second = out.second; second.checked = true;
    need(out.invoke_count == 1 && out.invoke_succeeded && !second.invoke_attempted, "accept_transition_order");
    if (out.first_label_is_known_accept) { second.stage = "first_action_already_accept"; return; }
    const ULONGLONG early_end = first_completed + AcceptTransitionBudgetMs < wait_end ?
        first_completed + AcceptTransitionBudgetMs : wait_end;
    if (early_end <= first_completed + 1000) { second.stage = "early_window_unavailable"; return; }
    // This is one separate observed transition, never a retry of the first Invoke.
    // Waiting is bounded and never changes focus or sends keys to the OS page.
    Sleep(1000);
    while (GetTickCount64() - first_completed < 1000) Sleep(1);
    if (!IsWindow(window) || !IsWindowVisible(window) || GetAncestor(GetForegroundWindow(), GA_ROOT) != window) {
        second.stage = "target_no_longer_foreground"; return;
    }
    budget(early_end); verify_target(window, owner, thread, process, out); second.owner_verified = true;
    Page first = read_page(automation, window, owner, early_end, out);
    second.first_page_verified = true;
    second.initial_heading_count = first.headings; second.initial_button_count = first.buttons;
    read_button_label(first.button.get(), second.first_label, early_end);
    if (!exact_observed_accept(second.first_label)) { second.stage = "label_not_observed_accept"; return; }
    budget(early_end); verify_target(window, owner, thread, process, out);
    Page fresh = read_page(automation, window, owner, early_end, out);
    second.recheck_page_verified = true;
    second.recheck_heading_count = fresh.headings; second.recheck_button_count = fresh.buttons;
    read_button_label(fresh.button.get(), second.recheck_label, early_end);
    if (!exact_observed_accept(second.recheck_label)) { second.stage = "accept_label_changed"; return; }
    BOOL same{};
    budget(early_end); hr(automation->CompareElements(first.button.get(), fresh.button.get(), &same), "second_same_accept_button");
    need(same != FALSE, "second_accept_button_replaced"); second.same_button_reverified = true;
    budget(early_end); verify_target(window, owner, thread, process, out); second.owner_reverified = true;
    budget(early_end); second.delay_ms = GetTickCount64() - first_completed;
    need(second.delay_ms >= 1000 && second.delay_ms < AcceptTransitionBudgetMs, "accept_transition_timing");
    out.stage = "invoke_observed_privacy_accept"; second.stage = "invoke_observed_accept";
    second.invoke_attempted = true; ++out.invoke_count;
    second.invoke_error = fresh.invoke->Invoke(); hr(second.invoke_error, "observed_accept_invoke");
    second.invoke_succeeded = true; second.stage = "invoked"; second.completed_tick = GetTickCount64();
}
PostPage observe_after_invoke(HWND window, DWORD owner, DWORD thread, HANDLE process, ULONGLONG end, Result& out,
    bool fixed_buttons = false) {
    PostPage observation; observation.attempted = true;
    try {
        budget(end); verify_target(window, owner, thread, process, out); observation.owner_verified = true;
        Apartment apartment(out); Com<IUIAutomation2> automation; Com<IUIAutomationElement> root;
        hr(CoCreateInstance(__uuidof(CUIAutomation8), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(IUIAutomation2), reinterpret_cast<void**>(automation.put())), "post_automation_create");
        need(automation.get() != nullptr, "post_automation_null");
        hr(automation->put_AutoSetFocus(FALSE), "post_no_focus");
        hr(automation->put_ConnectionTimeout(1000), "post_connection_timeout");
        hr(automation->put_TransactionTimeout(1000), "post_transaction_timeout");
        budget(end); hr(automation->ElementFromHandle(window, root.put()), "post_root");
        need(root.get() != nullptr, "post_null_root");
        UIA_HWND native{}; int root_owner{};
        budget(end); hr(root->get_CurrentNativeWindowHandle(&native), "post_root_handle");
        budget(end); hr(root->get_CurrentProcessId(&root_owner), "post_root_process");
        need(native == window && root_owner > 0 && static_cast<DWORD>(root_owner) == owner, "post_root_identity");
        observation.root_verified = true;
        auto privacy = matches(automation.get(), root.get(), owner, false, end);
        budget(end); hr(privacy->get_Length(&observation.headings[0]), "post_privacy_count");
        need(observation.headings[0] >= 0 && observation.headings[0] <= 8, "post_privacy_count_bound");
        std::array<Com<IUIAutomationCondition>, 4> conditions{
            number_property(automation.get(), UIA_ProcessIdPropertyId, static_cast<int>(owner), end),
            bool_property(automation.get(), UIA_IsPasswordPropertyId, false, end),
            number_property(automation.get(), UIA_ControlTypePropertyId, UIA_ButtonControlTypeId, end),
            text_property(automation.get(), UIA_AutomationIdPropertyId, AcceptId, end)};
        std::array<IUIAutomationCondition*, 4> raw{};
        for (std::size_t index = 0; index < raw.size(); ++index) raw[index] = conditions[index].get();
        Com<IUIAutomationCondition> combined; Com<IUIAutomationElementArray> buttons;
        budget(end); hr(automation->CreateAndConditionFromNativeArray(raw.data(), static_cast<int>(raw.size()), combined.put()), "post_button_condition");
        budget(end); hr(root->FindAll(TreeScope_Descendants, combined.get(), buttons.put()), "post_button_search");
        need(buttons.get() != nullptr, "post_null_buttons");
        budget(end); hr(buttons->get_Length(&observation.button_count), "post_button_count");
        need(observation.button_count >= 0 && observation.button_count <= 8, "post_button_count_bound");
        if (observation.button_count == 1) {
            Com<IUIAutomationElement> button;
            budget(end); hr(buttons->GetElement(0, button.put()), "post_button_element");
            need(button.get() != nullptr, "post_null_button");
            int actual_owner{}, type{}; BOOL password = TRUE, enabled = FALSE, offscreen = TRUE;
            Text id;
            budget(end); hr(button->get_CurrentProcessId(&actual_owner), "post_button_owner");
            budget(end); hr(button->get_CurrentControlType(&type), "post_button_type");
            budget(end); hr(button->get_CurrentIsPassword(&password), "post_button_password");
            budget(end); hr(button->get_CurrentAutomationId(&id.value), "post_button_id");
            need(actual_owner > 0 && static_cast<DWORD>(actual_owner) == owner && type == UIA_ButtonControlTypeId &&
                !password && text_equals(id.value, AcceptId), "post_button_identity");
            observation.button_verified = true;
            budget(end); hr(button->get_CurrentIsEnabled(&enabled), "post_button_enabled");
            budget(end); hr(button->get_CurrentIsOffscreen(&offscreen), "post_button_offscreen");
            observation.enabled = enabled != FALSE; observation.offscreen = offscreen != FALSE;
            Com<IUIAutomationInvokePattern> pattern;
            budget(end); observation.invoke_pattern_error = button->GetCurrentPatternAs(UIA_InvokePatternId,
                __uuidof(IUIAutomationInvokePattern), reinterpret_cast<void**>(pattern.put()));
            observation.invoke_available = SUCCEEDED(observation.invoke_pattern_error) && pattern.get() != nullptr;
            // Only this fixed non-password button on the still-verified privacy page exposes a name.
            if (observation.headings[0] > 0) read_button_label(button.get(), observation.label, end);
            else observation.label.status = "privacy_heading_absent";
        }
        for (std::size_t index = 1; index < observation.headings.size(); ++index) {
            auto headings = matches(automation.get(), root.get(), owner, false, end, KnownHeadings[index]);
            budget(end); hr(headings->get_Length(&observation.headings[index]), "post_known_heading_count");
            need(observation.headings[index] >= 0 && observation.headings[index] <= 8, "post_known_heading_count_bound");
        }
        if (fixed_buttons) for (std::size_t index = 0; index < observation.known_buttons.size(); ++index)
            observation.known_buttons[index] = fixed_button_label_count(automation.get(), root.get(), owner, KnownButtonLabels[index], end);
        observation.completed = true; observation.stage = "completed";
    } catch (const Failure& failure) { observation.stage = failure.stage; observation.error = failure.result; }
    catch (...) { observation.stage = "post_unexpected_exception"; observation.error = E_UNEXPECTED; }
    if (observation.owner_verified) {
        try { verify_target(window, owner, thread, process, out); observation.owner_stable = true; }
        catch (const Failure& failure) {
            observation = PostPage{}; observation.attempted = true;
            observation.stage = failure.stage; observation.error = failure.result;
        }
    }
    return observation; // Discard content if ownership changed during the bounded read.
}
void verify_fresh_foreground(HWND root, DWORD owner, DWORD thread, HANDLE process, Result& out) {
    verify_desktop(out); DWORD actual_thread{}, exit_code{};
    need(IsWindow(root) && IsWindowVisible(root) && GetAncestor(GetForegroundWindow(), GA_ROOT) == root &&
        window_owner(root, out.session, &actual_thread) == owner && actual_thread == thread &&
        GetProcessId(process) == owner && GetExitCodeProcess(process, &exit_code) != FALSE && exit_code == STILL_ACTIVE,
        "fresh_foreground_owner_changed");
}
void verify_search_target(HWND root, DWORD owner, DWORD thread, HANDLE process, Result& out) {
    verify_fresh_foreground(root, owner, thread, process, out);
    need(class_equals(root, TargetClass), "search_target_class");
    std::array<wchar_t, 257> family{}, app{}; UINT32 family_size = static_cast<UINT32>(family.size());
    const LONG family_result = GetPackageFamilyName(process, &family_size, family.data());
    need(family_result == ERROR_SUCCESS && family_size > 1 && family_size <= family.size() &&
        family[family_size - 1] == L'\0' && std::wcscmp(family.data(), SearchFamily) == 0,
        "search_target_family", family_result == ERROR_SUCCESS ? E_UNEXPECTED : HRESULT_FROM_WIN32(family_result));
    UINT32 app_size = static_cast<UINT32>(app.size());
    const LONG app_result = GetApplicationUserModelId(process, &app_size, app.data());
    need(app_result == ERROR_SUCCESS && app_size > 1 && app_size <= app.size() && app[app_size - 1] == L'\0' &&
        std::wcscmp(app.data(), SearchApplication) == 0, "search_target_application",
        app_result == ERROR_SUCCESS ? E_UNEXPECTED : HRESULT_FROM_WIN32(app_result));
}
Com<IUIAutomationElementArray> fixed_search_name(IUIAutomation2* automation, IUIAutomationElement* root,
    DWORD owner, const wchar_t* name, bool button, ULONGLONG end) {
    need(owner <= static_cast<DWORD>(INT_MAX), "search_process_range");
    std::array<Com<IUIAutomationCondition>, 5> conditions{
        number_property(automation, UIA_ProcessIdPropertyId, static_cast<int>(owner), end),
        bool_property(automation, UIA_IsPasswordPropertyId, false, end),
        bool_property(automation, UIA_IsOffscreenPropertyId, false, end),
        text_property(automation, UIA_NamePropertyId, name, end),
        number_property(automation, UIA_ControlTypePropertyId, UIA_ButtonControlTypeId, end)};
    std::array<IUIAutomationCondition*, 5> raw{};
    for (std::size_t index = 0; index < raw.size(); ++index) raw[index] = conditions[index].get();
    Com<IUIAutomationCondition> combined; Com<IUIAutomationElementArray> elements;
    budget(end); hr(automation->CreateAndConditionFromNativeArray(raw.data(), button ? 5 : 4, combined.put()), "search_name_condition");
    const auto subtree = static_cast<TreeScope>(TreeScope_Element | TreeScope_Children | TreeScope_Descendants);
    budget(end); hr(root->FindAll(subtree, combined.get(), elements.put()), "search_fixed_name");
    need(elements.get() != nullptr, "search_null_elements"); return elements;
}
SearchPage observe_search_page(HWND window, DWORD owner, DWORD thread, HANDLE process, ULONGLONG end, Result& out) {
    SearchPage observation; observation.attempted = true;
    try {
        budget(end); verify_search_target(window, owner, thread, process, out); observation.owner_verified = true;
        Apartment apartment(out); Com<IUIAutomation2> automation; Com<IUIAutomationElement> root;
        hr(CoCreateInstance(__uuidof(CUIAutomation8), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(IUIAutomation2), reinterpret_cast<void**>(automation.put())), "search_automation_create");
        need(automation.get() != nullptr, "search_automation_null");
        hr(automation->put_AutoSetFocus(FALSE), "search_no_focus");
        hr(automation->put_ConnectionTimeout(1000), "search_connection_timeout");
        hr(automation->put_TransactionTimeout(1000), "search_transaction_timeout");
        budget(end); hr(automation->ElementFromHandle(window, root.put()), "search_root");
        need(root.get() != nullptr, "search_null_root");
        UIA_HWND native{}; int root_owner{};
        budget(end); hr(root->get_CurrentNativeWindowHandle(&native), "search_root_handle");
        budget(end); hr(root->get_CurrentProcessId(&root_owner), "search_root_owner");
        need(native == window && root_owner > 0 && static_cast<DWORD>(root_owner) == owner, "search_root_identity");
        observation.root_verified = true;
        budget(end); hr(root->get_CurrentControlType(&observation.root_control_type), "search_root_control_type");
        Com<IUIAutomationWindowPattern> window_pattern;
        budget(end); observation.window_pattern_error = root->GetCurrentPatternAs(UIA_WindowPatternId,
            __uuidof(IUIAutomationWindowPattern), reinterpret_cast<void**>(window_pattern.put()));
        observation.window_pattern_available = SUCCEEDED(observation.window_pattern_error) && window_pattern.get() != nullptr;
        if (observation.window_pattern_available) {
            WindowInteractionState interaction{}; BOOL modal{}, topmost{};
            budget(end); observation.interaction_error = window_pattern->get_CurrentWindowInteractionState(&interaction);
            if (SUCCEEDED(observation.interaction_error)) observation.interaction_state = static_cast<int>(interaction);
            budget(end); observation.modal_error = window_pattern->get_CurrentIsModal(&modal);
            budget(end); observation.topmost_error = window_pattern->get_CurrentIsTopmost(&topmost);
            observation.modal = modal != FALSE; observation.topmost = topmost != FALSE;
        }
        for (std::size_t index = 0; index < observation.name_counts.size(); ++index) {
            auto elements = fixed_search_name(automation.get(), root.get(), owner, SearchNames[index], false, end);
            budget(end); hr(elements->get_Length(&observation.name_counts[index]), "search_name_count");
            need(observation.name_counts[index] >= 0 && observation.name_counts[index] <= 8, "search_name_count_bound");
        }
        for (std::size_t index = 0; index < observation.buttons.size(); ++index) {
            auto& metadata = observation.buttons[index];
            auto elements = fixed_search_name(automation.get(), root.get(), owner, DismissNames[index], true, end);
            budget(end); hr(elements->get_Length(&metadata.count), "search_button_count");
            need(metadata.count >= 0 && metadata.count <= 8, "search_button_count_bound");
            if (metadata.count != 1) continue;
            Com<IUIAutomationElement> button;
            budget(end); hr(elements->GetElement(0, button.put()), "search_button_element");
            need(button.get() != nullptr, "search_null_button");
            int actual_owner{}, type{}; BOOL password = TRUE, enabled = FALSE, offscreen = TRUE;
            budget(end); hr(button->get_CurrentProcessId(&actual_owner), "search_button_owner");
            budget(end); hr(button->get_CurrentControlType(&type), "search_button_type");
            budget(end); hr(button->get_CurrentIsPassword(&password), "search_button_password");
            need(actual_owner > 0 && static_cast<DWORD>(actual_owner) == owner && type == UIA_ButtonControlTypeId &&
                !password, "search_button_identity");
            metadata.identity_verified = true;
            budget(end); hr(button->get_CurrentIsEnabled(&enabled), "search_button_enabled");
            budget(end); hr(button->get_CurrentIsOffscreen(&offscreen), "search_button_offscreen");
            metadata.enabled = enabled != FALSE; metadata.offscreen = offscreen != FALSE;
            Text id; budget(end); metadata.id_error = button->get_CurrentAutomationId(&id.value);
            metadata.id_read = SUCCEEDED(metadata.id_error);
            if (metadata.id_read) metadata.id_safe = safe_identifier(id.value, id.value ? SysStringLen(id.value) : 0,
                metadata.automation_id, false);
            Com<IUIAutomationInvokePattern> pattern;
            budget(end); metadata.invoke_error = button->GetCurrentPatternAs(UIA_InvokePatternId,
                __uuidof(IUIAutomationInvokePattern), reinterpret_cast<void**>(pattern.put()));
            metadata.invoke_available = SUCCEEDED(metadata.invoke_error) && pattern.get() != nullptr;
        }
        observation.completed = true; observation.stage = "completed";
    } catch (const Failure& failure) { observation.stage = failure.stage; observation.error = failure.result; }
    catch (...) { observation.stage = "search_observation_exception"; observation.error = E_UNEXPECTED; }
    if (observation.owner_verified) {
        try { verify_search_target(window, owner, thread, process, out); observation.owner_stable = true; }
        catch (const Failure& failure) {
            observation = SearchPage{}; observation.attempted = true;
            observation.stage = failure.stage; observation.error = failure.result;
        }
    }
    return observation; // No WindowPattern.Close, Invoke, focus, input or value reads.
}
bool observed_search_candidate(const FreshForeground& fresh) noexcept {
    const auto& page = fresh.search_page;
    return fresh.attempted && fresh.exact_search_identity && fresh.owner_verified && fresh.owner_stable &&
        fresh.active_desktop_verified && fresh.original_target_destroyed && SUCCEEDED(fresh.error) &&
        page.completed && page.owner_verified && page.owner_stable && page.root_verified && SUCCEEDED(page.error) &&
        page.root_control_type == UIA_WindowControlTypeId && page.name_counts[0] == 1;
}
Com<IUIAutomationElement> read_search_action_root(IUIAutomation2* automation, HWND window, DWORD owner,
    ULONGLONG end, unsigned& count) {
    Com<IUIAutomationElement> root; budget(end);
    hr(automation->ElementFromHandle(window, root.put()), "escape_search_root");
    need(root.get() != nullptr, "escape_search_null_root");
    UIA_HWND native{}; int actual_owner{}, type{}; BOOL password = TRUE, offscreen = TRUE;
    budget(end); hr(root->get_CurrentNativeWindowHandle(&native), "escape_search_root_handle");
    budget(end); hr(root->get_CurrentProcessId(&actual_owner), "escape_search_root_owner");
    budget(end); hr(root->get_CurrentControlType(&type), "escape_search_root_type");
    budget(end); hr(root->get_CurrentIsPassword(&password), "escape_search_root_password");
    budget(end); hr(root->get_CurrentIsOffscreen(&offscreen), "escape_search_root_offscreen");
    need(native == window && actual_owner > 0 && static_cast<DWORD>(actual_owner) == owner &&
        type == UIA_WindowControlTypeId && !password && !offscreen, "escape_search_root_identity");
    // Only the fixed Name predicate is evaluated. No Name, Value or Text getter
    // reads a search query, arbitrary control, account field or password.
    auto elements = fixed_search_name(automation, root.get(), owner, L"Search", false, end);
    int length{}; budget(end); hr(elements->get_Length(&length), "escape_search_name_count");
    need(length >= 0 && length <= 8, "escape_search_name_count_bound"); count = static_cast<unsigned>(length);
    need(count == 1, "escape_search_name_not_unique");
    Com<IUIAutomationElement> match; budget(end);
    hr(elements->GetElement(0, match.put()), "escape_search_name_element");
    need(match.get() != nullptr, "escape_search_null_match");
    budget(end); hr(match->get_CurrentProcessId(&actual_owner), "escape_search_name_owner");
    budget(end); hr(match->get_CurrentIsPassword(&password), "escape_search_name_password");
    budget(end); hr(match->get_CurrentIsOffscreen(&offscreen), "escape_search_name_offscreen");
    need(actual_owner > 0 && static_cast<DWORD>(actual_owner) == owner && !password && !offscreen,
        "escape_search_name_identity");
    return root;
}
void observe_search_escape_target(const SearchEscapeTarget& target, Result& out) {
    auto& action = out.search_escape;
    if (!action.send_attempted || !target.window) return;
    ++action.target_observations; action.target_observation_valid = false; action.target_observation_error = S_OK;
    action.target_exists = false; action.target_visible = false; action.target_foreground = false;
    action.target_hidden_or_destroyed = false;
    try {
        verify_desktop(out);
        action.target_exists = IsWindow(target.window) != FALSE;
        if (!action.target_exists) {
            action.target_hidden_or_destroyed = true; action.target_observation_valid = true; return;
        }
        DWORD thread{}, exit_code{};
        need(window_owner(target.window, out.session, &thread) == target.owner && thread == target.thread &&
            GetProcessId(target.process.value) == target.owner &&
            GetExitCodeProcess(target.process.value, &exit_code) != FALSE && exit_code == STILL_ACTIVE,
            "escape_observed_target_owner_changed");
        action.target_visible = IsWindowVisible(target.window) != FALSE;
        action.target_foreground = GetAncestor(GetForegroundWindow(), GA_ROOT) == target.window;
        action.target_hidden_or_destroyed = !action.target_visible;
        action.target_observation_valid = true;
    } catch (const Failure& failure) { action.target_observation_error = failure.result; }
    // This observes only the pinned target HWND. It is not a claim that no new
    // Search window exists; ordinary-desktop and independent pixel proof differ.
}
void consider_search_escape(HWND original, ULONGLONG second_completed, const FreshForeground& snapshot,
    SearchEscapeTarget& target, ULONGLONG end, Result& out) {
    auto& action = out.search_escape;
    need(!action.checked && !action.send_attempted, "escape_action_already_considered");
    const ULONGLONG started = GetTickCount64(); action.checked = true; action.after_second_ms = started - second_completed;
    try {
        need(observed_search_candidate(snapshot), "escape_initial_observation_unverified"); action.first_snapshot_verified = true;
        budget(end); verify_desktop(out);
        need(original && !IsWindow(original), "escape_original_page_still_exists"); action.original_target_destroyed = true;
        target.window = GetAncestor(GetForegroundWindow(), GA_ROOT);
        need(target.window != nullptr, "escape_foreground_unavailable");
        target.owner = window_owner(target.window, out.session, &target.thread);
        target.process.value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target.owner);
        need(target.process.value != nullptr, "escape_process_open", last_error());
        budget(end); verify_search_target(target.window, target.owner, target.thread, target.process.value, out);
        action.owner_verified = true;
        Apartment apartment(out); Com<IUIAutomation2> automation;
        budget(end); hr(CoCreateInstance(__uuidof(CUIAutomation8), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(IUIAutomation2), reinterpret_cast<void**>(automation.put())), "escape_automation_create");
        need(automation.get() != nullptr, "escape_automation_null");
        hr(automation->put_AutoSetFocus(FALSE), "escape_no_focus");
        hr(automation->put_ConnectionTimeout(1000), "escape_connection_timeout");
        hr(automation->put_TransactionTimeout(1000), "escape_transaction_timeout");
        auto first = read_search_action_root(automation.get(), target.window, target.owner, end, action.initial_search_count);
        action.first_page_verified = true;
        budget(end); verify_search_target(target.window, target.owner, target.thread, target.process.value, out);
        auto fresh = read_search_action_root(automation.get(), target.window, target.owner, end, action.recheck_search_count);
        action.recheck_page_verified = true;
        BOOL same{}; budget(end); hr(automation->CompareElements(first.get(), fresh.get(), &same), "escape_compare_roots");
        need(same != FALSE, "escape_search_root_replaced"); action.same_root_reverified = true;
        budget(end); verify_search_target(target.window, target.owner, target.thread, target.process.value, out);
        constexpr int keys[]{VK_SHIFT, VK_LSHIFT, VK_RSHIFT, VK_CONTROL, VK_LCONTROL, VK_RCONTROL,
            VK_MENU, VK_LMENU, VK_RMENU, VK_LWIN, VK_RWIN, VK_ESCAPE};
        std::array<BYTE, 256> queued{}; action.key_state_checked = true;
        win32(GetKeyboardState(queued.data()), "escape_keyboard_state_unavailable"); action.keyboard_state_query_succeeded = true;
        for (unsigned index = 0; index < sizeof(keys) / sizeof(keys[0]); ++index) {
            if (queued[keys[index]] & 0x80U) action.queue_down_mask |= 1U << index;
            if (static_cast<unsigned short>(GetAsyncKeyState(keys[index])) & 0x8000U) action.async_down_mask |= 1U << index;
        }
        action.queue_highbits_up = action.queue_down_mask == 0; action.async_highbits_up = action.async_down_mask == 0;
        need(action.queue_highbits_up && action.async_highbits_up, "escape_key_already_down", HRESULT_FROM_WIN32(ERROR_BUSY));
        // GetAsyncKeyState's zero is ambiguous on API access failure. These are
        // observed high bits under verified active-desktop/owner guards, not a
        // proof of physical keyboard state or an atomic guard against a human.
        budget(end); verify_search_target(target.window, target.owner, target.thread, target.process.value, out);
        action.owner_reverified = true;
        INPUT pair[2]{}; pair[0].type = INPUT_KEYBOARD; pair[0].ki.wVk = VK_ESCAPE;
        pair[1].type = INPUT_KEYBOARD; pair[1].ki.wVk = VK_ESCAPE; pair[1].ki.dwFlags = KEYEVENTF_KEYUP;
        budget(end);
        action.send_attempted = true; action.send_call_count = 1; action.requested_input_count = 2;
        SetLastError(ERROR_SUCCESS);
        action.inserted_input_count = SendInput(2, pair, sizeof(INPUT)); action.send_last_error = GetLastError();
        action.pair_inserted = action.inserted_input_count == 2;
        action.key_cleanup_verified = action.inserted_input_count == 0;
        action.release_event_inserted = action.pair_inserted;
        // A partial result is never retried. Only the release matching our own
        // single possible down event may be inserted, once, before any throw.
        if (action.inserted_input_count == 1) {
            action.release_cleanup_attempted = true; action.cleanup_call_count = 1;
            SetLastError(ERROR_SUCCESS);
            action.cleanup_inserted_count = SendInput(1, &pair[1], sizeof(INPUT)); action.cleanup_last_error = GetLastError();
            action.release_event_inserted = action.cleanup_inserted_count == 1;
        }
        if (action.release_event_inserted) {
            const ULONGLONG release_end = GetTickCount64() + 250;
            do {
                verify_desktop(out); ++action.release_observations;
                action.escape_up_observed = (static_cast<unsigned short>(GetAsyncKeyState(VK_ESCAPE)) & 0x8000U) == 0;
                if (action.escape_up_observed) break;
                Sleep(10);
            } while (GetTickCount64() < release_end && GetTickCount64() < end);
            action.key_cleanup_verified = action.escape_up_observed;
        }
        observe_search_escape_target(target, out);
        need(action.pair_inserted, "escape_input_incomplete",
            HRESULT_FROM_WIN32(action.send_last_error ? action.send_last_error : ERROR_GEN_FAILURE));
        need(action.key_cleanup_verified, "escape_release_unverified", HRESULT_FROM_WIN32(ERROR_GEN_FAILURE));
        action.stage = "pair_inserted"; action.elapsed_ms = GetTickCount64() - started;
    } catch (const Failure& failure) {
        action.stage = failure.stage; action.error = failure.result; action.elapsed_ms = GetTickCount64() - started; throw;
    }
}
FreshForeground observe_fresh_foreground(HWND original, ULONGLONG second_completed, ULONGLONG end, Result& out) {
    const ULONGLONG started = GetTickCount64(); FreshForeground observation;
    observation.attempted = true; observation.after_second_ms = started - second_completed;
    try {
        budget(end); verify_desktop(out); observation.active_desktop_verified = true;
        observation.original_target_destroyed = original && !IsWindow(original);
        need(observation.original_target_destroyed, "original_target_not_destroyed");
        const HWND root = GetAncestor(GetForegroundWindow(), GA_ROOT);
        need(root != nullptr, "fresh_foreground_unavailable");
        DWORD thread{}; const DWORD owner = window_owner(root, out.session, &thread);
        Handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner), out};
        need(process.value != nullptr, "fresh_process_open", last_error());
        verify_fresh_foreground(root, owner, thread, process.value, out); observation.owner_verified = true;
        try {
            observation.class_category = foreground_class(root, observation.class_read, observation.class_error,
                &observation.class_identifier, &observation.class_safe);
            std::array<wchar_t, 257> family{}, app{}; UINT32 family_size = static_cast<UINT32>(family.size());
            budget(end); const LONG family_result = GetPackageFamilyName(process.value, &family_size, family.data());
            if (family_result == APPMODEL_ERROR_NO_PACKAGE) observation.package_category = 1;
            else if (family_result == ERROR_SUCCESS && family_size > 1 && family_size <= family.size() && family[family_size - 1] == L'\0') {
                observation.package_read = true;
                observation.package_safe = safe_identifier(family.data(), family_size - 1, observation.package_identifier, true);
                observation.package_category = std::wcscmp(family.data(), TargetFamily) == 0 ? 2U :
                    (std::wcscmp(family.data(), SearchFamily) == 0 ? 4U : 3U);
            } else observation.package_error = family_result == ERROR_SUCCESS ? E_UNEXPECTED : HRESULT_FROM_WIN32(family_result);
            UINT32 app_size = static_cast<UINT32>(app.size());
            budget(end); const LONG app_result = GetApplicationUserModelId(process.value, &app_size, app.data());
            if (app_result == ERROR_SUCCESS && app_size > 1 && app_size <= app.size() && app[app_size - 1] == L'\0') {
                observation.application_read = true;
                observation.application_safe = safe_identifier(app.data(), app_size - 1, observation.application_identifier, true);
                observation.application_category = std::wcscmp(app.data(), TargetApplication) == 0 ? 2U :
                    (std::wcscmp(app.data(), SearchApplication) == 0 ? 4U : 3U);
            } else observation.application_error = app_result == ERROR_SUCCESS ? E_UNEXPECTED : HRESULT_FROM_WIN32(app_result);
            observation.exact_cloud_identity = observation.class_category == 6 && observation.package_category == 2 &&
                observation.application_category == 2;
            observation.exact_search_identity = observation.class_category == 6 && observation.package_category == 4 &&
                observation.application_category == 4;
            if (observation.exact_cloud_identity) {
                observation.content_attempted = true;
                observation.page = observe_after_invoke(root, owner, thread, process.value, end, out, true);
            }
            if (observation.exact_search_identity) {
                observation.content_attempted = true;
                observation.search_page = observe_search_page(root, owner, thread, process.value, end, out);
            }
        } catch (const Failure& failure) { observation.stage = failure.stage; observation.error = failure.result; }
        catch (...) { observation.stage = "fresh_content_exception"; observation.error = E_UNEXPECTED; }
        // Inventory and content never inherit the destroyed original HWND's ownership.
        try { verify_fresh_foreground(root, owner, thread, process.value, out); observation.owner_stable = true; }
        catch (const Failure& failure) {
            observation = FreshForeground{}; observation.attempted = true;
            observation.stage = failure.stage; observation.error = failure.result;
        }
        if (observation.owner_stable && SUCCEEDED(observation.error)) observation.stage = observation.exact_cloud_identity ?
            (observation.page.completed ? "cloud_page_observed" : "cloud_page_unavailable") :
            (observation.exact_search_identity ? (observation.search_page.completed ? "search_page_observed" : "search_page_unavailable") :
             "other_foreground_observed");
    } catch (const Failure& failure) { observation.stage = failure.stage; observation.error = failure.result; }
    catch (...) { observation.stage = "fresh_unexpected_exception"; observation.error = E_UNEXPECTED; }
    observation.after_second_ms = started - second_completed; observation.elapsed_ms = GetTickCount64() - started;
    return observation;
}
void prepare(Result& out, ULONGLONG end) {
    const ULONGLONG wait_end = end - PostReadBudgetMs;
    SearchEscapeTarget search_target(out);
    need(environment_equals(L"GITHUB_ACTIONS", L"true") && environment_equals(L"RUNNER_ENVIRONMENT", L"github-hosted") &&
        environment_equals(L"RUNNER_OS", L"Windows"), "disposable_hosted_windows_required");
    out.disposable_environment_verified = true; verify_desktop(out);
    HWND foreground = GetAncestor(GetForegroundWindow(), GA_ROOT); need(foreground != nullptr, "foreground_unavailable");
    DWORD thread{}; const DWORD owner = window_owner(foreground, out.session, &thread);
    Handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner), out};
    need(process.value != nullptr, "foreground_process_open", last_error());
    out.target_initially_foreground = target_package(process.value);
    HWND observed_target{};
    if (out.target_initially_foreground) {
        observed_target = foreground; verify_target(foreground, owner, thread, process.value, out);
        out.target_owner_verified = true;
        Apartment apartment(out);
        Com<IUIAutomation2> automation;
        budget(wait_end); hr(CoCreateInstance(__uuidof(CUIAutomation8), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(IUIAutomation2), reinterpret_cast<void**>(automation.put())), "automation_create");
        need(automation.get() != nullptr, "automation_null_client");
        hr(automation->put_AutoSetFocus(FALSE), "automation_no_focus");
        hr(automation->put_ConnectionTimeout(1000), "automation_connection_timeout");
        hr(automation->put_TransactionTimeout(1000), "automation_transaction_timeout");
        Page first = read_page(automation.get(), foreground, owner, wait_end, out);
        out.initial_heading_count = first.headings; out.initial_button_count = first.buttons;
        verify_target(foreground, owner, thread, process.value, out);
        Page fresh = read_page(automation.get(), foreground, owner, wait_end, out);
        out.recheck_heading_count = fresh.headings; out.recheck_button_count = fresh.buttons;
        BOOL same{}; budget(wait_end); hr(automation->CompareElements(first.button.get(), fresh.button.get(), &same), "same_accept_button");
        need(same != FALSE, "accept_button_replaced"); out.same_button_reverified = true;
        read_button_label(fresh.button.get(), out.button_before, wait_end);
        out.first_label_is_known_accept = out.button_before.category == 3 || exact_observed_accept(out.button_before);
        // Last checks immediately precede the first action. A separately
        // observed exact Accept transition is the only possible second action.
        budget(wait_end); verify_target(foreground, owner, thread, process.value, out); out.target_owner_reverified = true;
        out.stage = "invoke_exact_privacy_button"; out.invoke_attempted = true; ++out.invoke_count;
        out.invoke_error = fresh.invoke->Invoke(); hr(out.invoke_error, "privacy_button_invoke"); out.invoke_succeeded = true;
        consider_observed_accept(automation.get(), foreground, owner, thread, process.value, GetTickCount64(), wait_end, out);
    }
    out.stage = "wait_ordinary_desktop";
    unsigned stable{};
    while (GetTickCount64() < wait_end) {
        if (out.second.invoke_succeeded && !out.fresh_foreground[0].attempted &&
            GetTickCount64() - out.second.completed_tick >= 5000) {
            const ULONGLONG limit = GetTickCount64() + 2000;
            out.fresh_foreground[0] = observe_fresh_foreground(observed_target, out.second.completed_tick,
                limit < wait_end ? limit : wait_end, out);
            if (observed_search_candidate(out.fresh_foreground[0])) {
                const ULONGLONG action_limit = GetTickCount64() + 2000;
                consider_search_escape(observed_target, out.second.completed_tick, out.fresh_foreground[0], search_target,
                    action_limit < wait_end ? action_limit : wait_end, out);
            }
        }
        ++out.wait_observations;
        const bool ready = ordinary_desktop(observed_target, out);
        observe_search_escape_target(search_target, out);
        stable = ready ? stable + 1 : 0; out.stable_observations = stable;
        if (stable >= 5) {
            out.ordinary_desktop_verified = true; break;
        }
        Sleep(250);
    }
    if (out.invoke_succeeded) out.post = observe_after_invoke(observed_target, owner, thread, process.value, end, out);
    if (out.second.invoke_succeeded && !out.ordinary_desktop_verified)
        out.fresh_foreground[1] = observe_fresh_foreground(observed_target, out.second.completed_tick, end, out);
    observe_search_escape_target(search_target, out);
    verify_desktop(out); out.final_active_input_desktop_verified = true;
    if (out.ordinary_desktop_verified) {
        out.stage = "completed"; out.status = out.invoke_attempted ? "completed" : "not_needed"; return;
    }
    throw Failure{"ordinary_desktop_timeout", HRESULT_FROM_WIN32(WAIT_TIMEOUT)};
}
void write_label(const ButtonLabel& label) {
    std::cout << "{\"status\":\"" << label.status << "\",\"hresult\":" << static_cast<std::uint32_t>(label.error)
        << ",\"category\":" << label.category << ",\"safe_ascii\":\"" << label.ascii.data() << "\"}";
}
template<std::size_t Size> void write_counts(const std::array<int, Size>& counts) {
    std::cout << '[';
    for (std::size_t index = 0; index < counts.size(); ++index) { if (index) std::cout << ','; std::cout << counts[index]; }
    std::cout << ']';
}
void write_page(const PostPage& page) {
    std::cout << "{\"attempted\":" << page.attempted << ",\"stage\":\"" << page.stage
        << "\",\"hresult\":" << static_cast<std::uint32_t>(page.error) << ",\"owner_verified\":" << page.owner_verified
        << ",\"owner_stable\":" << page.owner_stable << ",\"root_verified\":" << page.root_verified
        << ",\"completed\":" << page.completed << ",\"button_count\":" << page.button_count
        << ",\"button_verified\":" << page.button_verified << ",\"button_enabled\":" << page.enabled
        << ",\"button_offscreen\":" << page.offscreen << ",\"invoke_available\":" << page.invoke_available
        << ",\"invoke_pattern_hresult\":" << static_cast<std::uint32_t>(page.invoke_pattern_error)
        << ",\"heading_counts\":";
    write_counts(page.headings); std::cout << ",\"known_button_label_counts\":"; write_counts(page.known_buttons);
    std::cout << ",\"button_label\":"; write_label(page.label); std::cout << '}';
}
void write_search_page(const SearchPage& page) {
    std::cout << "{\"attempted\":" << page.attempted << ",\"stage\":\"" << page.stage
        << "\",\"hresult\":" << static_cast<std::uint32_t>(page.error) << ",\"owner_verified\":" << page.owner_verified
        << ",\"owner_stable\":" << page.owner_stable << ",\"root_verified\":" << page.root_verified
        << ",\"completed\":" << page.completed << ",\"root_control_type\":" << page.root_control_type
        << ",\"window_pattern_available\":" << page.window_pattern_available
        << ",\"window_pattern_hresult\":" << static_cast<std::uint32_t>(page.window_pattern_error)
        << ",\"interaction_state\":" << page.interaction_state << ",\"interaction_hresult\":" << static_cast<std::uint32_t>(page.interaction_error)
        << ",\"modal\":" << page.modal << ",\"modal_hresult\":" << static_cast<std::uint32_t>(page.modal_error)
        << ",\"topmost\":" << page.topmost << ",\"topmost_hresult\":" << static_cast<std::uint32_t>(page.topmost_error)
        << ",\"fixed_name_counts\":";
    write_counts(page.name_counts); std::cout << ",\"buttons\":[";
    for (std::size_t index = 0; index < page.buttons.size(); ++index) {
        if (index) std::cout << ',';
        const auto& button = page.buttons[index];
        std::cout << "{\"label_index\":" << index << ",\"count\":" << button.count << ",\"identity_verified\":" << button.identity_verified
            << ",\"enabled\":" << button.enabled << ",\"offscreen\":" << button.offscreen << ",\"invoke_available\":" << button.invoke_available
            << ",\"invoke_hresult\":" << static_cast<std::uint32_t>(button.invoke_error) << ",\"automation_id_read\":" << button.id_read
            << ",\"automation_id_safe\":" << button.id_safe << ",\"automation_id_hresult\":" << static_cast<std::uint32_t>(button.id_error)
            << ",\"automation_id\":\"" << button.automation_id.data() << "\"}";
    }
    std::cout << "]}";
}
void write_search_escape(const SearchEscape& action) {
    std::cout << "{\"stage\":\"" << action.stage << "\",\"hresult\":" << static_cast<std::uint32_t>(action.error)
        << ",\"after_second_ms\":" << action.after_second_ms << ",\"elapsed_ms\":" << action.elapsed_ms;
#define ACTION(name) std::cout << ",\"" #name "\":" << action.name
    ACTION(checked); ACTION(first_snapshot_verified); ACTION(original_target_destroyed);
    ACTION(owner_verified); ACTION(owner_reverified); ACTION(first_page_verified); ACTION(recheck_page_verified);
    ACTION(same_root_reverified); ACTION(initial_search_count); ACTION(recheck_search_count);
    ACTION(key_state_checked); ACTION(keyboard_state_query_succeeded); ACTION(async_highbits_up); ACTION(queue_highbits_up);
    ACTION(async_down_mask); ACTION(queue_down_mask); ACTION(send_attempted); ACTION(send_call_count);
    ACTION(requested_input_count); ACTION(inserted_input_count); ACTION(send_last_error); ACTION(pair_inserted);
    ACTION(release_cleanup_attempted); ACTION(cleanup_call_count); ACTION(cleanup_inserted_count); ACTION(cleanup_last_error);
    ACTION(release_event_inserted); ACTION(escape_up_observed); ACTION(release_observations); ACTION(key_cleanup_verified);
    ACTION(target_observations); ACTION(target_observation_valid); ACTION(target_exists); ACTION(target_visible);
    ACTION(target_foreground); ACTION(target_hidden_or_destroyed);
#undef ACTION
    std::cout << ",\"target_observation_hresult\":" << static_cast<std::uint32_t>(action.target_observation_error)
        << ",\"virtual_key\":" << VK_ESCAPE << ",\"physical_key_state_proven\":false,\"delivery_to_target_proven\":false}";
}
void write_fresh(const FreshForeground& fresh) {
    std::cout << "{\"attempted\":" << fresh.attempted << ",\"stage\":\"" << fresh.stage
        << "\",\"hresult\":" << static_cast<std::uint32_t>(fresh.error) << ",\"after_second_ms\":" << fresh.after_second_ms
        << ",\"elapsed_ms\":" << fresh.elapsed_ms << ",\"active_desktop_verified\":" << fresh.active_desktop_verified
        << ",\"original_target_destroyed\":" << fresh.original_target_destroyed << ",\"owner_verified\":" << fresh.owner_verified
        << ",\"owner_stable\":" << fresh.owner_stable << ",\"class_category\":" << fresh.class_category
        << ",\"package_category\":" << fresh.package_category << ",\"application_category\":" << fresh.application_category
        << ",\"class_hresult\":" << static_cast<std::uint32_t>(fresh.class_error)
        << ",\"package_hresult\":" << static_cast<std::uint32_t>(fresh.package_error)
        << ",\"application_hresult\":" << static_cast<std::uint32_t>(fresh.application_error)
        << ",\"class_read\":" << fresh.class_read << ",\"package_read\":" << fresh.package_read
        << ",\"application_read\":" << fresh.application_read << ",\"class_identifier_safe\":" << fresh.class_safe
        << ",\"package_identifier_safe\":" << fresh.package_safe << ",\"application_identifier_safe\":" << fresh.application_safe
        << ",\"class_identifier\":\"" << fresh.class_identifier.data() << "\",\"package_family\":\"" << fresh.package_identifier.data()
        << "\",\"application_id\":\"" << fresh.application_identifier.data() << "\",\"exact_cloud_identity\":" << fresh.exact_cloud_identity
        << ",\"exact_search_identity\":" << fresh.exact_search_identity << ",\"content_attempted\":" << fresh.content_attempted << ",\"page\":";
    write_page(fresh.page); std::cout << ",\"search_page\":"; write_search_page(fresh.search_page); std::cout << '}';
}
void write(const Result& out, ULONGLONG elapsed) {
    std::cout << std::boolalpha << "{\"schema\":\"first-logon-prepare/v1\",\"status\":\"" << out.status
        << "\",\"stage\":\"" << out.stage << "\",\"hresult\":" << static_cast<std::uint32_t>(out.error)
        << ",\"invoke_hresult\":" << static_cast<std::uint32_t>(out.invoke_error)
        << ",\"cleanup_hresult\":" << static_cast<std::uint32_t>(out.cleanup_error)
        << ",\"session_id\":" << out.session << ",\"elapsed_ms\":" << elapsed;
#define FIELD(name) std::cout << ",\"" #name "\":" << out.name
    FIELD(opted_in); FIELD(disposable_environment_verified); FIELD(input_default_desktop_verified);
    FIELD(target_initially_foreground); FIELD(target_owner_verified); FIELD(target_owner_reverified); FIELD(root_handle_verified);
    FIELD(initial_heading_count); FIELD(recheck_heading_count); FIELD(initial_button_count); FIELD(recheck_button_count);
    FIELD(same_button_reverified); FIELD(invoke_attempted); FIELD(invoke_count); FIELD(invoke_succeeded);
    FIELD(observed_page_hidden_or_destroyed); FIELD(explorer_shell_verified); FIELD(foreground_kind);
    FIELD(wait_guard); FIELD(shell_handle_present); FIELD(shell_window_exists); FIELD(shell_identity_checked);
    FIELD(foreground_present); FIELD(foreground_class_read); FIELD(foreground_class_category);
    FIELD(associated_console_present); FIELD(foreground_is_shell); FIELD(foreground_matches_associated_console);
    FIELD(foreground_shares_shell_process); FIELD(foreground_is_observed_target); FIELD(observed_target_sampled);
    FIELD(observed_target_exists); FIELD(observed_target_visible); FIELD(observed_target_cloak_query_attempted);
    FIELD(observed_target_cloak_flags);
    FIELD(wait_observations); FIELD(stable_observations); FIELD(ordinary_desktop_verified); FIELD(com_uninitialized); FIELD(cleanup_verified);
    FIELD(final_active_input_desktop_verified);
    FIELD(first_label_is_known_accept);
#undef FIELD
    std::cout << ",\"button_label_before\":"; write_label(out.button_before);
    std::cout << ",\"second_action\":{\"checked\":" << out.second.checked << ",\"stage\":\"" << out.second.stage
        << "\",\"delay_ms\":" << out.second.delay_ms << ",\"first_page_verified\":" << out.second.first_page_verified
        << ",\"recheck_page_verified\":" << out.second.recheck_page_verified << ",\"owner_verified\":" << out.second.owner_verified
        << ",\"owner_reverified\":" << out.second.owner_reverified << ",\"same_button_reverified\":" << out.second.same_button_reverified
        << ",\"initial_heading_count\":" << out.second.initial_heading_count << ",\"recheck_heading_count\":" << out.second.recheck_heading_count
        << ",\"initial_button_count\":" << out.second.initial_button_count << ",\"recheck_button_count\":" << out.second.recheck_button_count
        << ",\"invoke_attempted\":" << out.second.invoke_attempted << ",\"invoke_succeeded\":" << out.second.invoke_succeeded
        << ",\"invoke_hresult\":" << static_cast<std::uint32_t>(out.second.invoke_error) << ",\"first_label\":";
    write_label(out.second.first_label); std::cout << ",\"recheck_label\":"; write_label(out.second.recheck_label); std::cout << '}';
    std::cout << ",\"post_invoke\":"; write_page(out.post);
    std::cout << ",\"fresh_foreground\":[";
    write_fresh(out.fresh_foreground[0]); std::cout << ','; write_fresh(out.fresh_foreground[1]); std::cout << ']';
    std::cout << ",\"search_escape\":"; write_search_escape(out.search_escape);
    std::cout << ",\"foreground_class_hresult\":" << static_cast<std::uint32_t>(out.foreground_class_hresult)
        << ",\"observed_target_cloak_hresult\":" << static_cast<std::uint32_t>(out.observed_target_cloak_hresult)
        << ",\"privacy_toggle_values_changed_by_helper\":false,\"credential_fields_read\":false,"
        "\"search_values_read\":false,\"other_keys_sent\":false,\"focus_changed_by_helper\":false,"
        "\"other_ui_invoked\":false,\"force_closed_window\":false,\"session_functionality_verified\":false,"
        "\"remote_frame_verified\":false,\"input_channel_verified\":false,\"physical_isolation_verified\":false}\n";
}
} // namespace
int main(int argc, char** argv) {
    const ULONGLONG start = GetTickCount64(); Result out;
    try {
        out.opted_in = argc == 2 && std::strcmp(argv[1], "--allow-disposable-privacy-preparation") == 0;
        need(out.opted_in, "explicit_opt_in_required", E_ACCESSDENIED);
        prepare(out, start + TotalBudgetMs);
    } catch (const Failure& failure) { out.stage = failure.stage; out.error = failure.result; out.status = "failed"; }
    catch (...) { out.stage = "unexpected_exception"; out.error = E_UNEXPECTED; out.status = "failed"; }
    if (!out.search_escape.key_cleanup_verified) { out.cleanup_verified = false; out.cleanup_error = E_FAIL; }
    if (!out.cleanup_verified) { out.status = "failed"; out.stage = "own_cleanup_failed"; }
    const bool success = out.ordinary_desktop_verified && out.final_active_input_desktop_verified && out.cleanup_verified && SUCCEEDED(out.error) &&
        (!out.search_escape.checked || (out.search_escape.pair_inserted && out.search_escape.key_cleanup_verified &&
         out.search_escape.owner_reverified && out.search_escape.same_root_reverified && SUCCEEDED(out.search_escape.error))) &&
        ((out.invoke_count == 0 && !out.target_initially_foreground) ||
         (((out.invoke_count == 1 && !out.second.invoke_attempted) ||
           (out.invoke_count == 2 && !out.first_label_is_known_accept && out.second.invoke_succeeded &&
            out.second.owner_reverified && out.second.same_button_reverified)) &&
          out.invoke_succeeded && out.target_owner_reverified && out.same_button_reverified &&
          out.observed_page_hidden_or_destroyed && out.com_uninitialized));
    write(out, GetTickCount64() - start); return success ? 0 : 1;
}
