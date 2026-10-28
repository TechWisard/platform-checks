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
constexpr wchar_t TargetClass[] = L"Windows.UI.Core.CoreWindow";
constexpr wchar_t PrivacyHeading[] = L"Choose privacy settings for your device";
constexpr wchar_t AcceptId[] = L"OobeSettingsAcceptButton";
constexpr ULONGLONG TotalBudgetMs = 32000;
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
void budget(ULONGLONG end) { need(GetTickCount64() < end, "preparation_deadline", HRESULT_FROM_WIN32(WAIT_TIMEOUT)); }
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
unsigned foreground_class(HWND window, Result& out) {
    std::array<wchar_t, 128> value{};
    const int size = GetClassNameW(window, value.data(), static_cast<int>(value.size()));
    if (size <= 0 || size >= static_cast<int>(value.size() - 1)) {
        out.foreground_class_hresult = size <= 0 ? last_error() : HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    out.foreground_class_read = true;
    constexpr const wchar_t* classes[]{L"Progman", L"WorkerW", L"CabinetWClass", L"ConsoleWindowClass",
        L"CASCADIA_HOSTING_WINDOW_CLASS", L"Windows.UI.Core.CoreWindow", L"ApplicationFrameWindow"};
    for (unsigned index = 0; index < sizeof(classes) / sizeof(classes[0]); ++index)
        if (std::wcscmp(value.data(), classes[index]) == 0) return index + 1;
    return 255; // Unknown class text is never emitted or used to widen the gate.
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
    if (foreground) out.foreground_class_category = foreground_class(foreground, out);
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
    bool button, ULONGLONG end) {
    need(owner <= static_cast<DWORD>(INT_MAX), "automation_process_id_range");
    std::array<Com<IUIAutomationCondition>, 6> conditions{
        number_property(automation, UIA_ProcessIdPropertyId, static_cast<int>(owner), end),
        bool_property(automation, UIA_IsPasswordPropertyId, false, end),
        bool_property(automation, UIA_IsOffscreenPropertyId, false, end),
        number_property(automation, UIA_ControlTypePropertyId, button ? UIA_ButtonControlTypeId : UIA_TextControlTypeId, end),
        text_property(automation, button ? UIA_AutomationIdPropertyId : UIA_NamePropertyId, button ? AcceptId : PrivacyHeading, end),
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
void prepare(Result& out, ULONGLONG end) {
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
        budget(end); hr(CoCreateInstance(__uuidof(CUIAutomation8), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(IUIAutomation2), reinterpret_cast<void**>(automation.put())), "automation_create");
        need(automation.get() != nullptr, "automation_null_client");
        hr(automation->put_AutoSetFocus(FALSE), "automation_no_focus");
        hr(automation->put_ConnectionTimeout(1000), "automation_connection_timeout");
        hr(automation->put_TransactionTimeout(1000), "automation_transaction_timeout");
        Page first = read_page(automation.get(), foreground, owner, end, out);
        out.initial_heading_count = first.headings; out.initial_button_count = first.buttons;
        verify_target(foreground, owner, thread, process.value, out);
        Page fresh = read_page(automation.get(), foreground, owner, end, out);
        out.recheck_heading_count = fresh.headings; out.recheck_button_count = fresh.buttons;
        BOOL same{}; budget(end); hr(automation->CompareElements(first.button.get(), fresh.button.get(), &same), "same_accept_button");
        need(same != FALSE, "accept_button_replaced"); out.same_button_reverified = true;
        // Last checks immediately precede the one and only action. No generic
        // retry, other button, focus request, key injection or process stop.
        budget(end); verify_target(foreground, owner, thread, process.value, out); out.target_owner_reverified = true;
        out.stage = "invoke_exact_privacy_accept"; out.invoke_attempted = true; ++out.invoke_count;
        out.invoke_error = fresh.invoke->Invoke(); hr(out.invoke_error, "privacy_accept_invoke"); out.invoke_succeeded = true;
    }
    out.stage = "wait_ordinary_desktop";
    unsigned stable{};
    while (GetTickCount64() < end) {
        ++out.wait_observations;
        const bool ready = ordinary_desktop(observed_target, out);
        stable = ready ? stable + 1 : 0; out.stable_observations = stable;
        if (stable >= 5) {
            out.ordinary_desktop_verified = true; out.stage = "completed";
            out.status = out.invoke_attempted ? "completed" : "not_needed"; return;
        }
        Sleep(250);
    }
    throw Failure{"ordinary_desktop_timeout", HRESULT_FROM_WIN32(WAIT_TIMEOUT)};
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
#undef FIELD
    std::cout << ",\"foreground_class_hresult\":" << static_cast<std::uint32_t>(out.foreground_class_hresult)
        << ",\"observed_target_cloak_hresult\":" << static_cast<std::uint32_t>(out.observed_target_cloak_hresult)
        << ",\"privacy_toggle_values_changed_by_helper\":false,\"credential_fields_read\":false,"
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
    if (!out.cleanup_verified) { out.status = "failed"; out.stage = "own_cleanup_failed"; }
    const bool success = out.ordinary_desktop_verified && out.cleanup_verified && SUCCEEDED(out.error) &&
        ((out.invoke_count == 0 && !out.target_initially_foreground) ||
         (out.invoke_count == 1 && out.invoke_succeeded && out.target_owner_reverified && out.same_button_reverified &&
          out.observed_page_hidden_or_destroyed && out.com_uninitialized));
    write(out, GetTickCount64() - start); return success ? 0 : 1;
}
