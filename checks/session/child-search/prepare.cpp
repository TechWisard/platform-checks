#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <ole2.h>
#include <appmodel.h>
#include <wtsapi32.h>
#include <uiautomation.h>
#include <aclapi.h>
#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include "receipt.hpp"

namespace {
constexpr wchar_t SearchFamily[] = L"MicrosoftWindows.Client.CBS_cw5n1h2txyewy";
constexpr wchar_t SearchApplication[] = L"MicrosoftWindows.Client.CBS_cw5n1h2txyewy!CortanaUI";
constexpr wchar_t TargetClass[] = L"Windows.UI.Core.CoreWindow";
constexpr ULONGLONG TotalBudgetMs = 10000;
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
    HRESULT error{S_OK}, cleanup_error{S_OK};
    DWORD session{};
    ULONGLONG elapsed_ms{};
    unsigned receipt_error{};
    child_search::Receipt receipt;
    bool receipt_verified{}, receipt_owner_verified{}, receipt_readonly_verified{};
    bool directory_owner_verified{}, directory_readonly_verified{}, identity_verified{}, nonadministrator_verified{};
    bool active_child_verified{}, input_default_desktop_verified{}, console_parent_unchanged{}, target_found{};
    bool com_uninitialized{}, cleanup_verified{true};
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
struct LocalMemory final {
    PSECURITY_DESCRIPTOR value{};
    Result& result;
    explicit LocalMemory(Result& out) : result(out) {}
    ~LocalMemory() { if (value && LocalFree(value) != nullptr) { result.cleanup_verified = false; result.cleanup_error = last_error(); } }
};
void budget(ULONGLONG end) { need(GetTickCount64() < end, "preparation_deadline", HRESULT_FROM_WIN32(WAIT_TIMEOUT)); }
std::uint64_t unix_time() {
    FILETIME value{}; GetSystemTimeAsFileTime(&value);
    const auto ticks = (std::uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    need(ticks >= 116444736000000000ULL, "clock_before_unix_epoch");
    return (ticks - 116444736000000000ULL) / 10000000ULL;
}
std::vector<unsigned char> token_information(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD bytes{}; SetLastError(ERROR_SUCCESS);
    const BOOL initial = GetTokenInformation(token, kind, nullptr, 0, &bytes);
    need(!initial && GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytes > 0 && bytes <= 65536, "token_query_size");
    std::vector<unsigned char> data(bytes); DWORD returned{};
    win32(GetTokenInformation(token, kind, data.data(), bytes, &returned), "token_query");
    need(returned > 0 && returned <= bytes, "token_query_length"); return data;
}
void verify_identity(HANDLE token, Result& out) {
    auto user = token_information(token, TokenUser);
    need(user.size() >= sizeof(TOKEN_USER), "token_user_size");
    PSID sid = reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
    need(sid && IsValidSid(sid) && GetLengthSid(sid) == out.receipt.child_sid_bytes &&
        EqualSid(sid, out.receipt.child_sid.data()) != FALSE, "receipt_child_sid_mismatch");
    out.identity_verified = true;
    auto elevation = token_information(token, TokenElevation);
    need(elevation.size() >= sizeof(TOKEN_ELEVATION) && reinterpret_cast<TOKEN_ELEVATION*>(elevation.data())->TokenIsElevated == 0,
        "nonelevated_child_required");
    auto groups = token_information(token, TokenGroups);
    need(groups.size() >= sizeof(TOKEN_GROUPS), "token_group_size");
    auto* list = reinterpret_cast<TOKEN_GROUPS*>(groups.data());
    need(list->GroupCount <= 512 && offsetof(TOKEN_GROUPS, Groups) + std::size_t(list->GroupCount) * sizeof(SID_AND_ATTRIBUTES) <= groups.size(),
        "token_group_count");
    std::array<unsigned char, SECURITY_MAX_SID_SIZE> admin{}; DWORD admin_bytes = static_cast<DWORD>(admin.size());
    win32(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin.data(), &admin_bytes), "administrator_sid");
    // Deny-only administrator membership is also forbidden.
    for (DWORD index = 0; index < list->GroupCount; ++index)
        need(IsValidSid(list->Groups[index].Sid) && !EqualSid(list->Groups[index].Sid, admin.data()), "administrator_group_present");
    out.nonadministrator_verified = true;
}
void verify_readonly(HANDLE file, HANDLE impersonation, bool directory, Result& out) {
    LocalMemory security(out); PSID owner{}, group{}; PACL dacl{};
    const DWORD error = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, &group, &dacl, nullptr, &security.value);
    need(error == ERROR_SUCCESS && security.value && owner && group && dacl && IsValidSid(owner) &&
        EqualSid(owner, out.receipt.parent_sid.data()) != FALSE, "receipt_object_owner", HRESULT_FROM_WIN32(error ? error : ERROR_INVALID_OWNER));
    GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    alignas(PRIVILEGE_SET) std::array<unsigned char, 4096> privileges{}; DWORD bytes = static_cast<DWORD>(privileges.size()), granted{}; BOOL access{};
    win32(AccessCheck(security.value, impersonation, MAXIMUM_ALLOWED, &mapping,
        reinterpret_cast<PRIVILEGE_SET*>(privileges.data()), &bytes, &granted, &access), "receipt_object_access_check");
    constexpr DWORD writes = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
    need(access && (granted & FILE_READ_DATA) && !(granted & writes), "receipt_object_not_readonly_for_child");
    if (directory) { out.directory_owner_verified = true; out.directory_readonly_verified = true; }
    else { out.receipt_owner_verified = true; out.receipt_readonly_verified = true; }
}
void verify_desktop(Result& out) {
    DWORD session{}; win32(ProcessIdToSessionId(GetCurrentProcessId(), &session), "current_session");
    need(out.receipt_verified && session == out.receipt.child && session != 0 && session != out.receipt.parent &&
        (!out.session || session == out.session), "explicit_owned_child_session_required");
    need(WTSGetActiveConsoleSessionId() == out.receipt.console, "parent_console_changed");
    need(unix_time() < out.receipt.expires, "child_receipt_expired");
    out.console_parent_unchanged = true; out.session = session;
    LPWSTR state{}; DWORD state_bytes{};
    win32(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSConnectState, &state, &state_bytes), "current_session_state");
    const bool active = state && state_bytes == sizeof(WTS_CONNECTSTATE_CLASS) &&
        *reinterpret_cast<WTS_CONNECTSTATE_CLASS*>(state) == WTSActive;
    if (state) WTSFreeMemory(state);
    need(active, "current_child_not_active"); out.active_child_verified = true;
    const HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
    BOOL input{}; DWORD needed{}; std::array<wchar_t, 128> name{};
    win32(GetUserObjectInformationW(desktop, UOI_IO, &input, sizeof(input), &needed), "input_desktop_query");
    win32(GetUserObjectInformationW(desktop, UOI_NAME, name.data(), static_cast<DWORD>(sizeof(name)), &needed), "desktop_name_query");
    need(input && needed > 0 && needed <= sizeof(name) && name.back() == L'\0' && std::wcscmp(name.data(), L"Default") == 0,
        "default_input_desktop_required");
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
bool class_equals(HWND window, const wchar_t* expected) {
    std::array<wchar_t, 128> name{};
    const int count = GetClassNameW(window, name.data(), static_cast<int>(name.size()));
    need(count > 0 && count < static_cast<int>(name.size() - 1), "window_class_query", last_error());
    return std::wcscmp(name.data(), expected) == 0;
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
void perform_search_escape(SearchEscapeTarget& target, ULONGLONG end, HANDLE receipt_file, HANDLE directory,
    HANDLE impersonation, Result& out) {
    auto& action = out.search_escape; action.checked = true;
    const ULONGLONG started = GetTickCount64();
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
    verify_readonly(receipt_file, impersonation, false, out); verify_readonly(directory, impersonation, true, out);
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
    need(action.pair_inserted, "escape_input_incomplete", HRESULT_FROM_WIN32(action.send_last_error ? action.send_last_error : ERROR_GEN_FAILURE));
    need(action.key_cleanup_verified, "escape_release_unverified", HRESULT_FROM_WIN32(ERROR_GEN_FAILURE));
    // Observe only the pinned Search window. Actual loss of foreground or
    // hiding/destruction is separate evidence and never substitutes for the
    // parent's independent frame test. A visible HWND may cease obscuring it.
    const ULONGLONG observe_end = GetTickCount64() + 3000;
    do {
        budget(end); observe_search_escape_target(target, out);
        if (action.target_observation_valid && (action.target_hidden_or_destroyed || !action.target_foreground)) break;
        Sleep(50);
    } while (GetTickCount64() < observe_end);
    need(action.target_observation_valid && (action.target_hidden_or_destroyed || !action.target_foreground), "search_target_still_foreground");
    verify_desktop(out); action.elapsed_ms = GetTickCount64() - started;
}
bool is_exact_search(HANDLE process) {
    std::array<wchar_t, 257> family{}, application{};
    UINT32 size = static_cast<UINT32>(family.size());
    const LONG family_error = GetPackageFamilyName(process, &size, family.data());
    if (family_error == APPMODEL_ERROR_NO_PACKAGE) return false;
    need(family_error == ERROR_SUCCESS && size > 1 && size <= family.size() && family[size - 1] == L'\0',
        "foreground_family_query", HRESULT_FROM_WIN32(family_error ? family_error : ERROR_INVALID_DATA));
    if (std::wcscmp(family.data(), SearchFamily) != 0) return false;
    size = static_cast<UINT32>(application.size());
    const LONG application_error = GetApplicationUserModelId(process, &size, application.data());
    need(application_error == ERROR_SUCCESS && size > 1 && size <= application.size() && application[size - 1] == L'\0',
        "foreground_application_query", HRESULT_FROM_WIN32(application_error ? application_error : ERROR_INVALID_DATA));
    return std::wcscmp(application.data(), SearchApplication) == 0;
}
void run(Result& out) {
    const ULONGLONG end = GetTickCount64() + TotalBudgetMs;
    std::array<wchar_t, 1024> module{};
    const DWORD module_size = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
    need(module_size > 0 && module_size < module.size(), "module_path_length");
    std::wstring directory_path(module.data(), module_size);
    const auto slash = directory_path.find_last_of(L"\\/"); need(slash != std::wstring::npos, "module_directory_missing");
    directory_path.resize(slash);
    const std::wstring receipt_path = directory_path + L"\\child-search-receipt.bin";
    Handle directory(CreateFileW(directory_path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr), out);
    need(directory.value != INVALID_HANDLE_VALUE, "receipt_directory_open", last_error());
    BY_HANDLE_FILE_INFORMATION directory_info{};
    win32(GetFileInformationByHandle(directory.value, &directory_info), "receipt_directory_information");
    need((directory_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(directory_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
        "receipt_directory_reparse_point");
    Handle file(CreateFileW(receipt_path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr), out);
    need(file.value != INVALID_HANDLE_VALUE, "receipt_file_open", last_error());
    BY_HANDLE_FILE_INFORMATION info{}; win32(GetFileInformationByHandle(file.value, &info), "receipt_file_information");
    need(!(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) && info.nNumberOfLinks == 1 &&
        info.nFileSizeHigh == 0 && info.nFileSizeLow <= child_search::MaximumReceiptBytes, "receipt_file_layout");
    std::array<unsigned char, child_search::MaximumReceiptBytes> bytes{}; DWORD read{};
    win32(ReadFile(file.value, bytes.data(), info.nFileSizeLow, &read, nullptr), "receipt_file_read");
    need(read == info.nFileSizeLow, "receipt_file_short_read");
    out.receipt_error = static_cast<unsigned>(child_search::decode(bytes.data(), read, unix_time(), out.receipt));
    need(out.receipt_error == 0 && IsValidSid(out.receipt.parent_sid.data()) && IsValidSid(out.receipt.child_sid.data()), "receipt_shape_invalid");
    Handle token(nullptr, out); win32(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token.value), "current_token_open");
    verify_identity(token.value, out);
    Handle impersonation(nullptr, out); win32(DuplicateToken(token.value, SecurityImpersonation, &impersonation.value), "own_token_duplicate");
    verify_readonly(file.value, impersonation.value, false, out); verify_readonly(directory.value, impersonation.value, true, out);
    out.receipt_verified = true; budget(end); verify_desktop(out);
    SearchEscapeTarget target(out); target.window = GetAncestor(GetForegroundWindow(), GA_ROOT);
    need(target.window != nullptr && IsWindowVisible(target.window), "foreground_unavailable");
    target.owner = window_owner(target.window, out.session, &target.thread);
    if (!class_equals(target.window, TargetClass)) { out.status = "not_needed"; out.stage = "exact_search_not_observed"; return; }
    target.process.value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target.owner);
    need(target.process.value != nullptr, "foreground_process_open", last_error());
    verify_fresh_foreground(target.window, target.owner, target.thread, target.process.value, out);
    if (!is_exact_search(target.process.value)) { out.status = "not_needed"; out.stage = "exact_search_not_observed"; return; }
    out.target_found = true;
    perform_search_escape(target, end, file.value, directory.value, impersonation.value, out);
    out.status = "prepared"; out.stage = "pinned_search_left_foreground";
}
void write(const Result& out) {
    std::cout << "{\"schema\":\"child-search-prepare/v1\",\"status\":\"" << out.status << "\",\"stage\":\"" << out.stage
        << "\",\"hresult\":" << static_cast<std::uint32_t>(out.error) << ",\"binding_nonce\":\"";
    if (out.receipt_verified) {
        constexpr char hex[] = "0123456789ABCDEF";
        for (auto byte : out.receipt.nonce) std::cout << hex[byte >> 4] << hex[byte & 15];
    }
    std::cout << "\",\"elapsed_ms\":" << out.elapsed_ms << ",\"receipt_error\":" << out.receipt_error;
#define FLAG(name) std::cout << ",\"" #name "\":" << (out.name ? "true" : "false")
    FLAG(receipt_verified); FLAG(receipt_owner_verified); FLAG(receipt_readonly_verified); FLAG(directory_owner_verified);
    FLAG(directory_readonly_verified); FLAG(identity_verified); FLAG(nonadministrator_verified); FLAG(active_child_verified);
    FLAG(input_default_desktop_verified); FLAG(console_parent_unchanged); FLAG(target_found);
#undef FLAG
    const auto& a = out.search_escape;
#define FLAG(name) std::cout << ",\"" #name "\":" << (a.name ? "true" : "false")
    FLAG(owner_verified); FLAG(owner_reverified); FLAG(first_page_verified); FLAG(recheck_page_verified); FLAG(same_root_reverified);
    FLAG(keyboard_state_query_succeeded); FLAG(send_attempted); FLAG(pair_inserted); FLAG(release_cleanup_attempted);
    FLAG(release_event_inserted); FLAG(escape_up_observed); FLAG(key_cleanup_verified); FLAG(target_observation_valid); FLAG(target_hidden_or_destroyed);
    FLAG(target_exists); FLAG(target_visible); FLAG(target_foreground);
#undef FLAG
#define NUMBER(name) std::cout << ",\"" #name "\":" << a.name
    NUMBER(initial_search_count); NUMBER(recheck_search_count); NUMBER(queue_down_mask); NUMBER(async_down_mask);
    NUMBER(send_call_count); NUMBER(requested_input_count); NUMBER(inserted_input_count); NUMBER(send_last_error);
    NUMBER(cleanup_call_count); NUMBER(cleanup_inserted_count); NUMBER(cleanup_last_error); NUMBER(release_observations); NUMBER(target_observations);
#undef NUMBER
    std::cout << ",\"com_uninitialized\":" << (out.com_uninitialized ? "true" : "false") << ",\"cleanup_verified\":"
        << (out.cleanup_verified ? "true" : "false") << ",\"cleanup_hresult\":" << static_cast<std::uint32_t>(out.cleanup_error) << "}\n";
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    Result out; const ULONGLONG started = GetTickCount64();
    try {
        need(argc == 2 && std::wcscmp(argv[1], L"--allow-owned-child-search") == 0, "explicit_owned_child_opt_in_required");
        run(out);
    } catch (const Failure& error) { out.status = "failed"; out.stage = error.stage; out.error = error.result; }
    catch (...) { out.status = "failed"; out.stage = "unexpected_native_failure"; out.error = E_FAIL; }
    if (!out.search_escape.key_cleanup_verified) { out.cleanup_verified = false; out.cleanup_error = E_FAIL; }
    if (!out.cleanup_verified) out.status = "failed";
    out.elapsed_ms = GetTickCount64() - started; write(out);
    return std::strcmp(out.status, "failed") == 0 ? 1 : 0;
}
