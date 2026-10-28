#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <ole2.h>
#include <appmodel.h>
#include <wtsapi32.h>
#include <uiautomation.h>
#include <array>
#include <cstdint>
#include <cwchar>
#include <iostream>
#include <iterator>
#include <string_view>

namespace {
template<class T> class Com final {
    T* value_ = nullptr;
public:
    Com() = default;
    Com(const Com&) = delete;
    Com& operator=(const Com&) = delete;
    ~Com() { if (value_) value_->Release(); }
    T* operator->() const noexcept { return value_; }
    T** put() noexcept { if (value_) value_->Release(); value_ = nullptr; return &value_; }
    T* get() const noexcept { return value_; }
};
struct Failure { const char* stage; HRESULT result; };
void need(bool okay, const char* stage, HRESULT result = E_FAIL) {
    if (!okay) throw Failure{stage, result};
}
void hr(HRESULT result, const char* stage) { need(SUCCEEDED(result), stage, result); }
struct Apartment final {
    Apartment() { hr(CoInitializeEx(nullptr, COINIT_MULTITHREADED), "com_initialize"); }
    ~Apartment() { CoUninitialize(); }
};
struct Handle final {
    HANDLE value;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct Text final {
    BSTR value = nullptr;
    ~Text() { if (value) { SecureZeroMemory(value, SysStringByteLen(value)); SysFreeString(value); } }
};
struct Label { const wchar_t* text; const char* id; };
constexpr Label labels[] = {
    {L"Choose privacy settings for your device", "privacy_heading"},
    {L"Privacy settings", "privacy_settings"},
    {L"Accept", "accept"}, {L"Next", "next"}, {L"Back", "back"},
    {L"Yes", "yes"}, {L"No", "no"},
    {L"Hi", "hi"}, {L"Just a moment...", "just_a_moment"},
    {L"Just a moment", "just_a_moment_no_ellipsis"},
    {L"Getting things ready", "getting_ready"},
    {L"We're getting things ready for you", "getting_ready_for_you"},
    {L"This might take a few minutes", "may_take_minutes"},
    {L"Let's finish setting up your device", "finish_setup"},
    {L"Do more with your voice", "voice"},
    {L"Let Microsoft and apps use your location", "location_question"},
    {L"Find my device", "find_device"},
    {L"Send diagnostic data to Microsoft", "diagnostic_question"},
    {L"Improve inking & typing", "inking_question"},
    {L"Get tailored experiences with diagnostic data", "tailored_question"},
    {L"Let apps use advertising ID", "advertising_question"},
    {L"Location", "location"}, {L"Diagnostic data", "diagnostic_data"},
    {L"Inking & typing", "inking"}, {L"Tailored experiences", "tailored"},
    {L"Advertising ID", "advertising_id"},
    {L"Required only", "required_only"}, {L"Optional", "optional"},
    {L"Try again", "try_again"}, {L"Retry", "retry"},
    {L"Skip for now", "skip_for_now"}, {L"Something went wrong", "something_wrong"},
    {L"Sign in", "sign_in"}, {L"Microsoft account", "microsoft_account"},
    {L"Use recommended settings", "recommended_settings"}
};
struct Observation final {
    const char* stage = "start";
    const char* status = "unavailable";
    HRESULT result = S_OK;
    bool owner_verified = false, owner_stable = false, root_handle_matches = false;
    int elements = 0, visited = 0, hidden = 0, password_elements = 0, other_process_elements = 0;
    int property_errors = 0, unclassified_names = 0;
    bool bounded = false;
    std::array<unsigned, std::size(labels)> matches{};
    std::array<int, std::size(labels)> last_control_types{};
};
bool environment_equals(const wchar_t* name, const wchar_t* expected) {
    std::array<wchar_t, 64> value{};
    const DWORD length = GetEnvironmentVariableW(name, value.data(), static_cast<DWORD>(value.size()));
    return length > 0 && length < value.size() && std::wcscmp(value.data(), expected) == 0;
}
void observe(Observation& out) {
    need(environment_equals(L"GITHUB_ACTIONS", L"true") &&
        environment_equals(L"RUNNER_ENVIRONMENT", L"github-hosted") &&
        environment_equals(L"RUNNER_OS", L"Windows"), "disposable_windows_runner_required");
    DWORD current_session = 0;
    need(ProcessIdToSessionId(GetCurrentProcessId(), &current_session) != FALSE &&
        current_session != 0 && current_session == WTSGetActiveConsoleSessionId(), "interactive_console_required");
    HWND root = GetAncestor(GetForegroundWindow(), GA_ROOT);
    need(root != nullptr, "foreground_unavailable");
    DWORD owner = 0;
    const DWORD thread = GetWindowThreadProcessId(root, &owner);
    DWORD owner_session = 0;
    need(thread != 0 && owner != 0 && owner != GetCurrentProcessId() &&
        ProcessIdToSessionId(owner, &owner_session) != FALSE && owner_session == current_session,
        "same_session_foreground_required");
    std::array<wchar_t, 128> window_class{};
    need(GetClassNameW(root, window_class.data(), static_cast<int>(window_class.size())) > 0 &&
        std::wcscmp(window_class.data(), L"Windows.UI.Core.CoreWindow") == 0, "foreground_class_not_target");
    Handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner)};
    need(process.value != nullptr, "foreground_process_unavailable", HRESULT_FROM_WIN32(GetLastError()));
    std::array<wchar_t, 257> family{}, application{};
    UINT32 family_length = static_cast<UINT32>(family.size());
    UINT32 application_length = static_cast<UINT32>(application.size());
    const LONG family_result = GetPackageFamilyName(process.value, &family_length, family.data());
    const LONG application_result = GetApplicationUserModelId(process.value, &application_length, application.data());
    need(family_result == ERROR_SUCCESS && application_result == ERROR_SUCCESS &&
        family_length > 1 && family_length <= family.size() && application_length > 1 && application_length <= application.size() &&
        family[family_length - 1] == L'\0' && application[application_length - 1] == L'\0' &&
        std::wcscmp(family.data(), L"Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy") == 0 &&
        std::wcscmp(application.data(), L"Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy!App") == 0,
        "foreground_application_not_target");
    out.owner_verified = true;
    Apartment apartment;
    Com<IUIAutomation2> automation;
    hr(CoCreateInstance(__uuidof(CUIAutomation8), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IUIAutomation2), reinterpret_cast<void**>(automation.put())), "automation_create");
    hr(automation->put_AutoSetFocus(FALSE), "automation_no_focus");
    hr(automation->put_ConnectionTimeout(1000), "automation_connection_timeout");
    hr(automation->put_TransactionTimeout(1000), "automation_transaction_timeout");
    Com<IUIAutomationElement> element;
    hr(automation->ElementFromHandle(root, element.put()), "automation_window");
    need(element.get() != nullptr, "automation_null_window");
    UIA_HWND actual_window = nullptr;
    if (SUCCEEDED(element->get_CurrentNativeWindowHandle(&actual_window))) out.root_handle_matches = actual_window == root;
    Com<IUIAutomationCondition> condition;
    hr(automation->CreateTrueCondition(condition.put()), "automation_condition");
    Com<IUIAutomationElementArray> elements;
    // Scope is this one verified foreground window, never the desktop.
    const auto subtree = static_cast<TreeScope>(TreeScope_Element | TreeScope_Children | TreeScope_Descendants);
    hr(element->FindAll(subtree, condition.get(), elements.put()), "automation_subtree");
    need(elements.get() != nullptr, "automation_null_elements");
    hr(elements->get_Length(&out.elements), "automation_count");
    need(out.elements >= 0 && out.elements <= 512, "automation_element_limit");
    const ULONGLONG end = GetTickCount64() + 8000;
    for (int index = 0; index < out.elements; ++index) {
        if (GetTickCount64() >= end) { out.bounded = true; break; }
        Com<IUIAutomationElement> item;
        if (FAILED(elements->GetElement(index, item.put())) || !item.get()) { ++out.property_errors; continue; }
        ++out.visited;
        int process_id = 0, control_type = 0;
        BOOL offscreen = TRUE, password = TRUE;
        if (FAILED(item->get_CurrentProcessId(&process_id)) || FAILED(item->get_CurrentIsOffscreen(&offscreen)) ||
            FAILED(item->get_CurrentIsPassword(&password)) || FAILED(item->get_CurrentControlType(&control_type))) {
            ++out.property_errors; continue;
        }
        if (process_id <= 0 || static_cast<DWORD>(process_id) != owner) { ++out.other_process_elements; continue; }
        if (offscreen) { ++out.hidden; continue; }
        if (password) { ++out.password_elements; continue; }
        Text name;
        if (FAILED(item->get_CurrentName(&name.value))) { ++out.property_errors; continue; }
        const UINT length = name.value ? SysStringLen(name.value) : 0;
        if (length == 0) continue;
        bool matched = false;
        if (length <= 2048) {
            for (std::size_t label = 0; label < std::size(labels); ++label) {
                const std::wstring_view expected(labels[label].text);
                if (length == expected.size() && CompareStringOrdinal(name.value, static_cast<int>(length),
                    expected.data(), static_cast<int>(expected.size()), TRUE) == CSTR_EQUAL) {
                    ++out.matches[label]; out.last_control_types[label] = control_type; matched = true;
                }
            }
        }
        if (!matched) ++out.unclassified_names;
    }
    DWORD recheck_owner = 0;
    const DWORD recheck_thread = GetWindowThreadProcessId(root, &recheck_owner);
    out.owner_stable = recheck_thread == thread && recheck_owner == owner && GetAncestor(GetForegroundWindow(), GA_ROOT) == root;
    if (!out.owner_stable) { out.matches.fill(0); out.last_control_types.fill(0); throw Failure{"foreground_changed", S_FALSE}; }
    out.stage = "completed";
    out.status = out.bounded ? "partial_observation" : "observed";
}
void write(const Observation& out, ULONGLONG elapsed) {
    std::cout << "{\"schema\":\"startup-presentation/v1\",\"status\":\"" << out.status
        << "\",\"stage\":\"" << out.stage << "\",\"hresult\":" << static_cast<std::int32_t>(out.result)
        << ",\"target_owner_verified\":" << (out.owner_verified ? "true" : "false")
        << ",\"owner_stable\":" << (out.owner_stable ? "true" : "false")
        << ",\"root_handle_matches\":" << (out.root_handle_matches ? "true" : "false")
        << ",\"elements\":" << out.elements << ",\"visited\":" << out.visited
        << ",\"hidden\":" << out.hidden << ",\"password_elements_skipped\":" << out.password_elements
        << ",\"other_process_elements_skipped\":" << out.other_process_elements
        << ",\"property_errors\":" << out.property_errors << ",\"unclassified_names\":" << out.unclassified_names
        << ",\"elapsed_ms\":" << elapsed << ",\"label_matches\":[";
    bool first = true;
    for (std::size_t index = 0; index < out.matches.size(); ++index) {
        if (out.matches[index] == 0) continue;
        if (!first) std::cout << ',';
        first = false;
        std::cout << "{\"id\":\"" << labels[index].id << "\",\"count\":" << out.matches[index]
            << ",\"last_control_type\":" << out.last_control_types[index] << '}';
    }
    std::cout << "],\"input_sent\":false,\"window_changed\":false,\"session_functionality_verified\":false}" << std::endl;
}
}
int main() {
    const ULONGLONG start = GetTickCount64();
    Observation out;
    int code = 0;
    try { observe(out); }
    catch (const Failure& failure) { out.stage = failure.stage; out.result = failure.result; code = 77; }
    catch (...) { out.stage = "unexpected_exception"; out.result = E_UNEXPECTED; code = 1; }
    write(out, GetTickCount64() - start);
    return code;
}
