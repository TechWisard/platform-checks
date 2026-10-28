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
struct Label { const wchar_t* text; const char* id; bool action = false; };
constexpr Label labels[] = {
    {L"Choose privacy settings for your device", "privacy_heading"},
    {L"Privacy settings", "privacy_settings"},
    {L"Accept", "accept", true}, {L"Next", "next", true}, {L"Back", "back", true},
    {L"Yes", "yes", true}, {L"No", "no", true},
    {L"More", "more", true}, {L"Continue", "continue", true},
    {L"Done", "done", true}, {L"OK", "ok", true}, {L"Cancel", "cancel", true},
    {L"Learn more", "learn_more", true}, {L"Save", "save", true},
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
    {L"Try again", "try_again", true}, {L"Retry", "retry", true},
    {L"Skip for now", "skip_for_now", true}, {L"Something went wrong", "something_wrong"},
    {L"Sign in", "sign_in", true}, {L"Microsoft account", "microsoft_account"},
    {L"Use recommended settings", "recommended_settings", true}
};
constexpr std::size_t ActionLimit = 32;
struct ActionControl final {
    int element_index = -1, control_type = 0;
    const char* label_id = "unclassified";
    bool offscreen = true, enabled = false;
    std::array<char, 129> automation_id{};
    const char* automation_id_status = "unread";
    int invoke_available = -1, toggle_available = -1, scroll_item_available = -1;
    int toggle_state = -1;
    HRESULT first_error = S_OK;
};
struct Observation final {
    const char* stage = "start";
    const char* status = "unavailable";
    HRESULT result = S_OK;
    bool owner_verified = false, owner_stable = false, root_handle_matches = false;
    int elements = 0, visited = 0, hidden = 0, password_elements = 0, other_process_elements = 0;
    int property_errors = 0, unclassified_names = 0, hidden_unclassified_names = 0;
    bool bounded = false;
    std::array<unsigned, std::size(labels)> matches{};
    std::array<unsigned, std::size(labels)> hidden_matches{};
    std::array<int, std::size(labels)> last_control_types{};
    std::array<int, std::size(labels)> last_hidden_control_types{};
    bool privacy_heading_visible = false, action_metadata_attempted = false;
    int action_candidates = 0, action_elements_skipped = 0;
    std::size_t action_count = 0;
    std::array<ActionControl, ActionLimit> actions{};
};
std::size_t classify(BSTR name) {
    const UINT length = name ? SysStringLen(name) : 0;
    if (length > 0 && length <= 2048) {
        for (std::size_t index = 0; index < std::size(labels); ++index) {
            const std::wstring_view expected(labels[index].text);
            if (length == expected.size() && CompareStringOrdinal(name, static_cast<int>(length),
                expected.data(), static_cast<int>(expected.size()), TRUE) == CSTR_EQUAL) return index;
        }
    }
    return std::size(labels);
}
bool action_type(int type) noexcept {
    switch (type) {
    case UIA_ButtonControlTypeId: case UIA_CheckBoxControlTypeId: case UIA_RadioButtonControlTypeId:
    case UIA_HyperlinkControlTypeId: case UIA_ComboBoxControlTypeId: case UIA_ListItemControlTypeId:
    case UIA_MenuItemControlTypeId: case UIA_SplitButtonControlTypeId: case UIA_TabItemControlTypeId:
        return true;
    default: return false;
    }
}
bool within_budget(Observation& out, ULONGLONG end) noexcept {
    if (GetTickCount64() < end) return true;
    out.bounded = true; return false;
}
void metadata_error(Observation& out, ActionControl& action, HRESULT result) noexcept {
    ++out.property_errors;
    if (SUCCEEDED(action.first_error)) action.first_error = result;
}
template<class Query> bool metadata_read(Observation& out, ActionControl& action, ULONGLONG end, Query query) {
    if (!within_budget(out, end)) return false;
    const HRESULT result = query();
    if (FAILED(result)) { metadata_error(out, action, result); return false; }
    return true;
}
int pattern_available(IUIAutomationElement* item, PROPERTYID property, Observation& out,
    ActionControl& action, ULONGLONG end) {
    struct Value { VARIANT value{}; ~Value() { VariantClear(&value); } } value;
    if (!metadata_read(out, action, end, [&] { return item->GetCurrentPropertyValue(property, &value.value); })) return -1;
    if (value.value.vt != VT_BOOL || (value.value.boolVal != VARIANT_FALSE && value.value.boolVal != VARIANT_TRUE)) {
        metadata_error(out, action, DISP_E_TYPEMISMATCH); return -1;
    }
    return value.value.boolVal == VARIANT_TRUE ? 1 : 0;
}
void read_automation_id(IUIAutomationElement* item, Observation& out, ActionControl& action, ULONGLONG end) {
    Text text;
    if (!metadata_read(out, action, end, [&] { return item->get_CurrentAutomationId(&text.value); })) {
        action.automation_id_status = out.bounded ? "budget" : "error"; return;
    }
    const UINT length = text.value ? SysStringLen(text.value) : 0;
    if (!length) { action.automation_id_status = "empty"; return; }
    if (length > 128) { action.automation_id_status = "rejected_length"; return; }
    for (UINT i = 0; i < length; ++i) {
        const wchar_t c = text.value[i];
        if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
            (c >= L'0' && c <= L'9') || c == L'_' || c == L'-' || c == L'.' || c == L':')) {
            action.automation_id_status = "rejected_characters"; return;
        }
    }
    for (UINT i = 0; i < length; ++i) action.automation_id[i] = static_cast<char>(text.value[i]);
    action.automation_id_status = "safe_ascii";
}
void read_actions(IUIAutomationElementArray* elements, const std::array<int, ActionLimit>& candidates,
    std::size_t count, DWORD owner, ULONGLONG end, Observation& out) {
    for (std::size_t index = 0; index < count && within_budget(out, end); ++index) {
        ActionControl action; action.element_index = candidates[index];
        Com<IUIAutomationElement> item;
        if (!metadata_read(out, action, end, [&] { return elements->GetElement(candidates[index], item.put()); })) continue;
        if (!item.get()) { metadata_error(out, action, E_POINTER); continue; }
        int process_id = 0;
        BOOL password = TRUE, offscreen = TRUE, enabled = FALSE;
        if (!metadata_read(out, action, end, [&] { return item->get_CurrentProcessId(&process_id); }) ||
            !metadata_read(out, action, end, [&] { return item->get_CurrentIsPassword(&password); })) continue;
        if (process_id <= 0 || static_cast<DWORD>(process_id) != owner || password) { ++out.action_elements_skipped; continue; }
        if (!metadata_read(out, action, end, [&] { return item->get_CurrentControlType(&action.control_type); }) ||
            !metadata_read(out, action, end, [&] { return item->get_CurrentIsOffscreen(&offscreen); }) ||
            !metadata_read(out, action, end, [&] { return item->get_CurrentIsEnabled(&enabled); })) continue;
        Text name;
        const bool name_read = metadata_read(out, action, end, [&] { return item->get_CurrentName(&name.value); });
        const std::size_t label = name_read ? classify(name.value) : std::size(labels);
        if (!action_type(action.control_type) && !(label < std::size(labels) && labels[label].action)) {
            ++out.action_elements_skipped; continue;
        }
        if (label < std::size(labels)) action.label_id = labels[label].id;
        action.offscreen = offscreen != FALSE; action.enabled = enabled != FALSE;
        read_automation_id(item.get(), out, action, end);
        action.invoke_available = pattern_available(item.get(), UIA_IsInvokePatternAvailablePropertyId, out, action, end);
        action.toggle_available = pattern_available(item.get(), UIA_IsTogglePatternAvailablePropertyId, out, action, end);
        action.scroll_item_available = pattern_available(item.get(), UIA_IsScrollItemPatternAvailablePropertyId, out, action, end);
        if (action.toggle_available == 1 && within_budget(out, end)) {
            Com<IUIAutomationTogglePattern> toggle;
            if (metadata_read(out, action, end, [&] { return item->GetCurrentPatternAs(UIA_TogglePatternId,
                __uuidof(IUIAutomationTogglePattern), reinterpret_cast<void**>(toggle.put())); })) {
                if (!toggle.get()) metadata_error(out, action, E_POINTER);
                else {
                    ToggleState state = ToggleState_Indeterminate;
                    if (metadata_read(out, action, end, [&] { return toggle->get_CurrentToggleState(&state); })) {
                        if (state == ToggleState_Off || state == ToggleState_On || state == ToggleState_Indeterminate)
                            action.toggle_state = static_cast<int>(state);
                        else metadata_error(out, action, E_UNEXPECTED);
                    }
                }
            }
        }
        out.actions[out.action_count++] = action;
    }
}
void discard_page_details(Observation& out) noexcept {
    out.matches.fill(0); out.hidden_matches.fill(0);
    out.last_control_types.fill(0); out.last_hidden_control_types.fill(0);
    out.actions = {}; out.action_count = 0; out.privacy_heading_visible = false;
}
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
    std::array<int, ActionLimit> candidates{};
    std::size_t candidate_count = 0;
    for (int index = 0; index < out.elements; ++index) {
        if (!within_budget(out, end)) break;
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
        if (offscreen) ++out.hidden;
        if (password) { ++out.password_elements; continue; }
        Text name;
        const HRESULT name_result = item->get_CurrentName(&name.value);
        if (FAILED(name_result)) ++out.property_errors;
        const std::size_t label = SUCCEEDED(name_result) ? classify(name.value) : std::size(labels);
        if (label < std::size(labels)) {
            if (offscreen) { ++out.hidden_matches[label]; out.last_hidden_control_types[label] = control_type; }
            else { ++out.matches[label]; out.last_control_types[label] = control_type; }
        } else if (SUCCEEDED(name_result) && name.value && SysStringLen(name.value)) {
            if (offscreen) ++out.hidden_unclassified_names;
            else ++out.unclassified_names;
        }
        if (action_type(control_type) || (label < std::size(labels) && labels[label].action)) {
            ++out.action_candidates;
            if (candidate_count < candidates.size()) candidates[candidate_count++] = index;
        }
    }
    const auto recheck_owner = [&] {
        DWORD process_id = 0;
        const DWORD thread_id = GetWindowThreadProcessId(root, &process_id);
        out.owner_stable = thread_id == thread && process_id == owner && GetAncestor(GetForegroundWindow(), GA_ROOT) == root;
        if (!out.owner_stable) { discard_page_details(out); throw Failure{"foreground_changed", S_FALSE}; }
    };
    recheck_owner();
    out.privacy_heading_visible = out.matches[0] > 0;
    if (out.privacy_heading_visible && out.root_handle_matches && within_budget(out, end)) {
        out.action_metadata_attempted = true;
        // Do not emit IDs if an exception prevents the final owner recheck.
        out.owner_stable = false;
        read_actions(elements.get(), candidates, candidate_count, owner, end, out);
        recheck_owner();
    }
    out.stage = "completed";
    out.status = out.bounded ? "partial_observation" : "observed";
}
const char* nullable_boolean(int value) noexcept { return value < 0 ? "null" : value ? "true" : "false"; }
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
        << ",\"hidden_unclassified_names\":" << out.hidden_unclassified_names
        << ",\"observation_budget_exhausted\":" << (out.bounded ? "true" : "false")
        << ",\"elapsed_ms\":" << elapsed << ",\"label_matches\":[";
    bool first = true;
    for (std::size_t index = 0; index < out.matches.size(); ++index) {
        if (out.matches[index] == 0 && out.hidden_matches[index] == 0) continue;
        if (!first) std::cout << ',';
        first = false;
        // Preserve v1 count/last_control_type as the visible observations.
        std::cout << "{\"id\":\"" << labels[index].id << "\",\"count\":" << out.matches[index]
            << ",\"visible_count\":" << out.matches[index] << ",\"hidden_count\":" << out.hidden_matches[index]
            << ",\"last_control_type\":" << out.last_control_types[index]
            << ",\"last_hidden_control_type\":" << out.last_hidden_control_types[index] << '}';
    }
    std::cout << "],\"privacy_heading_visible\":" << (out.privacy_heading_visible ? "true" : "false")
        << ",\"action_metadata_attempted\":" << (out.action_metadata_attempted ? "true" : "false")
        << ",\"action_candidates\":" << out.action_candidates
        << ",\"action_metadata_limit\":" << ActionLimit
        << ",\"action_limit_reached\":" << (out.action_candidates > static_cast<int>(ActionLimit) ? "true" : "false")
        << ",\"action_elements_skipped\":" << out.action_elements_skipped << ",\"action_controls\":[";
    for (std::size_t index = 0; index < out.action_count; ++index) {
        if (index) std::cout << ',';
        const ActionControl& action = out.actions[index];
        std::cout << "{\"element_index\":" << action.element_index << ",\"fixed_label_id\":\"" << action.label_id
            << "\",\"control_type\":" << action.control_type << ",\"is_offscreen\":" << (action.offscreen ? "true" : "false")
            << ",\"is_enabled\":" << (action.enabled ? "true" : "false")
            << ",\"automation_id_status\":\"" << action.automation_id_status << "\",\"automation_id\":";
        if (action.automation_id[0]) std::cout << '"' << action.automation_id.data() << '"';
        else std::cout << "null";
        std::cout << ",\"invoke_available\":" << nullable_boolean(action.invoke_available)
            << ",\"toggle_available\":" << nullable_boolean(action.toggle_available)
            << ",\"scroll_item_available\":" << nullable_boolean(action.scroll_item_available)
            << ",\"toggle_state\":";
        if (action.toggle_state >= 0) std::cout << action.toggle_state; else std::cout << "null";
        std::cout << ",\"first_property_hresult\":" << static_cast<std::int32_t>(action.first_error) << '}';
    }
    std::cout << "],\"input_sent\":false,\"window_changed\":false,\"action_methods_called\":false,\"session_functionality_verified\":false}" << std::endl;
}
}
int main() {
    const ULONGLONG start = GetTickCount64();
    Observation out;
    int code = 0;
    try { observe(out); }
    catch (const Failure& failure) { out.stage = failure.stage; out.result = failure.result; code = 77; }
    catch (...) { out.stage = "unexpected_exception"; out.result = E_UNEXPECTED; code = 1; }
    if (!out.owner_stable) discard_page_details(out);
    write(out, GetTickCount64() - start);
    return code;
}
