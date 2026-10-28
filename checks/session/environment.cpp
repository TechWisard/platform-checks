// Independent, read-only Windows session/COM capability probe.
// This program NEVER enables child sessions, connects RDP, supplies credentials,
// creates accounts, changes registry values, or installs a driver.
// The interface property is invoked through the installed Microsoft type library;
// no handwritten interface vtable is assumed.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <windows.h>
#include <wtsapi32.h>
#include <oleauto.h>
#include <oleidl.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

template<class T> class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() { if (value_) value_->Release(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T* get() const noexcept { return value_; }
    T** out() noexcept { return &value_; }
    T* operator->() const noexcept { return value_; }
private:
    T* value_ = nullptr;
};

struct Module {
    HMODULE value;
    explicit Module(const wchar_t* name)
        : value(LoadLibraryExW(name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {}
    ~Module() { if (value) FreeLibrary(value); }
    Module(const Module&) = delete;
    Module& operator=(const Module&) = delete;
};

struct OleApartment {
    HRESULT status = OleInitialize(nullptr);
    ~OleApartment() { if (SUCCEEDED(status)) OleUninitialize(); }
};

struct Variant {
    VARIANT value;
    Variant() { VariantInit(&value); }
    ~Variant() { VariantClear(&value); }
};

struct ExceptionInfo {
    EXCEPINFO value{};
    ~ExceptionInfo() {
        SysFreeString(value.bstrSource);
        SysFreeString(value.bstrDescription);
        SysFreeString(value.bstrHelpFile);
    }
};

template<class Fn> Fn function(HMODULE module, const char* name) {
    if (!module) return nullptr;
    const FARPROC address = GetProcAddress(module, name);
    Fn result = nullptr;
    static_assert(sizeof(result) == sizeof(address), "Windows function-pointer size mismatch");
    std::memcpy(&result, &address, sizeof(result));
    return result;
}

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void result(const std::string& name, HRESULT code) {
    std::cout << name << "_hresult=" << static_cast<std::uint32_t>(code) << '\n';
}

GUID guid(const wchar_t* text) {
    GUID value{};
    require(SUCCEEDED(CLSIDFromString(text, &value)), "Invalid constant GUID");
    return value;
}

bool system_info() {
    using RtlGetVersionFn = LONG (WINAPI*)(OSVERSIONINFOW*);
    const auto get_version = function<RtlGetVersionFn>(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    require(get_version != nullptr, "RtlGetVersion missing");
    OSVERSIONINFOEXW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    const LONG status = get_version(reinterpret_cast<OSVERSIONINFOW*>(&version));
    require(status >= 0, "RtlGetVersion failed");
    std::cout << "os_major=" << version.dwMajorVersion << "\nos_minor=" << version.dwMinorVersion
              << "\nos_build=" << version.dwBuildNumber
              << "\nos_product_type=" << static_cast<unsigned>(version.wProductType) << '\n';
    DWORD product = 0;
    const BOOL product_ok = GetProductInfo(version.dwMajorVersion, version.dwMinorVersion,
        version.wServicePackMajor, version.wServicePackMinor, &product);
    std::cout << "product_info_ok=" << (product_ok != FALSE) << "\nos_product_sku=" << product << '\n';
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    std::cout << "native_processor_architecture=" << info.wProcessorArchitecture
              << "\npointer_bits=" << sizeof(void*) * 8U << '\n';
    using IsWow64Process2Fn = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto machine_info = function<IsWow64Process2Fn>(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (machine_info) {
        USHORT process_machine = 0;
        USHORT native_machine = 0;
        const BOOL ok = machine_info(GetCurrentProcess(), &process_machine, &native_machine);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        std::cout << "machine_info_ok=" << (ok != FALSE) << "\nmachine_info_error=" << error
                  << "\nprocess_machine=" << process_machine << "\nnative_machine=" << native_machine << '\n';
    }
    return product_ok != FALSE;
}

bool is_object_named(HANDLE object, const wchar_t* expected, const char* key) {
    std::array<wchar_t, 256> name{};
    DWORD needed = 0;
    const BOOL ok = GetUserObjectInformationW(object, UOI_NAME, name.data(),
        static_cast<DWORD>(name.size() * sizeof(wchar_t)), &needed);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    const bool matches = ok && needed >= sizeof(wchar_t) && needed <= name.size() * sizeof(wchar_t)
        && needed % sizeof(wchar_t) == 0 && name[needed / sizeof(wchar_t) - 1] == L'\0'
        && std::wcscmp(name.data(), expected) == 0;
    std::cout << key << "_query_ok=" << (ok != FALSE) << '\n'
              << key << "_query_error=" << error << '\n'
              << key << "_matches=" << matches << '\n';
    return matches;
}

bool session_environment() {
    DWORD session = 0;
    require(ProcessIdToSessionId(GetCurrentProcessId(), &session) != FALSE,
        "ProcessIdToSessionId failed");
    const DWORD console = WTSGetActiveConsoleSessionId();
    std::cout << "process_session_id=" << session << "\nconsole_session_id=" << console
              << "\nprocess_is_console=" << (session == console) << '\n';
    LPWSTR raw = nullptr;
    DWORD bytes = 0;
    const BOOL query_ok = WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session,
        WTSConnectState, &raw, &bytes);
    const DWORD query_error = query_ok ? ERROR_SUCCESS : GetLastError();
    const auto free_wts = [](wchar_t* p) { if (p) WTSFreeMemory(p); };
    std::unique_ptr<wchar_t, decltype(free_wts)> memory(raw, free_wts);
    WTS_CONNECTSTATE_CLASS state = WTSInit;
    if (query_ok) {
        require(raw && bytes == sizeof(state), "Invalid WTSConnectState result");
        std::memcpy(&state, raw, sizeof(state));
        require(static_cast<unsigned>(state) <= static_cast<unsigned>(WTSInit), "Unknown WTS state");
    }
    std::cout << "session_state_query_ok=" << (query_ok != FALSE)
              << "\nsession_state_query_error=" << query_error
              << "\nsession_state=" << static_cast<unsigned>(state) << '\n';
    const HWINSTA station = GetProcessWindowStation();
    const HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
    require(station && desktop, "Current station/desktop missing");
    const bool winsta0 = is_object_named(station, L"WinSta0", "window_station_winsta0");
    const bool default_desktop = is_object_named(desktop, L"Default", "desktop_default");
    USEROBJECTFLAGS flags{};
    DWORD needed = 0;
    const BOOL flags_ok = GetUserObjectInformationW(station, UOI_FLAGS, &flags, sizeof(flags), &needed);
    const bool visible = flags_ok && (flags.dwFlags & WSF_VISIBLE) != 0;
    std::cout << "window_station_visible=" << visible << '\n';
    const HDESK input = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    const DWORD input_error = input ? ERROR_SUCCESS : GetLastError();
    const bool input_accessible = input != nullptr;
    std::cout << "input_desktop_accessible=" << (input != nullptr)
              << "\ninput_desktop_error=" << input_error << '\n';
    if (input) require(CloseDesktop(input) != FALSE, "CloseDesktop failed");
    return session != 0 && query_ok && state == WTSActive && winsta0 && default_desktop && visible && input_accessible;
}

bool child_queries() {
    const Module module(L"wtsapi32.dll");
    if (!module.value) {
        const DWORD error = GetLastError();
        std::cout << "wts_module_error=" << error << '\n';
        return false;
    }
    using EnabledFn = BOOL (WINAPI*)(PBOOL);
    using ChildIdFn = BOOL (WINAPI*)(PULONG);
    const auto enabled_fn = function<EnabledFn>(module.value, "WTSIsChildSessionsEnabled");
    const auto id_fn = function<ChildIdFn>(module.value, "WTSGetChildSessionId");
    std::cout << "child_enabled_api_present=" << (enabled_fn != nullptr)
              << "\nchild_id_api_present=" << (id_fn != nullptr) << '\n';
    if (!enabled_fn || !id_fn) return false;
    BOOL enabled = FALSE;
    SetLastError(ERROR_SUCCESS);
    const BOOL enabled_ok = enabled_fn(&enabled);
    const DWORD enabled_error = enabled_ok ? ERROR_SUCCESS : GetLastError();
    ULONG child = MAXDWORD;
    SetLastError(ERROR_SUCCESS);
    const BOOL child_ok = id_fn(&child);
    const DWORD child_error = child_ok ? ERROR_SUCCESS : GetLastError();
    std::cout << "child_enabled_query_ok=" << (enabled_ok != FALSE)
              << "\nchild_enabled_query_error=" << enabled_error
              << "\nchild_feature_enabled=" << (enabled != FALSE)
              << "\nchild_id_query_ok=" << (child_ok != FALSE)
              << "\nchild_id_query_error=" << child_error
              << "\nexisting_child_id=" << child
              << "\nexisting_child_present=" << (child_ok && child != MAXDWORD) << '\n';
    // On the tested Windows 11/Server images absence is FALSE/ERROR_NOT_FOUND,
    // whereas the documented success form is TRUE/ULONG(-1). Preserve both raw
    // results above; no other error is interpreted as absence.
    const bool absent = (child_ok && child == MAXDWORD) ||
        (!child_ok && child_error == ERROR_NOT_FOUND);
    std::cout << "no_child_reported=" << absent << '\n';
    return enabled_ok && absent;
}

bool get_child_property(ITypeInfo* type, IUnknown* settings, unsigned index) {
    const std::string prefix = "control_" + std::to_string(index);
    LPOLESTR member_name = const_cast<LPOLESTR>(L"Property");
    MEMBERID member = MEMBERID_NIL;
    HRESULT hr = type->GetIDsOfNames(&member_name, 1, &member);
    result(prefix + "_property_member", hr);
    if (FAILED(hr)) return false;
    Variant argument;
    argument.value.vt = VT_BSTR;
    argument.value.bstrVal = SysAllocString(L"ConnectToChildSession");
    require(argument.value.bstrVal != nullptr, "SysAllocString failed");
    DISPPARAMS parameters{};
    parameters.rgvarg = &argument.value;
    parameters.cArgs = 1;
    Variant output;
    ExceptionInfo exception;
    UINT bad_argument = 0;
    hr = type->Invoke(settings, member, DISPATCH_PROPERTYGET, &parameters,
        &output.value, &exception.value, &bad_argument);
    result(prefix + "_connect_to_child_get", hr);
    std::cout << prefix << "_connect_to_child_vartype=" << output.value.vt << '\n';
    if (FAILED(hr)) {
        std::cout << prefix << "_connect_to_child_exception="
                  << static_cast<std::uint32_t>(exception.value.scode) << '\n';
        return false;
    }
    require(output.value.vt == VT_BOOL, "ConnectToChildSession returned non-BOOL VARIANT");
    std::cout << prefix << "_connect_to_child_value=" << (output.value.boolVal != VARIANT_FALSE) << '\n';
    return true;
}

bool controls() {
    const OleApartment apartment;
    result("ole_initialize", apartment.status);
    if (FAILED(apartment.status)) return false;
    const GUID extended_iid = guid(L"{302D8188-0052-4807-806A-362B628F9AC5}");
    const GUID input_iid = guid(L"{4606850E-76A7-4E28-A47E-C7174F619351}");
    std::array<wchar_t, MAX_PATH + 1> directory{};
    const UINT length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
    require(length > 0 && length < directory.size(), "GetSystemDirectoryW failed");
    const std::wstring library_path = std::wstring(directory.data(), length) + L"\\mstscax.dll";
    ComPtr<ITypeLib> library;
    HRESULT hr = LoadTypeLibEx(library_path.c_str(), REGKIND_NONE, library.out());
    result("rdp_typelib_load", hr);
    ComPtr<ITypeInfo> extended_type;
    if (SUCCEEDED(hr)) {
        hr = library->GetTypeInfoOfGuid(extended_iid, extended_type.out());
        result("extended_typeinfo", hr);
    }
    struct Control { const wchar_t* clsid; const wchar_t* progid; };
    const std::array<Control, 3> classes{{
        {L"{A0C63C30-F08D-4AB4-907C-34905D770C7D}", L"MsRdpClient10NotSafeForScripting"},
        {L"{8B918B82-7985-4C24-89DF-C33AD2BBFBCD}", L"MsRdpClient9NotSafeForScripting"},
        {L"{A3BC03A0-041D-42E3-AD22-882B7865C9C5}", L"MsRdpClient8NotSafeForScripting"}
    }};
    bool available = false;
    for (unsigned index = 0; index < classes.size(); ++index) {
        const std::string prefix = "control_" + std::to_string(index);
        const GUID clsid = guid(classes[index].clsid);
        const std::wstring registry_key = std::wstring(classes[index].progid) + L"\\CLSID";
        std::array<wchar_t, 64> registered{};
        DWORD bytes = static_cast<DWORD>(registered.size() * sizeof(wchar_t));
        const LSTATUS registry_status = RegGetValueW(HKEY_CLASSES_ROOT, registry_key.c_str(), nullptr,
            RRF_RT_REG_SZ, nullptr, registered.data(), &bytes);
        std::cout << prefix << "_progid_query_error=" << registry_status << '\n';
        if (registry_status == ERROR_SUCCESS) {
            GUID registered_id{};
            const HRESULT parsed = CLSIDFromString(registered.data(), &registered_id);
            std::cout << prefix << "_progid_matches_clsid="
                      << (SUCCEEDED(parsed) && IsEqualGUID(registered_id, clsid)) << '\n';
        }
        ComPtr<IUnknown> object;
        hr = CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER, IID_IUnknown,
            reinterpret_cast<void**>(object.out()));
        result(prefix + "_create", hr);
        if (FAILED(hr)) continue;
        ComPtr<IUnknown> extended;
        hr = object->QueryInterface(extended_iid, reinterpret_cast<void**>(extended.out()));
        result(prefix + "_extended_query", hr);
        if (SUCCEEDED(hr) && extended_type.get()) {
            const bool property_ok = get_child_property(extended_type.get(), extended.get(), index);
            available = available || property_ok;
        }
        ComPtr<IUnknown> sink;
        hr = object->QueryInterface(input_iid, reinterpret_cast<void**>(sink.out()));
        result(prefix + "_input_sink_query", hr);
        ComPtr<IOleObject> ole;
        hr = object->QueryInterface(IID_IOleObject, reinterpret_cast<void**>(ole.out()));
        result(prefix + "_ole_object_query", hr);
        if (SUCCEEDED(hr)) result(prefix + "_close", ole->Close(OLECLOSE_NOSAVE));
    }
    return available;
}

} // namespace

int main() {
    try {
        std::cout << "PROBE_KIND=READ_ONLY_SESSION_ENVIRONMENT\n";
        const bool system = system_info();
        const bool environment = session_environment();
        const bool queries = child_queries();
        const bool com = controls();
        const bool available = system && environment && queries && com;
        std::cout << "CAPABILITY_PREFLIGHT=" << (available ? "AVAILABLE" : "UNAVAILABLE")
                  << "\nCHILD_SESSION_CREATION=NOT_ATTEMPTED"
                  << "\nINDEPENDENT_USERS=NOT_TESTED"
                  << "\nPHYSICAL_MULTISEAT=NOT_TESTED"
                  << "\nSYSTEM_CONFIGURATION=UNCHANGED\n";
        return available ? 0 : 77;
    } catch (const std::exception& error) {
        std::cerr << "PROBE_FAILURE=" << error.what() << '\n';
        return 1;
    }
}
