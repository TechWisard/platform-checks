// Independent SetupAPI compatibility observation. No product code or driver.
#include <windows.h>
#include <setupapi.h>
#include <objbase.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iterator>

namespace {
constexpr GUID legacy_class{0x8ecc055d, 0x047f, 0x11d1,
    {0xa5, 0x37, 0x00, 0x00, 0xf8, 0x75, 0x3e, 0xd1}};
struct Call {
    bool attempted{};
    bool success{};
    DWORD error{};
    void save(BOOL value) noexcept {
        // Capture immediately: later logging/cleanup must not replace this code.
        attempted = true;
        success = value != FALSE;
        error = success ? ERROR_SUCCESS : GetLastError();
    }
};
struct Property {
    Call call;
    DWORD type{};
    DWORD bytes{};
    bool exact_service{};
    bool absent{};
    bool empty{};
    bool unbound() const noexcept { return absent || empty; }
};

bool same_id(HDEVINFO set, SP_DEVINFO_DATA& data, const wchar_t* expected) noexcept {
    std::array<wchar_t, 256> actual{};
    DWORD required{};
    if (!SetupDiGetDeviceInstanceIdW(set, &data, actual.data(),
            static_cast<DWORD>(actual.size()), &required)) return false;
    return required > 0 && required <= actual.size()
        && actual[required - 1] == L'\0' && _wcsicmp(actual.data(), expected) == 0;
}

Property read_service(HDEVINFO set, SP_DEVINFO_DATA& data, const wchar_t* service) noexcept {
    Property value;
    std::array<wchar_t, 256> buffer{};
    value.call.save(SetupDiGetDeviceRegistryPropertyW(set, &data, SPDRP_SERVICE,
        &value.type, reinterpret_cast<BYTE*>(buffer.data()),
        static_cast<DWORD>(sizeof(buffer)), &value.bytes));
    value.absent = !value.call.success && value.call.error == ERROR_INVALID_DATA;
    if (value.call.success && value.type == REG_SZ && value.bytes >= sizeof(wchar_t)
        && value.bytes <= sizeof(buffer) && value.bytes % sizeof(wchar_t) == 0) {
        const std::size_t chars = value.bytes / sizeof(wchar_t);
        value.empty = chars == 1 && buffer[0] == L'\0';
        value.exact_service = buffer[chars - 1] == L'\0'
            && chars == std::wcslen(service) + 1
            && std::wcscmp(buffer.data(), service) == 0;
    }
    return value;
}

// The only removable device is one created successfully by this process, whose
// full ID was checked after creation and again immediately before removal.
struct OwnedDevice {
    HDEVINFO set{INVALID_HANDLE_VALUE};
    SP_DEVINFO_DATA data{};
    std::array<wchar_t, 256> id{};
    bool created{};
    bool identity_verified{};
    bool registered{};
    bool cleanup_ran{};
    bool absent_after{};
    bool destroy_ok{true};
    bool reboot_required{};
    Call remove_parameters;
    Call remove_device;
    Call absence_query;

    OwnedDevice() noexcept { data.cbSize = sizeof(data); }
    OwnedDevice(const OwnedDevice&) = delete;
    OwnedDevice& operator=(const OwnedDevice&) = delete;
    ~OwnedDevice() { cleanup(); }

    void cleanup() noexcept {
        if (cleanup_ran) return;
        cleanup_ran = true;
        if (created && identity_verified && set != INVALID_HANDLE_VALUE
                && same_id(set, data, id.data())) {
            SP_REMOVEDEVICE_PARAMS removal{};
            removal.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
            removal.ClassInstallHeader.InstallFunction = DIF_REMOVE;
            removal.Scope = DI_REMOVEDEVICE_GLOBAL;
            remove_parameters.save(SetupDiSetClassInstallParamsW(set, &data,
                &removal.ClassInstallHeader, sizeof(removal)));
            if (remove_parameters.success) {
                remove_device.save(SetupDiCallClassInstaller(DIF_REMOVE, set, &data));
                SP_DEVINSTALL_PARAMS_W parameters{};
                parameters.cbSize = sizeof(parameters);
                if (SetupDiGetDeviceInstallParamsW(set, &data, &parameters))
                    reboot_required = (parameters.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0;
            }
        }
        if (set != INVALID_HANDLE_VALUE) {
            destroy_ok = SetupDiDestroyDeviceInfoList(set) != FALSE;
            set = INVALID_HANDLE_VALUE;
        }
        if (!created) {
            // Preflight never acquired ownership; do not remove anyone's node.
            return;
        }
        HDEVINFO fresh = SetupDiCreateDeviceInfoList(&legacy_class, nullptr);
        if (fresh == INVALID_HANDLE_VALUE) return;
        SP_DEVINFO_DATA found{};
        found.cbSize = sizeof(found);
        absence_query.save(SetupDiOpenDeviceInfoW(fresh, id.data(), nullptr, 0, &found));
        absent_after = !absence_query.success && absence_query.error == ERROR_NO_SUCH_DEVINST;
        if (!SetupDiDestroyDeviceInfoList(fresh)) destroy_ok = false;
    }

    bool clean() const noexcept {
        return cleanup_ran && (!created || absent_after) && destroy_ok && !reboot_required;
    }
};

void emit_call(const char* name, const Call& call) noexcept {
    std::printf("\"%s\":{\"attempted\":%s,\"success\":%s,\"error\":%lu}", name,
        call.attempted ? "true" : "false", call.success ? "true" : "false", call.error);
}
void emit_property(const char* name, const Property& value) noexcept {
    std::printf("\"%s\":{", name);
    emit_call("query", value.call);
    std::printf(",\"type\":%lu,\"bytes\":%lu,\"exact_service\":%s,\"absent\":%s,\"empty\":%s,\"unbound\":%s}",
        value.type, value.bytes, value.exact_service ? "true" : "false", value.absent ? "true" : "false",
        value.empty ? "true" : "false", value.unbound() ? "true" : "false");
}
void emit_ascii_wide(const wchar_t* text) noexcept {
    std::putchar('"');
    for (const wchar_t* at = text; *at; ++at) {
        if (*at == L'\\' || *at == L'"') std::putchar('\\');
        // Only the program's fixed ASCII prefixes and a generated GUID are used.
        std::putchar(*at >= 32 && *at < 127 ? static_cast<int>(*at) : '?');
    }
    std::putchar('"');
}

int run(bool consent) noexcept {
    OwnedDevice owned;
    Call elevation, service_absence, information_set, preexisting_node;
    Call creation, registration, config_flags, service_set, service_clear;
    Property before, after, cleared;
    bool nonce_ok{}, elevated{}, setter_observed{}, invariant_ok{true};
    std::array<wchar_t, 96> service{};
    const char* reason = consent ? "initialization" : "explicit_disposable_flag_required";
    if (consent) {
        HANDLE token{};
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION value{};
            DWORD bytes{};
            elevation.save(GetTokenInformation(token, TokenElevation, &value, sizeof(value), &bytes));
            elevated = elevation.success && bytes == sizeof(value) && value.TokenIsElevated != 0;
            if (!CloseHandle(token)) invariant_ok = false;
        } else elevation.save(FALSE);
    }
    if (consent && !elevated) reason = "elevated_disposable_runner_required";
    if (consent && elevated) {
        GUID nonce{};
        std::array<wchar_t, 40> formatted{};
        if (SUCCEEDED(CoCreateGuid(&nonce)) && StringFromGUID2(nonce, formatted.data(),
                static_cast<int>(formatted.size())) == 39) {
            std::array<wchar_t, 33> hex{};
            std::size_t n{};
            for (wchar_t ch : formatted) {
                if ((ch >= L'0' && ch <= L'9') || (ch >= L'A' && ch <= L'F')
                    || (ch >= L'a' && ch <= L'f')) {
                    if (n >= 32) { n = 0; break; }
                    hex[n++] = ch;
                }
            }
            if (n == 32) {
                nonce_ok = std::swprintf(owned.id.data(), owned.id.size(),
                    L"ROOT\\PLATFORM_CHECKS_ROOT_%ls\\0000", hex.data()) > 0
                    && std::swprintf(service.data(), service.size(),
                    L"PcRootProbe_%ls", hex.data()) > 0;
            }
        }
        if (!nonce_ok) reason = "unique_identity_generation_failed";
    }
    if (nonce_ok) {
        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (manager) {
            SC_HANDLE existing = OpenServiceW(manager, service.data(), SERVICE_QUERY_STATUS);
            const DWORD error = existing ? ERROR_SUCCESS : GetLastError();
            service_absence.attempted = true;
            service_absence.success = !existing && error == ERROR_SERVICE_DOES_NOT_EXIST;
            service_absence.error = service_absence.success ? ERROR_SUCCESS : error;
            if (existing && !CloseServiceHandle(existing)) invariant_ok = false;
            if (!CloseServiceHandle(manager)) invariant_ok = false;
        } else service_absence.save(FALSE);
        if (!service_absence.success) reason = "test_service_not_proven_absent";
    }
    if (service_absence.success) {
        owned.set = SetupDiCreateDeviceInfoList(&legacy_class, nullptr);
        information_set.save(owned.set != INVALID_HANDLE_VALUE);
        if (information_set.success) {
            preexisting_node.save(SetupDiOpenDeviceInfoW(owned.set, owned.id.data(), nullptr, 0, &owned.data));
            if (preexisting_node.success || preexisting_node.error != ERROR_NO_SUCH_DEVINST)
                reason = "test_node_not_proven_absent";
            else {
                creation.save(SetupDiCreateDeviceInfoW(owned.set, owned.id.data(),
                    &legacy_class, nullptr, nullptr, 0, &owned.data));
                owned.created = creation.success;
                if (!creation.success) reason = "create_rejected";
            }
        } else reason = "information_set_rejected";
    }
    if (owned.created) {
        owned.identity_verified = same_id(owned.set, owned.data, owned.id.data());
        if (!owned.identity_verified) {
            invariant_ok = false;
            reason = "created_identity_mismatch";
        } else {
            registration.save(SetupDiCallClassInstaller(DIF_REGISTERDEVICE, owned.set, &owned.data));
            owned.registered = registration.success;
            if (!registration.success) reason = "register_rejected";
        }
    }
    if (owned.registered) {
        const DWORD flags = 0;
        config_flags.save(SetupDiSetDeviceRegistryPropertyW(owned.set, &owned.data,
            SPDRP_CONFIGFLAGS, reinterpret_cast<const BYTE*>(&flags), sizeof(flags)));
        if (!config_flags.success) reason = "config_flags_rejected";
        before = read_service(owned.set, owned.data, service.data());
        // A node with an unexpected existing binding is never rewritten.
        if (!before.unbound()) {
            invariant_ok = false;
            reason = "unexpected_initial_service_property";
        } else if (config_flags.success) {
            const DWORD bytes = static_cast<DWORD>((std::wcslen(service.data()) + 1) * sizeof(wchar_t));
            service_set.save(SetupDiSetDeviceRegistryPropertyW(owned.set, &owned.data,
                SPDRP_SERVICE, reinterpret_cast<const BYTE*>(service.data()), bytes));
            setter_observed = true;
            after = read_service(owned.set, owned.data, service.data());
            reason = service_set.success ? "service_setter_accepted" : "service_setter_rejected";
            if (service_set.success != after.exact_service) invariant_ok = false;
            if (!service_set.success && (before.absent != after.absent || before.empty != after.empty)) invariant_ok = false;
            if (after.exact_service) {
                service_clear.save(SetupDiSetDeviceRegistryPropertyW(owned.set, &owned.data,
                    SPDRP_SERVICE, nullptr, 0));
                cleared = read_service(owned.set, owned.data, service.data());
                if (service_clear.success != cleared.unbound()) invariant_ok = false;
            }
        }
    }
    owned.cleanup();
    const bool verified = setter_observed && invariant_ok && owned.clean();
    const bool unavailable = !setter_observed && invariant_ok && owned.clean();
    const char* status = verified ? "observed" : (unavailable ? "unavailable" : "failed");
    std::printf("{\"schema\":\"root-device-property-observation/v1\",\"status\":\"%s\",\"reason\":\"%s\",", status, reason);
    std::printf("\"instance_id\":"); emit_ascii_wide(owned.id.data());
    std::printf(",\"temporary_service_name\":"); emit_ascii_wide(service.data());
    std::printf(",\"class_guid\":\"8ecc055d-047f-11d1-a537-0000f8753ed1\",\"pointer_bits\":%u,",
        static_cast<unsigned>(sizeof(void*) * 8));
    const char* names[]{"elevation", "test_service_absence", "information_set", "preexisting_node",
        "create", "register", "config_flags", "service_set", "service_clear"};
    const Call* calls[]{&elevation, &service_absence, &information_set, &preexisting_node,
        &creation, &registration, &config_flags, &service_set, &service_clear};
    for (std::size_t n = 0; n < std::size(calls); ++n) {
        if (n) std::putchar(',');
        emit_call(names[n], *calls[n]);
    }
    std::putchar(','); emit_property("before", before);
    std::putchar(','); emit_property("after", after);
    std::putchar(','); emit_property("cleared", cleared);
    std::putchar(','); emit_call("remove_parameters", owned.remove_parameters);
    std::putchar(','); emit_call("remove", owned.remove_device);
    std::putchar(','); emit_call("absence_query", owned.absence_query);
    std::printf(",\"identity_verified\":%s,\"owned_node_created\":%s,\"setter_observed\":%s,\"setter_accepted\":%s,"
        "\"cleanup_verified\":%s,\"node_absent_after\":%s,\"reboot_required\":%s,"
        "\"driver_package_added\":false,\"kernel_driver_service_created\":false,"
        "\"kernel_driver_load_requested\":false,\"class_filters_modified\":false,"
        "\"private_product_present\":false,\"native_multiseat_verified\":false}\n",
        owned.identity_verified ? "true" : "false", owned.created ? "true" : "false",
        setter_observed ? "true" : "false", service_set.success ? "true" : "false",
        owned.clean() ? "true" : "false", owned.absent_after ? "true" : "false",
        owned.reboot_required ? "true" : "false");
    return verified ? 0 : (unavailable ? 77 : 1);
}
} // namespace

int main(int argc, char** argv) {
    const bool explicit_scope = argc == 2 && std::strcmp(argv[1], "--disposable-root-probe") == 0;
    return run(explicit_scope);
}
