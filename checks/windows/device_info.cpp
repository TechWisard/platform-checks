#include "common.hpp"

#include <setupapi.h>

#include <set>
#include <vector>

namespace {

class InfoSet {
public:
    InfoSet() : value(SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES)) {
        if (value == INVALID_HANDLE_VALUE) check::win_error("SetupDiGetClassDevsW", GetLastError());
    }
    ~InfoSet() { SetupDiDestroyDeviceInfoList(value); }
    InfoSet(const InfoSet&) = delete;
    InfoSet& operator=(const InfoSet&) = delete;
    HDEVINFO value;
};

std::string instance_id(HDEVINFO set, SP_DEVINFO_DATA& device) {
    DWORD required = 0;
    if (!SetupDiGetDeviceInstanceIdW(set, &device, nullptr, 0, &required)) {
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) check::win_error("SetupDiGetDeviceInstanceIdW(size)", error);
    }
    for (unsigned attempt = 0; attempt < check::attempts; ++attempt) {
        check::require(required != 0 && required <= check::max_chars, "PnP identity size is invalid");
        std::vector<wchar_t> buffer(static_cast<std::size_t>(required) + 1, L'\0');
        if (SetupDiGetDeviceInstanceIdW(set, &device, buffer.data(), static_cast<DWORD>(buffer.size()), &required)) {
            const auto result = check::utf8(check::bounded_wide(buffer.data(), buffer.size()));
            check::require(!result.empty(), "PnP identity is empty");
            return result;
        }
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) check::win_error("SetupDiGetDeviceInstanceIdW(data)", error);
    }
    throw std::runtime_error("PnP identity changed during all bounded attempts");
}

bool description(HDEVINFO set, SP_DEVINFO_DATA& device) {
    DWORD required = 0;
    DWORD type = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_DEVICEDESC, &type, nullptr, 0, &required)) {
        const DWORD error = GetLastError();
        if (error == ERROR_INVALID_DATA || error == ERROR_NOT_FOUND) return false;
        if (error != ERROR_INSUFFICIENT_BUFFER) check::win_error("SetupDiGetDeviceRegistryPropertyW(size)", error);
    }
    for (unsigned attempt = 0; attempt < check::attempts; ++attempt) {
        if (required == 0) return false;
        check::require(required <= check::max_chars * sizeof(wchar_t) && required % sizeof(wchar_t) == 0,
            "Registry string size is invalid");
        std::vector<wchar_t> buffer(required / sizeof(wchar_t) + 1, L'\0');
        const DWORD capacity = static_cast<DWORD>((buffer.size() - 1) * sizeof(wchar_t));
        if (SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_DEVICEDESC, &type,
            reinterpret_cast<PBYTE>(buffer.data()), capacity, &required)) {
            check::require(type == REG_SZ || type == REG_EXPAND_SZ, "Description property has unexpected type");
            (void)check::utf8(check::bounded_wide(buffer.data(), buffer.size()));
            return true;
        }
        const DWORD error = GetLastError();
        if (error == ERROR_INVALID_DATA || error == ERROR_NOT_FOUND) return false;
        if (error != ERROR_INSUFFICIENT_BUFFER) check::win_error("SetupDiGetDeviceRegistryPropertyW(data)", error);
    }
    throw std::runtime_error("Registry description changed during all bounded attempts");
}

check::Counts query() {
    InfoSet set;
    std::set<std::string> identities;
    std::size_t descriptions = 0;
    for (DWORD index = 0; index < check::max_records; ++index) {
        SP_DEVINFO_DATA data{};
        data.cbSize = static_cast<DWORD>(sizeof(data));
        if (!SetupDiEnumDeviceInfo(set.value, index, &data)) {
            const DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) return {identities.size(), descriptions};
            check::win_error("SetupDiEnumDeviceInfo", error);
        }
        check::require(identities.insert(instance_id(set.value, data)).second, "Duplicate PnP identity");
        if (description(set.value, data)) ++descriptions;
    }
    throw std::runtime_error("PnP record bound exceeded");
}

} // namespace

int main() {
    return check::run("device_info", [] { check::repeat(query); });
}
