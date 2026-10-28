#include "common.hpp"

#include <set>
#include <vector>

namespace {

std::string device_path(HANDLE device) {
    UINT chars = 0;
    if (GetRawInputDeviceInfoW(device, RIDI_DEVICENAME, nullptr, &chars) == static_cast<UINT>(-1)) {
        check::win_error("GetRawInputDeviceInfoW(size)", GetLastError());
    }
    for (unsigned attempt = 0; attempt < check::attempts; ++attempt) {
        check::require(chars != 0 && chars <= check::max_chars, "Raw Input identity size is invalid");
        std::vector<wchar_t> buffer(static_cast<std::size_t>(chars) + 1, L'\0');
        UINT capacity = static_cast<UINT>(buffer.size());
        if (GetRawInputDeviceInfoW(device, RIDI_DEVICENAME, buffer.data(), &capacity) != static_cast<UINT>(-1)) {
            const auto result = check::utf8(check::bounded_wide(buffer.data(), buffer.size()));
            check::require(!result.empty(), "Raw Input identity is empty");
            return result;
        }
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) check::win_error("GetRawInputDeviceInfoW(data)", error);
        chars = capacity;
    }
    throw std::runtime_error("Raw Input identity changed during all bounded attempts");
}

check::Counts query() {
    std::vector<RAWINPUTDEVICELIST> list;
    bool complete = false;
    for (unsigned attempt = 0; attempt < check::attempts; ++attempt) {
        UINT count = 0;
        if (GetRawInputDeviceList(nullptr, &count, sizeof(RAWINPUTDEVICELIST)) == static_cast<UINT>(-1)) {
            check::win_error("GetRawInputDeviceList(size)", GetLastError());
        }
        if (count == 0) return {};
        check::require(count <= check::max_records, "Raw Input record bound exceeded");
        list.resize(count);
        const UINT found = GetRawInputDeviceList(list.data(), &count, sizeof(RAWINPUTDEVICELIST));
        if (found == static_cast<UINT>(-1)) {
            const DWORD error = GetLastError();
            if (error == ERROR_INSUFFICIENT_BUFFER) continue;
            check::win_error("GetRawInputDeviceList(data)", error);
        }
        check::require(found <= list.size(), "Raw Input returned an invalid count");
        list.resize(found);
        complete = true;
        break;
    }
    check::require(complete, "Raw Input list changed during all bounded attempts");
    std::set<std::pair<DWORD, std::string>> paths;
    for (const auto& device : list) {
        check::require(device.dwType == RIM_TYPEKEYBOARD || device.dwType == RIM_TYPEMOUSE ||
            device.dwType == RIM_TYPEHID, "Unknown Raw Input record type");
        if (device.dwType != RIM_TYPEKEYBOARD && device.dwType != RIM_TYPEMOUSE) continue;
        check::require(paths.emplace(device.dwType, device_path(device.hDevice)).second, "Duplicate Raw Input identity");
        RID_DEVICE_INFO info{};
        info.cbSize = static_cast<DWORD>(sizeof(info));
        UINT size = static_cast<UINT>(sizeof(info));
        const UINT found = GetRawInputDeviceInfoW(device.hDevice, RIDI_DEVICEINFO, &info, &size);
        if (found == static_cast<UINT>(-1)) check::win_error("GetRawInputDeviceInfoW(info)", GetLastError());
        check::require(found <= sizeof(info) && info.dwType == device.dwType, "Raw Input details disagree with list");
    }
    return {list.size(), paths.size()};
}

} // namespace

int main() {
    return check::run("raw_input", [] { check::repeat(query); });
}
