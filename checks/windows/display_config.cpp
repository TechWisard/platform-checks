#include "common.hpp"

#include <set>
#include <tuple>
#include <vector>

namespace {

void status(LONG result, const char* operation) {
    if (result == ERROR_NOT_SUPPORTED) {
        throw check::Skipped{"No compatible WDDM display configuration", static_cast<DWORD>(result)};
    }
    if (result == ERROR_ACCESS_DENIED) {
        throw check::Skipped{"Console desktop is unavailable to this process", static_cast<DWORD>(result)};
    }
    if (result != ERROR_SUCCESS) check::win_error(operation, static_cast<DWORD>(result));
}

check::Counts query() {
    std::vector<DISPLAYCONFIG_PATH_INFO> paths;
    std::vector<DISPLAYCONFIG_MODE_INFO> modes;
    bool complete = false;
    for (unsigned attempt = 0; attempt < check::attempts; ++attempt) {
        UINT32 path_count = 0;
        UINT32 mode_count = 0;
        status(GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &path_count, &mode_count),
            "GetDisplayConfigBufferSizes");
        if (path_count == 0) return {};
        check::require(path_count <= check::max_records && mode_count <= check::max_records * 4,
            "Topology exceeds record bound");
        paths.resize(path_count);
        modes.resize(std::max<UINT32>(mode_count, 1));
        const auto result = QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, &path_count, paths.data(),
            &mode_count, modes.data(), nullptr);
        if (result == ERROR_INSUFFICIENT_BUFFER) continue;
        status(result, "QueryDisplayConfig");
        check::require(path_count <= paths.size() && mode_count <= modes.size(), "Invalid returned counts");
        paths.resize(path_count);
        modes.resize(mode_count);
        complete = true;
        break;
    }
    check::require(complete, "Topology changed during all bounded attempts");
    std::set<std::tuple<LONG, DWORD, UINT32>> targets;
    for (const auto& path : paths) {
        check::require((path.flags & DISPLAYCONFIG_PATH_ACTIVE) != 0, "Inactive path in active result");
        check::require(targets.emplace(path.targetInfo.adapterId.HighPart,
            path.targetInfo.adapterId.LowPart, path.targetInfo.id).second, "Duplicate active target");
        if (path.sourceInfo.modeInfoIdx != DISPLAYCONFIG_PATH_MODE_IDX_INVALID) {
            check::require(path.sourceInfo.modeInfoIdx < modes.size(), "Source mode index is out of bounds");
            const auto& mode = modes[path.sourceInfo.modeInfoIdx];
            check::require(mode.infoType == DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE, "Source index has wrong mode type");
            check::require(mode.sourceMode.width > 0 && mode.sourceMode.height > 0, "Source mode has zero dimensions");
        }
        if (path.targetInfo.modeInfoIdx != DISPLAYCONFIG_PATH_MODE_IDX_INVALID) {
            check::require(path.targetInfo.modeInfoIdx < modes.size(), "Target mode index is out of bounds");
            check::require(modes[path.targetInfo.modeInfoIdx].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_TARGET,
                "Target index has wrong mode type");
        }
        DISPLAYCONFIG_TARGET_DEVICE_NAME target{};
        target.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
        target.header.size = static_cast<UINT32>(sizeof(target));
        target.header.adapterId = path.targetInfo.adapterId;
        target.header.id = path.targetInfo.id;
        status(DisplayConfigGetDeviceInfo(&target.header), "DisplayConfigGetDeviceInfo");
        (void)check::utf8(check::bounded_wide(target.monitorDevicePath, std::size(target.monitorDevicePath)));
        (void)check::utf8(check::bounded_wide(target.monitorFriendlyDeviceName, std::size(target.monitorFriendlyDeviceName)));
    }
    return {paths.size(), modes.size()};
}

} // namespace

int main() {
    return check::run("display_config", [] { check::repeat(query); });
}
