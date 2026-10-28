#include "common.hpp"

#include <wtsapi32.h>

#include <memory>
#include <set>

namespace {

struct SessionDeleter {
    void operator()(WTS_SESSION_INFOW* value) const noexcept { WTSFreeMemory(value); }
};

check::Counts query() {
    WTS_SESSION_INFOW* allocated = nullptr;
    DWORD count = 0;
    const BOOL result = WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &allocated, &count);
    const DWORD error = result ? ERROR_SUCCESS : GetLastError();
    std::unique_ptr<WTS_SESSION_INFOW, SessionDeleter> sessions(allocated);
    if (!result) check::win_error("WTSEnumerateSessionsW", error);
    check::require(count <= check::max_records && (count == 0 || sessions), "Invalid WTS result list");
    DWORD current_session = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &current_session)) {
        check::win_error("ProcessIdToSessionId", GetLastError());
    }
    bool found_current = false;
    std::set<DWORD> identities;
    std::size_t active = 0;
    for (DWORD index = 0; index < count; ++index) {
        const auto& session = sessions.get()[index];
        check::require(identities.insert(session.SessionId).second, "Duplicate WTS session identity");
        check::require(static_cast<unsigned>(session.State) <= static_cast<unsigned>(WTSInit),
            "Unknown WTS connection state");
        if (session.SessionId == current_session) found_current = true;
        if (session.State == WTSActive) ++active;
    }
    check::require(found_current, "WTS enumeration does not contain current process session");
    return {count, active};
}

} // namespace

int main() {
    return check::run("sessions", [] { check::repeat(query); });
}
