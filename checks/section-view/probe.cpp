// Independent Windows API diagnostic. Own anonymous memory only; no driver.
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstring>

namespace {
constexpr SIZE_T pageBytes = 4096;
using CreateSection = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PLARGE_INTEGER, ULONG, ULONG, HANDLE);
using MapSection = NTSTATUS (NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
using UnmapSection = NTSTATUS (NTAPI*)(HANDLE, PVOID);
using GetNativeVersion = NTSTATUS (NTAPI*)(PRTL_OSVERSIONINFOW);
template<class T> T resolve(HMODULE module, const char* name) {
    const FARPROC address = GetProcAddress(module, name);
    T result = nullptr;
    static_assert(sizeof(result) == sizeof(address), "Windows function pointer size");
    std::memcpy(&result, &address, sizeof(result));
    return result;
}
struct Api { CreateSection create; MapSection map; UnmapSection unmap; };
struct Result {
    const char* name = nullptr;
    const char* stage = "create";
    NTSTATUS status = 0;
    DWORD error = 0;
    bool mapped = false;
    bool initialRead = false;
    DWORD initialProtect = 0;
    bool rwAttempted = false;
    bool rwSucceeded = false;
    DWORD rwError = 0;
    bool rwSharedWrite = false;
    bool restored = false;
    bool clearVisible = false;
    bool handlesClosed = false;
    bool afterClose = false;
    bool producerUnmapped = false;
    bool afterProducerUnmap = false;
    bool consumerUnmapped = false;
    NTSTATUS cleanupStatus = 0;
    DWORD cleanupError = 0;
    bool cleanup = true;
    bool pass = false;
};
bool closeHandle(HANDLE& handle, DWORD& error) {
    if (!handle) return true;
    if (!CloseHandle(handle)) {
        const DWORD currentError = GetLastError();
        if (!error) error = currentError;
        return false;
    }
    handle = nullptr;
    return true;
}
bool unmap(const Api& api, PVOID& view, NTSTATUS& status) {
    if (!view) return true;
    const NTSTATUS currentStatus = api.unmap(GetCurrentProcess(), view);
    if (currentStatus != 0) { if (status == 0) status = currentStatus; return false; }
    view = nullptr;
    return true;
}
Result observe(const Api& api, const char* name, bool sectionReadOnly, bool reduceAccess) {
    Result r;
    r.name = name;
    HANDLE section = nullptr, readHandle = nullptr;
    PVOID producer = nullptr, consumer = nullptr;
    LARGE_INTEGER maximum{};
    maximum.QuadPart = static_cast<LONGLONG>(pageBytes);
    do {
        const ACCESS_MASK access = SECTION_MAP_READ | SECTION_QUERY |
            (sectionReadOnly ? 0UL : SECTION_MAP_WRITE);
        r.status = api.create(&section, access, nullptr, &maximum,
            sectionReadOnly ? PAGE_READONLY : PAGE_READWRITE, SEC_COMMIT, nullptr);
        if (r.status != 0) break;
        r.stage = "producer_map";
        SIZE_T bytes = pageBytes;
        r.status = api.map(section, GetCurrentProcess(), &producer, 0, 0, nullptr,
            &bytes, 2, 0, sectionReadOnly ? PAGE_READONLY : PAGE_READWRITE);
        if (r.status != 0 || bytes < pageBytes) break;
        auto* write = static_cast<volatile unsigned char*>(producer);
        if (!sectionReadOnly) write[37] = 0x31;
        HANDLE mapHandle = section;
        if (reduceAccess) {
            r.stage = "duplicate_read_handle";
            if (!DuplicateHandle(GetCurrentProcess(), section, GetCurrentProcess(),
                &readHandle, SECTION_MAP_READ, FALSE, 0)) { r.error = GetLastError(); break; }
            mapHandle = readHandle;
        }
        r.stage = "consumer_map";
        bytes = pageBytes;
        r.status = api.map(mapHandle, GetCurrentProcess(), &consumer, 0, 0, nullptr,
            &bytes, 2, 0, PAGE_READONLY);
        if (r.status != 0 || bytes < pageBytes) break;
        r.mapped = true;
        auto* read = static_cast<volatile unsigned char*>(consumer);
        r.initialRead = read[37] == (sectionReadOnly ? 0 : 0x31);
        MEMORY_BASIC_INFORMATION memory{};
        r.stage = "query_initial_protection";
        if (VirtualQuery(consumer, &memory, sizeof(memory)) != sizeof(memory)) {
            r.error = GetLastError(); break;
        }
        r.initialProtect = memory.Protect;
        DWORD previous = 0;
        SetLastError(ERROR_SUCCESS);
        r.rwAttempted = true;
        r.rwSucceeded = VirtualProtect(consumer, pageBytes, PAGE_READWRITE, &previous) != FALSE;
        r.rwError = r.rwSucceeded ? ERROR_SUCCESS : GetLastError();
        if (r.rwSucceeded) {
            read[37] = 0x5a;
            r.rwSharedWrite = write[37] == 0x5a;
            DWORD ignored = 0;
            r.restored = VirtualProtect(consumer, pageBytes, PAGE_READONLY, &ignored) != FALSE;
            if (!r.restored) { r.stage = "restore_readonly"; r.error = GetLastError(); break; }
        } else r.restored = true;
        if (!sectionReadOnly) write[37] = 0;
        r.clearVisible = read[37] == 0;
        r.stage = "close_section_handles";
        const bool readClosed = closeHandle(readHandle, r.error);
        const bool sectionClosed = closeHandle(section, r.error);
        r.handlesClosed = readClosed && sectionClosed;
        if (!r.handlesClosed) break;
        r.afterClose = read[37] == 0;
        r.stage = "unmap_producer";
        r.producerUnmapped = unmap(api, producer, r.status);
        if (!r.producerUnmapped) break;
        r.afterProducerUnmap = read[37] == 0;
        r.stage = "unmap_consumer";
        r.consumerUnmapped = unmap(api, consumer, r.status);
        if (!r.consumerUnmapped) break;
        r.pass = r.initialRead && r.initialProtect == PAGE_READONLY && r.restored &&
            r.clearVisible && r.afterClose && r.afterProducerUnmap &&
            (!sectionReadOnly || !r.rwSucceeded);
        r.stage = r.pass ? "complete" : "observation_mismatch";
    } while (false);
    const bool consumerClean = unmap(api, consumer, r.cleanupStatus);
    const bool producerClean = unmap(api, producer, r.cleanupStatus);
    const bool readClean = closeHandle(readHandle, r.cleanupError);
    const bool sectionClean = closeHandle(section, r.cleanupError);
    r.cleanup = consumerClean && producerClean && readClean && sectionClean;
    r.pass = r.pass && r.cleanup;
    return r;
}
const char* boolean(bool value) { return value ? "true" : "false"; }
void print(const Result& r) {
    std::printf("{\"name\":\"%s\",\"stage\":\"%s\",\"ntstatus\":\"0x%08lx\",\"win32_error\":%lu,"
        "\"mapped\":%s,\"initial_shared_read\":%s,\"initial_protection\":%lu,"
        "\"rw_attempted\":%s,\"rw_succeeded\":%s,\"rw_error\":%lu,\"rw_shared_write\":%s,"
        "\"readonly_restored\":%s,\"clear_visible\":%s,\"handles_closed\":%s,"
        "\"view_after_handles_closed\":%s,\"producer_unmapped\":%s,"
        "\"view_after_producer_unmapped\":%s,\"consumer_unmapped\":%s,\"cleanup_ntstatus\":\"0x%08lx\",\"cleanup_error\":%lu,\"cleanup\":%s,\"pass\":%s}",
        r.name, r.stage, static_cast<unsigned long>(r.status), r.error,
        boolean(r.mapped), boolean(r.initialRead), r.initialProtect,
        boolean(r.rwAttempted), boolean(r.rwSucceeded), r.rwError, boolean(r.rwSharedWrite),
        boolean(r.restored), boolean(r.clearVisible), boolean(r.handlesClosed),
        boolean(r.afterClose), boolean(r.producerUnmapped), boolean(r.afterProducerUnmap),
        boolean(r.consumerUnmapped), static_cast<unsigned long>(r.cleanupStatus), r.cleanupError, boolean(r.cleanup), boolean(r.pass));
}
} // namespace
int main() {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 2;
    const Api api{resolve<CreateSection>(ntdll, "NtCreateSection"),
        resolve<MapSection>(ntdll, "NtMapViewOfSection"), resolve<UnmapSection>(ntdll, "NtUnmapViewOfSection")};
    const GetNativeVersion version = resolve<GetNativeVersion>(ntdll, "RtlGetVersion");
    RTL_OSVERSIONINFOW os{};
    os.dwOSVersionInfoSize = sizeof(os);
    if (!api.create || !api.map || !api.unmap || !version || version(&os) != 0) return 2;
    const Result results[] = {observe(api, "rw_section_full_handle", false, false),
        observe(api, "rw_section_read_handle", false, true),
        observe(api, "ro_section_read_handle", true, true)};
    std::printf("{\"schema\":\"windows.section-view-observation.v1\",\"os\":{\"major\":%lu,\"minor\":%lu,\"build\":%lu},"
        "\"kernel_driver_executed\":false,\"observations\":[", os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber);
    bool pass = true;
    for (unsigned i = 0; i < 3; ++i) { if (i) std::printf(","); print(results[i]); pass = pass && results[i].pass; }
    std::printf("],\"pass\":%s}\n", boolean(pass));
    return pass ? 0 : 1;
}
