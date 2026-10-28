#include "fragment.hpp"

#include <cstdint>
#include <filesystem>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fragments {
namespace {
#ifdef _WIN32
struct ReadHandle {
    HANDLE value;
    explicit ReadHandle(HANDLE handle) : value(handle) {}
    ~ReadHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    ReadHandle(const ReadHandle&) = delete;
    ReadHandle& operator=(const ReadHandle&) = delete;
};

bool special_windows_path(const std::filesystem::path& path) {
    auto value = path.native();
    for (auto& c : value) {
        if (c == L'/') c = L'\\';
        else if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>(c - L'a' + L'A');
    }
    if (value.rfind(L"\\\\.\\", 0) == 0 || value.rfind(L"\\??\\", 0) == 0) return true;
    if (value.rfind(L"\\\\?\\", 0) == 0) {
        if (value.size() >= 7 && value[4] >= L'A' && value[4] <= L'Z' && value[5] == L':' && value[6] == L'\\') {
            value.erase(0, 4); // Extended drive path; keep checking DOS device components.
        } else if (value.rfind(L"\\\\?\\UNC\\", 0) == 0) {
            value = L"\\\\" + value.substr(8);
        } else return true; // GLOBALROOT, physical devices and other namespaces.
    }
    std::size_t offset = value.size() >= 2 && value[1] == L':' ? 2 : 0;
    while (offset < value.size()) {
        const auto end = value.find(L'\\', offset);
        auto component = value.substr(offset, end == std::wstring::npos ? value.size() - offset : end - offset);
        component.resize(component.find_first_of(L".:") == std::wstring::npos ? component.size() : component.find_first_of(L".:"));
        while (!component.empty() && component.back() == L' ') component.pop_back();
        if (component == L"CON" || component == L"PRN" || component == L"AUX" || component == L"NUL" ||
            component == L"CONIN$" || component == L"CONOUT$" || component == L"CLOCK$") return true;
        if (component.size() == 4 && (component.compare(0, 3, L"COM") == 0 || component.compare(0, 3, L"LPT") == 0)) {
            const wchar_t number = component[3];
            if ((number >= L'1' && number <= L'9') || number == L'\u00b9' || number == L'\u00b2' || number == L'\u00b3') return true;
        }
        if (end == std::wstring::npos) break;
        offset = end + 1;
    }
    return false;
}
#else
struct ReadDescriptor {
    int value;
    explicit ReadDescriptor(int descriptor) : value(descriptor) {}
    ~ReadDescriptor() { if (value >= 0) ::close(value); }
    ReadDescriptor(const ReadDescriptor&) = delete;
    ReadDescriptor& operator=(const ReadDescriptor&) = delete;
};
#endif

} // namespace

std::string json_escape(std::string_view text) {
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(text.size() + 2);
    out += '"';
    for (std::size_t i = 0; i < text.size();) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); ++i; continue; }
        if (c < 32 || c == 127) {
            out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; ++i; continue;
        }
        if (c < 128) { out += static_cast<char>(c); ++i; continue; }
        std::size_t length = c >= 0xC2 && c <= 0xDF ? 2 : c >= 0xE0 && c <= 0xEF ? 3 : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
        bool valid = length != 0 && i + length <= text.size();
        if (valid) {
            for (std::size_t j = 1; j < length; ++j) {
                const auto next = static_cast<unsigned char>(text[i + j]);
                if (next < 0x80 || next > 0xBF) valid = false;
            }
            const auto second = static_cast<unsigned char>(text[i + 1]);
            if ((c == 0xE0 && second < 0xA0) || (c == 0xED && second > 0x9F) ||
                (c == 0xF0 && second < 0x90) || (c == 0xF4 && second > 0x8F)) valid = false;
        }
        if (valid) { out.append(text.substr(i, length)); i += length; }
        else { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; ++i; }
    }
    out += '"';
    return out;
}

std::string read_file_bounded(const std::string& path, std::size_t limit) {
    if (path.empty() || path.find('\0') != std::string::npos) throw Error("Invalid input filename.");
    const auto native_path = std::filesystem::u8path(path);
    std::string data;
    char buffer[8192];
#ifdef _WIN32
    if (special_windows_path(native_path)) throw Error("Special Windows device paths are not accepted as input files: " + path);
    ReadHandle file(CreateFileW(native_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) throw Error("Cannot open input file: " + path);
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileType(file.value) != FILE_TYPE_DISK || !GetFileInformationByHandle(file.value, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        throw Error("Input must be a regular file, not a directory, symlink or device: " + path);
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 0) throw Error("Cannot inspect input file size: " + path);
    if (static_cast<std::uint64_t>(size.QuadPart) > limit) throw Error("Input file exceeds the size limit.");
    data.reserve(static_cast<std::size_t>(size.QuadPart));
    for (;;) {
        DWORD count = 0;
        if (!ReadFile(file.value, buffer, static_cast<DWORD>(sizeof(buffer)), &count, nullptr)) {
            throw Error("Read failed: " + path);
        }
        if (count == 0) break;
        if (static_cast<std::size_t>(count) > limit - data.size()) throw Error("Input file exceeds the size limit.");
        data.append(buffer, static_cast<std::size_t>(count));
    }
#else
    ReadDescriptor file(::open(native_path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW));
    if (file.value < 0) throw Error("Cannot safely open input file: " + path + ": " + std::strerror(errno));
    struct stat info{};
    if (::fstat(file.value, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0) {
        throw Error("Input must be a regular file, not a directory, symlink or device: " + path);
    }
    if (static_cast<std::uint64_t>(info.st_size) > limit) throw Error("Input file exceeds the size limit.");
    data.reserve(static_cast<std::size_t>(info.st_size));
    for (;;) {
        const auto count = ::read(file.value, buffer, sizeof(buffer));
        if (count < 0) {
            if (errno == EINTR) continue;
            throw Error("Read failed: " + path + ": " + std::strerror(errno));
        }
        if (count == 0) break;
        if (static_cast<std::size_t>(count) > limit - data.size()) throw Error("Input file exceeds the size limit.");
        data.append(buffer, static_cast<std::size_t>(count));
    }
#endif
    return data;
}

} // namespace fragments
