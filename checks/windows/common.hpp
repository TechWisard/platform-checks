#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>

namespace check {

inline constexpr unsigned attempts = 4;
inline constexpr std::size_t max_records = 4096;
inline constexpr std::size_t max_chars = 32768;

inline void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

[[noreturn]] inline void win_error(const char* operation, DWORD value) {
    throw std::runtime_error(std::string(operation) + " failed, code=" + std::to_string(value));
}

inline void hresult(HRESULT value, const char* operation) {
    if (FAILED(value)) {
        throw std::runtime_error(std::string(operation) + " failed, HRESULT=" +
            std::to_string(static_cast<std::uint32_t>(value)));
    }
}

inline std::wstring_view bounded_wide(const wchar_t* value, std::size_t capacity) {
    if (!value) return {};
    std::size_t length = 0;
    while (length < capacity && value[length] != L'\0') ++length;
    require(length != capacity, "Unterminated UTF-16 string");
    return {value, length};
}

inline std::string utf8(std::wstring_view value) {
    if (value.empty()) return {};
    require(value.size() <= max_chars, "UTF-16 input exceeds bound");
    const int length = static_cast<int>(value.size());
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), length, nullptr, 0, nullptr, nullptr);
    if (size <= 0) win_error("WideCharToMultiByte(size)", GetLastError());
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), length,
        result.data(), size, nullptr, nullptr) != size) {
        win_error("WideCharToMultiByte(data)", GetLastError());
    }
    return result;
}

struct Skipped {
    const char* reason;
    DWORD code;
};

inline DWORD handle_count() {
    DWORD count = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &count)) {
        win_error("GetProcessHandleCount", GetLastError());
    }
    return count;
}

struct Counts {
    std::size_t primary = 0;
    std::size_t secondary = 0;
};

// Repetition detects large linear handle growth, not every possible memory leak.
template<class Query>
void repeat(Query&& query) {
    for (unsigned iteration = 0; iteration < 3; ++iteration) (void)query();
    const DWORD baseline = handle_count();
    Counts observed{};
    constexpr unsigned repetitions = 24;
    for (unsigned iteration = 0; iteration < repetitions; ++iteration) {
        const auto counts = query();
        observed.primary = std::max(observed.primary, counts.primary);
        observed.secondary = std::max(observed.secondary, counts.secondary);
    }
    const DWORD final_count = handle_count();
    require(final_count <= baseline + 16, "Repeated queries grew process handles by more than 16");
    std::cout << "queries=" << repetitions << " max_count=" << observed.primary
              << " max_secondary_count=" << observed.secondary
              << " handles_before=" << baseline << " handles_after=" << final_count << '\n';
}

template<class Action>
int run(const char* name, Action&& action) {
    try {
        action();
        std::cout << "PASS " << name << '\n';
        return 0;
    } catch (const Skipped& skipped) {
        std::cout << "SKIP " << name << ": " << skipped.reason << "; code=" << skipped.code << '\n';
        return 77;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << name << ": " << error.what() << '\n';
        return 1;
    }
}

} // namespace check
