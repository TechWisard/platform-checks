#include "fragment.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace {
std::size_t checks = 0;
std::size_t skips = 0;

void require(bool condition, const char* description) {
    ++checks;
    if (!condition) throw std::runtime_error(description);
}

template<class Function>
void rejects(const Function& action, const char* description) {
    bool rejected = false;
    try { action(); }
    catch (const fragments::Error&) { rejected = true; }
    require(rejected, description);
}

struct FixtureDirectory {
    std::filesystem::path path;
    FixtureDirectory() {
        const auto token = std::chrono::steady_clock::now().time_since_epoch().count();
        for (unsigned int attempt = 0; attempt < 64; ++attempt) {
            path = std::filesystem::temp_directory_path() /
                ("bounded-input-check-" + std::to_string(token) + "-" + std::to_string(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(path, error)) {
#ifndef _WIN32
                if (::chmod(path.c_str(), 0700) != 0) throw std::runtime_error("fixture directory permissions");
#endif
                return;
            }
            if (error && error != std::errc::file_exists) throw std::runtime_error("fixture directory creation");
        }
        throw std::runtime_error("fixture directory collision limit");
    }
    ~FixtureDirectory() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
    FixtureDirectory(const FixtureDirectory&) = delete;
    FixtureDirectory& operator=(const FixtureDirectory&) = delete;
};

void write_fixture(const std::filesystem::path& path, const std::string& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    file.close();
    if (!file) throw std::runtime_error("fixture file write");
}

void json_checks() {
    using fragments::json_escape;
    require(json_escape("") == "\"\"", "empty JSON string");
    require(json_escape("simple ASCII") == "\"simple ASCII\"", "ASCII preservation");
    require(json_escape("\"\\") == "\"\\\"\\\\\"", "quotes and backslash");
    require(json_escape(std::string("\0\n\r\t\x1b\x7f", 6)) ==
            "\"\\u0000\\u000a\\u000d\\u0009\\u001b\\u007f\"", "control characters");
    const std::vector<std::string> valid{
        "\xC2\x80", "\xDF\xBF", "\xE0\xA0\x80", "\xED\x9F\xBF",
        "\xEE\x80\x80", "\xEF\xBF\xBF", "\xF0\x90\x80\x80", "\xF4\x8F\xBF\xBF"
    };
    for (const auto& bytes : valid) require(json_escape(bytes) == '"' + bytes + '"', "valid UTF-8 boundary");
    require(json_escape("\x80") == "\"\\u0080\"", "isolated continuation byte");
    require(json_escape("\xC0\xAF") == "\"\\u00c0\\u00af\"", "overlong UTF-8 sequence");
    require(json_escape("\xED\xA0\x80") == "\"\\u00ed\\u00a0\\u0080\"", "surrogate UTF-8 sequence");
    require(json_escape("\xF4\x90\x80\x80") == "\"\\u00f4\\u0090\\u0080\\u0080\"", "out-of-range UTF-8 sequence");
    require(json_escape("\xE2\x82") == "\"\\u00e2\\u0082\"", "truncated UTF-8 sequence");
    require(json_escape("\xE2\x28\xA1") == "\"\\u00e2(\\u00a1\"", "bad UTF-8 continuation");
}

void input_checks() {
    FixtureDirectory fixture;
    const auto file = fixture.path / "input.bin";
    const auto input = file.u8string();
    rejects([] { fragments::read_file_bounded("", 64); }, "empty filename rejected");
    rejects([&] { fragments::read_file_bounded(input + std::string("\0suffix", 7), 64); }, "embedded NUL rejected");
    rejects([&] { fragments::read_file_bounded(input, 64); }, "missing file rejected");
    rejects([&] { fragments::read_file_bounded(fixture.path.u8string(), 64); }, "directory rejected");
    write_fixture(file, "");
    require(fragments::read_file_bounded(input, 0).empty(), "empty file with zero limit");
    for (const std::size_t size : {std::size_t{1}, std::size_t{8191}, std::size_t{8192}, std::size_t{8193}, std::size_t{32769}}) {
        std::string bytes(size, '\0');
        for (std::size_t i = 0; i < size; ++i) bytes[i] = static_cast<char>(i % 256);
        write_fixture(file, bytes);
        require(fragments::read_file_bounded(input, size) == bytes, "exact size bound accepts binary bytes");
        require(fragments::read_file_bounded(input, size + 1) == bytes, "larger bound preserves binary bytes");
        rejects([&] { fragments::read_file_bounded(input, size - 1); }, "size bound rejects excessive file");
    }
    write_fixture(file, "small");
    require(fragments::read_file_bounded(input, std::numeric_limits<std::size_t>::max()) == "small", "maximum bound with small input");
    const auto unicode_file = fixture.path / std::filesystem::u8path(u8"sample-\u00e9-\u4e2d.bin");
    write_fixture(unicode_file, "unicode path");
    require(fragments::read_file_bounded(unicode_file.u8string(), 12) == "unicode path", "UTF-8 filename roundtrip");
    const auto link = fixture.path / "link.bin";
    std::error_code link_error;
    std::filesystem::create_symlink(file, link, link_error);
    if (!link_error) {
        rejects([&] { fragments::read_file_bounded(link.u8string(), 64); }, "symlink or reparse point rejected");
    } else {
#ifdef _WIN32
        if (link_error.value() != ERROR_PRIVILEGE_NOT_HELD && link_error != std::errc::permission_denied &&
            link_error != std::errc::operation_not_permitted && link_error != std::errc::operation_not_supported)
            throw std::runtime_error("unexpected symlink fixture creation error");
        ++skips;
        std::cout << "SKIP: symlink fixture unavailable under Windows token policy\n";
#else
        throw std::runtime_error("symlink fixture creation error");
#endif
    }
#ifdef _WIN32
    for (const std::string& path : std::vector<std::string>{"NUL", "nul.txt", "CON", "con ", "CONIN$", "CONOUT$",
             "AUX.bin", "PRN", "COM1", "com9.txt", "LPT1", "LPT9.bin", "\\\\.\\NUL",
             "\\\\.\\pipe\\synthetic-test", "\\\\?\\GLOBALROOT\\Device\\Null", "\\??\\NUL"})
        rejects([&] { fragments::read_file_bounded(path, 64); }, "reserved Windows path rejected");
#else
    const auto fifo = fixture.path / "input.fifo";
    require(::mkfifo(fifo.c_str(), 0600) == 0, "FIFO fixture creation");
    rejects([&] { fragments::read_file_bounded(fifo.u8string(), 64); }, "FIFO rejected without waiting for writer");
    rejects([] { fragments::read_file_bounded("/dev/null", 64); }, "character device rejected");
#endif
}

int hex_digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

int encode_lines() {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.size() > 131072 || line.size() % 2 != 0) return 2;
        std::string bytes;
        bytes.reserve(line.size() / 2);
        for (std::size_t i = 0; i < line.size(); i += 2) {
            const int high = hex_digit(line[i]);
            const int low = hex_digit(line[i + 1]);
            if (high < 0 || low < 0) return 2;
            bytes += static_cast<char>(high * 16 + low);
        }
        std::cout << fragments::json_escape(bytes) << '\n';
    }
    return std::cin.eof() && std::cout ? 0 : 1;
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--encode-lines") return encode_lines();
        if (argc != 1) return 64;
        json_checks();
        input_checks();
        std::cout << "PASS: " << checks << " fragment assertions; " << skips << " skipped capability checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
