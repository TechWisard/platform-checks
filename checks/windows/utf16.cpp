#include "common.hpp"

#include <array>
#include <vector>

namespace {

template<class Action>
void rejected(Action&& action) {
    bool threw = false;
    try { action(); }
    catch (const std::runtime_error&) { threw = true; }
    check::require(threw, "Invalid input was accepted");
}

void roundtrip(const std::wstring& input) {
    const auto converted = check::utf8(input);
    if (input.empty()) {
        check::require(converted.empty(), "Empty conversion changed length");
        return;
    }
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        converted.data(), static_cast<int>(converted.size()), nullptr, 0);
    check::require(length > 0, "Converted result is not strict UTF-8");
    std::wstring restored(static_cast<std::size_t>(length), L'\0');
    check::require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, converted.data(),
        static_cast<int>(converted.size()), restored.data(), length) == length,
        "Reverse conversion failed");
    check::require(restored == input, "UTF-16 round trip changed input");
}

} // namespace

int main() {
    return check::run("utf16", [] {
        check::require(check::bounded_wide(nullptr, 0).empty(), "Null string is not empty");
        const wchar_t terminated[]{L'a', L'\0', L'b'};
        check::require(check::bounded_wide(terminated, 3) == L"a", "String bound ignored terminator");
        const wchar_t unterminated[]{L'a', L'b'};
        rejected([&] { (void)check::bounded_wide(unterminated, 2); });
        rejected([&] { (void)check::bounded_wide(terminated, 0); });
        rejected([] { (void)check::utf8(std::wstring(check::max_chars + 1, L'x')); });
        rejected([] { (void)check::utf8(std::wstring(1, static_cast<wchar_t>(0xd800))); });
        rejected([] { (void)check::utf8(std::wstring(1, static_cast<wchar_t>(0xdc00))); });
        rejected([] { (void)check::utf8(std::wstring{static_cast<wchar_t>(0xd800), L'a'}); });
        roundtrip(L"");
        roundtrip(L"plain text");
        roundtrip(std::wstring{L'a', L'\0', L'b'});
        roundtrip(std::wstring{static_cast<wchar_t>(0x0416), static_cast<wchar_t>(0x4e2d),
            static_cast<wchar_t>(0xd83d), static_cast<wchar_t>(0xde00)});
        roundtrip(std::wstring(check::max_chars, L'x'));
        std::uint32_t state = 0x7284ba31u;
        for (unsigned iteration = 0; iteration < 1000; ++iteration) {
            std::wstring input;
            for (unsigned index = 0; index < iteration % 64; ++index) {
                state = state * 1664525u + 1013904223u;
                auto point = state % 0x110000u;
                if (point >= 0xd800u && point <= 0xdfffu) point = 0x20u;
                if (point <= 0xffffu) input.push_back(static_cast<wchar_t>(point));
                else {
                    point -= 0x10000u;
                    input.push_back(static_cast<wchar_t>(0xd800u + (point >> 10)));
                    input.push_back(static_cast<wchar_t>(0xdc00u + (point & 0x3ffu)));
                }
            }
            roundtrip(input);
        }
        std::cout << "generated_roundtrips=1000 invalid_cases=6\n";
    });
}
