#include "receipt.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
using child_search::ReceiptError;
constexpr std::uint64_t Now = 1793232000;
void check(bool value) { if (!value) throw std::runtime_error("receipt_contract_failed"); }
void put32(std::vector<unsigned char>& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) bytes.at(offset + index) = static_cast<unsigned char>(value >> (index * 8));
}
void put64(std::vector<unsigned char>& bytes, std::size_t offset, std::uint64_t value) {
    put32(bytes, offset, static_cast<std::uint32_t>(value)); put32(bytes, offset + 4, static_cast<std::uint32_t>(value >> 32));
}
std::vector<unsigned char> fixture() {
    std::vector<unsigned char> bytes(128);
    std::memcpy(bytes.data(), "CHSEARCH", 8); put32(bytes, 8, 1);
    put32(bytes, 12, 2); put32(bytes, 16, 1); put32(bytes, 20, 2);
    put64(bytes, 24, Now); put64(bytes, 32, Now + 90);
    put32(bytes, 40, 28); put32(bytes, 44, 28); bytes[48] = 1;
    for (std::size_t offset : {std::size_t(72), std::size_t(100)}) {
        bytes[offset] = 1; bytes[offset + 1] = 5; bytes[offset + 7] = 5;
        put32(bytes, offset + 8, 21); put32(bytes, offset + 12, 100); put32(bytes, offset + 16, 200); put32(bytes, offset + 20, 300);
    }
    put32(bytes, 72 + 24, 1000); put32(bytes, 100 + 24, 1001);
    return bytes;
}
ReceiptError decode(const std::vector<unsigned char>& bytes, std::uint64_t now = Now) {
    child_search::Receipt value; return child_search::decode(bytes.data(), bytes.size(), now, value);
}
} // namespace
int main() {
    unsigned passed{};
    auto base = fixture();
    child_search::Receipt value;
    check(child_search::decode(base.data(), base.size(), Now, value) == ReceiptError::none);
    check(value.parent == 2 && value.child == 1 && value.console == 2 && value.issued == Now && value.expires == Now + 90 &&
        value.parent_sid_bytes == 28 && value.child_sid_bytes == 28 && value.nonce[0] == 1); ++passed;
    for (std::size_t length = 0; length < base.size(); ++length)
        check(child_search::decode(base.data(), length, Now, value) != ReceiptError::none);
    auto extra = base; extra.push_back(0); check(decode(extra) != ReceiptError::none);
    check(child_search::decode(nullptr, base.size(), Now, value) == ReceiptError::size); ++passed;
    for (std::uint32_t session : {0U, 1U, 0xffffffffU}) {
        auto invalid = base; put32(invalid, 12, session); check(decode(invalid) == ReceiptError::sessions);
    }
    for (std::uint32_t session : {0U, 2U, 0xffffffffU}) {
        auto invalid = base; put32(invalid, 16, session); check(decode(invalid) == ReceiptError::sessions);
    }
    auto wrong_console = base; put32(wrong_console, 20, 3); check(decode(wrong_console) == ReceiptError::sessions); ++passed;
    check(decode(base, Now - 1) == ReceiptError::expired);
    check(decode(base, Now + 89) == ReceiptError::none); check(decode(base, Now + 90) == ReceiptError::expired);
    auto wrong_lifetime = base; put64(wrong_lifetime, 32, Now + 91); check(decode(wrong_lifetime) == ReceiptError::lifetime);
    auto wrong_issued = base; put64(wrong_issued, 24, UINT64_MAX); check(decode(wrong_issued) == ReceiptError::lifetime); ++passed;
    for (std::size_t offset : {std::size_t(40), std::size_t(44)}) for (std::uint32_t length : {0U, 7U, 9U, 69U, 0xffffffffU}) {
        auto invalid = base; put32(invalid, offset, length); check(decode(invalid) == ReceiptError::sid_size);
    }
    for (std::size_t offset : {std::size_t(72), std::size_t(100)}) {
        auto invalid = base; invalid[offset] = 2; check(decode(invalid) == ReceiptError::sid_size);
        invalid = base; invalid[offset + 1] = 16; check(decode(invalid) == ReceiptError::sid_size);
    }
    auto same_sid = base; std::memcpy(same_sid.data() + 100, same_sid.data() + 72, 28); check(decode(same_sid) == ReceiptError::same_sid); ++passed;
    auto zero_nonce = base; zero_nonce[48] = 0; check(decode(zero_nonce) == ReceiptError::zero_nonce);
    auto magic = base; magic[0] = 0; check(decode(magic) == ReceiptError::magic);
    auto version = base; put32(version, 8, 2); check(decode(version) == ReceiptError::version); ++passed;
    // A rejected parse must not replace an earlier validated receipt.
    value.parent = 777; check(child_search::decode(zero_nonce.data(), zero_nonce.size(), Now, value) == ReceiptError::zero_nonce);
    check(value.parent == 777); ++passed;
    std::cout << "{\"schema\":\"child-search-receipt-tests/v1\",\"passed\":" << passed
        << ",\"failed\":0,\"native_helper_executed\":false,\"acl_or_identity_verified\":false}\n";
}
