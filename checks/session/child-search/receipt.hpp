#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace child_search {
constexpr std::size_t HeaderBytes = 72;
constexpr std::size_t MaximumSidBytes = 68;
constexpr std::size_t MaximumReceiptBytes = HeaderBytes + 2 * MaximumSidBytes;
struct Receipt {
    std::uint32_t parent{}, child{}, console{};
    std::uint64_t issued{}, expires{};
    std::uint32_t parent_sid_bytes{}, child_sid_bytes{};
    std::array<unsigned char, 24> nonce{};
    std::array<unsigned char, MaximumSidBytes> parent_sid{}, child_sid{};
};
enum class ReceiptError : unsigned { none, size, magic, version, sessions, lifetime, expired, sid_size, same_sid, zero_nonce };
inline std::uint32_t read32(const unsigned char* data) noexcept {
    return std::uint32_t(data[0]) | (std::uint32_t(data[1]) << 8) | (std::uint32_t(data[2]) << 16) | (std::uint32_t(data[3]) << 24);
}
inline std::uint64_t read64(const unsigned char* data) noexcept {
    return std::uint64_t(read32(data)) | (std::uint64_t(read32(data + 4)) << 32);
}
inline bool sid_shape(const unsigned char* value, std::size_t bytes) noexcept {
    return bytes >= 8 && bytes <= MaximumSidBytes && value[0] == 1 && value[1] <= 15 && bytes == 8U + 4U * value[1];
}
inline ReceiptError decode(const unsigned char* data, std::size_t bytes, std::uint64_t now, Receipt& output) noexcept {
    if (!data || bytes < HeaderBytes + 16 || bytes > MaximumReceiptBytes) return ReceiptError::size;
    if (std::memcmp(data, "CHSEARCH", 8) != 0) return ReceiptError::magic;
    if (read32(data + 8) != 1) return ReceiptError::version;
    Receipt value;
    value.parent = read32(data + 12); value.child = read32(data + 16); value.console = read32(data + 20);
    if (!value.parent || !value.child || value.parent == value.child || value.console != value.parent ||
        value.parent == 0xffffffffU || value.child == 0xffffffffU) return ReceiptError::sessions;
    value.issued = read64(data + 24); value.expires = read64(data + 32);
    if (value.issued < 946684800 || value.issued > 4102444800 || value.expires != value.issued + 90) return ReceiptError::lifetime;
    if (now < value.issued || now >= value.expires) return ReceiptError::expired;
    value.parent_sid_bytes = read32(data + 40); value.child_sid_bytes = read32(data + 44);
    if (value.parent_sid_bytes < 8 || value.parent_sid_bytes > MaximumSidBytes || value.child_sid_bytes < 8 ||
        value.child_sid_bytes > MaximumSidBytes || bytes != HeaderBytes + value.parent_sid_bytes + value.child_sid_bytes ||
        !sid_shape(data + HeaderBytes, value.parent_sid_bytes) ||
        !sid_shape(data + HeaderBytes + value.parent_sid_bytes, value.child_sid_bytes)) return ReceiptError::sid_size;
    std::memcpy(value.nonce.data(), data + 48, value.nonce.size());
    bool nonzero = false; for (auto byte : value.nonce) nonzero = nonzero || byte != 0;
    if (!nonzero) return ReceiptError::zero_nonce;
    std::memcpy(value.parent_sid.data(), data + HeaderBytes, value.parent_sid_bytes);
    std::memcpy(value.child_sid.data(), data + HeaderBytes + value.parent_sid_bytes, value.child_sid_bytes);
    if (value.parent_sid_bytes == value.child_sid_bytes &&
        std::memcmp(value.parent_sid.data(), value.child_sid.data(), value.parent_sid_bytes) == 0) return ReceiptError::same_sid;
    output = value; return ReceiptError::none;
}
} // namespace child_search
