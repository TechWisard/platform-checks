#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace fragments {
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
std::string json_escape(std::string_view text);
std::string read_file_bounded(const std::string& path, std::size_t limit);
} // namespace fragments
