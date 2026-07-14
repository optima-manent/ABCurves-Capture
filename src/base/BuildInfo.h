#pragma once

#include "protocol/protocol_v1.hpp"

#include <iostream>
#include <string>
#include <string_view>

namespace abdc {

[[nodiscard]] inline bool IsVersionRequest(
    const int argc, wchar_t** const argv) noexcept {
    return argc == 2 && argv != nullptr && argv[1] != nullptr &&
           std::wstring_view(argv[1]) == L"--version";
}

[[nodiscard]] inline std::string BuildVersionLine(
    const std::string_view executable_name) {
    return std::string(executable_name) + " " + ABDC_VERSION +
           " protocol=" +
           std::to_string(protocol::V1Constants::protocol_version) +
           " source=" + ABDC_SOURCE_REVISION + "\n";
}

// A child process connected to a Windows text-mode pipe emits CRLF even
// though BuildVersionLine is represented with LF in memory. Accept exactly
// those two encodings; do not trim or otherwise weaken build identity.
[[nodiscard]] inline bool BuildVersionOutputMatches(
    const std::string_view actual,
    const std::string_view executable_name) {
    const auto expected_lf = BuildVersionLine(executable_name);
    if (actual == expected_lf) return true;
    auto expected_crlf = expected_lf;
    expected_crlf.insert(expected_crlf.size() - 1U, 1U, '\r');
    return actual == expected_crlf;
}

inline int PrintBuildVersion(const std::string_view executable_name) {
    std::cout << BuildVersionLine(executable_name);
    return std::cout ? 0 : 1;
}

}  // namespace abdc
