#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace abdc::session {

// Random grouping keys only: no username, SID, serial number, device path, or
// hardware fingerprint participates. A contributor may delete/reset the local
// participant file at any time.
[[nodiscard]] std::string LoadOrCreateParticipantId(
    const std::filesystem::path& settings_directory);
[[nodiscard]] std::string CreateSessionId();
[[nodiscard]] bool IsPseudonymousId(std::string_view value,
                                    std::string_view prefix) noexcept;

}  // namespace abdc::session
