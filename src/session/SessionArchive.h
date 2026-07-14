#pragma once

#include "session/SessionValidator.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace abdc::session {

struct SessionArchiveResult {
    std::filesystem::path path;
    std::string sha256;
    std::uint64_t size_bytes = 0;
    std::uint32_t member_count = 0;
};

struct SessionArchiveValidation {
    bool valid = false;
    std::string error;
    std::optional<ValidatedSession> session;
};

[[nodiscard]] std::filesystem::path SubmissionArchivePath(
    const std::filesystem::path& sealed_session_directory);

// Creates a canonical, deterministic ZIP containing one top-level session
// directory. Members use standard streaming Deflate when it saves space and
// automatically fall back to stored ZIP members when compression is unavailable
// or ineffective. Session bytes and checksums remain unchanged after extraction.
[[nodiscard]] SessionArchiveResult CreateSessionArchive(
    const std::filesystem::path& sealed_session_directory,
    const std::filesystem::path& output_archive);

// Accepts both the current Deflate profile and legacy stored submission ZIPs,
// extracts into a private temporary directory, then runs the normal sealed-
// session validator.
[[nodiscard]] SessionArchiveValidation ValidateSessionArchive(
    const std::filesystem::path& archive);

}  // namespace abdc::session
