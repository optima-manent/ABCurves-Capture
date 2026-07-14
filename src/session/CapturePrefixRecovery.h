#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace abdc::session {

enum class RecoveredArtifactState {
    FinalAlreadyPresent,
    VerifiedPrefixPublished,
    UnverifiedBytesPreserved,
    Missing,
};

[[nodiscard]] const char* ToString(RecoveredArtifactState state) noexcept;

struct RecoveredArtifact {
    std::string kind;
    RecoveredArtifactState state = RecoveredArtifactState::Missing;
    std::filesystem::path published_path;
    std::filesystem::path unverified_path;
    std::uint64_t original_bytes = 0;
    std::uint64_t retained_bytes = 0;
    std::uint64_t record_count = 0;
    std::string detail;
};

struct CapturePrefixRecoveryResult {
    std::vector<RecoveredArtifact> artifacts;
    std::uint64_t warning_count = 0;
    bool any_verified_source = false;
    bool any_unverified_bytes = false;
};

// Converts helper-owned partials into sealable artifacts after an interrupted
// or destructive stop. Only incomplete tails are trimmed. A checksum/header
// violation preserves the original bytes under an .unverified name and is
// described in capture/recovery.json.
[[nodiscard]] CapturePrefixRecoveryResult RecoverCapturePrefix(
    const std::filesystem::path& absolute_capture_directory);

}  // namespace abdc::session
