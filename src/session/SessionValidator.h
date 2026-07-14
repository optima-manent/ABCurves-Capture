#pragma once

#include "session/SessionWorkspace.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace abdc::session {

struct ValidatedSession {
    std::string session_id;
    SessionStatus status = SessionStatus::Interrupted;
    std::uint64_t total_artifact_bytes = 0;
    std::vector<SessionArtifact> artifacts;
};

// Validates publication markers, manifest identity/status, the checksum-list
// digest, every listed artifact digest, and the absence of unlisted files or
// links. Throws on the first integrity or containment violation.
[[nodiscard]] ValidatedSession ValidateSealedSession(
    const std::filesystem::path& session_directory);

}  // namespace abdc::session
