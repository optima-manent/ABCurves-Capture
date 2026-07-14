#pragma once

#include "session/SessionWorkspace.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace abdc::session {

enum class AbandonedRecoveryState {
    Recovered,
    SkippedActiveWriter,
    Failed,
};

struct AbandonedSessionRecoveryResult final {
    AbandonedRecoveryState state = AbandonedRecoveryState::Failed;
    std::filesystem::path partial_workspace;
    std::filesystem::path sealed_session;
    std::filesystem::path archive;
    SessionStatus status = SessionStatus::Interrupted;
    bool verified_authoritative_source = false;
    std::uint64_t raw_pcap_records = 0;
    std::uint64_t decoded_reports = 0;
    std::uint64_t gameplay_events = 0;
    std::uint64_t warning_count = 0;
    std::string detail;
};

// Acquires the workspace's exclusive OS lease before inspecting or mutating it.
// Complete framed records survive; only incomplete tails are trimmed. A lease
// held by either writer returns SkippedActiveWriter. Legacy/unleased, unsafe,
// or corrupt workspaces are not automatically trusted. The root scan also
// finishes the missing SEND_THIS archive of an already immutable sealed
// session, without rewriting its scientific manifest or status.
[[nodiscard]] AbandonedSessionRecoveryResult RecoverAbandonedSession(
    const std::filesystem::path& partial_workspace,
    std::int64_t ended_utc_ns);

[[nodiscard]] std::vector<AbandonedSessionRecoveryResult>
RecoverAbandonedSessions(const std::filesystem::path& sessions_root,
                         std::int64_t ended_utc_ns);

}  // namespace abdc::session
