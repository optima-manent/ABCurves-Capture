#pragma once

#include "base/Json.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace abdc::session {

enum class SessionStatus {
    Recording,
    Complete,
    CompleteWithWarnings,
    Interrupted,
    CaptureLost,
};

[[nodiscard]] const char* ToString(SessionStatus status) noexcept;

struct SessionCreateOptions {
    std::filesystem::path output_root;
    std::string session_id;
    std::string user_id;
    std::string application_version;
    std::string source_revision;
    std::string protocol_id;
    std::string protocol_sha256;
    std::uint64_t scenario_seed = 0;
    double trainer_sensitivity = 1.0;
    std::int64_t qpc_frequency = 0;
    std::int64_t started_utc_ns = 0;
    json::Value device = json::Value::Object{};
    json::Value protocol_plan;
    json::Value presentation;
};

struct SessionSealOptions {
    SessionStatus status = SessionStatus::Complete;
    std::int64_t ended_utc_ns = 0;
    std::uint64_t raw_pcap_records = 0;
    std::uint64_t decoded_reports = 0;
    std::uint64_t gameplay_events = 0;
    std::uint64_t warning_count = 0;
    bool recovery_was_required = false;
    bool verified_authoritative_source = false;
    std::string stop_reason;
};

struct SessionArtifact {
    std::string relative_path;
    std::uint64_t size_bytes = 0;
    std::string sha256;
};

struct SessionSealResult {
    std::filesystem::path directory;
    SessionStatus status = SessionStatus::Interrupted;
    std::vector<SessionArtifact> artifacts;
    std::string checksum_list_sha256;
};

enum class SessionLeaseFailure {
    Missing,
    Busy,
    Invalid,
};

// OpenAbandoned reports lease failures separately so startup recovery can
// leave a live writer alone and route legacy/untrusted workspaces to manual
// review. No recovery inspection or mutation occurs before the exclusive
// lease has been acquired.
class SessionLeaseError final : public std::runtime_error {
public:
    SessionLeaseError(SessionLeaseFailure failure, std::string message);

    [[nodiscard]] SessionLeaseFailure failure() const noexcept {
        return failure_;
    }

private:
    SessionLeaseFailure failure_;
};

class SessionWorkspace final {
public:
    static SessionWorkspace Create(const SessionCreateOptions& options);
    static SessionWorkspace OpenAbandoned(
        const std::filesystem::path& partial_workspace);

    SessionWorkspace(SessionWorkspace&&) noexcept = default;
    SessionWorkspace& operator=(SessionWorkspace&&) noexcept = default;
    SessionWorkspace(const SessionWorkspace&) = delete;
    SessionWorkspace& operator=(const SessionWorkspace&) = delete;

    [[nodiscard]] const std::filesystem::path& Path() const noexcept { return path_; }
    [[nodiscard]] const std::filesystem::path& CaptureDirectory() const noexcept {
        return capture_directory_;
    }
    [[nodiscard]] const std::filesystem::path& GameplayDirectory() const noexcept {
        return gameplay_directory_;
    }
    [[nodiscard]] const std::filesystem::path& ClocksDirectory() const noexcept {
        return clocks_directory_;
    }
    [[nodiscard]] const std::filesystem::path& DerivedDirectory() const noexcept {
        return derived_directory_;
    }
    [[nodiscard]] const std::filesystem::path& LeasePath() const noexcept {
        return lease_path_;
    }

    void UpdateRuntimeSummary(std::uint64_t event_count,
                              std::uint64_t warning_count,
                              std::string detail);
    void UpdateCaptureHelperPid(std::uint32_t helper_pid);
    SessionSealResult Seal(const SessionSealOptions& options);
    // The normal participant calls this only after the canonical submission
    // archive has passed independent validation. Recovery workspaces retain
    // their exclusive lease until destruction instead.
    void ReleaseFinalizationLease();

private:
    SessionWorkspace(std::filesystem::path path,
                     std::filesystem::path lease_path,
                     std::shared_ptr<void> lease_handle,
                     bool exclusive_lease,
                     SessionCreateOptions options,
                     json::Value manifest);

    void PersistManifest();
    [[nodiscard]] std::vector<SessionArtifact> InventoryArtifacts() const;

    std::filesystem::path path_;
    std::filesystem::path capture_directory_;
    std::filesystem::path gameplay_directory_;
    std::filesystem::path clocks_directory_;
    std::filesystem::path derived_directory_;
    std::filesystem::path lease_path_;
    // The participant and helper each hold a shared Win32 lease. Recovery
    // holds an exclusive lease in this same slot through seal/archive work.
    std::shared_ptr<void> lease_handle_;
    bool exclusive_lease_ = false;
    SessionCreateOptions options_;
    json::Value manifest_;
    bool sealed_ = false;
};

[[nodiscard]] bool IsSafeSessionId(std::string_view value) noexcept;

}  // namespace abdc::session
