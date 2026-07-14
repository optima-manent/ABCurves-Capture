#pragma once

#include "platform/ClockAnchor.h"
#include "session/ClockJournal.h"
#include "session/FailurePolicy.h"
#include "session/GameplayJournal.h"
#include "session/SessionArchive.h"
#include "session/SessionValidator.h"
#include "session/SessionWorkspace.h"
#include "trainer/TrainerEngine.h"

#include <cstdint>
#include <exception>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace abdc::session {

// This is deliberately a privacy-safe, post-certification identity. It does
// not contain a Windows device path, serial number, machine name, or USBPcap
// root path. Production discovery owns the mapping from its private handles to
// selection_token and must report a real identity change through the capture
// control snapshot.
struct LockedMouseIdentity final {
    std::string selection_token;
    std::string display_name;
    std::uint16_t vendor_id = 0;
    std::uint16_t product_id = 0;
    std::uint16_t usb_bus = 0;
    std::uint16_t usb_device = 0;
    std::uint8_t interrupt_in_endpoint = 0;
    std::string hid_descriptor_sha256;
    bool operator==(const LockedMouseIdentity&) const = default;
};

struct CaptureStartRequest final {
    std::filesystem::path capture_directory;
    // External to the .partial workspace so it survives atomic publication.
    // Both the participant and elevated helper hold a shared OS handle.
    std::filesystem::path session_lease;
    LockedMouseIdentity locked_mouse;
    std::int64_t qpc_frequency = 0;
};

struct RecordingCaptureCounters final {
    std::uint64_t source_bytes = 0;
    std::uint64_t raw_pcap_records = 0;
    std::uint64_t decoded_reports = 0;
    std::uint64_t anomaly_count = 0;
    std::uint64_t queue_overflow_events = 0;
    std::uint64_t bytes_discarded = 0;
    bool operator==(const RecordingCaptureCounters&) const = default;
};

// ready means the certified USB device address is open and raw capture is
// writable. stop_complete means the helper has finished all publication work.
// A fatal issue is sticky and must identify a FailurePolicy destructive issue.
struct RecordingCaptureSnapshot final {
    bool ready = false;
    bool running = false;
    bool stop_requested = false;
    bool stop_complete = false;
    bool clean_stop = false;
    // The stop deadline elapsed and the helper could not be proven exited.
    // Capture artifacts must remain partial while a writer may still exist.
    bool shutdown_failed = false;
    std::uint32_t helper_pid = 0;
    std::optional<RuntimeIssue> fatal_issue;
    std::string detail;
    RecordingCaptureCounters counters;
};

// UI, process elevation, named pipes, and the actual helper are outside this
// interface. This keeps the scientific session lifecycle deterministic and
// hardware-free in tests. Implementations must make Snapshot thread-safe.
class IRecordingCaptureControl {
public:
    virtual ~IRecordingCaptureControl() = default;
    virtual void BeginCapture(const CaptureStartRequest& request) = 0;
    virtual void RequestStop() = 0;
    [[nodiscard]] virtual RecordingCaptureSnapshot Snapshot() const = 0;
};

struct RawInputSource final {
    // Tokens are privacy-safe application identities, never Windows device
    // paths. selected_device is advisory until it also matches the locked
    // post-certification token.
    bool selected_device = false;
    std::string device_token;
    std::uint32_t button_flags = 0;
    std::int32_t button_data = 0;
};

struct RecordingSessionOptions final {
    SessionCreateOptions workspace;
    trainer::TrainerConfig trainer;
    LockedMouseIdentity locked_mouse;

    // Optional application-produced, privacy-safe certification document.
    // Runtime native paths and Raw Input handles are forbidden upstream; the
    // session layer nests this under the independently validated locked route.
    json::Value certification_metadata;

    // Used only for a technically interrupted target that never reached a
    // successful presentation acknowledgement. Such events also carry
    // presentation_interrupted=true and no first_presented_qpc.
    RenderEvidence unpresented_render_calibration;

    bool retain_raw_input_witness = true;

    // Zero selects two seconds in the configured QPC domain. Checkpoints flush
    // existing anchors; callers add deterministic anchors with AddClockAnchor.
    std::int64_t checkpoint_interval_ticks = 0;
};

enum class RecordingSessionState {
    AwaitingCaptureReady,
    Recording,
    Paused,
    StopRequested,
    Finalizing,
    Finalized,
    FinalizationFailed,
};

[[nodiscard]] const char* ToString(RecordingSessionState state) noexcept;

struct RecordingSessionResult final {
    bool success = false;
    bool recovery_was_required = false;
    bool verified_authoritative_source = false;
    SessionStatus status = SessionStatus::Interrupted;
    std::uint64_t raw_pcap_records = 0;
    std::uint64_t decoded_reports = 0;
    std::uint64_t gameplay_events = 0;
    std::uint64_t gameplay_blocks = 0;
    std::uint64_t warning_count = 0;
    std::string stop_reason;
    std::string error;
    std::optional<SessionSealResult> seal;
    std::optional<ValidatedSession> validation;
    std::optional<SessionArchiveResult> archive;
};

[[nodiscard]] std::string ValidateRecordingSessionOptions(
    const RecordingSessionOptions& options);
[[nodiscard]] json::Value SanitizedMouseIdentityJson(
    const LockedMouseIdentity& identity);

// Single-thread-affine application-independent lifecycle coordinator. The
// injected capture implementation may run concurrently, but all methods on
// RecordingSession itself are called by the application/session thread.
class RecordingSession final {
public:
    static std::unique_ptr<RecordingSession> Create(
        RecordingSessionOptions options,
        IRecordingCaptureControl& capture);

    ~RecordingSession();
    RecordingSession(const RecordingSession&) = delete;
    RecordingSession& operator=(const RecordingSession&) = delete;

    // Returns false without changing trainer state while capture is still
    // preparing. A fatal snapshot transitions directly to safe stopping.
    [[nodiscard]] bool TryStart(std::int64_t qpc);

    void AdvanceTo(std::int64_t qpc);
    void SubmitRawInput(const trainer::RawInputPacket& packet,
                        const RawInputSource& source);
    [[nodiscard]] bool AcknowledgeTargetPresented(
        std::int64_t first_presented_qpc,
        const RenderEvidence& render);

    void SetFocus(bool focused, bool minimized, std::int64_t qpc);
    void ManualPause(std::int64_t qpc);
    [[nodiscard]] bool ManualResume(std::int64_t qpc);
    // Resumes a pause created by a recovered display/graphics/suspend issue.
    // The application calls this only after all UI environment blockers clear.
    [[nodiscard]] bool ResumeAfterRecoverableIssue(std::int64_t qpc,
                                                   std::string reason);

    // Applies FailurePolicy exactly once for this report. Optional witness and
    // timing issues only append metadata; destructive issues never retry.
    void ReportIssue(RuntimeIssue issue, std::int64_t qpc, std::string detail);

    void AddClockAnchor(const platform::ClockAnchor& anchor);
    void SampleClockAnchor(std::string source);
    void Checkpoint(std::int64_t qpc);

    // User cancellation is sealable but interrupted. Normal protocol
    // completion is detected automatically by AdvanceTo.
    void RequestParticipantStop(std::int64_t qpc,
                                std::string reason = "participant_cancelled");

    // Returns false while a requested capture stop is still draining. Once an
    // attempt begins it is never retried automatically; inspect Result().
    [[nodiscard]] bool TryFinalize(std::int64_t qpc,
                                   std::int64_t ended_utc_ns);

    [[nodiscard]] RecordingSessionState state() const noexcept { return state_; }
    [[nodiscard]] const RecordingSessionOptions& options() const noexcept {
        return options_;
    }
    [[nodiscard]] const trainer::TrainerEngine& trainer() const noexcept {
        return trainer_;
    }
    [[nodiscard]] const std::filesystem::path& WorkspacePath() const noexcept {
        return workspace_.Path();
    }
    [[nodiscard]] const std::filesystem::path& CaptureDirectory() const noexcept {
        return workspace_.CaptureDirectory();
    }
    [[nodiscard]] std::uint64_t JournaledEventCount() const noexcept {
        return journaled_event_count_;
    }
    [[nodiscard]] std::uint64_t JournaledBlockCount() const noexcept {
        return journaled_block_count_;
    }
    [[nodiscard]] std::uint64_t WarningCount() const noexcept {
        return warning_count_;
    }
    [[nodiscard]] const std::optional<RecordingSessionResult>& Result() const noexcept {
        return result_;
    }

private:
    RecordingSession(RecordingSessionOptions options,
                     IRecordingCaptureControl& capture,
                     SessionWorkspace workspace);

    [[nodiscard]] std::optional<std::int64_t> CurrentEventId() const noexcept;
    [[nodiscard]] std::optional<std::size_t> CurrentBlockOrdinal() const noexcept;
    void RequireTimelineQpc(std::int64_t qpc) const;
    void ObserveCapture(std::int64_t qpc);
    void DrainFinalizedTrainerRecords();
    void MaybeCheckpoint(std::int64_t qpc);
    void AppendIssueAnnotation(RuntimeIssue issue,
                               std::int64_t qpc,
                               const std::string& detail);
    void BeginStop(SessionStatus status,
                   std::int64_t qpc,
                   std::string reason,
                   bool recover_capture_prefix);
    void BeginDestructiveStop(RuntimeIssue issue,
                              std::int64_t qpc,
                              const std::string& detail);
    void HandleIntegrityFailure(std::int64_t qpc,
                                const std::exception& error);
    void HandleStorageFailure(std::int64_t qpc, const std::exception& error);
    [[nodiscard]] bool CaptureCanFinalize(
        const RecordingCaptureSnapshot& snapshot) const noexcept;

    RecordingSessionOptions options_;
    IRecordingCaptureControl& capture_;
    SessionWorkspace workspace_;
    GameplayJournal gameplay_;
    ClockJournal clocks_;
    trainer::TrainerEngine trainer_;

    RecordingSessionState state_ = RecordingSessionState::AwaitingCaptureReady;
    std::int64_t checkpoint_interval_ticks_ = 0;
    std::int64_t next_checkpoint_qpc_ = 0;
    std::size_t next_event_to_journal_ = 0;
    std::size_t next_block_to_journal_ = 0;
    std::uint64_t journaled_event_count_ = 0;
    std::uint64_t journaled_block_count_ = 0;
    std::uint64_t warning_count_ = 0;
    bool capture_begin_called_ = false;
    bool stop_forwarded_ = false;
    bool recover_capture_prefix_ = false;
    bool capture_fatal_observed_ = false;
    bool storage_failed_ = false;
    bool focused_ = true;
    bool minimized_ = false;
    SessionStatus requested_status_ = SessionStatus::Interrupted;
    std::string stop_reason_;
    std::string failure_detail_;
    RenderEvidence current_render_calibration_;
    std::unordered_map<std::int64_t, RenderEvidence> event_render_evidence_;
    std::optional<RecordingSessionResult> result_;
};

}  // namespace abdc::session
