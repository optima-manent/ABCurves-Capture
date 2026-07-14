#include "session/RecordingSession.h"

#include "session/CaptureArtifactValidation.h"
#include "session/CapturePrefixRecovery.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace abdc::session {
namespace {

constexpr std::size_t kMaximumDeviceNameBytes = 160U;
constexpr std::size_t kMaximumDetailBytes = 2'048U;

[[nodiscard]] bool IsSafeToken(const std::string_view value,
                               const std::size_t maximum = 128U) noexcept {
    if (value.empty() || value.size() > maximum) return false;
    return std::all_of(value.begin(), value.end(), [](const char character) {
        const auto c = static_cast<unsigned char>(character);
        return (c >= static_cast<unsigned char>('a') &&
                c <= static_cast<unsigned char>('z')) ||
               (c >= static_cast<unsigned char>('A') &&
                c <= static_cast<unsigned char>('Z')) ||
               (c >= static_cast<unsigned char>('0') &&
                c <= static_cast<unsigned char>('9')) ||
               c == static_cast<unsigned char>('-') ||
               c == static_cast<unsigned char>('_') ||
               c == static_cast<unsigned char>('.');
    });
}

[[nodiscard]] bool IsSafeDisplayName(const std::string_view value) noexcept {
    if (value.empty() || value.size() > kMaximumDeviceNameBytes) return false;
    return std::none_of(value.begin(), value.end(), [](const char character) {
        const auto c = static_cast<unsigned char>(character);
        return c == 0U || c < 0x20U || c == 0x7fU;
    });
}

[[nodiscard]] bool IsSha256(const std::string_view value) noexcept {
    return value.size() == 64U &&
        std::all_of(value.begin(), value.end(), [](const char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f') ||
                   (character >= 'A' && character <= 'F');
        });
}

[[nodiscard]] bool IsValidRenderEvidence(const RenderEvidence& render) noexcept {
    if (render.viewport_width_px <= 0 || render.viewport_height_px <= 0 ||
        render.viewport_width_px > 1'000'000 ||
        render.viewport_height_px > 1'000'000 ||
        !IsSafeToken(render.transform_revision) ||
        !std::isfinite(render.pixels_per_count_x) ||
        !std::isfinite(render.pixels_per_count_y) ||
        !std::isfinite(render.counts_per_pixel_x) ||
        !std::isfinite(render.counts_per_pixel_y) ||
        !std::isfinite(render.effective_radians_per_count) ||
        !std::isfinite(render.crosshair_scale) ||
        render.pixels_per_count_x <= 0.0 ||
        render.pixels_per_count_y <= 0.0 ||
        render.counts_per_pixel_x <= 0.0 ||
        render.counts_per_pixel_y <= 0.0) {
        return false;
    }
    if (render.effective_radians_per_count <= 0.0 ||
        render.crosshair_scale < 0.25 || render.crosshair_scale > 2.0) {
        return false;
    }
    const auto reciprocal = [](const double first, const double second) {
        const double product = first * second;
        return std::isfinite(product) &&
               std::abs(product - 1.0) <=
                   1.0e-9 * std::max(1.0, std::abs(product));
    };
    return reciprocal(render.pixels_per_count_x, render.counts_per_pixel_x) &&
           reciprocal(render.pixels_per_count_y, render.counts_per_pixel_y);
}

[[nodiscard]] std::string SafeDetail(std::string detail) {
    std::replace(detail.begin(), detail.end(), '\0', ' ');
    if (detail.size() > kMaximumDetailBytes) detail.resize(kMaximumDetailBytes);
    return detail;
}

[[nodiscard]] std::int64_t SaturatingAdd(const std::int64_t left,
                                         const std::int64_t right) noexcept {
    if (right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) {
        return std::numeric_limits<std::int64_t>::max();
    }
    return left + right;
}

[[nodiscard]] bool IsCaptureLossIssue(const RuntimeIssue issue) noexcept {
    switch (issue) {
    case RuntimeIssue::CaptureHelperLost:
    case RuntimeIssue::SelectedDeviceChanged:
    case RuntimeIssue::NativeQueueOverflow:
    case RuntimeIssue::CaptureBytesDiscarded:
    case RuntimeIssue::PcapFramingLost:
        return true;
    case RuntimeIssue::StorageWriteFailed:
    case RuntimeIssue::IntegrityFailed:
    case RuntimeIssue::RawInputUsbDifference:
    case RuntimeIssue::RawInputUnavailable:
    case RuntimeIssue::GameplayInputUnavailable:
    case RuntimeIssue::OtherMouseActivity:
    case RuntimeIssue::DecodeFailure:
    case RuntimeIssue::FailedUsbTransfer:
    case RuntimeIssue::PcapTimestampRegression:
    case RuntimeIssue::ClockFitUncertain:
    case RuntimeIssue::FrameStall:
    case RuntimeIssue::FocusLost:
    case RuntimeIssue::Minimized:
    case RuntimeIssue::DisplayChanged:
    case RuntimeIssue::GraphicsDeviceLost:
    case RuntimeIssue::SystemSuspend:
        return false;
    }
    return true;
}

[[nodiscard]] GameplayJournalIdentity JournalIdentity(
    const RecordingSessionOptions& options) {
    return {
        options.workspace.session_id,
        options.workspace.user_id,
        options.workspace.qpc_frequency,
        options.workspace.trainer_sensitivity,
    };
}

[[nodiscard]] CaptureArtifactIdentity CaptureIdentity(
    const RecordingSessionOptions& options) {
    return {
        options.locked_mouse.usb_bus,
        options.locked_mouse.usb_device,
        options.locked_mouse.interrupt_in_endpoint,
        options.locked_mouse.hid_descriptor_sha256,
        options.workspace.qpc_frequency,
    };
}

}  // namespace

const char* ToString(const RecordingSessionState state) noexcept {
    switch (state) {
    case RecordingSessionState::AwaitingCaptureReady:
        return "awaiting_capture_ready";
    case RecordingSessionState::Recording: return "recording";
    case RecordingSessionState::Paused: return "paused";
    case RecordingSessionState::StopRequested: return "stop_requested";
    case RecordingSessionState::Finalizing: return "finalizing";
    case RecordingSessionState::Finalized: return "finalized";
    case RecordingSessionState::FinalizationFailed: return "finalization_failed";
    }
    return "unknown";
}

json::Value SanitizedMouseIdentityJson(const LockedMouseIdentity& identity) {
    if (!IsSafeToken(identity.selection_token) ||
        !IsSafeDisplayName(identity.display_name) || identity.vendor_id == 0U ||
        identity.product_id == 0U || identity.usb_bus == 0U ||
        identity.usb_device == 0U ||
        (identity.interrupt_in_endpoint != 0U &&
         ((identity.interrupt_in_endpoint & 0x80U) == 0U ||
          (identity.interrupt_in_endpoint & 0x0fU) == 0U ||
          (identity.interrupt_in_endpoint & 0x70U) != 0U)) ||
        (!identity.hid_descriptor_sha256.empty() &&
         !IsSha256(identity.hid_descriptor_sha256))) {
        throw std::invalid_argument("locked mouse identity is invalid or not sanitized");
    }
    json::Value value = json::Value::Object{};
    value["identity_scope"] = "certified_usb_device";
    value["selection_token"] = identity.selection_token;
    value["display_name"] = identity.display_name;
    value["vendor_id"] = static_cast<std::int64_t>(identity.vendor_id);
    value["product_id"] = static_cast<std::int64_t>(identity.product_id);
    value["usb_bus"] = static_cast<std::int64_t>(identity.usb_bus);
    value["usb_device"] = static_cast<std::int64_t>(identity.usb_device);
    value["interrupt_in_endpoint"] =
        static_cast<std::int64_t>(identity.interrupt_in_endpoint);
    value["hid_descriptor_sha256"] = identity.hid_descriptor_sha256;
    value["privacy"] = "sanitized_no_serial_no_os_path";
    return value;
}

std::string ValidateRecordingSessionOptions(
    const RecordingSessionOptions& options) {
    try {
        (void)SanitizedMouseIdentityJson(options.locked_mouse);
    } catch (const std::exception& error) {
        return error.what();
    }
    if (!options.certification_metadata.IsNull()) {
        if (!std::holds_alternative<json::Value::Object>(
                options.certification_metadata.Data())) {
            return "certification metadata must be a JSON object";
        }
        try {
            if (json::DumpCanonical(options.certification_metadata, false).size() >
                64U * 1024U) {
                return "certification metadata exceeds its size bound";
            }
        } catch (const std::exception& error) {
            return error.what();
        }
    }
    if (!IsValidRenderEvidence(options.unpresented_render_calibration)) {
        return "unpresented-event render calibration is invalid";
    }
    if (options.workspace.qpc_frequency <= 0 ||
        options.trainer.qpc_frequency != options.workspace.qpc_frequency) {
        return "trainer and session QPC frequencies differ";
    }
    if (options.trainer.scenario_seed != options.workspace.scenario_seed) {
        return "trainer and session scenario seeds differ";
    }
    if (!std::isfinite(options.trainer.trainer_sensitivity) ||
        options.trainer.trainer_sensitivity !=
            options.workspace.trainer_sensitivity) {
        return "trainer and session sensitivity values differ";
    }
    if (options.checkpoint_interval_ticks < 0) {
        return "checkpoint interval cannot be negative";
    }
    if (options.workspace.qpc_frequency >
        std::numeric_limits<std::int64_t>::max() / 2LL &&
        options.checkpoint_interval_ticks == 0) {
        return "QPC frequency is too large for the default checkpoint interval";
    }
    return {};
}

RecordingSession::RecordingSession(RecordingSessionOptions options,
                                   IRecordingCaptureControl& capture,
                                   SessionWorkspace workspace)
    : options_(std::move(options)),
      capture_(capture),
      workspace_(std::move(workspace)),
      gameplay_(workspace_.GameplayDirectory(), JournalIdentity(options_)),
      clocks_(workspace_.ClocksDirectory(), options_.workspace.qpc_frequency),
      trainer_(options_.trainer),
      checkpoint_interval_ticks_(options_.checkpoint_interval_ticks == 0
          ? options_.workspace.qpc_frequency * 2LL
          : options_.checkpoint_interval_ticks),
      current_render_calibration_(options_.unpresented_render_calibration) {}

RecordingSession::~RecordingSession() {
    // An abandoned partial remains recoverable on the next launch, but the
    // helper must never be allowed to outlive its owning session object.
    if (capture_begin_called_ && !stop_forwarded_ &&
        state_ != RecordingSessionState::Finalized) {
        stop_forwarded_ = true;
        try {
            capture_.RequestStop();
        } catch (...) {
        }
    }
}

std::unique_ptr<RecordingSession> RecordingSession::Create(
    RecordingSessionOptions options,
    IRecordingCaptureControl& capture) {
    if (const auto error = ValidateRecordingSessionOptions(options);
        !error.empty()) {
        throw std::invalid_argument(error);
    }

    options.workspace.device = SanitizedMouseIdentityJson(options.locked_mouse);
    if (!options.certification_metadata.IsNull()) {
        options.workspace.device["certification"] =
            options.certification_metadata;
    }
    auto workspace = SessionWorkspace::Create(options.workspace);
    auto result = std::unique_ptr<RecordingSession>(
        new RecordingSession(std::move(options), capture, std::move(workspace)));

    CaptureStartRequest request;
    request.capture_directory = result->workspace_.CaptureDirectory();
    request.session_lease = result->workspace_.LeasePath();
    request.locked_mouse = result->options_.locked_mouse;
    request.qpc_frequency = result->options_.workspace.qpc_frequency;
    try {
        capture.BeginCapture(request);
        result->capture_begin_called_ = true;
        const auto snapshot = capture.Snapshot();
        if (snapshot.helper_pid != 0U) {
            result->workspace_.UpdateCaptureHelperPid(snapshot.helper_pid);
        }
    } catch (...) {
        try {
            capture.RequestStop();
        } catch (...) {
        }
        // The partial workspace is intentionally left discoverable by startup
        // recovery if an implementation started before reporting failure.
        throw;
    }
    return result;
}

std::optional<std::int64_t> RecordingSession::CurrentEventId() const noexcept {
    if (const auto* event = trainer_.current_event()) return event->event_id;
    if (const auto* target = trainer_.pending_target()) return target->event_id;
    return std::nullopt;
}

std::optional<std::size_t> RecordingSession::CurrentBlockOrdinal() const noexcept {
    if (const auto* block = trainer_.current_block()) return block->ordinal;
    return std::nullopt;
}

void RecordingSession::RequireTimelineQpc(const std::int64_t qpc) const {
    if (qpc < 0) throw std::invalid_argument("session timeline QPC is negative");
    if (trainer_.state() != trainer::EngineState::idle &&
        qpc < trainer_.now_qpc()) {
        throw std::logic_error("session timeline QPC regressed");
    }
}

void RecordingSession::AppendIssueAnnotation(const RuntimeIssue issue,
                                             const std::int64_t qpc,
                                             const std::string& detail) {
    LifecycleAnnotation annotation;
    annotation.qpc = qpc;
    annotation.name = "issue_" + std::string(ToString(issue));
    annotation.block_ordinal = CurrentBlockOrdinal();
    annotation.event_id = CurrentEventId();
    annotation.detail = SafeDetail(detail.empty()
        ? std::string(ToString(issue))
        : detail);
    gameplay_.AppendLifecycle(annotation);
}

void RecordingSession::HandleStorageFailure(const std::int64_t qpc,
                                            const std::exception& error) {
    if (storage_failed_ || state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed) {
        return;
    }
    storage_failed_ = true;
    ++warning_count_;
    recover_capture_prefix_ = true;
    requested_status_ = SessionStatus::Interrupted;
    stop_reason_ = "storage_write_failed";
    failure_detail_ = SafeDetail(error.what());

    try {
        if (trainer_.state() != trainer::EngineState::idle &&
            trainer_.state() != trainer::EngineState::paused &&
            trainer_.state() != trainer::EngineState::complete &&
            qpc >= trainer_.now_qpc()) {
            trainer_.Pause(qpc);
        }
    } catch (...) {
    }
    state_ = RecordingSessionState::StopRequested;
    if (!stop_forwarded_) {
        stop_forwarded_ = true;
        try {
            capture_.RequestStop();
        } catch (...) {
        }
    }
}

void RecordingSession::HandleIntegrityFailure(const std::int64_t qpc,
                                              const std::exception& error) {
    if (state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed ||
        state_ == RecordingSessionState::StopRequested) {
        return;
    }
    ++warning_count_;
    requested_status_ = SessionStatus::Interrupted;
    recover_capture_prefix_ = true;
    stop_reason_ = "runtime_integrity_failed";
    failure_detail_ = SafeDetail(error.what());
    try {
        gameplay_.AppendLifecycle({
            qpc,
            "runtime_integrity_failed",
            CurrentBlockOrdinal(),
            CurrentEventId(),
            failure_detail_,
        });
    } catch (const std::exception& storage_error) {
        HandleStorageFailure(qpc, storage_error);
        return;
    }
    state_ = RecordingSessionState::StopRequested;
    if (!stop_forwarded_) {
        stop_forwarded_ = true;
        try {
            capture_.RequestStop();
        } catch (const std::exception& capture_error) {
            requested_status_ = SessionStatus::CaptureLost;
            stop_reason_ = "capture_stop_request_failed";
            failure_detail_ = SafeDetail(capture_error.what());
        }
    }
}

void RecordingSession::BeginStop(const SessionStatus status,
                                 const std::int64_t qpc,
                                 std::string reason,
                                 const bool recover_capture_prefix) {
    if (state_ == RecordingSessionState::Finalizing ||
        state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed) {
        return;
    }
    reason = SafeDetail(std::move(reason));
    if (reason.empty()) reason = "session_stopped";

    if (state_ == RecordingSessionState::StopRequested) {
        if (status == SessionStatus::CaptureLost) requested_status_ = status;
        recover_capture_prefix_ = recover_capture_prefix_ || recover_capture_prefix;
        if (status == SessionStatus::CaptureLost || stop_reason_.empty()) {
            stop_reason_ = std::move(reason);
        }
    } else {
        if (trainer_.state() != trainer::EngineState::idle &&
            trainer_.state() != trainer::EngineState::paused &&
            trainer_.state() != trainer::EngineState::complete) {
            trainer_.Pause(qpc);
            DrainFinalizedTrainerRecords();
        }
        requested_status_ = status;
        recover_capture_prefix_ = recover_capture_prefix;
        stop_reason_ = std::move(reason);
        if (!storage_failed_) {
            gameplay_.AppendLifecycle({
                qpc,
                "capture_stop_requested",
                CurrentBlockOrdinal(),
                CurrentEventId(),
                stop_reason_,
            });
        }
        state_ = RecordingSessionState::StopRequested;
    }

    if (!stop_forwarded_) {
        stop_forwarded_ = true;
        try {
            capture_.RequestStop();
        } catch (const std::exception& error) {
            ++warning_count_;
            requested_status_ = SessionStatus::CaptureLost;
            recover_capture_prefix_ = true;
            stop_reason_ = "capture_stop_request_failed";
            if (!storage_failed_) {
                try {
                    AppendIssueAnnotation(RuntimeIssue::CaptureHelperLost, qpc,
                                          error.what());
                } catch (...) {
                }
            }
        }
    }
}

void RecordingSession::BeginDestructiveStop(const RuntimeIssue issue,
                                            const std::int64_t qpc,
                                            const std::string& detail) {
    if (state_ == RecordingSessionState::Finalizing ||
        state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed) {
        return;
    }
    ++warning_count_;
    if (!storage_failed_ && issue != RuntimeIssue::StorageWriteFailed) {
        try {
            AppendIssueAnnotation(issue, qpc, detail);
        } catch (const std::exception& error) {
            HandleStorageFailure(qpc, error);
            return;
        }
    }
    const SessionStatus status = IsCaptureLossIssue(issue)
        ? SessionStatus::CaptureLost
        : SessionStatus::Interrupted;
    try {
        BeginStop(status, qpc, std::string(ToString(issue)), true);
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::exception& error) {
        HandleStorageFailure(qpc, error);
    }
}

void RecordingSession::ObserveCapture(const std::int64_t qpc) {
    if (!capture_begin_called_ || state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed ||
        state_ == RecordingSessionState::Finalizing) {
        return;
    }
    if (state_ == RecordingSessionState::StopRequested &&
        recover_capture_prefix_) {
        return;
    }
    const auto snapshot = capture_.Snapshot();
    if (snapshot.counters.queue_overflow_events != 0U) {
        BeginDestructiveStop(RuntimeIssue::NativeQueueOverflow, qpc,
                             "capture queue overflowed");
        return;
    }
    if (snapshot.counters.bytes_discarded != 0U) {
        BeginDestructiveStop(RuntimeIssue::CaptureBytesDiscarded, qpc,
                             "capture reported discarded source bytes");
        return;
    }
    if (snapshot.fatal_issue && !capture_fatal_observed_) {
        capture_fatal_observed_ = true;
        if (ActionFor(*snapshot.fatal_issue) ==
            RuntimeAction::StopCaptureAndPreservePrefix) {
            BeginDestructiveStop(*snapshot.fatal_issue, qpc, snapshot.detail);
        } else {
            ReportIssue(*snapshot.fatal_issue, qpc, snapshot.detail);
        }
        return;
    }
    if ((state_ == RecordingSessionState::Recording ||
         state_ == RecordingSessionState::Paused) &&
        !snapshot.running && !snapshot.stop_complete && !stop_forwarded_) {
        BeginDestructiveStop(RuntimeIssue::CaptureHelperLost, qpc,
                             snapshot.detail.empty()
                                 ? "capture stopped without a session request"
                                 : snapshot.detail);
    }
}

bool RecordingSession::TryStart(const std::int64_t qpc) {
    RequireTimelineQpc(qpc);
    if (state_ != RecordingSessionState::AwaitingCaptureReady) return false;
    ObserveCapture(qpc);
    if (state_ != RecordingSessionState::AwaitingCaptureReady) return false;
    const auto snapshot = capture_.Snapshot();
    if (!snapshot.ready || !snapshot.running || snapshot.fatal_issue ||
        !focused_ || minimized_) {
        return false;
    }

    try {
        trainer_.Start(qpc);
        state_ = RecordingSessionState::Recording;
        gameplay_.AppendLifecycle({
            qpc,
            "trainer_started",
            CurrentBlockOrdinal(),
            CurrentEventId(),
            "authoritative capture ready; trainer started",
        });
        next_checkpoint_qpc_ = SaturatingAdd(qpc, checkpoint_interval_ticks_);
        Checkpoint(qpc);
        return state_ == RecordingSessionState::Recording;
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(qpc, error);
        return false;
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(qpc, error);
        return false;
    } catch (const std::exception& error) {
        HandleStorageFailure(qpc, error);
        return false;
    }
}

void RecordingSession::DrainFinalizedTrainerRecords() {
    const auto& events = trainer_.events();
    while (next_event_to_journal_ < events.size()) {
        const auto& event = events[next_event_to_journal_];
        auto render = current_render_calibration_;
        if (const auto found = event_render_evidence_.find(event.event_id);
            found != event_render_evidence_.end()) {
            render = found->second;
        }
        try {
            gameplay_.AppendEvent(event, render);
            ++journaled_event_count_;
        } catch (const GameplayRecordValidationError& error) {
            // The USB source remains authoritative and useful. Preserve that
            // stream, exclude only this contradictory convenience record, and
            // leave an auditable reason for preprocessing.
            ++warning_count_;
            const auto annotation_qpc = event.tail_end_qpc.value_or(
                event.technical_interruption_qpc.value_or(
                    event.natural_resolution_qpc.value_or(
                        event.event_start_qpc.value_or(
                            event.target_generated_qpc))));
            gameplay_.AppendLifecycle({
                annotation_qpc,
                "gameplay_event_excluded",
                event.block_ordinal,
                event.event_id,
                SafeDetail(error.what()),
            });
        }
        event_render_evidence_.erase(event.event_id);
        ++next_event_to_journal_;
    }

    const auto& blocks = trainer_.block_results();
    while (next_block_to_journal_ < blocks.size() &&
           blocks[next_block_to_journal_].completed_qpc.has_value()) {
        const auto& block = blocks[next_block_to_journal_];
        try {
            gameplay_.AppendBlockResult(block);
            ++journaled_block_count_;
        } catch (const GameplayRecordValidationError& error) {
            ++warning_count_;
            gameplay_.AppendLifecycle({
                block.completed_qpc.value_or(
                    block.gameplay_started_qpc.value_or(
                        block.countdown_started_qpc)),
                "gameplay_block_excluded",
                block.ordinal,
                std::nullopt,
                SafeDetail(error.what()),
            });
        }
        ++next_block_to_journal_;
    }
}

void RecordingSession::MaybeCheckpoint(const std::int64_t qpc) {
    if (state_ == RecordingSessionState::AwaitingCaptureReady ||
        state_ == RecordingSessionState::Finalizing ||
        state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed ||
        qpc < next_checkpoint_qpc_) {
        return;
    }
    Checkpoint(qpc);
}

void RecordingSession::AdvanceTo(const std::int64_t qpc) {
    RequireTimelineQpc(qpc);
    ObserveCapture(qpc);
    if (state_ != RecordingSessionState::Recording &&
        state_ != RecordingSessionState::Paused) {
        return;
    }
    try {
        trainer_.AdvanceTo(qpc);
        DrainFinalizedTrainerRecords();
        state_ = trainer_.state() == trainer::EngineState::paused
            ? RecordingSessionState::Paused
            : RecordingSessionState::Recording;
        if (trainer_.state() == trainer::EngineState::complete) {
            BeginStop(SessionStatus::Complete, qpc, "participant_completed", false);
            return;
        }
        MaybeCheckpoint(qpc);
        ObserveCapture(qpc);
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::exception& error) {
        HandleStorageFailure(qpc, error);
    }
}

void RecordingSession::SubmitRawInput(const trainer::RawInputPacket& packet,
                                      const RawInputSource& source) {
    RequireTimelineQpc(packet.qpc);
    ObserveCapture(packet.qpc);
    if (state_ != RecordingSessionState::Recording &&
        state_ != RecordingSessionState::Paused) {
        return;
    }

    const bool selected = source.selected_device &&
        source.device_token == options_.locked_mouse.selection_token;
    try {
        if (options_.retain_raw_input_witness && selected) {
            const bool retained = gameplay_.TryAppendRawInputWitness({
                packet.qpc,
                selected,
                source.device_token,
                packet.dx_counts,
                packet.dy_counts,
                source.button_flags,
                source.button_data,
            });
            if (!retained) {
                ++warning_count_;
                AppendIssueAnnotation(
                    RuntimeIssue::RawInputUnavailable, packet.qpc,
                    "malformed optional Raw Input witness packet was not retained");
            }
        }

        // Raw Input is gameplay control only. Other mice are never submitted
        // to the virtual camera and no USB/Raw-Input reconciliation is made.
        if (selected && state_ == RecordingSessionState::Recording) {
            trainer_.SubmitRawInput(packet);
            DrainFinalizedTrainerRecords();
            if (trainer_.state() == trainer::EngineState::complete) {
                BeginStop(SessionStatus::Complete, packet.qpc,
                          "participant_completed", false);
                return;
            }
        }
        MaybeCheckpoint(packet.qpc);
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(packet.qpc, error);
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(packet.qpc, error);
    } catch (const std::exception& error) {
        HandleStorageFailure(packet.qpc, error);
    }
}

bool RecordingSession::AcknowledgeTargetPresented(
    const std::int64_t first_presented_qpc,
    const RenderEvidence& render) {
    if (!IsValidRenderEvidence(render)) {
        throw std::invalid_argument("presentation render evidence is invalid");
    }
    RequireTimelineQpc(first_presented_qpc);
    ObserveCapture(first_presented_qpc);
    if (state_ != RecordingSessionState::Recording) return false;

    const auto target = trainer_.target_view();
    if (!target) return false;
    try {
        const bool accepted =
            trainer_.AcknowledgeTargetPresented(first_presented_qpc);
        gameplay_.AppendPresentation({
            first_presented_qpc,
            target->event_id,
            accepted,
            render,
            accepted ? "first target frame presented"
                     : "presentation acknowledgement was not applicable",
        });
        if (accepted) {
            current_render_calibration_ = render;
            event_render_evidence_[target->event_id] = render;
        }
        DrainFinalizedTrainerRecords();
        MaybeCheckpoint(first_presented_qpc);
        return accepted;
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(first_presented_qpc, error);
        return false;
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(first_presented_qpc, error);
        return false;
    } catch (const std::exception& error) {
        HandleStorageFailure(first_presented_qpc, error);
        return false;
    }
}

void RecordingSession::SetFocus(const bool focused,
                                const bool minimized,
                                const std::int64_t qpc) {
    RequireTimelineQpc(qpc);
    ObserveCapture(qpc);
    if (state_ == RecordingSessionState::Finalizing ||
        state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed ||
        state_ == RecordingSessionState::StopRequested) {
        return;
    }
    if (focused_ == focused && minimized_ == minimized) return;
    const bool was_effectively_focused = focused_ && !minimized_;
    const bool is_effectively_focused = focused && !minimized;
    const auto event_id = CurrentEventId();

    try {
        gameplay_.AppendFocus({qpc, focused, minimized, event_id});
        focused_ = focused;
        minimized_ = minimized;
        if (trainer_.state() != trainer::EngineState::idle &&
            was_effectively_focused != is_effectively_focused) {
            const auto before = trainer_.state();
            trainer_.SetFocused(is_effectively_focused, qpc);
            DrainFinalizedTrainerRecords();
            const auto after = trainer_.state();
            if (before != trainer::EngineState::paused &&
                after == trainer::EngineState::paused) {
                gameplay_.AppendPause({
                    qpc,
                    true,
                    minimized ? "minimized" : "focus_lost",
                    event_id,
                });
            } else if (before == trainer::EngineState::paused &&
                       after != trainer::EngineState::paused) {
                gameplay_.AppendPause({
                    qpc,
                    false,
                    "focus_restored",
                    event_id,
                });
            }
            state_ = after == trainer::EngineState::paused
                ? RecordingSessionState::Paused
                : RecordingSessionState::Recording;
        }
        MaybeCheckpoint(qpc);
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::exception& error) {
        HandleStorageFailure(qpc, error);
    }
}

void RecordingSession::ManualPause(const std::int64_t qpc) {
    RequireTimelineQpc(qpc);
    ObserveCapture(qpc);
    if (state_ != RecordingSessionState::Recording) return;
    const auto event_id = CurrentEventId();
    try {
        trainer_.Pause(qpc);
        DrainFinalizedTrainerRecords();
        gameplay_.AppendPause({qpc, true, "manual_pause", event_id});
        state_ = RecordingSessionState::Paused;
        MaybeCheckpoint(qpc);
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::exception& error) {
        HandleStorageFailure(qpc, error);
    }
}

bool RecordingSession::ManualResume(const std::int64_t qpc) {
    return ResumeAfterRecoverableIssue(qpc, "manual_resume");
}

bool RecordingSession::ResumeAfterRecoverableIssue(
    const std::int64_t qpc, std::string reason) {
    RequireTimelineQpc(qpc);
    ObserveCapture(qpc);
    if (state_ != RecordingSessionState::Paused || !focused_ || minimized_) {
        return false;
    }
    reason = SafeDetail(std::move(reason));
    if (reason.empty()) reason = "recoverable_issue_cleared";
    try {
        trainer_.Resume(qpc);
        gameplay_.AppendPause({qpc, false, std::move(reason), CurrentEventId()});
        state_ = RecordingSessionState::Recording;
        MaybeCheckpoint(qpc);
        return true;
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(qpc, error);
        return false;
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(qpc, error);
        return false;
    } catch (const std::exception& error) {
        HandleStorageFailure(qpc, error);
        return false;
    }
}

void RecordingSession::ReportIssue(const RuntimeIssue issue,
                                   const std::int64_t qpc,
                                   std::string detail) {
    RequireTimelineQpc(qpc);
    detail = SafeDetail(std::move(detail));
    const auto action = ActionFor(issue);
    if (action == RuntimeAction::StopCaptureAndPreservePrefix) {
        BeginDestructiveStop(issue, qpc, detail);
        return;
    }

    ++warning_count_;
    try {
        AppendIssueAnnotation(issue, qpc, detail);
        if (action == RuntimeAction::ContinueWithAnnotation ||
            state_ == RecordingSessionState::AwaitingCaptureReady) {
            return;
        }
        if (issue == RuntimeIssue::FocusLost) {
            SetFocus(false, false, qpc);
            return;
        }
        if (issue == RuntimeIssue::Minimized) {
            SetFocus(false, true, qpc);
            return;
        }
        if (state_ == RecordingSessionState::Recording) {
            const auto event_id = CurrentEventId();
            trainer::TechnicalOutcome outcome;
            switch (issue) {
            case RuntimeIssue::DisplayChanged:
                outcome = trainer::TechnicalOutcome::display_changed;
                break;
            case RuntimeIssue::GraphicsDeviceLost:
                outcome = trainer::TechnicalOutcome::graphics_device_lost;
                break;
            case RuntimeIssue::SystemSuspend:
                outcome = trainer::TechnicalOutcome::system_suspend;
                break;
            case RuntimeIssue::GameplayInputUnavailable:
                outcome =
                    trainer::TechnicalOutcome::gameplay_input_unavailable;
                break;
            default:
                outcome = trainer::TechnicalOutcome::manual_pause;
                break;
            }
            trainer_.PauseForTechnicalInterruption(outcome, qpc);
            DrainFinalizedTrainerRecords();
            gameplay_.AppendPause(
                {qpc, true, std::string(ToString(issue)), event_id});
            state_ = RecordingSessionState::Paused;
        }
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::exception& error) {
        HandleStorageFailure(qpc, error);
    }
}

void RecordingSession::AddClockAnchor(const platform::ClockAnchor& anchor) {
    if (state_ == RecordingSessionState::Finalizing ||
        state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed) {
        throw std::logic_error("cannot append a clock anchor after finalization");
    }
    // Structural/caller errors are not mislabeled as storage failures.
    (void)platform::ClockAnchorToJson(anchor);
    try {
        clocks_.Append(anchor);
    } catch (const std::exception& error) {
        const auto qpc = trainer_.state() == trainer::EngineState::idle
            ? anchor.qpc_midpoint
            : std::max(anchor.qpc_midpoint, trainer_.now_qpc());
        HandleStorageFailure(qpc, error);
    }
}

void RecordingSession::SampleClockAnchor(std::string source) {
    AddClockAnchor(platform::SamplePreciseClockAnchor(std::move(source)));
}

void RecordingSession::Checkpoint(const std::int64_t qpc) {
    RequireTimelineQpc(qpc);
    if (state_ == RecordingSessionState::Finalizing ||
        state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed) {
        return;
    }
    try {
        gameplay_.Checkpoint();
        clocks_.Checkpoint();
        workspace_.UpdateRuntimeSummary(
            journaled_event_count_, warning_count_, ToString(state_));
        next_checkpoint_qpc_ = SaturatingAdd(qpc, checkpoint_interval_ticks_);
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::exception& error) {
        HandleStorageFailure(qpc, error);
    }
}

void RecordingSession::RequestParticipantStop(const std::int64_t qpc,
                                              std::string reason) {
    RequireTimelineQpc(qpc);
    if (state_ == RecordingSessionState::Finalizing ||
        state_ == RecordingSessionState::Finalized ||
        state_ == RecordingSessionState::FinalizationFailed ||
        state_ == RecordingSessionState::StopRequested) {
        return;
    }
    reason = SafeDetail(std::move(reason));
    if (reason.empty()) reason = "participant_cancelled";
    try {
        BeginStop(SessionStatus::Interrupted, qpc, std::move(reason), false);
    } catch (const protocol::ProtocolError& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::logic_error& error) {
        HandleIntegrityFailure(qpc, error);
    } catch (const std::exception& error) {
        HandleStorageFailure(qpc, error);
    }
}

bool RecordingSession::CaptureCanFinalize(
    const RecordingCaptureSnapshot& snapshot) const noexcept {
    if (snapshot.stop_complete && !snapshot.running) return true;
    return recover_capture_prefix_ && !snapshot.running &&
           (requested_status_ == SessionStatus::CaptureLost || storage_failed_ ||
            snapshot.fatal_issue.has_value() || capture_fatal_observed_ ||
            snapshot.counters.queue_overflow_events != 0U ||
            snapshot.counters.bytes_discarded != 0U);
}

bool RecordingSession::TryFinalize(const std::int64_t qpc,
                                   const std::int64_t ended_utc_ns) {
    if (result_) return true;
    RequireTimelineQpc(qpc);
    if (ended_utc_ns <= 0) {
        throw std::invalid_argument("session end UTC is invalid");
    }
    ObserveCapture(qpc);
    if (state_ != RecordingSessionState::StopRequested) return false;

    auto snapshot = capture_.Snapshot();
    if (!CaptureCanFinalize(snapshot)) return false;
    state_ = RecordingSessionState::Finalizing;

    RecordingSessionResult completed;
    completed.status = requested_status_;
    completed.stop_reason = stop_reason_;
    completed.error = failure_detail_;
    completed.raw_pcap_records = snapshot.counters.raw_pcap_records;
    completed.decoded_reports = snapshot.counters.decoded_reports;
    completed.gameplay_events = journaled_event_count_;
    completed.gameplay_blocks = journaled_block_count_;
    bool verified_authoritative_source = false;
    bool unverified_source_annotated = false;

    try {
        const auto authoritative_capture =
            workspace_.CaptureDirectory() / "mouse_usb.pcap";
        const auto authoritative_partial =
            workspace_.CaptureDirectory() / "mouse_usb.pcap.partial";
        const auto authoritative_status =
            std::filesystem::symlink_status(authoritative_capture);
        const bool authoritative_published =
            authoritative_status.type() ==
                std::filesystem::file_type::regular &&
            !std::filesystem::is_symlink(authoritative_status);
        if (requested_status_ == SessionStatus::Complete &&
            (!snapshot.stop_complete || !snapshot.clean_stop ||
             snapshot.fatal_issue ||
             snapshot.counters.queue_overflow_events != 0U ||
             snapshot.counters.bytes_discarded != 0U)) {
            requested_status_ = SessionStatus::CaptureLost;
            recover_capture_prefix_ = true;
            stop_reason_ = "capture_stop_not_clean";
            ++warning_count_;
        }
        if (requested_status_ != SessionStatus::CaptureLost &&
            (!authoritative_published ||
             std::filesystem::exists(authoritative_partial))) {
            requested_status_ = SessionStatus::CaptureLost;
            recover_capture_prefix_ = true;
            stop_reason_ = "authoritative_capture_not_published";
            ++warning_count_;
        }

        if (recover_capture_prefix_) {
            const auto recovery =
                RecoverCapturePrefix(workspace_.CaptureDirectory());
            warning_count_ += recovery.warning_count;
            for (const auto& artifact : recovery.artifacts) {
                if (artifact.kind == "device_pcap") {
                    completed.raw_pcap_records = std::max(
                        completed.raw_pcap_records, artifact.record_count);
                } else if (artifact.kind == "decoded_reports") {
                    completed.decoded_reports = std::max(
                    completed.decoded_reports, artifact.record_count);
                }
            }
            if (!recovery.any_verified_source) {
                ++warning_count_;
                gameplay_.AppendLifecycle({
                    qpc,
                    "authoritative_source_unverified",
                    CurrentBlockOrdinal(),
                    CurrentEventId(),
                    "no verified selected-device PCAP prefix was recoverable",
                });
                unverified_source_annotated = true;
            }
        }

        // Publication is not evidence by itself. Re-read every claimed source
        // through its strict parser and compare its embedded identity with the
        // certified device address before the session can call it authoritative.
        const auto expected_capture = CaptureIdentity(options_);
        if (!recover_capture_prefix_) {
            const auto validated = ValidateCaptureArtifacts(
                workspace_.CaptureDirectory(), expected_capture);
            if (validated.raw_pcap_records !=
                    snapshot.counters.raw_pcap_records ||
                validated.decoded_reports !=
                    snapshot.counters.decoded_reports ||
                validated.anomaly_records !=
                    snapshot.counters.anomaly_count) {
                ++warning_count_;
                gameplay_.AppendLifecycle({
                    qpc,
                    "capture_counter_recomputed",
                    CurrentBlockOrdinal(),
                    CurrentEventId(),
                    "published capture counts replaced helper status counters",
                });
            }
            completed.raw_pcap_records = validated.raw_pcap_records;
            completed.decoded_reports = validated.decoded_reports;
            if (validated.derivative_failures != 0U) {
                warning_count_ += validated.derivative_failures;
                gameplay_.AppendLifecycle({
                    qpc,
                    "capture_derivative_unavailable",
                    CurrentBlockOrdinal(),
                    CurrentEventId(),
                    "one or more optional decoded or diagnostic capture files failed validation",
                });
            }
        } else {
            const auto pcap = workspace_.CaptureDirectory() /
                "mouse_usb.pcap";
            const auto reports = workspace_.CaptureDirectory() /
                "mouse_reports.abcr2";
            const auto anomalies = workspace_.CaptureDirectory() /
                "capture_anomalies.jsonl";
            if (std::filesystem::is_regular_file(pcap)) {
                completed.raw_pcap_records =
                    ValidateDevicePcap(pcap, expected_capture);
            } else {
                completed.raw_pcap_records = 0U;
            }
            std::uint64_t derivative_failures = 0U;
            completed.decoded_reports = 0U;
            if (std::filesystem::is_regular_file(reports)) {
                try {
                    completed.decoded_reports =
                        ValidateDecodedReportStream(reports, expected_capture);
                } catch (const std::exception&) {
                    ++derivative_failures;
                }
            }
            if (std::filesystem::is_regular_file(anomalies)) {
                try {
                    (void)ValidateCaptureAnomalyJournal(anomalies);
                } catch (const std::exception&) {
                    ++derivative_failures;
                }
            }
            if (derivative_failures != 0U) {
                warning_count_ += derivative_failures;
                gameplay_.AppendLifecycle({
                    qpc,
                    "capture_derivative_unavailable",
                    CurrentBlockOrdinal(),
                    CurrentEventId(),
                    "one or more optional decoded or diagnostic capture files failed recovery validation",
                });
            }
        }

        // A valid global PCAP header establishes framing, not evidence that the
        // selected mouse produced any captured traffic. Preserve an empty file
        // and finish the session, but never advertise it as an authoritative
        // source prefix.
        verified_authoritative_source = completed.raw_pcap_records != 0U;
        if (!verified_authoritative_source && !unverified_source_annotated) {
            ++warning_count_;
            gameplay_.AppendLifecycle({
                qpc,
                "authoritative_source_unverified",
                CurrentBlockOrdinal(),
                CurrentEventId(),
                "selected-device PCAP contained no captured records",
            });
            unverified_source_annotated = true;
        }

        warning_count_ += snapshot.counters.anomaly_count;
        DrainFinalizedTrainerRecords();
        gameplay_.Finalize();
        clocks_.Finalize();

        SessionStatus final_status = requested_status_;
        if (final_status == SessionStatus::Complete && warning_count_ != 0U) {
            final_status = SessionStatus::CompleteWithWarnings;
        }
        workspace_.UpdateRuntimeSummary(
            journaled_event_count_, warning_count_, stop_reason_);

        SessionSealOptions seal_options;
        seal_options.status = final_status;
        seal_options.ended_utc_ns = ended_utc_ns;
        seal_options.raw_pcap_records = completed.raw_pcap_records;
        seal_options.decoded_reports = completed.decoded_reports;
        seal_options.gameplay_events = journaled_event_count_;
        seal_options.warning_count = warning_count_;
        seal_options.recovery_was_required = recover_capture_prefix_;
        seal_options.verified_authoritative_source =
            verified_authoritative_source;
        seal_options.stop_reason = stop_reason_;
        completed.seal = workspace_.Seal(seal_options);
        completed.validation =
            ValidateSealedSession(completed.seal->directory);

        const auto archive_path =
            SubmissionArchivePath(completed.seal->directory);
        completed.archive =
            CreateSessionArchive(completed.seal->directory, archive_path);
        // CreateSessionArchive validates the completed temporary ZIP before
        // its atomic publication. Re-extracting the unchanged archive here
        // doubled finalization work and introduced no additional guarantee.
        workspace_.ReleaseFinalizationLease();

        completed.success = true;
        completed.recovery_was_required = recover_capture_prefix_;
        completed.verified_authoritative_source =
            verified_authoritative_source;
        completed.status = final_status;
        completed.stop_reason = stop_reason_;
        completed.gameplay_events = journaled_event_count_;
        completed.gameplay_blocks = journaled_block_count_;
        completed.warning_count = warning_count_;
        state_ = RecordingSessionState::Finalized;
        result_ = std::move(completed);
        return true;
    } catch (const std::exception& error) {
        completed.success = false;
        completed.recovery_was_required = recover_capture_prefix_;
        completed.verified_authoritative_source =
            verified_authoritative_source;
        completed.status = requested_status_;
        completed.stop_reason = stop_reason_;
        completed.gameplay_events = journaled_event_count_;
        completed.gameplay_blocks = journaled_block_count_;
        completed.warning_count = warning_count_;
        completed.error = error.what();
        state_ = RecordingSessionState::FinalizationFailed;
        result_ = std::move(completed);
        return true;
    }
}

}  // namespace abdc::session
