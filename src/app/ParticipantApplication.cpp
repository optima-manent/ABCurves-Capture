#include "app/ParticipantApplication.h"

#include "base/BuildInfo.h"
#include "base/Json.h"
#include "protocol/protocol_v1.hpp"
#include "session/PseudonymousIdentity.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <bcrypt.h>
#include <shellapi.h>
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>

namespace abdc::app {
namespace {

using namespace std::chrono_literals;

std::array<std::byte, 32> RandomBytes() {
    std::array<std::byte, 32> value{};
    const auto status = BCryptGenRandom(
        nullptr, reinterpret_cast<PUCHAR>(value.data()),
        static_cast<ULONG>(value.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) throw std::runtime_error("system random generator failed");
    return value;
}

std::uint64_t RandomU64() {
    std::uint64_t value = 0;
    const auto status = BCryptGenRandom(
        nullptr, reinterpret_cast<PUCHAR>(&value), sizeof(value),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) throw std::runtime_error("system random generator failed");
    return value;
}

std::int64_t UtcNowNs() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

AudioEngine::Sfx PopSound(const HitSound sound) noexcept {
    switch (sound) {
    case HitSound::Pop1: return AudioEngine::Sfx::Pop1;
    case HitSound::Pop2: return AudioEngine::Sfx::Pop2;
    case HitSound::Pop3: return AudioEngine::Sfx::Pop3;
    }
    return AudioEngine::Sfx::Pop1;
}

std::int64_t RelativeNanoseconds(const std::int64_t qpc,
                                 const std::int64_t origin,
                                 const std::int64_t frequency) noexcept {
    if (qpc <= origin || frequency <= 0) return 0;
    const long double result =
        static_cast<long double>(qpc - origin) * 1'000'000'000.0L /
        static_cast<long double>(frequency);
    return result >= static_cast<long double>(
                         std::numeric_limits<std::int64_t>::max())
               ? std::numeric_limits<std::int64_t>::max()
               : static_cast<std::int64_t>(result);
}

void AddActivity(device::ActivityTotals& totals,
                 const std::int64_t dx, const std::int64_t dy,
                 const bool left_down, const bool left_up) noexcept {
    totals.canonical_dx += dx;
    totals.canonical_dy += dy;
    ++totals.packet_count;
    const auto magnitude = [](const std::int64_t value) -> std::uint64_t {
        return value < 0
            ? static_cast<std::uint64_t>(-(value + 1)) + 1U
            : static_cast<std::uint64_t>(value);
    };
    const auto addition = magnitude(dx) + magnitude(dy);
    totals.absolute_motion_counts =
        addition > std::numeric_limits<std::uint64_t>::max() -
                       totals.absolute_motion_counts
            ? std::numeric_limits<std::uint64_t>::max()
            : totals.absolute_motion_counts + addition;
    if (left_down) ++totals.left_down_edges;
    if (left_up) ++totals.left_up_edges;
}

ParticipantEvent Event(const ParticipantEventKind kind) {
    ParticipantEvent event;
    event.kind = kind;
    return event;
}

DestructiveFailure ParticipantFailure(const session::RuntimeIssue issue) noexcept {
    switch (issue) {
    case session::RuntimeIssue::SelectedDeviceChanged:
        return DestructiveFailure::SelectedDeviceChanged;
    case session::RuntimeIssue::NativeQueueOverflow:
    case session::RuntimeIssue::CaptureBytesDiscarded:
        return DestructiveFailure::QueueOverflow;
    case session::RuntimeIssue::PcapFramingLost:
        return DestructiveFailure::FramingCorruption;
    case session::RuntimeIssue::StorageWriteFailed:
        return DestructiveFailure::StorageFailure;
    case session::RuntimeIssue::IntegrityFailed:
        return DestructiveFailure::IntegrityFailure;
    default:
        return DestructiveFailure::HelperLost;
    }
}

bool FutureReady(const auto& future) {
    return future.wait_for(0ms) == std::future_status::ready;
}

bool CountdownReachedGameplay(const trainer::EngineState state) noexcept {
    switch (state) {
    case trainer::EngineState::awaiting_presentation:
    case trainer::EngineState::event_active:
    case trainer::EngineState::event_tail:
    case trainer::EngineState::inter_target_delay:
    case trainer::EngineState::complete:
        return true;
    case trainer::EngineState::idle:
    case trainer::EngineState::countdown:
    case trainer::EngineState::paused:
        return false;
    }
    return false;
}

std::int64_t SaturatingFutureTick(const std::int64_t now,
                                  const std::int64_t delta) noexcept {
    return delta > 0 && now > std::numeric_limits<std::int64_t>::max() - delta
        ? std::numeric_limits<std::int64_t>::max()
        : now + delta;
}

}  // namespace

int ParticipantApplication::Run(const HINSTANCE instance,
                                const int show_command) {
    if (!Initialize(instance, show_command)) return 1;
    MainLoop();
    return 0;
}

bool ParticipantApplication::Initialize(const HINSTANCE instance,
                                        const int show_command) {
    paths_ = ResolveApplicationPaths();
    PrepareApplicationPaths(paths_);
    const auto loaded = LoadParticipantSettings(paths_.settings_file);
    settings_ = loaded.settings;
    participant_id_ =
        session::LoadOrCreateParticipantId(paths_.participant_identity_directory);
    highscores_ = std::make_unique<HighscoreStore>(paths_.highscores_file);

    if (!window_.Create(instance, show_command, L"ABCurves Capture Trainer",
                        1280, 800)) {
        return false;
    }
    window_.on_raw_input = [this](HRAWINPUT input, const std::int64_t qpc) {
        HandleRawInput(input, qpc);
    };
    window_.on_key = [this](const UINT key, const bool down) {
        HandleKey(key, down);
    };
    window_.on_mouse_move = [this](const int x, const int y) {
        HandleMouseMove(x, y);
    };
    window_.on_mouse_button =
        [this](const int x, const int y, const bool down) {
            HandleMouseButton(x, y, down);
        };
    window_.on_focus = [this](const bool focused) { HandleFocus(focused); };
    window_.on_resize = [this](const UINT width, const UINT height) {
        HandleResize(width, height);
    };
    window_.on_system_event =
        [this](const UINT message, const WPARAM wparam, const LPARAM lparam) {
            HandleSystemEvent(message, wparam, lparam);
        };
    window_.on_close = [this] { return HandleClose(); };

    if (!raw_input_.Register(window_.Handle())) return false;
    renderer_ready_ = renderer_.Initialize(window_.Handle());
    if (!renderer_ready_) return false;

    (void)audio_.Initialize();
    if (settings_.fullscreen) window_.ToggleFullscreen();
    StartAbandonedSessionRecovery();
    return true;
}

void ParticipantApplication::MainLoop() {
    while (window_.PumpMessages()) {
        const auto now = clock_.NowTicks();
        Tick(now);
        try {
            Render(now);
        } catch (...) {
            HandlePresentationFailure(
                now, "participant interface rendering failed");
        }
        audio_.Update();
        std::this_thread::sleep_for(1ms);
    }
}

void ParticipantApplication::Tick(const std::int64_t now_qpc) {
    PollAbandonedSessionRecovery();
    PollInventoryScan();
    PollCertification(now_qpc);
    PollRecordingBootstrap(now_qpc);
    PollLiveInputRebind(now_qpc);
    DriveRecording(now_qpc);

    if (graphics_pause_active_ && now_qpc >= next_graphics_retry_qpc_) {
        next_graphics_retry_qpc_ = now_qpc + clock_.TicksFromMilliseconds(1000.0);
        try {
            renderer_ready_ = renderer_.Initialize(window_.Handle());
        } catch (...) {
            renderer_ready_ = false;
        }
        if (renderer_ready_) {
            graphics_pause_active_ = false;
            ResetPresentationWatchdog();
            if (recording_) {
                (void)flow_.Apply(Event(ParticipantEventKind::DisplayStable));
                if (flow_.State().stage == ParticipantStage::ResumeCountdown) {
                    (void)recording_->ResumeAfterRecoverableIssue(
                        now_qpc, "graphics_device_restored");
                }
            }
        }
    }
    UpdateMouseCapture();
}

void ParticipantApplication::StartAbandonedSessionRecovery() {
    if (startup_recovery_complete_ || abandoned_recovery_future_) return;
    startup_recovery_ui_ = {};
    startup_recovery_ui_.in_progress = true;
    const auto sessions_root = paths_.sessions_directory;
    try {
        abandoned_recovery_future_.emplace(std::async(
            std::launch::async, [sessions_root] {
                return session::RecoverAbandonedSessions(
                    sessions_root, UtcNowNs());
            }));
    } catch (...) {
        // Thread launch failure must not masquerade as a successful check. The
        // original workspaces remain untouched and the participant may proceed
        // after seeing the review notice.
        startup_recovery_ui_.in_progress = false;
        startup_recovery_ui_.check_failed = true;
        startup_recovery_complete_ = true;
    }
}

void ParticipantApplication::PollAbandonedSessionRecovery() {
    if (!abandoned_recovery_future_ ||
        !FutureReady(*abandoned_recovery_future_)) {
        return;
    }

    const auto increment = [](std::uint64_t& value) noexcept {
        if (value != std::numeric_limits<std::uint64_t>::max()) ++value;
    };
    try {
        const auto results = abandoned_recovery_future_->get();
        for (const auto& result : results) {
            switch (result.state) {
            case session::AbandonedRecoveryState::Recovered:
                if (result.archive.empty()) {
                    increment(startup_recovery_ui_.failed_workspace_count);
                    break;
                }
                increment(startup_recovery_ui_.recovered_archive_count);
                if (!result.verified_authoritative_source) {
                    increment(startup_recovery_ui_.review_archive_count);
                }
                startup_recovery_ui_.recovered_archive_filename =
                    result.archive.filename().string();
                break;
            case session::AbandonedRecoveryState::SkippedActiveWriter:
                increment(startup_recovery_ui_.active_writer_count);
                break;
            case session::AbandonedRecoveryState::Failed:
                increment(startup_recovery_ui_.failed_workspace_count);
                break;
            }
        }
    } catch (...) {
        startup_recovery_ui_.check_failed = true;
    }
    abandoned_recovery_future_.reset();
    startup_recovery_ui_.in_progress = false;
    startup_recovery_complete_ = true;
    if (close_requested_) RequestFinalWindowClose();
}

void ParticipantApplication::StartInventoryScan() {
    if (!startup_recovery_complete_ || inventory_future_) return;
    inventory_salt_ = RandomBytes();
    const auto salt = inventory_salt_;
    inventory_future_.emplace(std::async(std::launch::async, [salt] {
        return DiscoverParticipantInventory(salt);
    }));
}

void ParticipantApplication::PollInventoryScan() {
    if (!inventory_future_ || !FutureReady(*inventory_future_)) return;
    try {
        inventory_ = inventory_future_->get();
    } catch (...) {
        inventory_ = {};
    }
    inventory_future_.reset();
    selected_mouse_.reset();
    certified_raw_input_routes_.clear();
}

void ParticipantApplication::SelectMouse(const std::size_t choice_index) {
    if (!startup_recovery_complete_ || inventory_future_ ||
        choice_index >= inventory_.choices.size() ||
        !inventory_.choices[choice_index].ready) {
        return;
    }
    try {
        auto topologies =
            CertificationTopologiesForChoice(inventory_, choice_index);
        auto certification = device::CertificationFlow::Prepare(
            inventory_.discovery,
            inventory_.choices[choice_index].physical_device_token,
            topologies);
        if (certification.Decision().state !=
            device::CertificationState::AwaitingProbe) {
            return;
        }
        selected_mouse_ = choice_index;
        selected_topologies_ = std::move(topologies);
        certification_ = std::move(certification);
        certification_success_.reset();
        certified_raw_input_routes_.clear();
        certified_usb_identity_.reset();
        certified_descriptor_.clear();
        (void)flow_.Apply(Event(ParticipantEventKind::SelectPhysicalMouse));
    } catch (...) {
    }
}

void ParticipantApplication::StartCertification() {
    if (!startup_recovery_complete_ || !certification_ ||
        certification_->Decision().state !=
            device::CertificationState::AwaitingProbe ||
        probe_client_) {
        return;
    }
    const auto routes = certification_->Routes();
    if (routes.empty()) return;

    acquisition::CertificationProbeLaunchConfig launch;
    launch.usbpcap_root_index = routes.front().transport.usbpcap_root_index;
    launch.filtered_device_address = routes.front().transport.device_address;
    launch.discover_device_address = true;
    launch.expected_packet_bus = 0;
    launch.maximum_duration_ns = 10'000'000'000LL;
    for (const auto& route : routes) {
        if (route.transport.usbpcap_root_index != launch.usbpcap_root_index ||
            route.transport.device_address != launch.filtered_device_address) {
            MarkCertificationAttemptFailed(false,
                                           "selected routes disagree on USB device");
            return;
        }
        acquisition::CertificationProbeLaunchRoute item;
        item.probe_route_token = route.probe_route_token;
        item.endpoint_address = route.transport.endpoint_address;
        item.descriptor_evidence = route.transport.descriptor_evidence;
        item.canonical_decoder_spec = route.transport.decoder_spec;
        launch.routes.push_back(std::move(item));
    }

    if (!flow_.Apply(Event(ParticipantEventKind::BeginCertification)).accepted) {
        return;
    }
    probe_client_ =
        std::make_unique<acquisition::CertificationProbeClient>();
    const auto started = probe_client_->Start(launch);
    if (!started.started) {
        const bool denied = started.failure ==
                            acquisition::CertificationProbeStartFailure::UacDenied;
        probe_client_.reset();
        MarkCertificationAttemptFailed(denied, started.message);
    }
}

void ParticipantApplication::BeginProbeSampling(const std::int64_t now_qpc) {
    probe_sampling_ = true;
    probe_sampling_started_qpc_ = now_qpc;
    probe_raw_.clear();
    other_probe_raw_totals_ = {};
    for (const auto& route : certification_->Routes()) {
        ProbeRawAccumulator accumulator;
        accumulator.samples.reserve(131'072U);
        probe_raw_.emplace(route.probe_route_token, std::move(accumulator));
    }
}

void ParticipantApplication::PollCertification(const std::int64_t now_qpc) {
    if (!probe_client_) return;
    const auto snapshot = probe_client_->Snapshot();
    if (snapshot.ready && !probe_sampling_) BeginProbeSampling(now_qpc);
    if (snapshot.state == acquisition::CertificationProbeClientState::Completed &&
        snapshot.result) {
        auto result = *snapshot.result;
        probe_client_.reset();
        probe_sampling_ = false;
        CompleteCertification(std::move(result));
        if (close_requested_) RequestFinalWindowClose();
    } else if (snapshot.state ==
                   acquisition::CertificationProbeClientState::Cancelled) {
        probe_client_.reset();
        probe_sampling_ = false;
        if (close_requested_) RequestFinalWindowClose();
    } else if (snapshot.state ==
               acquisition::CertificationProbeClientState::Failed) {
        probe_client_.reset();
        probe_sampling_ = false;
        MarkCertificationAttemptFailed(false, snapshot.message);
        if (close_requested_) RequestFinalWindowClose();
    }
}

void ParticipantApplication::AccumulateProbeRawInput(
    const platform::RawMousePacket& packet) {
    if (!probe_sampling_ || !certification_ || !selected_mouse_) return;
    const auto dx = packet.dx;
    const auto dy = -packet.dy;  // canonical research space is Y-up.

    bool belongs_to_selected_physical = false;
    for (const auto& mouse : inventory_.discovery.mice) {
        if (mouse.raw_input_handle != packet.device_handle) continue;
        belongs_to_selected_physical =
            mouse.topology.physical_device_token ==
            inventory_.choices[*selected_mouse_].physical_device_token;
        break;
    }
    if (!belongs_to_selected_physical) {
        AddActivity(other_probe_raw_totals_, dx, dy, packet.left_down,
                    packet.left_up);
        return;
    }

    for (auto& [_, accumulator] : probe_raw_) {
        // The participant selected one physical mouse. Windows may surface
        // that mouse as several Raw Input top-level collections, with motion
        // and button observations arriving on sibling handles. Every decoder
        // candidate for the selected USB device therefore receives the same
        // aggregate physical-mouse witness.
        AddActivity(accumulator.totals, dx, dy, packet.left_down,
                    packet.left_up);
        if (accumulator.samples.size() >= 131'072U) continue;
        if (!accumulator.origin_qpc) accumulator.origin_qpc = packet.receipt_qpc;
        device::GestureSample sample;
        sample.relative_time_ns = RelativeNanoseconds(
            packet.receipt_qpc, *accumulator.origin_qpc, clock_.Frequency());
        sample.canonical_dx = static_cast<std::int32_t>(std::clamp<std::int64_t>(
            dx, std::numeric_limits<std::int32_t>::min(),
            std::numeric_limits<std::int32_t>::max()));
        sample.canonical_dy = static_cast<std::int32_t>(std::clamp<std::int64_t>(
            dy, std::numeric_limits<std::int32_t>::min(),
            std::numeric_limits<std::int32_t>::max()));
        sample.left_down = packet.left_down;
        sample.left_up = packet.left_up;
        accumulator.samples.push_back(sample);
    }
}

void ParticipantApplication::CompleteCertification(
    acquisition::CertificationProbeTransportResult transport_result) {
    if (!certification_ || transport_result.cancelled ||
        !transport_result.probe.clean) {
        MarkCertificationAttemptFailed(false, transport_result.probe.detail);
        return;
    }
    auto evidence = std::move(transport_result.probe.evidence);
    for (auto& item : evidence) {
        const auto found = probe_raw_.find(item.probe_route_token);
        if (found == probe_raw_.end()) {
            MarkCertificationAttemptFailed(false,
                                           "probe route did not receive Raw Input evidence");
            return;
        }
        item.selected_raw_input_totals = found->second.totals;
        item.selected_raw_input_samples = found->second.samples;
        item.other_raw_input_totals = other_probe_raw_totals_;
    }
    const auto& decision = certification_->SubmitProbe(evidence);
    if (decision.state != device::CertificationState::Certified ||
        !decision.success) {
        const bool no_activity =
            decision.issue == device::CertificationIssue::InsufficientMovement ||
            decision.issue == device::CertificationIssue::ClickNotObserved ||
            decision.issue == device::CertificationIssue::UsbActivityNotObserved;
        (void)flow_.Apply(Event(no_activity
            ? ParticipantEventKind::CertificationNoActivity
            : ParticipantEventKind::CertificationAmbiguous));
        last_certification_detail_ = decision.explanation;
        return;
    }

    if (!transport_result.probe.validated_identity) {
        MarkCertificationAttemptFailed(
            false, "probe selected no usable USB interrupt stream");
        return;
    }
    const auto identity = *transport_result.probe.validated_identity;
    const auto& lock = decision.success->lock;
    const auto routes = certification_->Routes();
    const auto topology_address = routes.empty()
        ? 0U
        : routes.front().transport.device_address;
    if (identity.usbpcap_root_index != lock.usbpcap_root_index ||
        identity.topology_device_address != topology_address ||
        identity.packet_device != lock.device_address ||
        (!identity.whole_root_capture &&
         identity.filtered_device_address != lock.device_address) ||
        (identity.whole_root_capture &&
         identity.filtered_device_address != 0U)) {
        MarkCertificationAttemptFailed(false,
                                       "probe identity disagreed with certified route");
        return;
    }
    std::vector<device::RawDeviceRoute> raw_routes;
    try {
        raw_routes = device::BuildRawDeviceRoutes(
            inventory_.discovery,
            decision.success->live_identity.raw_interface_token,
            decision.success->live_identity.physical_device_token);
    } catch (const std::exception&) {
        MarkCertificationAttemptFailed(
            false, "selected physical mouse input routes were unavailable");
        return;
    }
    certification_success_ = *decision.success;
    certified_raw_input_routes_ = std::move(raw_routes);
    certified_usb_identity_ = identity;
    if (const auto winner = WinningTransport()) {
        certified_descriptor_ = winner->descriptor_evidence;
    }
    (void)flow_.Apply(Event(ParticipantEventKind::CertificationSucceeded));
    (void)flow_.Apply(ParticipantEvent::SetSensitivity(
        settings_.trainer_sensitivity));
    (void)flow_.Apply(Event(
        settings_.protocol == ProtocolPreference::FullResearch
            ? ParticipantEventKind::ChooseFullResearch
            : ParticipantEventKind::ChooseQuickPractice));
}

void ParticipantApplication::MarkCertificationAttemptFailed(
    const bool permission_denied, std::string detail) {
    last_certification_detail_ = std::move(detail);
    if (certification_ &&
        certification_->Decision().state ==
            device::CertificationState::AwaitingProbe) {
        std::vector<device::CertificationProbeEvidence> failed;
        for (const auto& route : certification_->Routes()) {
            device::CertificationProbeEvidence item;
            item.probe_route_token = route.probe_route_token;
            item.probe_duration_ns = 1;
            item.source_capture_intact = false;
            failed.push_back(std::move(item));
        }
        (void)certification_->SubmitProbe(failed);
    }
    (void)flow_.Apply(Event(permission_denied
        ? ParticipantEventKind::CertificationPermissionDenied
        : ParticipantEventKind::CertificationAmbiguous));
}

void ParticipantApplication::StartRecordingAsync() {
    if (!startup_recovery_complete_ || !certification_success_ ||
        !certified_usb_identity_ || session_future_ || recording_) {
        return;
    }
    if (!flow_.Apply(Event(ParticipantEventKind::StartCapture)).accepted) return;

    acquisition::CaptureHelperRecordingConfig capture_config;
    capture_config.usbpcap_root_index =
        certification_success_->lock.usbpcap_root_index;
    capture_config.filtered_device_address =
        certification_success_->lock.device_address;
    capture_config.descriptor_evidence = certified_descriptor_;

    session::RecordingSessionOptions options;
    options.workspace.output_root = paths_.sessions_directory;
    options.workspace.session_id = session::CreateSessionId();
    options.workspace.user_id = participant_id_;
    options.workspace.application_version = ABDC_VERSION;
    options.workspace.source_revision = ABDC_SOURCE_REVISION;
    options.workspace.protocol_id = "abcurves.capture-trainer.protocol-v3";
    options.workspace.protocol_sha256 = protocol::ProtocolSha256();
    options.workspace.scenario_seed = RandomU64();
    options.workspace.trainer_sensitivity = settings_.trainer_sensitivity;
    options.workspace.qpc_frequency = clock_.Frequency();
    options.workspace.started_utc_ns = UtcNowNs();

    options.trainer.qpc_frequency = clock_.Frequency();
    options.trainer.scenario_seed = options.workspace.scenario_seed;
    options.trainer.trainer_sensitivity = settings_.trainer_sensitivity;
    options.trainer.block_duration_ms =
        ParticipantBlockDurationMs(settings_.protocol);
    if (settings_.protocol == ProtocolPreference::QuickPractice) {
        options.trainer.block_ordinals = protocol::QuickTestBlockOrdinalsV1();
    }

    json::Value plan = json::Value::Object{};
    plan["kind"] = settings_.protocol == ProtocolPreference::FullResearch
        ? "full_research"
        : "quick_practice";
    plan["block_duration_ms"] = options.trainer.block_duration_ms;
    json::Value ordinals = json::Value::Array{};
    json::Value block_ids = json::Value::Array{};
    const auto& selected_ordinals = options.trainer.block_ordinals.empty()
        ? [&]() -> const std::vector<std::size_t>& {
              static const std::vector<std::size_t> all = [] {
                  std::vector<std::size_t> values;
                  values.reserve(protocol::OrderedBlocksV1().size());
                  for (const auto& block : protocol::OrderedBlocksV1()) {
                      values.push_back(block.ordinal);
                  }
                  return values;
              }();
              return all;
          }()
        : options.trainer.block_ordinals;
    for (const auto ordinal : selected_ordinals) {
        ordinals.AsArray().emplace_back(static_cast<std::int64_t>(ordinal));
        block_ids.AsArray().emplace_back(
            protocol::OrderedBlocksV1().at(ordinal).block_id);
    }
    plan["canonical_block_ordinals"] = std::move(ordinals);
    plan["block_ids"] = std::move(block_ids);
    options.workspace.protocol_plan = std::move(plan);

    json::Value presentation = json::Value::Object{};
    presentation["crosshair_scale"] = settings_.crosshair_scale;
    presentation["target_highlight_enabled"] =
        settings_.target_highlight_enabled;
    presentation["fullscreen_at_start"] = window_.IsFullscreen();
    presentation["raw_input_axis_adapter"] = "windows_y_down_to_canonical_y_up";
    presentation["usb_axis_storage"] = "native_hid_signed_counts";
    options.workspace.presentation = std::move(presentation);

    const auto& safe = certification_success_->lock;
    options.locked_mouse.selection_token =
        certification_success_->live_identity.raw_interface_token;
    options.locked_mouse.display_name = safe.product_name;
    options.locked_mouse.vendor_id = safe.vendor_id;
    options.locked_mouse.product_id = safe.product_id;
    options.locked_mouse.usb_bus = certified_usb_identity_->packet_bus;
    options.locked_mouse.usb_device = certified_usb_identity_->packet_device;
    options.locked_mouse.interrupt_in_endpoint = safe.endpoint_address;
    options.locked_mouse.hid_descriptor_sha256 = safe.descriptor_sha256;

    options.certification_metadata =
        json::Parse(certification_success_->sanitized_manifest_json);
    json::Value packet_identity = json::Value::Object{};
    packet_identity["usbpcap_root_index"] =
        static_cast<std::int64_t>(certified_usb_identity_->usbpcap_root_index);
    packet_identity["topology_device_address"] =
        static_cast<std::int64_t>(
            certified_usb_identity_->topology_device_address);
    packet_identity["filtered_device_address"] =
        static_cast<std::int64_t>(certified_usb_identity_->filtered_device_address);
    packet_identity["packet_bus"] =
        static_cast<std::int64_t>(certified_usb_identity_->packet_bus);
    packet_identity["packet_device"] =
        static_cast<std::int64_t>(certified_usb_identity_->packet_device);
    packet_identity["probe_capture_scope"] =
        certified_usb_identity_->whole_root_capture
            ? "transient_whole_root"
            : "exact_address";
    packet_identity["recording_filtered_device_address"] =
        static_cast<std::int64_t>(safe.device_address);
    options.certification_metadata["validated_usbpcap_identity"] =
        std::move(packet_identity);

    options.unpresented_render_calibration = CurrentRenderEvidence();
    options.retain_raw_input_witness = true;

    session_result_handled_ = false;
    observed_event_count_ = 0;
    observed_block_count_ = 0;
    selected_raw_input_warning_reported_ = false;
    selected_input_route_unavailable_ = false;
    live_input_rebind_rescan_requested_ = false;
    session_future_.emplace(std::async(
        std::launch::async,
        [capture_config = std::move(capture_config),
         options = std::move(options)]() mutable {
            SessionBootstrap result;
            result.capture =
                std::make_unique<acquisition::CaptureHelperRecordingControl>(
                    std::move(capture_config));
            result.session = session::RecordingSession::Create(
                std::move(options), *result.capture);
            return result;
        }));
}

void ParticipantApplication::PollRecordingBootstrap(
    const std::int64_t now_qpc) {
    if (!session_future_ || !FutureReady(*session_future_)) return;
    try {
        auto bootstrap = session_future_->get();
        recording_capture_ = std::move(bootstrap.capture);
        recording_ = std::move(bootstrap.session);
        session_future_.reset();
        recording_->SampleClockAnchor("capture_ready");
        final_clock_anchor_sampled_ = false;
        next_clock_anchor_qpc_ = SaturatingFutureTick(
            now_qpc, clock_.TicksFromMilliseconds(30'000.0));
        next_storage_check_qpc_ = SaturatingFutureTick(
            now_qpc, clock_.TicksFromMilliseconds(10'000.0));
        (void)flow_.Apply(Event(ParticipantEventKind::CaptureStarted));
        if (close_requested_) {
            FinishAndSave(now_qpc, "window_close_requested");
        }
    } catch (...) {
        session_future_.reset();
        (void)flow_.Apply(ParticipantEvent::Failure(
            DestructiveFailure::HelperLost));
        (void)flow_.Apply(Event(
            ParticipantEventKind::PrefixPreservationFailed));
        if (close_requested_) RequestFinalWindowClose();
    }
}

void ParticipantApplication::StartLiveInputRebind() {
    if (!recording_ || !certification_success_) return;
    if (live_input_rebind_future_) {
        live_input_rebind_rescan_requested_ = true;
        return;
    }
    live_input_rebind_rescan_requested_ = false;
    const auto salt = inventory_salt_;
    live_input_rebind_future_.emplace(
        std::async(std::launch::async, [salt] {
            return device::DiscoverWindowsMouseInterfaces(salt);
        }));
}

void ParticipantApplication::PollLiveInputRebind(
    const std::int64_t now_qpc) {
    if (!live_input_rebind_future_ ||
        !FutureReady(*live_input_rebind_future_)) {
        return;
    }

    bool rebound = false;
    try {
        const auto snapshot = live_input_rebind_future_->get();
        if (certification_success_) {
            auto& live = certification_success_->live_identity;
            const auto status = device::ClassifySelectedInterface(
                snapshot, live.raw_interface_token,
                live.physical_device_token, live.raw_input_handle);
            if (status == device::SelectedInterfaceStatus::Present ||
                status == device::SelectedInterfaceStatus::HandleReplaced) {
                const device::MouseInterfaceCandidate* selected = nullptr;
                for (const auto& mouse : snapshot.mice) {
                    if (mouse.session_token != live.raw_interface_token) continue;
                    if (selected != nullptr) {
                        selected = nullptr;
                        break;
                    }
                    selected = &mouse;
                }
                if (selected != nullptr && selected->raw_input_handle != 0U) {
                    live.raw_input_handle = selected->raw_input_handle;
                    certified_raw_input_routes_ = device::BuildRawDeviceRoutes(
                        snapshot, live.raw_interface_token,
                        live.physical_device_token);
                    rebound = true;
                }
            }
        }
    } catch (...) {
        // Keep capture alive and the trainer paused. A later Windows device
        // arrival can request one more coherent discovery snapshot.
    }
    live_input_rebind_future_.reset();

    if (rebound && selected_input_route_unavailable_) {
        selected_input_route_unavailable_ = false;
        (void)flow_.Apply(
            Event(ParticipantEventKind::GameplayInputRestored));
        if (recording_ &&
            flow_.State().stage == ParticipantStage::ResumeCountdown) {
            (void)recording_->ResumeAfterRecoverableIssue(
                now_qpc, "gameplay_input_restored");
        }
    } else if (live_input_rebind_rescan_requested_) {
        StartLiveInputRebind();
    }
}

void ParticipantApplication::DriveRecording(const std::int64_t now_qpc) {
    if (!recording_) return;
    const auto before_advance = recording_->state();
    if ((before_advance ==
             session::RecordingSessionState::AwaitingCaptureReady ||
         before_advance == session::RecordingSessionState::Recording ||
         before_advance == session::RecordingSessionState::Paused) &&
        now_qpc >= next_storage_check_qpc_) {
        try {
            constexpr std::uintmax_t kMinimumFreeBytes =
                64ULL * 1024ULL * 1024ULL;
            if (std::filesystem::space(paths_.sessions_directory).available <
                kMinimumFreeBytes) {
                recording_->ReportIssue(
                    session::RuntimeIssue::StorageWriteFailed, now_qpc,
                    "session storage has less than 64 MiB available");
            }
        } catch (const std::exception&) {
            // Capacity telemetry is advisory. Actual writes and durable raw
            // checkpoints remain the authoritative storage-integrity guard.
        }
        next_storage_check_qpc_ = SaturatingFutureTick(
            now_qpc, clock_.TicksFromMilliseconds(10'000.0));
    }
    recording_->AdvanceTo(now_qpc);
    ObserveCompletedEventsAndBlocks();

    const auto recording_state = recording_->state();
    if ((recording_state == session::RecordingSessionState::AwaitingCaptureReady ||
         recording_state == session::RecordingSessionState::Recording ||
         recording_state == session::RecordingSessionState::Paused) &&
        now_qpc >= next_clock_anchor_qpc_) {
        recording_->SampleClockAnchor("periodic_30s");
        next_clock_anchor_qpc_ = SaturatingFutureTick(
            now_qpc, clock_.TicksFromMilliseconds(30'000.0));
    }

    const auto engine_state = recording_->trainer().state();
    if (flow_.State().stage == ParticipantStage::Countdown &&
        CountdownReachedGameplay(engine_state)) {
        (void)flow_.Apply(Event(ParticipantEventKind::CountdownFinished));
    } else if (flow_.State().stage == ParticipantStage::ResumeCountdown &&
               CountdownReachedGameplay(engine_state)) {
        (void)flow_.Apply(Event(
            ParticipantEventKind::ResumeCountdownFinished));
    }

    if (recording_->state() == session::RecordingSessionState::StopRequested) {
        if (!final_clock_anchor_sampled_) {
            recording_->SampleClockAnchor("capture_stop_observed");
            final_clock_anchor_sampled_ = true;
        }
        const auto capture = recording_capture_->Snapshot();
        if (capture.shutdown_failed) {
            if (flow_.State().stage == ParticipantStage::StoppingAndSaving) {
                (void)flow_.Apply(ParticipantEvent::Failure(
                    DestructiveFailure::HelperLost));
            }
            if (flow_.State().stage ==
                ParticipantStage::StoppingAndPreserving) {
                (void)flow_.Apply(Event(
                    ParticipantEventKind::PrefixPreservationFailed));
            }
            window_.ReleaseMouse();
            if (close_requested_) RequestFinalWindowClose();
            return;
        }
        if (flow_.State().stage != ParticipantStage::StoppingAndSaving &&
            flow_.State().stage != ParticipantStage::StoppingAndPreserving) {
            if (capture.fatal_issue) {
                (void)flow_.Apply(ParticipantEvent::Failure(
                    ParticipantFailure(*capture.fatal_issue)));
            } else {
                (void)flow_.Apply(Event(ParticipantEventKind::FinishSession));
            }
        }
        (void)recording_->TryFinalize(now_qpc, UtcNowNs());
    }

    if (!recording_->Result() || session_result_handled_) return;
    session_result_handled_ = true;
    const auto& result = *recording_->Result();
    if (result.archive) submission_archive_ = result.archive->path;
    const bool archive_ready = result.success && result.archive.has_value();
    const bool recovery_result = result.recovery_was_required ||
                                 result.status == session::SessionStatus::CaptureLost;
    if (recovery_result &&
        flow_.State().stage == ParticipantStage::StoppingAndSaving) {
        (void)flow_.Apply(ParticipantEvent::Failure(
            DestructiveFailure::CaptureLost));
    }
    if (flow_.State().stage == ParticipantStage::StoppingAndPreserving) {
        const auto outcome = !archive_ready
            ? ParticipantEventKind::PrefixPreservationFailed
            : result.verified_authoritative_source
                ? ParticipantEventKind::PrefixPreserved
                : ParticipantEventKind::UnverifiedArchivePreserved;
        (void)flow_.Apply(Event(outcome));
    } else if (flow_.State().stage == ParticipantStage::StoppingAndSaving) {
        if (archive_ready) {
            (void)flow_.Apply(Event(ParticipantEventKind::SaveCompleted));
        } else {
            (void)flow_.Apply(ParticipantEvent::Failure(
                DestructiveFailure::IntegrityFailure));
            (void)flow_.Apply(Event(
                ParticipantEventKind::PrefixPreservationFailed));
        }
    }
    window_.ReleaseMouse();
    if (close_requested_) RequestFinalWindowClose();
}

void ParticipantApplication::BeginTrainerCountdown(
    const std::int64_t now_qpc) {
    if (!recording_ || !flow_.State().CanBeginCountdown()) return;
    if (recording_->TryStart(now_qpc)) {
        recording_->SampleClockAnchor("trainer_start");
        (void)flow_.Apply(Event(ParticipantEventKind::BeginCountdown));
        window_.CaptureMouse();
    }
}

void ParticipantApplication::PauseTrainer(const std::int64_t now_qpc) {
    if (!recording_) return;
    if (flow_.Apply(Event(ParticipantEventKind::ManualPause)).accepted) {
        recording_->ManualPause(now_qpc);
        window_.ReleaseMouse();
    }
}

void ParticipantApplication::ResumeTrainer(const std::int64_t now_qpc) {
    if (!recording_ || !flow_.State().CanResume()) return;
    if (recording_->ManualResume(now_qpc) &&
        flow_.Apply(Event(ParticipantEventKind::Resume)).accepted) {
        window_.CaptureMouse();
    }
}

void ParticipantApplication::FinishAndSave(const std::int64_t now_qpc,
                                           std::string reason) {
    if (!recording_) return;
    if (flow_.State().stage != ParticipantStage::StoppingAndSaving &&
        flow_.State().stage != ParticipantStage::StoppingAndPreserving) {
        (void)flow_.Apply(Event(ParticipantEventKind::FinishSession));
    }
    recording_->RequestParticipantStop(now_qpc, std::move(reason));
    window_.ReleaseMouse();
}

void ParticipantApplication::ObserveCompletedEventsAndBlocks() {
    if (!recording_) return;
    const auto& events = recording_->trainer().events();
    while (observed_event_count_ < events.size()) {
        const auto& event = events[observed_event_count_++];
        if (settings_.audio_enabled &&
            (event.natural_outcome == trainer::NaturalOutcome::hit_click ||
             event.natural_outcome == trainer::NaturalOutcome::hit_dwell)) {
            audio_.PlaySfx(PopSound(settings_.hit_sound));
        }
    }
    const auto& blocks = recording_->trainer().block_results();
    while (observed_block_count_ < blocks.size() &&
           blocks[observed_block_count_].completed_qpc.has_value()) {
        const auto& block = blocks[observed_block_count_++];
        if (block.ordinal < protocol::OrderedBlocksV1().size()) {
            (void)highscores_->RecordScore(
                CanonicalHighscoreKey(
                    protocol::OrderedBlocksV1().at(block.ordinal)),
                block.score);
        }
    }
}

void ParticipantApplication::HandleRawInput(
    HRAWINPUT input, const std::int64_t receipt_qpc) {
    const auto mouse = raw_input_.ReadMouse(input, receipt_qpc);
    if (!mouse) return;
    AccumulateProbeRawInput(*mouse);
    if (!recording_ || !certification_success_) return;

    const auto raw_origin = device::OriginForRawHandle(
        certified_raw_input_routes_, mouse->device_handle);
    const bool selected =
        raw_origin == device::RawDeviceOrigin::SelectedActive ||
        raw_origin == device::RawDeviceOrigin::SelectedPhysicalSibling;
    trainer::RawInputPacket packet;
    packet.qpc = mouse->receipt_qpc;
    if (mouse->relative) {
        packet.dx_counts = mouse->dx;
        packet.dy_counts = -mouse->dy;
        packet.left_button_down = mouse->left_down;
        packet.left_button_up = mouse->left_up;
    }

    session::RawInputSource source;
    source.selected_device = selected && mouse->relative;
    source.device_token = source.selected_device
        ? certification_success_->live_identity.raw_interface_token
        : "other-mouse";
    source.button_flags = mouse->native_button_flags;
    source.button_data = mouse->wheel;
    recording_->SubmitRawInput(packet, source);

    if (mouse->device_handle ==
            certification_success_->live_identity.raw_input_handle &&
        !mouse->relative &&
        !selected_raw_input_warning_reported_) {
        selected_raw_input_warning_reported_ = true;
        recording_->ReportIssue(
            session::RuntimeIssue::RawInputUnavailable, receipt_qpc,
            "selected Windows input packet was absolute; USB capture continued");
        (void)flow_.Apply(ParticipantEvent::Warning(
            OptionalWarning::InputWitnessUnavailable));
    }
}

void ParticipantApplication::HandleKey(const UINT key, const bool down) {
    if (!down) {
        keys_down_.erase(key);
        return;
    }
    if (!keys_down_.insert(key).second) return;
    const auto now = clock_.NowTicks();
    if (key == VK_F11) {
        if (recording_ && IsGameplayStage()) {
            (void)flow_.Apply(Event(ParticipantEventKind::DisplayChanged));
            recording_->ReportIssue(session::RuntimeIssue::DisplayChanged, now,
                                    "fullscreen mode changed");
        }
        window_.ToggleFullscreen();
        settings_.fullscreen = window_.IsFullscreen();
        (void)SaveParticipantSettings(paths_.settings_file, settings_);
        return;
    }
    if (key != VK_ESCAPE) return;
    switch (flow_.State().stage) {
    case ParticipantStage::Playing:
    case ParticipantStage::Countdown:
    case ParticipantStage::ResumeCountdown:
        PauseTrainer(now);
        break;
    case ParticipantStage::Paused:
        ResumeTrainer(now);
        break;
    default:
        break;
    }
}

void ParticipantApplication::HandleMouseMove(const int x, const int y) {
    mouse_ndc_x_ = MouseNdcX(x);
    mouse_ndc_y_ = MouseNdcY(y);
    if (!dragging_slider_) return;
    for (const auto& hitbox : last_ui_.hitboxes) {
        if (hitbox.action != *dragging_slider_ ||
            hitbox.role != ParticipantUiControlRole::Slider) {
            continue;
        }
        if (const auto value =
                ParticipantSliderNormalizedValue(hitbox, mouse_ndc_x_)) {
            ApplySlider(*dragging_slider_, *value);
        }
        break;
    }
}

void ParticipantApplication::HandleMouseButton(const int x, const int y,
                                               const bool down) {
    mouse_ndc_x_ = MouseNdcX(x);
    mouse_ndc_y_ = MouseNdcY(y);
    if (!down) {
        dragging_slider_.reset();
        return;
    }
    const auto hit = HitTestParticipantUi(last_ui_.hitboxes, mouse_ndc_x_,
                                          mouse_ndc_y_);
    if (!hit) return;
    if (hit->normalized_value) {
        dragging_slider_ = hit->action;
        ApplySlider(hit->action, *hit->normalized_value);
    } else {
        ActivateUiHit(*hit);
    }
}

void ParticipantApplication::HandleFocus(const bool focused) {
    const auto now = clock_.NowTicks();
    if (recording_) {
        recording_->SetFocus(focused, IsIconic(window_.Handle()) != FALSE, now);
    }
    if (focused) {
        (void)flow_.Apply(Event(ParticipantEventKind::FocusRestored));
        if (recording_ &&
            flow_.State().stage == ParticipantStage::ResumeCountdown) {
            (void)recording_->ResumeAfterRecoverableIssue(
                now, "environment_restored");
        }
    } else {
        (void)flow_.Apply(Event(ParticipantEventKind::FocusLost));
        window_.ReleaseMouse();
    }
}

void ParticipantApplication::HandleResize(const UINT width,
                                          const UINT height) {
    if (!renderer_ready_ || width == 0U || height == 0U) return;
    const auto now = clock_.NowTicks();
    bool resized = false;
    try {
        resized = renderer_.Resize(width, height);
    } catch (...) {
    }
    if (!resized) {
        HandlePresentationFailure(now, "render surface resize failed");
        return;
    }
    if (recording_) {
        (void)flow_.Apply(Event(ParticipantEventKind::DisplayStable));
        if (flow_.State().stage == ParticipantStage::ResumeCountdown) {
            (void)recording_->ResumeAfterRecoverableIssue(
                clock_.NowTicks(), "display_stable");
        }
    }
}

void ParticipantApplication::HandlePresentationFailure(
    const std::int64_t qpc, const std::string_view detail) noexcept {
    const bool newly_unavailable = !graphics_pause_active_;
    renderer_ready_ = false;
    graphics_pause_active_ = true;
    next_graphics_retry_qpc_ = qpc;
    ResetPresentationWatchdog();
    if (!newly_unavailable) return;

    try {
        if (recording_ && IsGameplayStage()) {
            (void)flow_.Apply(Event(ParticipantEventKind::DisplayChanged));
            recording_->ReportIssue(
                session::RuntimeIssue::GraphicsDeviceLost, qpc,
                std::string(detail));
        }
    } catch (...) {
        // Presentation is not authoritative capture. The recording session's
        // own storage/integrity boundary decides whether it must stop.
    }
}

void ParticipantApplication::ResetPresentationWatchdog() noexcept {
    pending_presentation_event_id_.reset();
    pending_presentation_since_qpc_ = 0;
}

void ParticipantApplication::HandleSystemEvent(
    const UINT message, const WPARAM wparam, const LPARAM lparam) {
    const auto now = clock_.NowTicks();
    if (message == WM_INPUT_DEVICE_CHANGE) {
        const auto changed_handle = static_cast<std::uintptr_t>(lparam);
        const auto changed_origin = device::OriginForRawHandle(
            certified_raw_input_routes_, changed_handle);
        const bool selected_physical_handle =
            changed_origin == device::RawDeviceOrigin::SelectedActive ||
            changed_origin == device::RawDeviceOrigin::SelectedPhysicalSibling;
        if (recording_ && certification_success_ && wparam == GIDC_REMOVAL &&
            selected_physical_handle) {
            if (!selected_input_route_unavailable_) {
                selected_input_route_unavailable_ = true;
                (void)flow_.Apply(
                    Event(ParticipantEventKind::GameplayInputLost));
                recording_->ReportIssue(
                    session::RuntimeIssue::GameplayInputUnavailable, now,
                    "Windows removed the selected gameplay input handle; "
                    "authoritative USB capture remains in control");
            }
            StartLiveInputRebind();
        } else if (recording_ && certification_success_ &&
                   wparam == GIDC_ARRIVAL) {
            StartLiveInputRebind();
        }
        return;
    }
    if (message == WM_SIZE) {
        if (wparam == SIZE_MINIMIZED) {
            (void)flow_.Apply(Event(ParticipantEventKind::Minimized));
            if (recording_) recording_->SetFocus(false, true, now);
            window_.ReleaseMouse();
        } else {
            if (recording_ && IsGameplayStage()) {
                (void)flow_.Apply(Event(ParticipantEventKind::DisplayChanged));
                recording_->ReportIssue(session::RuntimeIssue::DisplayChanged,
                                        now, "trainer viewport changed");
            }
            (void)flow_.Apply(Event(ParticipantEventKind::Restored));
            if (recording_) {
                recording_->SetFocus(window_.HasFocus(), false, now);
            }
        }
        return;
    }
    if (message == WM_DISPLAYCHANGE || message == WM_DPICHANGED) {
        if (recording_ && IsGameplayStage()) {
            (void)flow_.Apply(Event(ParticipantEventKind::DisplayChanged));
            recording_->ReportIssue(session::RuntimeIssue::DisplayChanged, now,
                                    "display configuration changed");
        }
        HandleResize(window_.ClientWidth(), window_.ClientHeight());
        return;
    }
    if (message == WM_POWERBROADCAST && recording_) {
        if (wparam == PBT_APMSUSPEND) {
            (void)flow_.Apply(Event(ParticipantEventKind::FocusLost));
            recording_->ReportIssue(session::RuntimeIssue::SystemSuspend, now,
                                    "Windows is suspending");
            window_.ReleaseMouse();
        } else if (wparam == PBT_APMRESUMEAUTOMATIC ||
                   wparam == PBT_APMRESUMESUSPEND) {
            recording_->SetFocus(window_.HasFocus(),
                                 IsIconic(window_.Handle()) != FALSE, now);
            if (window_.HasFocus()) {
                (void)flow_.Apply(Event(ParticipantEventKind::FocusRestored));
                if (flow_.State().stage ==
                    ParticipantStage::ResumeCountdown) {
                    (void)recording_->ResumeAfterRecoverableIssue(
                        now, "system_resume");
                }
            }
        }
    }
}

bool ParticipantApplication::HandleClose() {
    if (allow_close_) return true;
    close_requested_ = true;
    const auto stage = flow_.State().stage;
    if (abandoned_recovery_future_) return false;
    if (probe_client_) {
        (void)probe_client_->RequestCancel();
        return false;
    }
    if (session_future_) return false;
    if (stage == ParticipantStage::Error ||
        stage == ParticipantStage::Complete ||
        stage == ParticipantStage::Cancelled) {
        allow_close_ = true;
        return true;
    }
    if (recording_ && !recording_->Result()) {
        FinishAndSave(clock_.NowTicks(), "window_close_requested");
        return false;
    }
    if (stage == ParticipantStage::StoppingAndSaving ||
        stage == ParticipantStage::StoppingAndPreserving) {
        return false;
    }
    allow_close_ = true;
    return true;
}

void ParticipantApplication::ActivateUiHit(const ParticipantUiHit& hit) {
    const auto now = clock_.NowTicks();
    switch (hit.action) {
    case ParticipantUiAction::AcceptPrivacy:
        if (!startup_recovery_complete_) break;
        if (flow_.Apply(Event(ParticipantEventKind::AcceptPrivacy)).accepted) {
            StartInventoryScan();
        }
        break;
    case ParticipantUiAction::Exit:
        PostMessageW(window_.Handle(), WM_CLOSE, 0, 0);
        break;
    case ParticipantUiAction::SelectMouse:
        SelectMouse(hit.item_index);
        break;
    case ParticipantUiAction::RefreshMouseList:
        StartInventoryScan();
        break;
    case ParticipantUiAction::BeginCertification:
        StartCertification();
        break;
    case ParticipantUiAction::RetryCertification:
        if (certification_) (void)certification_->Retry();
        (void)flow_.Apply(Event(ParticipantEventKind::RetryCertification));
        break;
    case ParticipantUiAction::ChooseDifferentMouse:
        if (probe_client_) (void)probe_client_->RequestCancel();
        if (certification_) (void)certification_->Cancel();
        certification_.reset();
        certification_success_.reset();
        certified_raw_input_routes_.clear();
        certified_usb_identity_.reset();
        certified_descriptor_.clear();
        selected_mouse_.reset();
        (void)flow_.Apply(Event(ParticipantEventKind::ChooseDifferentMouse));
        break;
    case ParticipantUiAction::Cancel:
        if (probe_client_) (void)probe_client_->RequestCancel();
        if (certification_) (void)certification_->Cancel();
        (void)flow_.Apply(Event(ParticipantEventKind::Cancel));
        break;
    case ParticipantUiAction::ToggleTargetHighlight:
        settings_.target_highlight_enabled =
            !settings_.target_highlight_enabled;
        break;
    case ParticipantUiAction::ChooseFullResearch:
        settings_.protocol = ProtocolPreference::FullResearch;
        (void)flow_.Apply(Event(ParticipantEventKind::ChooseFullResearch));
        break;
    case ParticipantUiAction::ChooseQuickPractice:
        settings_.protocol = ProtocolPreference::QuickPractice;
        (void)flow_.Apply(Event(ParticipantEventKind::ChooseQuickPractice));
        break;
    case ParticipantUiAction::ConfirmConfiguration:
        if (flow_.Apply(Event(ParticipantEventKind::ConfirmConfiguration)).accepted) {
            (void)SaveParticipantSettings(paths_.settings_file, settings_);
        }
        break;
    case ParticipantUiAction::EditConfiguration:
        (void)flow_.Apply(Event(ParticipantEventKind::EditConfiguration));
        break;
    case ParticipantUiAction::StartCapture:
        StartRecordingAsync();
        break;
    case ParticipantUiAction::BeginCountdown:
        BeginTrainerCountdown(now);
        break;
    case ParticipantUiAction::Pause:
        PauseTrainer(now);
        break;
    case ParticipantUiAction::Resume:
        ResumeTrainer(now);
        break;
    case ParticipantUiAction::FinishAndSave:
        FinishAndSave(now, "participant_finished_early");
        break;
    case ParticipantUiAction::ToggleAudio:
        settings_.audio_enabled = !settings_.audio_enabled;
        (void)SaveParticipantSettings(paths_.settings_file, settings_);
        break;
    case ParticipantUiAction::SelectPop1:
    case ParticipantUiAction::SelectPop2:
    case ParticipantUiAction::SelectPop3:
        settings_.hit_sound = hit.action == ParticipantUiAction::SelectPop1
            ? HitSound::Pop1
            : hit.action == ParticipantUiAction::SelectPop2 ? HitSound::Pop2
                                                             : HitSound::Pop3;
        if (settings_.audio_enabled) audio_.PlaySfx(PopSound(settings_.hit_sound));
        (void)SaveParticipantSettings(paths_.settings_file, settings_);
        break;
    case ParticipantUiAction::OpenSendThisFolder:
        OpenSubmissionFolder();
        break;
    case ParticipantUiAction::Done:
        RequestFinalWindowClose();
        break;
    case ParticipantUiAction::None:
    case ParticipantUiAction::SetCrosshairScale:
    case ParticipantUiAction::SetSensitivity:
        break;
    }
}

void ParticipantApplication::ApplySlider(const ParticipantUiAction action,
                                         const double normalized) {
    const double value = std::clamp(normalized, 0.0, 1.0);
    if (action == ParticipantUiAction::SetCrosshairScale) {
        settings_.crosshair_scale = kMinimumCrosshairScale +
            value * (kMaximumCrosshairScale - kMinimumCrosshairScale);
    } else if (action == ParticipantUiAction::SetSensitivity) {
        settings_.trainer_sensitivity = kMinimumTrainerSensitivity +
            value * (kMaximumTrainerSensitivity - kMinimumTrainerSensitivity);
        (void)flow_.Apply(
            ParticipantEvent::SetSensitivity(settings_.trainer_sensitivity));
    }
}

void ParticipantApplication::UpdateMouseCapture() {
    const auto stage = flow_.State().stage;
    const bool should_capture = window_.HasFocus() &&
        (stage == ParticipantStage::Countdown ||
         stage == ParticipantStage::Playing ||
         stage == ParticipantStage::ResumeCountdown);
    if (should_capture && !window_.HasMouseCapture()) {
        window_.CaptureMouse();
    } else if (!should_capture && window_.HasMouseCapture()) {
        window_.ReleaseMouse();
    }
}

void ParticipantApplication::OpenSubmissionFolder() const {
    const auto directory = submission_archive_.empty()
        ? paths_.sessions_directory
        : submission_archive_.parent_path();
    (void)ShellExecuteW(window_.Handle(), L"open", directory.c_str(), nullptr,
                        nullptr, SW_SHOWNORMAL);
}

void ParticipantApplication::RequestFinalWindowClose() {
    allow_close_ = true;
    PostMessageW(window_.Handle(), WM_CLOSE, 0, 0);
}

ParticipantUiInput ParticipantApplication::BuildUiInput(
    const std::int64_t now_qpc) const {
    ParticipantUiInput input;
    input.flow = flow_.State();
    input.settings = settings_;
    input.startup_recovery = startup_recovery_ui_;
    input.startup_recovery.close_requested = close_requested_;
    input.mice = inventory_.participant_options;
    input.mouse_scan_in_progress = inventory_future_.has_value();
    input.selected_mouse = selected_mouse_;
    if (!submission_archive_.empty()) {
        input.send_this_filename = submission_archive_.filename().string();
    }
    if (probe_sampling_) {
        const auto elapsed = clock_.TicksToMilliseconds(
            std::max<std::int64_t>(0, now_qpc - probe_sampling_started_qpc_));
        input.certification_progress = std::clamp(elapsed / 10'000.0, 0.0, 1.0);
    }

    if (!recording_) return input;
    const auto& trainer = recording_->trainer();
    const auto remaining_countdown = trainer.countdown_remaining_ms();
    if (remaining_countdown > 0) {
        input.countdown_number = static_cast<int>(
            std::max<std::int64_t>(1, (remaining_countdown + 999) / 1000));
        input.gameplay.countdown = input.countdown_number;
    }
    const auto* block = trainer.current_block();
    if (block) {
        input.gameplay.challenge_name = block->display_name;
        input.gameplay.block_index =
            static_cast<std::uint32_t>(trainer.current_plan_index() + 1U);
        input.gameplay.block_count = static_cast<std::uint32_t>(
            trainer.planned_block_ordinals().size());
        if (highscores_) {
            input.gameplay.highscore = highscores_->BestScore(
                CanonicalHighscoreKey(*block)).value_or(0);
        }
    }
    input.gameplay.score = trainer.current_score();
    input.gameplay.remaining_seconds =
        std::max<std::int64_t>(0, trainer.block_remaining_ms()) / 1000.0;
    if (!window_.HasFocus()) {
        input.gameplay.warnings.push_back(
            ParticipantHudWarning::ReturnToWindow);
    }
    if (!flow_.State().warnings.empty()) {
        input.gameplay.warnings.push_back(
            ParticipantHudWarning::MomentMarkedForReview);
    }
    return input;
}

session::RenderEvidence ParticipantApplication::CurrentRenderEvidence() const {
    session::RenderEvidence evidence;
    evidence.viewport_width_px = static_cast<int>(window_.ClientWidth());
    evidence.viewport_height_px = static_cast<int>(window_.ClientHeight());
    const auto calibration = protocol::CountSpaceCalibrationForSensitivity(
        settings_.trainer_sensitivity);
    const double shortest = static_cast<double>(std::min(
        window_.ClientWidth(), window_.ClientHeight()));
    const double pixels_per_count =
        calibration.effective_radians_per_count * shortest /
        protocol::V1Constants::pi;
    evidence.pixels_per_count_x = pixels_per_count;
    evidence.pixels_per_count_y = pixels_per_count;
    evidence.counts_per_pixel_x = 1.0 / pixels_per_count;
    evidence.counts_per_pixel_y = 1.0 / pixels_per_count;
    evidence.transform_revision = "linear-countspace-v1";
    evidence.effective_radians_per_count =
        calibration.effective_radians_per_count;
    evidence.crosshair_scale = settings_.crosshair_scale;
    evidence.target_highlight_enabled = settings_.target_highlight_enabled;
    evidence.fullscreen = window_.IsFullscreen();
    return evidence;
}

void ParticipantApplication::Render(const std::int64_t now_qpc) {
    if (!renderer_ready_) return;
    last_ui_ = BuildParticipantUi(BuildUiInput(now_qpc));

    double target_x = 0.0;
    double target_y = 0.0;
    double target_radius = 1.0;
    bool target_visible = false;
    bool presentation_required = false;
    std::optional<std::int64_t> target_event_id;
    bool inside_target = false;
    float target_visual_strength = 1.0F;
    std::int64_t camera_x = 0;
    std::int64_t camera_y = 0;
    double radians_per_count =
        protocol::CountSpaceCalibrationForSensitivity(
            settings_.trainer_sensitivity)
            .effective_radians_per_count;

    if (recording_) {
        const auto camera = recording_->trainer().camera();
        camera_x = camera.x;
        camera_y = camera.y;
        if (flow_.State().stage == ParticipantStage::Playing) {
            if (const auto target = recording_->trainer().target_view()) {
                target_x = target->relative_x_counts;
                target_y = target->relative_y_counts;
                target_radius = target->radius_counts;
                target_visible = true;
                presentation_required = target->presentation_required;
                target_event_id = target->event_id;
                target_visual_strength = target->visual_strength;
                inside_target = target_x * target_x + target_y * target_y <=
                                target_radius * target_radius;
            }
        }
    }

    const auto stage = flow_.State().stage;
    const bool aiming = stage == ParticipantStage::Countdown ||
                        stage == ParticipantStage::Playing ||
                        stage == ParticipantStage::ResumeCountdown;
    const auto rendered = renderer_.Render(
        target_x, target_y, target_radius, camera_x, camera_y,
        radians_per_count, settings_.crosshair_scale, aiming,
        settings_.target_highlight_enabled, inside_target, target_visible,
        target_visual_strength,
        aiming, last_ui_.layer);

    if (rendered.status == RenderStatus::DeviceLost ||
        rendered.status == RenderStatus::Failed) {
        HandlePresentationFailure(
            now_qpc, "graphics presentation device was lost");
        return;
    }

    const bool target_presented = rendered.status == RenderStatus::Ok &&
        rendered.target_drawn;
    if (presentation_required && target_event_id.has_value() &&
        !target_presented) {
        if (pending_presentation_event_id_ != target_event_id) {
            pending_presentation_event_id_ = target_event_id;
            pending_presentation_since_qpc_ = now_qpc;
        } else if (now_qpc - pending_presentation_since_qpc_ >=
                   clock_.TicksFromMilliseconds(250.0)) {
            HandlePresentationFailure(
                now_qpc, "target could not be presented promptly");
        }
        return;
    }

    ResetPresentationWatchdog();
    if (target_presented && presentation_required && recording_ &&
        flow_.State().stage == ParticipantStage::Playing) {
        (void)recording_->AcknowledgeTargetPresented(
            clock_.NowTicks(), CurrentRenderEvidence());
    }
}

std::optional<device::ResolvedUsbMouseTransport>
ParticipantApplication::WinningTransport() const {
    if (!certification_ || !certification_success_) return std::nullopt;
    const auto& lock = certification_success_->lock;
    for (const auto& route : certification_->Routes()) {
        const auto& transport = route.transport;
        if (transport.usbpcap_root_index == lock.usbpcap_root_index &&
            transport.interface_number == lock.interface_number &&
            transport.endpoint_address == lock.endpoint_address &&
            transport.descriptor_sha256 == lock.descriptor_sha256) {
            return transport;
        }
    }
    return std::nullopt;
}

bool ParticipantApplication::IsGameplayStage() const noexcept {
    const auto stage = flow_.State().stage;
    return stage == ParticipantStage::Countdown ||
           stage == ParticipantStage::Playing ||
           stage == ParticipantStage::Paused ||
           stage == ParticipantStage::ResumeCountdown;
}

float ParticipantApplication::MouseNdcX(const int x) const noexcept {
    return static_cast<float>(2.0 * static_cast<double>(x) /
                              static_cast<double>(window_.ClientWidth()) -
                              1.0);
}

float ParticipantApplication::MouseNdcY(const int y) const noexcept {
    return static_cast<float>(1.0 -
        2.0 * static_cast<double>(y) /
            static_cast<double>(window_.ClientHeight()));
}

}  // namespace abdc::app
