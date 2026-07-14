#pragma once

#include "acquisition/CaptureHelperRecordingControl.h"
#include "acquisition/CertificationProbeClient.h"
#include "app/ApplicationPaths.h"
#include "app/HighscoreStore.h"
#include "app/ParticipantFlow.h"
#include "app/ParticipantInventory.h"
#include "app/ParticipantSettings.h"
#include "app/ParticipantUi.h"
#include "audio/AudioEngine.h"
#include "device/CertificationFlow.h"
#include "platform/QpcClock.h"
#include "platform/RawInput.h"
#include "platform/Win32Window.h"
#include "render/D3D11Renderer.h"
#include "session/AbandonedSessionRecovery.h"
#include "session/RecordingSession.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace abdc::app {

class ParticipantApplication final {
public:
    int Run(HINSTANCE instance, int show_command);

private:
    struct ProbeRawAccumulator final {
        std::optional<std::int64_t> origin_qpc;
        device::ActivityTotals totals;
        std::vector<device::GestureSample> samples;
    };

    struct SessionBootstrap final {
        std::unique_ptr<acquisition::CaptureHelperRecordingControl> capture;
        std::unique_ptr<session::RecordingSession> session;
    };

    bool Initialize(HINSTANCE instance, int show_command);
    void MainLoop();
    void Tick(std::int64_t now_qpc);
    void Render(std::int64_t now_qpc);

    void StartAbandonedSessionRecovery();
    void PollAbandonedSessionRecovery();
    void StartInventoryScan();
    void PollInventoryScan();
    void SelectMouse(std::size_t choice_index);
    void StartCertification();
    void PollCertification(std::int64_t now_qpc);
    void BeginProbeSampling(std::int64_t now_qpc);
    void AccumulateProbeRawInput(const platform::RawMousePacket& packet);
    void CompleteCertification(
        acquisition::CertificationProbeTransportResult transport_result);
    void MarkCertificationAttemptFailed(bool permission_denied,
                                        std::string detail);

    void StartRecordingAsync();
    void PollRecordingBootstrap(std::int64_t now_qpc);
    void StartLiveInputRebind();
    void PollLiveInputRebind(std::int64_t now_qpc);
    void DriveRecording(std::int64_t now_qpc);
    void BeginTrainerCountdown(std::int64_t now_qpc);
    void PauseTrainer(std::int64_t now_qpc);
    void ResumeTrainer(std::int64_t now_qpc);
    void FinishAndSave(std::int64_t now_qpc, std::string reason);
    void ObserveCompletedEventsAndBlocks();

    void HandleRawInput(HRAWINPUT input, std::int64_t receipt_qpc);
    void HandleKey(UINT key, bool down);
    void HandleMouseMove(int x, int y);
    void HandleMouseButton(int x, int y, bool down);
    void HandleFocus(bool focused);
    void HandleResize(UINT width, UINT height);
    void HandleSystemEvent(UINT message, WPARAM wparam, LPARAM lparam);
    [[nodiscard]] bool HandleClose();
    void HandlePresentationFailure(std::int64_t qpc,
                                   std::string_view detail) noexcept;
    void ResetPresentationWatchdog() noexcept;

    void ActivateUiHit(const ParticipantUiHit& hit);
    void ApplySlider(ParticipantUiAction action, double normalized);
    void UpdateMouseCapture();
    void OpenSubmissionFolder() const;
    void RequestFinalWindowClose();

    [[nodiscard]] ParticipantUiInput BuildUiInput(
        std::int64_t now_qpc) const;
    [[nodiscard]] session::RenderEvidence CurrentRenderEvidence() const;
    [[nodiscard]] std::optional<device::ResolvedUsbMouseTransport>
    WinningTransport() const;
    [[nodiscard]] bool IsGameplayStage() const noexcept;
    [[nodiscard]] float MouseNdcX(int x) const noexcept;
    [[nodiscard]] float MouseNdcY(int y) const noexcept;

    QpcClock clock_;
    Win32Window window_;
    platform::RawInputSource raw_input_;
    D3D11Renderer renderer_;
    AudioEngine audio_;
    ParticipantFlow flow_;
    ParticipantSettings settings_;
    ApplicationPaths paths_;
    std::unique_ptr<HighscoreStore> highscores_;
    std::string participant_id_;

    std::optional<std::future<std::vector<
        session::AbandonedSessionRecoveryResult>>> abandoned_recovery_future_;
    ParticipantStartupRecoveryUi startup_recovery_ui_;
    bool startup_recovery_complete_ = false;

    std::array<std::byte, 32> inventory_salt_{};
    std::optional<std::future<ParticipantInventory>> inventory_future_;
    ParticipantInventory inventory_;
    std::optional<std::size_t> selected_mouse_;
    std::vector<device::CertificationTopology> selected_topologies_;
    std::optional<device::CertificationFlow> certification_;
    std::optional<device::CertificationSuccess> certification_success_;
    std::vector<device::RawDeviceRoute> certified_raw_input_routes_;
    std::optional<acquisition::ValidatedCertificationUsbIdentity>
        certified_usb_identity_;
    std::vector<std::byte> certified_descriptor_;

    std::unique_ptr<acquisition::CertificationProbeClient> probe_client_;
    std::unordered_map<std::string, ProbeRawAccumulator> probe_raw_;
    device::ActivityTotals other_probe_raw_totals_;
    bool probe_sampling_ = false;
    std::int64_t probe_sampling_started_qpc_ = 0;
    std::string last_certification_detail_;

    std::optional<std::future<SessionBootstrap>> session_future_;
    std::optional<std::future<device::DiscoverySnapshot>>
        live_input_rebind_future_;
    std::unique_ptr<acquisition::CaptureHelperRecordingControl>
        recording_capture_;
    std::unique_ptr<session::RecordingSession> recording_;
    std::filesystem::path submission_archive_;

    ParticipantUiResult last_ui_;
    std::optional<ParticipantUiAction> dragging_slider_;
    float mouse_ndc_x_ = 0.0F;
    float mouse_ndc_y_ = 0.0F;
    std::unordered_set<UINT> keys_down_;
    std::size_t observed_event_count_ = 0;
    std::size_t observed_block_count_ = 0;
    bool selected_raw_input_warning_reported_ = false;
    bool selected_input_route_unavailable_ = false;
    bool live_input_rebind_rescan_requested_ = false;
    bool session_result_handled_ = false;
    bool final_clock_anchor_sampled_ = false;
    std::int64_t next_clock_anchor_qpc_ = 0;
    std::int64_t next_storage_check_qpc_ = 0;
    bool renderer_ready_ = false;
    bool graphics_pause_active_ = false;
    std::int64_t next_graphics_retry_qpc_ = 0;
    std::optional<std::int64_t> pending_presentation_event_id_;
    std::int64_t pending_presentation_since_qpc_ = 0;
    bool close_requested_ = false;
    bool allow_close_ = false;
};

}  // namespace abdc::app
