#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace abdc::app {

enum class ParticipantStage {
    WelcomePrivacy,
    ChooseMouse,
    CertificationReady,
    Certifying,
    CertificationNeedsAction,
    ConfigureSession,
    ReadyToStart,
    StartingCapture,
    Ready,
    Countdown,
    Playing,
    Paused,
    ResumeCountdown,
    StoppingAndSaving,
    StoppingAndPreserving,
    Complete,
    Error,
    Cancelled,
};

enum class RunLength {
    FullResearch,
    QuickPractice,
};

enum class CertificationProblem {
    Ambiguous,
    NoActivity,
    PermissionDenied,
};

// These are research annotations. They are deliberately not collection gates.
enum class OptionalWarning {
    CaptureTimingAnomaly,
    DecodeAnomaly,
    ClockUncertainty,
    InputWitnessUnavailable,
};

enum class DestructiveFailure {
    HelperLost,
    CaptureLost,
    SelectedDeviceChanged,
    QueueOverflow,
    FramingCorruption,
    StorageFailure,
    IntegrityFailure,
};

enum class PreservedPrefixOutcome {
    NotRequired,
    Pending,
    Preserved,
    ArchiveWithoutVerifiedSource,
    PreservationFailed,
};

enum class ParticipantEventKind {
    AcceptPrivacy,
    SelectPhysicalMouse,
    BeginCertification,
    CertificationSucceeded,
    CertificationAmbiguous,
    CertificationNoActivity,
    CertificationPermissionDenied,
    RetryCertification,
    ChooseDifferentMouse,
    SetSensitivity,
    ChooseFullResearch,
    ChooseQuickPractice,
    ConfirmConfiguration,
    EditConfiguration,
    StartCapture,
    CaptureStarted,
    BeginCountdown,
    CountdownFinished,
    ManualPause,
    FocusLost,
    FocusRestored,
    Minimized,
    Restored,
    DisplayChanged,
    DisplayStable,
    GameplayInputLost,
    GameplayInputRestored,
    Resume,
    ResumeCountdownFinished,
    AddOptionalWarning,
    FinishSession,
    SaveCompleted,
    PrefixPreserved,
    UnverifiedArchivePreserved,
    PrefixPreservationFailed,
    DestructiveFailure,
    Cancel,
};

struct ParticipantEvent final {
    ParticipantEventKind kind{};
    double sensitivity{};
    OptionalWarning warning{OptionalWarning::CaptureTimingAnomaly};
    abdc::app::DestructiveFailure failure{
        abdc::app::DestructiveFailure::CaptureLost};

    [[nodiscard]] static ParticipantEvent SetSensitivity(double value) noexcept;
    [[nodiscard]] static ParticipantEvent Warning(OptionalWarning value) noexcept;
    [[nodiscard]] static ParticipantEvent Failure(
        abdc::app::DestructiveFailure value) noexcept;
};

struct WarningAnnotation final {
    OptionalWarning kind{};
    std::uint32_t occurrences{};

    bool operator==(const WarningAnnotation&) const = default;
};

struct ParticipantFlowState final {
    ParticipantStage stage{ParticipantStage::WelcomePrivacy};
    std::optional<double> sensitivity;
    std::optional<RunLength> run_length;
    std::optional<CertificationProblem> certification_problem;
    std::optional<abdc::app::DestructiveFailure> destructive_failure;
    std::uint32_t certification_attempts{};
    std::uint32_t discarded_active_events{};
    std::vector<WarningAnnotation> warnings;
    PreservedPrefixOutcome preserved_prefix{PreservedPrefixOutcome::NotRequired};
    bool send_this_available{};

    [[nodiscard]] bool CaptureActive() const noexcept;
    [[nodiscard]] bool TrainerActive() const noexcept;
    [[nodiscard]] bool CanRetry() const noexcept;
    [[nodiscard]] bool CanResume() const noexcept;
    [[nodiscard]] bool CanBeginCountdown() const noexcept;
    [[nodiscard]] bool WaitingForGameplayInput() const noexcept;

    bool operator==(const ParticipantFlowState&) const = default;

private:
    friend class ParticipantFlow;
    std::uint32_t environment_blockers{};
    bool manually_paused{};
};

struct ParticipantPresentation final {
    std::string title;
    std::string detail;
    std::string primary_action;
    std::string secondary_action;
};

struct ParticipantTransitionResult final {
    bool accepted{};
    bool discarded_active_event{};
};

class ParticipantFlow final {
public:
    [[nodiscard]] const ParticipantFlowState& State() const noexcept;
    [[nodiscard]] ParticipantPresentation Presentation() const;

    // Rejected events leave State() byte-for-byte logically unchanged.
    [[nodiscard]] ParticipantTransitionResult Apply(const ParticipantEvent& event);

private:
    [[nodiscard]] static bool ApplyTo(ParticipantFlowState& state,
                                      const ParticipantEvent& event);
    [[nodiscard]] static bool PauseForBlocker(ParticipantFlowState& state,
                                              std::uint32_t blocker) noexcept;
    [[nodiscard]] static bool ClearBlocker(ParticipantFlowState& state,
                                           std::uint32_t blocker) noexcept;

    ParticipantFlowState state_;
};

}  // namespace abdc::app
