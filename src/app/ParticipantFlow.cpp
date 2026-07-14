#include "app/ParticipantFlow.h"

#include <algorithm>
#include <cmath>
#include <utility>

namespace abdc::app {
namespace {

constexpr std::uint32_t kFocusBlocker = 1U << 0U;
constexpr std::uint32_t kMinimizedBlocker = 1U << 1U;
constexpr std::uint32_t kDisplayBlocker = 1U << 2U;
constexpr std::uint32_t kGameplayInputBlocker = 1U << 3U;

bool IsGameplayStage(ParticipantStage stage) noexcept {
    switch (stage) {
    case ParticipantStage::Ready:
    case ParticipantStage::Countdown:
    case ParticipantStage::Playing:
    case ParticipantStage::Paused:
    case ParticipantStage::ResumeCountdown:
        return true;
    default:
        return false;
    }
}

bool IsPreCaptureStage(ParticipantStage stage) noexcept {
    switch (stage) {
    case ParticipantStage::WelcomePrivacy:
    case ParticipantStage::ChooseMouse:
    case ParticipantStage::CertificationReady:
    case ParticipantStage::Certifying:
    case ParticipantStage::CertificationNeedsAction:
    case ParticipantStage::ConfigureSession:
    case ParticipantStage::ReadyToStart:
        return true;
    default:
        return false;
    }
}

bool CanReceiveRuntimeWarning(ParticipantStage stage) noexcept {
    return stage == ParticipantStage::StartingCapture || IsGameplayStage(stage) ||
           stage == ParticipantStage::StoppingAndSaving;
}

bool CanSufferDestructiveFailure(ParticipantStage stage) noexcept {
    return stage == ParticipantStage::StartingCapture || IsGameplayStage(stage) ||
           stage == ParticipantStage::StoppingAndSaving;
}

void AddWarning(ParticipantFlowState& state, OptionalWarning warning) {
    const auto found = std::find_if(
        state.warnings.begin(), state.warnings.end(),
        [warning](const WarningAnnotation& annotation) {
            return annotation.kind == warning;
        });
    if (found == state.warnings.end()) {
        state.warnings.push_back({warning, 1U});
    } else {
        ++found->occurrences;
    }
}

ParticipantPresentation CertificationProblemPresentation(
    CertificationProblem problem) {
    switch (problem) {
    case CertificationProblem::Ambiguous:
        return {"We could not identify one mouse",
                "Try once more or choose a different mouse.", "Try again",
                "Choose another mouse"};
    case CertificationProblem::NoActivity:
        return {"Mouse data was not detected",
                "Move the selected mouse and click when the check asks you to.",
                "Try again", "Choose another mouse"};
    case CertificationProblem::PermissionDenied:
        return {"Permission was not granted",
                "Permission is needed to read the selected mouse.", "Try again",
                "Cancel"};
    }
    return {};
}

}  // namespace

ParticipantEvent ParticipantEvent::SetSensitivity(double value) noexcept {
    ParticipantEvent event{ParticipantEventKind::SetSensitivity};
    event.sensitivity = value;
    return event;
}

ParticipantEvent ParticipantEvent::Warning(OptionalWarning value) noexcept {
    ParticipantEvent event{ParticipantEventKind::AddOptionalWarning};
    event.warning = value;
    return event;
}

ParticipantEvent ParticipantEvent::Failure(
    abdc::app::DestructiveFailure value) noexcept {
    ParticipantEvent event{ParticipantEventKind::DestructiveFailure};
    event.failure = value;
    return event;
}

bool ParticipantFlowState::CaptureActive() const noexcept {
    return IsGameplayStage(stage);
}

bool ParticipantFlowState::TrainerActive() const noexcept {
    return stage == ParticipantStage::Playing;
}

bool ParticipantFlowState::CanRetry() const noexcept {
    return stage == ParticipantStage::CertificationNeedsAction;
}

bool ParticipantFlowState::CanResume() const noexcept {
    return stage == ParticipantStage::Paused && environment_blockers == 0U;
}

bool ParticipantFlowState::CanBeginCountdown() const noexcept {
    return stage == ParticipantStage::Ready && environment_blockers == 0U;
}

bool ParticipantFlowState::WaitingForGameplayInput() const noexcept {
    return (environment_blockers & kGameplayInputBlocker) != 0U;
}

const ParticipantFlowState& ParticipantFlow::State() const noexcept {
    return state_;
}

ParticipantPresentation ParticipantFlow::Presentation() const {
    switch (state_.stage) {
    case ParticipantStage::WelcomePrivacy:
        return {"Help improve mouse research",
                "Review what this study records before you continue.", "Continue",
                "Exit"};
    case ParticipantStage::ChooseMouse:
        return {"Choose your mouse", "Select the mouse you will use to play.",
                "Use this mouse", "Cancel"};
    case ParticipantStage::CertificationReady:
        return {"Check this mouse",
                "Move it and click once when the check begins.", "Begin check",
                "Choose another mouse"};
    case ParticipantStage::Certifying:
        return {"Checking your mouse", "Move the selected mouse and click once.",
                "", "Cancel"};
    case ParticipantStage::CertificationNeedsAction:
        return CertificationProblemPresentation(*state_.certification_problem);
    case ParticipantStage::ConfigureSession:
        return {"Choose your session",
                "Set your in-game sensitivity and choose a session length.",
                "Confirm", "Cancel"};
    case ParticipantStage::ReadyToStart:
        return {"Ready to begin",
                "Your mouse and session settings are ready.", "Start", "Back"};
    case ParticipantStage::StartingCapture:
        return {"Starting collection", "This should only take a moment.", "", ""};
    case ParticipantStage::Ready:
        return {"Get comfortable",
                state_.WaitingForGameplayInput()
                    ? "Waiting for the selected mouse to reconnect."
                    : "Start when you are ready to aim.",
                state_.CanBeginCountdown() ? "Start countdown" : "",
                "Finish and save"};
    case ParticipantStage::Countdown:
        return {"Starting soon", "Get ready.", "", "Pause"};
    case ParticipantStage::Playing:
        return {"Aim trainer", "Complete the targets at your natural pace.",
                "Pause", "Finish and save"};
    case ParticipantStage::Paused:
        if (state_.CanResume()) {
            return {"Paused", "Resume when you are ready.", "Resume",
                    "Finish and save"};
        }
        return {"Paused", "Return to the trainer to continue.", "",
                "Finish and save"};
    case ParticipantStage::ResumeCountdown:
        return {"Resuming soon", "Get ready.", "", "Pause"};
    case ParticipantStage::StoppingAndSaving:
        return {"Saving your session", "Please keep this window open.", "", ""};
    case ParticipantStage::StoppingAndPreserving:
        return {"Protecting your saved data",
                "Collection stopped; the available evidence is being saved.", "", ""};
    case ParticipantStage::Complete:
        if (state_.warnings.empty()) {
            return {"Session saved", "Send the SEND_THIS file to the research team.",
                    "Done", ""};
        }
        return {"Session saved",
                "A few moments were marked for review. Send the SEND_THIS file.",
                "Done", ""};
    case ParticipantStage::Error:
        if (state_.preserved_prefix == PreservedPrefixOutcome::Preserved) {
            return {"Collection stopped safely",
                    "Usable data was preserved in the SEND_THIS file.", "Done", ""};
        }
        return {"Collection stopped",
                "The saved data could not be finished safely.", "Done", ""};
    case ParticipantStage::Cancelled:
        return {"Session cancelled", "No session was started.", "Close", ""};
    }
    return {};
}

ParticipantTransitionResult ParticipantFlow::Apply(const ParticipantEvent& event) {
    ParticipantFlowState next = state_;
    const auto discarded_before = next.discarded_active_events;
    if (!ApplyTo(next, event)) {
        return {};
    }
    const bool discarded = next.discarded_active_events != discarded_before;
    state_ = std::move(next);
    return {true, discarded};
}

bool ParticipantFlow::PauseForBlocker(ParticipantFlowState& state,
                                      std::uint32_t blocker) noexcept {
    // Capture is already active on Ready, but the trainer has not started and
    // there is no event or countdown to interrupt. Returning to the window
    // must therefore remain Ready rather than inventing a resume countdown.
    if (!IsGameplayStage(state.stage) || state.stage == ParticipantStage::Ready) {
        return false;
    }

    state.environment_blockers |= blocker;
    if (state.stage != ParticipantStage::Paused) {
        if (state.stage == ParticipantStage::Playing) {
            ++state.discarded_active_events;
        }
        state.stage = ParticipantStage::Paused;
    }
    return true;
}

bool ParticipantFlow::ClearBlocker(ParticipantFlowState& state,
                                   std::uint32_t blocker) noexcept {
    if (state.stage != ParticipantStage::Paused ||
        (state.environment_blockers & blocker) == 0U) {
        return false;
    }
    state.environment_blockers &= ~blocker;
    if (state.environment_blockers == 0U && !state.manually_paused) {
        state.stage = ParticipantStage::ResumeCountdown;
    }
    return true;
}

bool ParticipantFlow::ApplyTo(ParticipantFlowState& state,
                              const ParticipantEvent& event) {
    switch (event.kind) {
    case ParticipantEventKind::AcceptPrivacy:
        if (state.stage != ParticipantStage::WelcomePrivacy) {
            return false;
        }
        state.stage = ParticipantStage::ChooseMouse;
        return true;

    case ParticipantEventKind::SelectPhysicalMouse:
        if (state.stage != ParticipantStage::ChooseMouse) {
            return false;
        }
        state.certification_problem.reset();
        state.stage = ParticipantStage::CertificationReady;
        return true;

    case ParticipantEventKind::BeginCertification:
        if (state.stage != ParticipantStage::CertificationReady) {
            return false;
        }
        ++state.certification_attempts;
        state.stage = ParticipantStage::Certifying;
        return true;

    case ParticipantEventKind::CertificationSucceeded:
        if (state.stage != ParticipantStage::Certifying) {
            return false;
        }
        state.certification_problem.reset();
        state.stage = ParticipantStage::ConfigureSession;
        return true;

    case ParticipantEventKind::CertificationAmbiguous:
    case ParticipantEventKind::CertificationNoActivity:
    case ParticipantEventKind::CertificationPermissionDenied:
        if (state.stage != ParticipantStage::Certifying) {
            return false;
        }
        if (event.kind == ParticipantEventKind::CertificationAmbiguous) {
            state.certification_problem = CertificationProblem::Ambiguous;
        } else if (event.kind == ParticipantEventKind::CertificationNoActivity) {
            state.certification_problem = CertificationProblem::NoActivity;
        } else {
            state.certification_problem = CertificationProblem::PermissionDenied;
        }
        state.stage = ParticipantStage::CertificationNeedsAction;
        return true;

    case ParticipantEventKind::RetryCertification:
        if (state.stage != ParticipantStage::CertificationNeedsAction) {
            return false;
        }
        state.certification_problem.reset();
        state.stage = ParticipantStage::CertificationReady;
        return true;

    case ParticipantEventKind::ChooseDifferentMouse:
        if (state.stage != ParticipantStage::CertificationReady &&
            state.stage != ParticipantStage::CertificationNeedsAction) {
            return false;
        }
        state.certification_problem.reset();
        state.stage = ParticipantStage::ChooseMouse;
        return true;

    case ParticipantEventKind::SetSensitivity:
        if (state.stage != ParticipantStage::ConfigureSession ||
            !std::isfinite(event.sensitivity) || event.sensitivity <= 0.0) {
            return false;
        }
        state.sensitivity = event.sensitivity;
        return true;

    case ParticipantEventKind::ChooseFullResearch:
    case ParticipantEventKind::ChooseQuickPractice:
        if (state.stage != ParticipantStage::ConfigureSession) {
            return false;
        }
        state.run_length = event.kind == ParticipantEventKind::ChooseFullResearch
                               ? RunLength::FullResearch
                               : RunLength::QuickPractice;
        return true;

    case ParticipantEventKind::ConfirmConfiguration:
        if (state.stage != ParticipantStage::ConfigureSession ||
            !state.sensitivity.has_value() || !state.run_length.has_value()) {
            return false;
        }
        state.stage = ParticipantStage::ReadyToStart;
        return true;

    case ParticipantEventKind::EditConfiguration:
        if (state.stage != ParticipantStage::ReadyToStart) {
            return false;
        }
        state.stage = ParticipantStage::ConfigureSession;
        return true;

    case ParticipantEventKind::StartCapture:
        if (state.stage != ParticipantStage::ReadyToStart) {
            return false;
        }
        state.stage = ParticipantStage::StartingCapture;
        return true;

    case ParticipantEventKind::CaptureStarted:
        if (state.stage != ParticipantStage::StartingCapture) {
            return false;
        }
        state.stage = ParticipantStage::Ready;
        return true;

    case ParticipantEventKind::BeginCountdown:
        if (!state.CanBeginCountdown()) {
            return false;
        }
        state.stage = ParticipantStage::Countdown;
        return true;

    case ParticipantEventKind::CountdownFinished:
        if (state.stage != ParticipantStage::Countdown) {
            return false;
        }
        state.stage = ParticipantStage::Playing;
        return true;

    case ParticipantEventKind::ManualPause:
        if (state.stage != ParticipantStage::Playing &&
            state.stage != ParticipantStage::Countdown &&
            state.stage != ParticipantStage::ResumeCountdown) {
            return false;
        }
        if (state.stage == ParticipantStage::Playing) {
            ++state.discarded_active_events;
        }
        state.manually_paused = true;
        state.stage = ParticipantStage::Paused;
        return true;

    case ParticipantEventKind::FocusLost:
        return PauseForBlocker(state, kFocusBlocker);
    case ParticipantEventKind::Minimized:
        return PauseForBlocker(state, kMinimizedBlocker);
    case ParticipantEventKind::DisplayChanged:
        return PauseForBlocker(state, kDisplayBlocker);
    case ParticipantEventKind::FocusRestored:
        return ClearBlocker(state, kFocusBlocker);
    case ParticipantEventKind::Restored:
        return ClearBlocker(state, kMinimizedBlocker);
    case ParticipantEventKind::DisplayStable:
        return ClearBlocker(state, kDisplayBlocker);
    case ParticipantEventKind::GameplayInputLost:
        if (state.stage == ParticipantStage::Ready) {
            if ((state.environment_blockers & kGameplayInputBlocker) != 0U) {
                return false;
            }
            state.environment_blockers |= kGameplayInputBlocker;
            return true;
        }
        return PauseForBlocker(state, kGameplayInputBlocker);
    case ParticipantEventKind::GameplayInputRestored:
        if (state.stage == ParticipantStage::Ready &&
            (state.environment_blockers & kGameplayInputBlocker) != 0U) {
            state.environment_blockers &= ~kGameplayInputBlocker;
            return true;
        }
        return ClearBlocker(state, kGameplayInputBlocker);

    case ParticipantEventKind::Resume:
        if (!state.CanResume()) {
            return false;
        }
        state.manually_paused = false;
        state.stage = ParticipantStage::ResumeCountdown;
        return true;

    case ParticipantEventKind::ResumeCountdownFinished:
        if (state.stage != ParticipantStage::ResumeCountdown) {
            return false;
        }
        state.stage = ParticipantStage::Playing;
        return true;

    case ParticipantEventKind::AddOptionalWarning:
        if (!CanReceiveRuntimeWarning(state.stage)) {
            return false;
        }
        AddWarning(state, event.warning);
        return true;

    case ParticipantEventKind::FinishSession:
        if (!IsGameplayStage(state.stage)) {
            return false;
        }
        state.environment_blockers = 0U;
        state.manually_paused = false;
        state.stage = ParticipantStage::StoppingAndSaving;
        return true;

    case ParticipantEventKind::SaveCompleted:
        if (state.stage != ParticipantStage::StoppingAndSaving) {
            return false;
        }
        state.send_this_available = true;
        state.stage = ParticipantStage::Complete;
        return true;

    case ParticipantEventKind::DestructiveFailure:
        if (!CanSufferDestructiveFailure(state.stage)) {
            return false;
        }
        state.destructive_failure = event.failure;
        state.preserved_prefix = PreservedPrefixOutcome::Pending;
        state.environment_blockers = 0U;
        state.manually_paused = false;
        state.stage = ParticipantStage::StoppingAndPreserving;
        return true;

    case ParticipantEventKind::PrefixPreserved:
        if (state.stage != ParticipantStage::StoppingAndPreserving) {
            return false;
        }
        state.preserved_prefix = PreservedPrefixOutcome::Preserved;
        state.send_this_available = true;
        state.stage = ParticipantStage::Error;
        return true;

    case ParticipantEventKind::UnverifiedArchivePreserved:
        if (state.stage != ParticipantStage::StoppingAndPreserving) {
            return false;
        }
        state.preserved_prefix =
            PreservedPrefixOutcome::ArchiveWithoutVerifiedSource;
        state.send_this_available = true;
        state.stage = ParticipantStage::Error;
        return true;

    case ParticipantEventKind::PrefixPreservationFailed:
        if (state.stage != ParticipantStage::StoppingAndPreserving) {
            return false;
        }
        state.preserved_prefix = PreservedPrefixOutcome::PreservationFailed;
        state.send_this_available = false;
        state.stage = ParticipantStage::Error;
        return true;

    case ParticipantEventKind::Cancel:
        if (!IsPreCaptureStage(state.stage)) {
            return false;
        }
        state.stage = ParticipantStage::Cancelled;
        return true;
    }
    return false;
}

}  // namespace abdc::app
