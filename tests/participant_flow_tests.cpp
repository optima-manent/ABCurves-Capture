#include "TestHarness.h"

#include "app/ParticipantFlow.h"

#include <array>
#include <cmath>
#include <string>

namespace {

using abdc::app::ParticipantEvent;
using abdc::app::ParticipantEventKind;
using abdc::app::ParticipantFlow;
using abdc::app::ParticipantStage;

void Apply(ParticipantFlow& flow, ParticipantEventKind kind) {
    EXPECT_TRUE(flow.Apply(ParticipantEvent{kind}).accepted);
}

void ReachCertifying(ParticipantFlow& flow) {
    Apply(flow, ParticipantEventKind::AcceptPrivacy);
    Apply(flow, ParticipantEventKind::SelectPhysicalMouse);
    Apply(flow, ParticipantEventKind::BeginCertification);
}

void ReachPlaying(ParticipantFlow& flow) {
    ReachCertifying(flow);
    Apply(flow, ParticipantEventKind::CertificationSucceeded);
    EXPECT_TRUE(flow.Apply(ParticipantEvent::SetSensitivity(1.25)).accepted);
    Apply(flow, ParticipantEventKind::ChooseFullResearch);
    Apply(flow, ParticipantEventKind::ConfirmConfiguration);
    Apply(flow, ParticipantEventKind::StartCapture);
    Apply(flow, ParticipantEventKind::CaptureStarted);
    Apply(flow, ParticipantEventKind::BeginCountdown);
    Apply(flow, ParticipantEventKind::CountdownFinished);
}

}  // namespace

TEST_CASE("participant flow follows the simple full research happy path") {
    using namespace abdc::app;
    ParticipantFlow flow;
    EXPECT_EQ(flow.State().stage, ParticipantStage::WelcomePrivacy);
    EXPECT_TRUE(!flow.State().CaptureActive());
    EXPECT_TRUE(!flow.State().TrainerActive());

    ReachPlaying(flow);
    EXPECT_EQ(flow.State().stage, ParticipantStage::Playing);
    EXPECT_TRUE(flow.State().CaptureActive());
    EXPECT_TRUE(flow.State().TrainerActive());
    EXPECT_EQ(flow.State().certification_attempts, 1U);
    EXPECT_EQ(*flow.State().run_length, RunLength::FullResearch);
    EXPECT_EQ(*flow.State().sensitivity, 1.25);

    Apply(flow, ParticipantEventKind::FinishSession);
    EXPECT_EQ(flow.State().stage, ParticipantStage::StoppingAndSaving);
    EXPECT_TRUE(!flow.State().CaptureActive());
    Apply(flow, ParticipantEventKind::SaveCompleted);
    EXPECT_EQ(flow.State().stage, ParticipantStage::Complete);
    EXPECT_TRUE(flow.State().send_this_available);
    EXPECT_TRUE(flow.Presentation().detail.find("SEND_THIS") != std::string::npos);
}

TEST_CASE("ambiguous certification requires explicit retry and never loops") {
    using namespace abdc::app;
    ParticipantFlow flow;
    ReachCertifying(flow);
    Apply(flow, ParticipantEventKind::CertificationAmbiguous);

    EXPECT_EQ(flow.State().stage, ParticipantStage::CertificationNeedsAction);
    EXPECT_TRUE(flow.State().CanRetry());
    EXPECT_EQ(flow.State().certification_attempts, 1U);

    const auto before = flow.State();
    const auto late_result = flow.Apply(
        ParticipantEvent{ParticipantEventKind::CertificationSucceeded});
    EXPECT_TRUE(!late_result.accepted);
    EXPECT_EQ(flow.State(), before);

    Apply(flow, ParticipantEventKind::RetryCertification);
    EXPECT_EQ(flow.State().stage, ParticipantStage::CertificationReady);
    EXPECT_EQ(flow.State().certification_attempts, 1U);
    EXPECT_TRUE(!flow.State().CanRetry());

    // Retry is a user choice, not an automatic second attempt.
    Apply(flow, ParticipantEventKind::BeginCertification);
    EXPECT_EQ(flow.State().certification_attempts, 2U);
    Apply(flow, ParticipantEventKind::CertificationSucceeded);
    EXPECT_EQ(flow.State().stage, ParticipantStage::ConfigureSession);
}

TEST_CASE("no activity can choose another mouse without an automatic attempt") {
    using namespace abdc::app;
    ParticipantFlow flow;
    ReachCertifying(flow);
    Apply(flow, ParticipantEventKind::CertificationNoActivity);
    Apply(flow, ParticipantEventKind::ChooseDifferentMouse);
    EXPECT_EQ(flow.State().stage, ParticipantStage::ChooseMouse);
    EXPECT_EQ(flow.State().certification_attempts, 1U);
    Apply(flow, ParticipantEventKind::SelectPhysicalMouse);
    EXPECT_EQ(flow.State().stage, ParticipantStage::CertificationReady);
    EXPECT_EQ(flow.State().certification_attempts, 1U);
}

TEST_CASE("permission denial is concise retryable and cancellable") {
    using namespace abdc::app;
    ParticipantFlow flow;
    ReachCertifying(flow);
    Apply(flow, ParticipantEventKind::CertificationPermissionDenied);
    EXPECT_TRUE(flow.State().CanRetry());
    EXPECT_TRUE(flow.Presentation().title.find("Permission") != std::string::npos);
    Apply(flow, ParticipantEventKind::Cancel);
    EXPECT_EQ(flow.State().stage, ParticipantStage::Cancelled);
    EXPECT_TRUE(!flow.State().CaptureActive());
}

TEST_CASE("configuration requires valid sensitivity and an explicit run length") {
    using namespace abdc::app;
    ParticipantFlow flow;
    ReachCertifying(flow);
    Apply(flow, ParticipantEventKind::CertificationSucceeded);

    const auto untouched = flow.State();
    EXPECT_TRUE(!flow.Apply(ParticipantEvent::SetSensitivity(0.0)).accepted);
    EXPECT_EQ(flow.State(), untouched);
    EXPECT_TRUE(!flow.Apply(ParticipantEvent::SetSensitivity(
        std::nan(""))).accepted);
    EXPECT_EQ(flow.State(), untouched);
    EXPECT_TRUE(!flow.Apply(
        ParticipantEvent{ParticipantEventKind::ConfirmConfiguration}).accepted);

    EXPECT_TRUE(flow.Apply(ParticipantEvent::SetSensitivity(0.8)).accepted);
    Apply(flow, ParticipantEventKind::ChooseQuickPractice);
    Apply(flow, ParticipantEventKind::ConfirmConfiguration);
    EXPECT_EQ(*flow.State().run_length, RunLength::QuickPractice);
    EXPECT_EQ(flow.State().stage, ParticipantStage::ReadyToStart);
}

TEST_CASE("Alt-Tab pauses one event and returning starts the resume countdown") {
    using namespace abdc::app;
    ParticipantFlow flow;
    ReachPlaying(flow);

    const auto pause = flow.Apply(ParticipantEvent{ParticipantEventKind::FocusLost});
    EXPECT_TRUE(pause.accepted);
    EXPECT_TRUE(pause.discarded_active_event);
    EXPECT_EQ(flow.State().discarded_active_events, 1U);
    EXPECT_EQ(flow.State().stage, ParticipantStage::Paused);
    EXPECT_TRUE(flow.State().CaptureActive());
    EXPECT_TRUE(!flow.State().TrainerActive());
    EXPECT_TRUE(!flow.State().CanResume());

    Apply(flow, ParticipantEventKind::FocusRestored);
    EXPECT_EQ(flow.State().stage, ParticipantStage::ResumeCountdown);
    EXPECT_TRUE(!flow.State().TrainerActive());
    Apply(flow, ParticipantEventKind::ResumeCountdownFinished);
    EXPECT_EQ(flow.State().stage, ParticipantStage::Playing);

    // A second cycle is independent and discards only its current event.
    Apply(flow, ParticipantEventKind::FocusLost);
    Apply(flow, ParticipantEventKind::FocusRestored);
    Apply(flow, ParticipantEventKind::ResumeCountdownFinished);
    EXPECT_EQ(flow.State().discarded_active_events, 2U);
}

TEST_CASE("focus loss before the first countdown remains ready") {
    using namespace abdc::app;
    ParticipantFlow flow;
    ReachCertifying(flow);
    Apply(flow, ParticipantEventKind::CertificationSucceeded);
    EXPECT_TRUE(flow.Apply(ParticipantEvent::SetSensitivity(1.0)).accepted);
    Apply(flow, ParticipantEventKind::ChooseFullResearch);
    Apply(flow, ParticipantEventKind::ConfirmConfiguration);
    Apply(flow, ParticipantEventKind::StartCapture);
    Apply(flow, ParticipantEventKind::CaptureStarted);
    EXPECT_EQ(flow.State().stage, ParticipantStage::Ready);
    EXPECT_TRUE(!flow.Apply(
        ParticipantEvent{ParticipantEventKind::FocusLost}).accepted);
    EXPECT_EQ(flow.State().stage, ParticipantStage::Ready);
    EXPECT_TRUE(!flow.Apply(
        ParticipantEvent{ParticipantEventKind::FocusRestored}).accepted);
    EXPECT_EQ(flow.State().stage, ParticipantStage::Ready);
}

TEST_CASE("nested environment pauses cannot resume too early") {
    using namespace abdc::app;
    ParticipantFlow flow;
    ReachPlaying(flow);
    Apply(flow, ParticipantEventKind::FocusLost);
    Apply(flow, ParticipantEventKind::Minimized);
    Apply(flow, ParticipantEventKind::DisplayChanged);
    Apply(flow, ParticipantEventKind::GameplayInputLost);
    EXPECT_EQ(flow.State().discarded_active_events, 1U);

    Apply(flow, ParticipantEventKind::FocusRestored);
    Apply(flow, ParticipantEventKind::Restored);
    Apply(flow, ParticipantEventKind::GameplayInputRestored);
    EXPECT_TRUE(!flow.State().CanResume());
    const auto before = flow.State();
    EXPECT_TRUE(!flow.Apply(ParticipantEvent{ParticipantEventKind::Resume}).accepted);
    EXPECT_EQ(flow.State(), before);
    Apply(flow, ParticipantEventKind::DisplayStable);
    EXPECT_EQ(flow.State().stage, ParticipantStage::ResumeCountdown);
}

TEST_CASE("each environment interruption has the same event-local policy") {
    using namespace abdc::app;
    struct Interruption final {
        ParticipantEventKind interrupt;
        ParticipantEventKind recover;
    };
    constexpr std::array interruptions{
        Interruption{ParticipantEventKind::FocusLost,
                     ParticipantEventKind::FocusRestored},
        Interruption{ParticipantEventKind::Minimized,
                     ParticipantEventKind::Restored},
        Interruption{ParticipantEventKind::DisplayChanged,
                     ParticipantEventKind::DisplayStable},
        Interruption{ParticipantEventKind::GameplayInputLost,
                     ParticipantEventKind::GameplayInputRestored},
    };

    for (const auto interruption : interruptions) {
        ParticipantFlow flow;
        ReachPlaying(flow);
        const auto result = flow.Apply(ParticipantEvent{interruption.interrupt});
        EXPECT_TRUE(result.accepted);
        EXPECT_TRUE(result.discarded_active_event);
        EXPECT_EQ(flow.State().discarded_active_events, 1U);
        EXPECT_TRUE(flow.State().CaptureActive());
        EXPECT_TRUE(!flow.State().TrainerActive());

        Apply(flow, interruption.recover);
        EXPECT_EQ(flow.State().stage, ParticipantStage::ResumeCountdown);
    }
}

TEST_CASE("selected gameplay input must be present before the first countdown") {
    using namespace abdc::app;
    ParticipantFlow ready_flow;
    ReachCertifying(ready_flow);
    Apply(ready_flow, ParticipantEventKind::CertificationSucceeded);
    EXPECT_TRUE(ready_flow.Apply(ParticipantEvent::SetSensitivity(1.0)).accepted);
    Apply(ready_flow, ParticipantEventKind::ChooseQuickPractice);
    Apply(ready_flow, ParticipantEventKind::ConfirmConfiguration);
    Apply(ready_flow, ParticipantEventKind::StartCapture);
    Apply(ready_flow, ParticipantEventKind::CaptureStarted);

    EXPECT_TRUE(ready_flow.State().CanBeginCountdown());
    Apply(ready_flow, ParticipantEventKind::GameplayInputLost);
    EXPECT_TRUE(ready_flow.State().WaitingForGameplayInput());
    EXPECT_TRUE(!ready_flow.State().CanBeginCountdown());
    EXPECT_TRUE(!ready_flow.Apply(ParticipantEvent{
        ParticipantEventKind::BeginCountdown}).accepted);
    Apply(ready_flow, ParticipantEventKind::GameplayInputRestored);
    EXPECT_TRUE(ready_flow.State().CanBeginCountdown());
}

TEST_CASE("manual pause also discards only the active event") {
    ParticipantFlow flow;
    ReachPlaying(flow);
    const auto result = flow.Apply(
        ParticipantEvent{ParticipantEventKind::ManualPause});
    EXPECT_TRUE(result.accepted);
    EXPECT_TRUE(result.discarded_active_event);
    EXPECT_TRUE(flow.State().CanResume());
    EXPECT_TRUE(flow.State().CaptureActive());
}

TEST_CASE("optional warnings annotate without controlling any stage") {
    using namespace abdc::app;
    ParticipantFlow flow;
    ReachPlaying(flow);
    constexpr std::array warnings{
        OptionalWarning::CaptureTimingAnomaly,
        OptionalWarning::DecodeAnomaly,
        OptionalWarning::ClockUncertainty,
        OptionalWarning::InputWitnessUnavailable,
    };
    for (const auto warning : warnings) {
        const auto stage_before = flow.State().stage;
        EXPECT_TRUE(flow.Apply(ParticipantEvent::Warning(warning)).accepted);
        EXPECT_EQ(flow.State().stage, stage_before);
        EXPECT_TRUE(flow.State().CaptureActive());
        EXPECT_TRUE(flow.State().TrainerActive());
    }
    EXPECT_EQ(flow.State().warnings.size(), warnings.size());

    EXPECT_TRUE(flow.Apply(ParticipantEvent::Warning(
        OptionalWarning::DecodeAnomaly)).accepted);
    EXPECT_EQ(flow.State().warnings[1].occurrences, 2U);

    Apply(flow, ParticipantEventKind::FinishSession);
    Apply(flow, ParticipantEventKind::SaveCompleted);
    EXPECT_EQ(flow.State().stage, ParticipantStage::Complete);
    EXPECT_TRUE(flow.State().send_this_available);
    EXPECT_TRUE(flow.Presentation().detail.find("marked for review") !=
                std::string::npos);
}

TEST_CASE("every destructive runtime failure stops and preserves the prefix") {
    using namespace abdc::app;
    constexpr std::array failures{
        DestructiveFailure::HelperLost,
        DestructiveFailure::CaptureLost,
        DestructiveFailure::SelectedDeviceChanged,
        DestructiveFailure::QueueOverflow,
        DestructiveFailure::FramingCorruption,
        DestructiveFailure::StorageFailure,
        DestructiveFailure::IntegrityFailure,
    };

    for (const auto failure : failures) {
        ParticipantFlow flow;
        ReachPlaying(flow);
        EXPECT_TRUE(flow.Apply(ParticipantEvent::Failure(failure)).accepted);
        EXPECT_EQ(flow.State().stage, ParticipantStage::StoppingAndPreserving);
        EXPECT_TRUE(!flow.State().CaptureActive());
        EXPECT_TRUE(!flow.State().TrainerActive());
        EXPECT_EQ(flow.State().preserved_prefix,
                  PreservedPrefixOutcome::Pending);
        EXPECT_EQ(*flow.State().destructive_failure, failure);
        Apply(flow, ParticipantEventKind::PrefixPreserved);
        EXPECT_EQ(flow.State().stage, ParticipantStage::Error);
        EXPECT_EQ(flow.State().preserved_prefix,
                  PreservedPrefixOutcome::Preserved);
        EXPECT_TRUE(flow.State().send_this_available);
        EXPECT_TRUE(flow.Presentation().detail.find("SEND_THIS") !=
                    std::string::npos);
    }
}

TEST_CASE("failed prefix preservation is explicit") {
    using namespace abdc::app;
    ParticipantFlow flow;
    ReachPlaying(flow);
    EXPECT_TRUE(flow.Apply(ParticipantEvent::Failure(
        DestructiveFailure::StorageFailure)).accepted);
    Apply(flow, ParticipantEventKind::PrefixPreservationFailed);
    EXPECT_EQ(flow.State().preserved_prefix,
              PreservedPrefixOutcome::PreservationFailed);
    EXPECT_TRUE(!flow.State().send_this_available);
}

TEST_CASE("illegal transitions are rejected without mutation") {
    using namespace abdc::app;
    ParticipantFlow flow;
    constexpr std::array illegal_at_welcome{
        ParticipantEventKind::BeginCertification,
        ParticipantEventKind::CertificationSucceeded,
        ParticipantEventKind::RetryCertification,
        ParticipantEventKind::StartCapture,
        ParticipantEventKind::CaptureStarted,
        ParticipantEventKind::FocusLost,
        ParticipantEventKind::Resume,
        ParticipantEventKind::FinishSession,
        ParticipantEventKind::SaveCompleted,
        ParticipantEventKind::PrefixPreserved,
    };
    for (const auto kind : illegal_at_welcome) {
        const auto before = flow.State();
        const auto result = flow.Apply(ParticipantEvent{kind});
        EXPECT_TRUE(!result.accepted);
        EXPECT_TRUE(!result.discarded_active_event);
        EXPECT_EQ(flow.State(), before);
    }
    const auto before_warning = flow.State();
    EXPECT_TRUE(!flow.Apply(ParticipantEvent::Warning(
        OptionalWarning::ClockUncertainty)).accepted);
    EXPECT_EQ(flow.State(), before_warning);
    const auto before_failure = flow.State();
    EXPECT_TRUE(!flow.Apply(ParticipantEvent::Failure(
        DestructiveFailure::CaptureLost)).accepted);
    EXPECT_EQ(flow.State(), before_failure);
}
