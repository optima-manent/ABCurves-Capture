#include "TestHarness.h"

#include "app/ParticipantUi.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <string>

namespace {

using abdc::app::ParticipantStage;
using abdc::app::ParticipantUiAction;
using abdc::app::ParticipantUiHitbox;
using abdc::app::ParticipantUiInput;
using abdc::app::ParticipantUiResult;

bool HasAction(const ParticipantUiResult& result, ParticipantUiAction action) {
    return std::any_of(result.hitboxes.begin(), result.hitboxes.end(),
                       [action](const ParticipantUiHitbox& hitbox) {
                           return hitbox.action == action && hitbox.enabled;
                       });
}

const ParticipantUiHitbox& FindAction(const ParticipantUiResult& result,
                                      ParticipantUiAction action) {
    const auto found = std::find_if(
        result.hitboxes.begin(), result.hitboxes.end(),
        [action](const ParticipantUiHitbox& hitbox) {
            return hitbox.action == action;
        });
    if (found == result.hitboxes.end()) {
        throw std::runtime_error("participant action not found");
    }
    return *found;
}

const RenderText& FindText(const ParticipantUiResult& result,
                           const std::string& text) {
    const auto found = std::find_if(
        result.layer.texts.begin(), result.layer.texts.end(),
        [&](const RenderText& item) { return item.text == text; });
    if (found == result.layer.texts.end()) {
        throw std::runtime_error("participant text not found");
    }
    return *found;
}

std::string LowerAscii(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](char character) {
        if (character >= 'A' && character <= 'Z') {
            return static_cast<char>(character + ('a' - 'A'));
        }
        return character;
    });
    return text;
}

ParticipantUiInput InputFor(ParticipantStage stage) {
    ParticipantUiInput input;
    input.flow.stage = stage;
    input.flow.sensitivity = 1.0;
    input.flow.run_length = abdc::app::RunLength::FullResearch;
    input.flow.certification_problem =
        abdc::app::CertificationProblem::Ambiguous;
    input.flow.send_this_available = true;
    input.settings.trainer_sensitivity = 1.0;
    input.settings.crosshair_scale = 0.75;
    input.mice.push_back({"runtime-only", "Friendly Gaming Mouse", true, {}});
    input.selected_mouse = 0U;
    input.certification_progress = 0.4;
    input.countdown_number = 3;
    input.gameplay.challenge_name = "Default";
    input.gameplay.block_index = 2U;
    input.gameplay.block_count = 10U;
    input.gameplay.remaining_seconds = 42.0;
    return input;
}

}  // namespace

TEST_CASE("every participant stage renders nonempty accessible text") {
    constexpr std::array stages{
        ParticipantStage::WelcomePrivacy,
        ParticipantStage::ChooseMouse,
        ParticipantStage::CertificationReady,
        ParticipantStage::Certifying,
        ParticipantStage::CertificationNeedsAction,
        ParticipantStage::ConfigureSession,
        ParticipantStage::ReadyToStart,
        ParticipantStage::StartingCapture,
        ParticipantStage::Ready,
        ParticipantStage::Countdown,
        ParticipantStage::Playing,
        ParticipantStage::Paused,
        ParticipantStage::ResumeCountdown,
        ParticipantStage::StoppingAndSaving,
        ParticipantStage::StoppingAndPreserving,
        ParticipantStage::Complete,
        ParticipantStage::Error,
        ParticipantStage::Cancelled,
    };

    for (const ParticipantStage stage : stages) {
        const auto result = abdc::app::BuildParticipantUi(InputFor(stage));
        EXPECT_TRUE(!result.layer.texts.empty());
        EXPECT_TRUE(!result.accessible_text.empty());
    }
}

TEST_CASE("startup recovery gates welcome and reports deferred close") {
    ParticipantUiInput input = InputFor(ParticipantStage::WelcomePrivacy);
    input.startup_recovery.in_progress = true;
    auto result = abdc::app::BuildParticipantUi(input);
    EXPECT_TRUE(!HasAction(result, ParticipantUiAction::AcceptPrivacy));
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::Exit));
    EXPECT_TRUE(result.accessible_text.find("CHECKING FOR AN EARLIER") !=
                std::string::npos);
    EXPECT_TRUE(!FindAction(result, ParticipantUiAction::AcceptPrivacy).enabled);

    input.startup_recovery.close_requested = true;
    result = abdc::app::BuildParticipantUi(input);
    EXPECT_TRUE(!HasAction(result, ParticipantUiAction::AcceptPrivacy));
    EXPECT_TRUE(!HasAction(result, ParticipantUiAction::Exit));
    EXPECT_TRUE(result.accessible_text.find("CLOSE REQUESTED") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("WILL CLOSE WHEN THE CHECK FINISHES") !=
                std::string::npos);
}

TEST_CASE("welcome consent discloses selected-device USB and shared keys") {
    const auto result = abdc::app::BuildParticipantUi(
        InputFor(ParticipantStage::WelcomePrivacy));
    EXPECT_TRUE(result.accessible_text.find("RAW USB TRAFFIC") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("KEYS MAY BE CAPTURED") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("AVOID PRIVATE TYPING") !=
                std::string::npos);
}

TEST_CASE("startup recovery distinguishes recovered review files") {
    ParticipantUiInput input = InputFor(ParticipantStage::WelcomePrivacy);
    input.startup_recovery.recovered_archive_count = 2U;
    input.startup_recovery.review_archive_count = 1U;
    auto result = abdc::app::BuildParticipantUi(input);
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::AcceptPrivacy));
    EXPECT_TRUE(result.accessible_text.find(
                    "2 PREVIOUS SESSION FILES RECOVERED") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("REQUIRES RESEARCHER REVIEW") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("USABLE") == std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("USEFUL") == std::string::npos);

    input.startup_recovery.recovered_archive_count = 1U;
    input.startup_recovery.review_archive_count = 0U;
    input.startup_recovery.recovered_archive_filename =
        "session_recovered_SEND_THIS.zip";
    result = abdc::app::BuildParticipantUi(input);
    EXPECT_TRUE(result.accessible_text.find(
                    "1 PREVIOUS SESSION FILE RECOVERED") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find(
                    "session_recovered_SEND_THIS.zip") !=
                std::string::npos);
}

TEST_CASE("startup recovery failures preserve neutral original-file wording") {
    ParticipantUiInput input = InputFor(ParticipantStage::WelcomePrivacy);
    input.startup_recovery.failed_workspace_count = 1U;
    const auto result = abdc::app::BuildParticipantUi(input);
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::AcceptPrivacy));
    EXPECT_TRUE(result.accessible_text.find("NEEDS TECHNICAL REVIEW") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find(
                    "ORIGINAL FILES WERE LEFT UNCHANGED") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("USABLE") == std::string::npos);

    input.startup_recovery.failed_workspace_count = 0U;
    input.startup_recovery.check_failed = true;
    const auto check_failed = abdc::app::BuildParticipantUi(input);
    EXPECT_TRUE(check_failed.accessible_text.find(
                    "PREVIOUS SESSION FILES COULD NOT BE CHECKED") !=
                std::string::npos);
    EXPECT_TRUE(check_failed.accessible_text.find(
                    "NO EARLIER FILE WAS CALLED RECOVERED") !=
                std::string::npos);
}

TEST_CASE("mouse rows use friendly labels and return deterministic row actions") {
    ParticipantUiInput input = InputFor(ParticipantStage::ChooseMouse);
    input.mice = {
        {"secret-a", "  Nova\tMouse  ", true, {}},
        {"secret-b", R"(\\?\HID#VID_1234&PID_ABCD#PRIVATE)", true, {}},
        {"secret-c", "Office Mouse", false, "private diagnostic"},
    };
    input.selected_mouse = 0U;
    const auto result = abdc::app::BuildParticipantUi(input);

    EXPECT_TRUE(result.accessible_text.find("Nova Mouse") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("MOUSE 2") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("secret-a") == std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("VID_1234") == std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("private diagnostic") ==
                std::string::npos);
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::RefreshMouseList));

    const auto rows = std::count_if(
        result.hitboxes.begin(), result.hitboxes.end(),
        [](const ParticipantUiHitbox& hitbox) {
            return hitbox.action == ParticipantUiAction::SelectMouse;
        });
    EXPECT_EQ(rows, 3);

    const ParticipantUiHitbox& first = *std::find_if(
        result.hitboxes.begin(), result.hitboxes.end(),
        [](const ParticipantUiHitbox& hitbox) {
            return hitbox.action == ParticipantUiAction::SelectMouse &&
                   hitbox.item_index == 0U;
        });
    const auto hit = abdc::app::HitTestParticipantUi(
        result.hitboxes, (first.left + first.right) * 0.5F,
        (first.top + first.bottom) * 0.5F);
    EXPECT_TRUE(hit.has_value());
    EXPECT_EQ(hit->action, ParticipantUiAction::SelectMouse);
    EXPECT_EQ(hit->item_index, 0U);
    EXPECT_TRUE(!hit->normalized_value.has_value());

    const ParticipantUiHitbox& unavailable = *std::find_if(
        result.hitboxes.begin(), result.hitboxes.end(),
        [](const ParticipantUiHitbox& hitbox) {
            return hitbox.action == ParticipantUiAction::SelectMouse &&
                   hitbox.item_index == 2U;
        });
    EXPECT_TRUE(!unavailable.enabled);
    EXPECT_TRUE(!abdc::app::HitTestParticipantUi(
                     result.hitboxes,
                     (unavailable.left + unavailable.right) * 0.5F,
                     (unavailable.top + unavailable.bottom) * 0.5F)
                     .has_value());
}

TEST_CASE("configuration preserves the complete three panel trainer menu") {
    ParticipantUiInput input = InputFor(ParticipantStage::ConfigureSession);
    input.settings.hit_sound = abdc::app::HitSound::Pop2;
    const auto result = abdc::app::BuildParticipantUi(input);

    constexpr std::array required_actions{
        ParticipantUiAction::SetCrosshairScale,
        ParticipantUiAction::SetSensitivity,
        ParticipantUiAction::ToggleTargetHighlight,
        ParticipantUiAction::ChooseFullResearch,
        ParticipantUiAction::ChooseQuickPractice,
        ParticipantUiAction::ConfirmConfiguration,
        ParticipantUiAction::Cancel,
        ParticipantUiAction::ToggleAudio,
        ParticipantUiAction::SelectPop1,
        ParticipantUiAction::SelectPop2,
        ParticipantUiAction::SelectPop3,
    };
    for (const ParticipantUiAction action : required_actions) {
        EXPECT_TRUE(HasAction(result, action));
    }
    EXPECT_EQ(result.layer.crosshair_previews.size(), 1U);
    EXPECT_TRUE(result.accessible_text.find("FULL RESEARCH") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("QUICK TEST") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("AUDIO ON") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("POP 1") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("POP 2") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("POP 3") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("ESC PAUSES") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("F11 FULLSCREEN") !=
                std::string::npos);
}

TEST_CASE("slider hit values are clamped at and beyond both edges") {
    const auto result = abdc::app::BuildParticipantUi(
        InputFor(ParticipantStage::ConfigureSession));
    const ParticipantUiHitbox& slider =
        FindAction(result, ParticipantUiAction::SetSensitivity);

    EXPECT_EQ(*abdc::app::ParticipantSliderNormalizedValue(
                  slider, slider.left - 10.0F),
              0.0);
    EXPECT_EQ(*abdc::app::ParticipantSliderNormalizedValue(slider, slider.left),
              0.0);
    EXPECT_TRUE(std::abs(
                    *abdc::app::ParticipantSliderNormalizedValue(
                        slider, (slider.left + slider.right) * 0.5F) -
                    0.5) < 0.000001);
    EXPECT_EQ(*abdc::app::ParticipantSliderNormalizedValue(slider, slider.right),
              1.0);
    EXPECT_EQ(*abdc::app::ParticipantSliderNormalizedValue(
                  slider, slider.right + 10.0F),
              1.0);

    const auto left_hit = abdc::app::HitTestParticipantUi(
        result.hitboxes, slider.left,
        (slider.top + slider.bottom) * 0.5F);
    const auto right_hit = abdc::app::HitTestParticipantUi(
        result.hitboxes, slider.right,
        (slider.top + slider.bottom) * 0.5F);
    EXPECT_TRUE(left_hit.has_value());
    EXPECT_TRUE(right_hit.has_value());
    EXPECT_EQ(*left_hit->normalized_value, 0.0);
    EXPECT_EQ(*right_hit->normalized_value, 1.0);
    EXPECT_TRUE(!abdc::app::HitTestParticipantUi(
                     result.hitboxes,
                     std::numeric_limits<float>::quiet_NaN(), 0.0F)
                     .has_value());
}

TEST_CASE("manual pause retains settings and audio with an explicit resume") {
    ParticipantUiInput input = InputFor(ParticipantStage::Paused);
    const auto result = abdc::app::BuildParticipantUi(input);
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::Resume));
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::FinishAndSave));
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::SetCrosshairScale));
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::ToggleTargetHighlight));
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::ToggleAudio));
    EXPECT_TRUE(!FindAction(result, ParticipantUiAction::SetSensitivity).enabled);
    EXPECT_TRUE(result.accessible_text.find("RESUME") != std::string::npos);
}

TEST_CASE("certification failure exposes one finite retry choice and cancel") {
    ParticipantUiInput input =
        InputFor(ParticipantStage::CertificationNeedsAction);
    input.flow.certification_problem =
        abdc::app::CertificationProblem::NoActivity;
    const auto result = abdc::app::BuildParticipantUi(input);
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::RetryCertification));
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::ChooseDifferentMouse));
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::Cancel));
    EXPECT_TRUE(!HasAction(result, ParticipantUiAction::BeginCertification));
    EXPECT_TRUE(result.accessible_text.find("NOTHING WILL RETRY") !=
                std::string::npos);
}

TEST_CASE("complete screen clearly labels the SEND_THIS artifact") {
    ParticipantUiInput input = InputFor(ParticipantStage::Complete);
    input.flow.send_this_available = true;
    const auto result = abdc::app::BuildParticipantUi(input);
    EXPECT_TRUE(result.accessible_text.find("SEND_THIS") != std::string::npos);
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::OpenSendThisFolder));
    EXPECT_TRUE(HasAction(result, ParticipantUiAction::Done));
}

TEST_CASE("gameplay HUD keeps only useful progress score time and warnings") {
    abdc::app::ParticipantGameplayHudInput input;
    input.challenge_name = "Chain Links";
    input.block_index = 2U;
    input.block_count = 10U;
    input.score = 1250;
    input.highscore = 2400;
    input.remaining_seconds = 65.0;
    input.countdown = 3;
    input.warnings = {
        abdc::app::ParticipantHudWarning::MomentMarkedForReview};
    const auto result = abdc::app::BuildGameplayHud(input);
    EXPECT_TRUE(result.accessible_text.find("CHAIN LINKS") !=
                std::string::npos ||
                result.accessible_text.find("Chain Links") !=
                    std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("2/10") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("BLOCK") == std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("REPEAT") == std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("SCORE 1250") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("HIGH 2400") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("ABCURVES") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("AIM TRAINER") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("1:05") != std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("COLLECTION OK") ==
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("MARKED FOR REVIEW") !=
                std::string::npos);
    EXPECT_TRUE(result.accessible_text.find("GET READY") != std::string::npos);

    const auto& score = FindText(result, "SCORE 1250");
    const auto& timer = FindText(result, "1:05");
    const auto& challenge = FindText(result, "Chain Links");
    EXPECT_TRUE(score.y > 0.8F && score.x < -0.5F);
    EXPECT_TRUE(timer.y > 0.8F && std::abs(timer.x) < 0.01F);
    EXPECT_TRUE(challenge.y > 0.8F && challenge.x > 0.5F);

    const auto& logo = FindText(result, "ABCURVES");
    const auto& logo_subtitle = FindText(result, "AIM TRAINER");
    EXPECT_TRUE(logo.x > 0.5F && logo.y < -0.75F);
    EXPECT_TRUE(logo_subtitle.x > 0.5F && logo_subtitle.y < logo.y);
    EXPECT_TRUE(logo.color.g != logo_subtitle.color.g ||
                logo.color.b != logo_subtitle.color.b);
}

TEST_CASE("participant-visible strings never expose implementation rituals") {
    constexpr std::array forbidden{
        "rawinput reconciliation",
        "raw input reconciliation",
        "checkpoint",
        "pcap parser",
    };
    constexpr std::array stages{
        ParticipantStage::WelcomePrivacy,
        ParticipantStage::ChooseMouse,
        ParticipantStage::CertificationReady,
        ParticipantStage::Certifying,
        ParticipantStage::CertificationNeedsAction,
        ParticipantStage::ConfigureSession,
        ParticipantStage::ReadyToStart,
        ParticipantStage::StartingCapture,
        ParticipantStage::Ready,
        ParticipantStage::Countdown,
        ParticipantStage::Playing,
        ParticipantStage::Paused,
        ParticipantStage::ResumeCountdown,
        ParticipantStage::StoppingAndSaving,
        ParticipantStage::StoppingAndPreserving,
        ParticipantStage::Complete,
        ParticipantStage::Error,
        ParticipantStage::Cancelled,
    };
    for (const ParticipantStage stage : stages) {
        ParticipantUiInput input = InputFor(stage);
        input.mice[0].product_name = "RawInput reconciliation checkpoint";
        const std::string visible = LowerAscii(
            abdc::app::BuildParticipantUi(input).accessible_text);
        for (const std::string_view term : forbidden) {
            EXPECT_TRUE(visible.find(term) == std::string::npos);
        }
    }
}
