#pragma once

#include "app/ParticipantFlow.h"
#include "app/ParticipantSettings.h"
#include "render/RenderTypes.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace abdc::app {

// ParticipantUi is deliberately a pure view layer. These actions describe UI
// intent; the application controller decides which ParticipantEvent or setting
// change (if any) is appropriate for the current state.
enum class ParticipantUiAction {
    None,
    AcceptPrivacy,
    Exit,
    SelectMouse,
    RefreshMouseList,
    BeginCertification,
    RetryCertification,
    ChooseDifferentMouse,
    Cancel,
    SetCrosshairScale,
    SetSensitivity,
    ToggleTargetHighlight,
    ChooseFullResearch,
    ChooseQuickPractice,
    ConfirmConfiguration,
    EditConfiguration,
    StartCapture,
    BeginCountdown,
    Pause,
    Resume,
    FinishAndSave,
    ToggleAudio,
    SelectPop1,
    SelectPop2,
    SelectPop3,
    OpenSendThisFolder,
    Done,
};

enum class ParticipantUiControlRole {
    Button,
    Slider,
    ListRow,
};

struct ParticipantUiHitbox final {
    ParticipantUiAction action{ParticipantUiAction::None};
    ParticipantUiControlRole role{ParticipantUiControlRole::Button};
    float left{};
    float top{};
    float right{};
    float bottom{};
    bool enabled{true};
    std::size_t item_index{};
    std::string accessible_name;

    [[nodiscard]] bool Contains(float ndc_x, float ndc_y) const noexcept;
};

struct ParticipantUiHit final {
    ParticipantUiAction action{ParticipantUiAction::None};
    std::size_t item_index{};
    std::optional<double> normalized_value;
};

struct ParticipantMouseOption final {
    // This token is returned only as an item index into the controller-owned
    // list. It is never rendered by this module.
    std::string runtime_token;
    std::string product_name;
    bool available{true};
    std::string unavailable_reason;
};

enum class ParticipantHudWarning {
    MomentSkipped,
    MomentMarkedForReview,
    ReturnToWindow,
};

struct ParticipantGameplayHudInput final {
    std::string challenge_name;
    std::uint32_t block_index{1U};
    std::uint32_t block_count{1U};
    std::int64_t score{};
    std::int64_t highscore{};
    double remaining_seconds{};
    std::optional<int> countdown;
    std::vector<ParticipantHudWarning> warnings;
};

// Startup recovery is intentionally summarized without implementation details
// or native paths. An archive that lacks verified authoritative mouse evidence
// is counted separately so the UI never implies that it is research-usable.
struct ParticipantStartupRecoveryUi final {
    bool in_progress{};
    bool close_requested{};
    bool check_failed{};
    std::uint64_t recovered_archive_count{};
    std::uint64_t review_archive_count{};
    std::uint64_t failed_workspace_count{};
    std::uint64_t active_writer_count{};
    std::string recovered_archive_filename;
};

struct ParticipantUiInput final {
    ParticipantFlowState flow;
    ParticipantSettings settings;
    ParticipantStartupRecoveryUi startup_recovery;
    std::vector<ParticipantMouseOption> mice;
    bool mouse_scan_in_progress{};
    std::optional<std::size_t> selected_mouse;
    double certification_progress{};
    int countdown_number{};
    std::string send_this_filename;
    ParticipantGameplayHudInput gameplay;
};

struct ParticipantUiResult final {
    RenderUiLayer layer;
    std::vector<ParticipantUiHitbox> hitboxes;

    // Newline-separated rendered labels in reading order. This gives the
    // Win32 shell one concise source for narration without scraping vertices.
    std::string accessible_text;
};

// Produces an ASCII, single-line, privacy-safe participant label. Native paths,
// hardware identifiers, control characters, and implementation diagnostics are
// replaced by fallback_text instead of being exposed on screen.
[[nodiscard]] std::string SanitizeParticipantLabel(
    std::string_view text,
    std::string_view fallback_text = "Mouse");

// The first enabled hitbox in drawing order wins. Coordinates are normalized
// device coordinates: x in [-1, 1], y in [-1, 1], with y increasing upward.
[[nodiscard]] std::optional<ParticipantUiHit> HitTestParticipantUi(
    std::span<const ParticipantUiHitbox> hitboxes,
    float ndc_x,
    float ndc_y) noexcept;

// Returns a clamped [0, 1] value for a slider even when x lies outside its
// visual bounds. Non-slider and zero-width hitboxes return nullopt.
[[nodiscard]] std::optional<double> ParticipantSliderNormalizedValue(
    const ParticipantUiHitbox& hitbox,
    float ndc_x) noexcept;

[[nodiscard]] ParticipantUiResult BuildParticipantUi(
    const ParticipantUiInput& input);

[[nodiscard]] ParticipantUiResult BuildGameplayHud(
    const ParticipantGameplayHudInput& input);

}  // namespace abdc::app
