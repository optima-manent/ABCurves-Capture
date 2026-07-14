#include "app/ParticipantUi.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <utility>

namespace abdc::app {
namespace {

constexpr std::size_t kNoItem = std::numeric_limits<std::size_t>::max();

struct UiRect final {
    float left{};
    float top{};
    float right{};
    float bottom{};
};

constexpr UiRect kLeftPanel{-0.96F, 0.70F, -0.33F, -0.72F};
constexpr UiRect kCenterPanel{-0.29F, 0.70F, 0.29F, -0.72F};
constexpr UiRect kRightPanel{0.33F, 0.70F, 0.96F, -0.72F};

constexpr RenderColor Color(float r, float g, float b, float a = 1.0F) {
    return {r, g, b, a};
}

constexpr RenderColor kBackground = Color(0.010F, 0.014F, 0.022F);
constexpr RenderColor kPanel = Color(0.026F, 0.034F, 0.048F, 0.97F);
constexpr RenderColor kPanelAlt = Color(0.034F, 0.044F, 0.061F, 0.98F);
constexpr RenderColor kText = Color(0.88F, 0.95F, 0.96F);
constexpr RenderColor kSoft = Color(0.68F, 0.78F, 0.82F);
constexpr RenderColor kMuted = Color(0.42F, 0.50F, 0.56F);
constexpr RenderColor kCyan = Color(0.30F, 0.90F, 0.94F);
constexpr RenderColor kGreen = Color(0.16F, 0.91F, 0.48F);
constexpr RenderColor kAmber = Color(1.00F, 0.70F, 0.24F);
constexpr RenderColor kRed = Color(0.98F, 0.28F, 0.31F);
constexpr RenderColor kPurple = Color(0.85F, 0.48F, 0.98F);

bool IsFinite(float value) noexcept {
    return std::isfinite(static_cast<double>(value));
}

std::string LowerAscii(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    for (const unsigned char character : text) {
        if (character >= static_cast<unsigned char>('A') &&
            character <= static_cast<unsigned char>('Z')) {
            result.push_back(static_cast<char>(character + ('a' - 'A')));
        } else {
            result.push_back(static_cast<char>(character));
        }
    }
    return result;
}

bool LooksLikePrivateOrInternalText(std::string_view text) {
    const std::string lower = LowerAscii(text);
    constexpr std::array<std::string_view, 14U> blocked{
        "rawinput", "raw input", "reconciliation", "checkpoint",
        "pcap parser", "usbpcap", "\\\\?\\", "hid#", "vid_",
        "pid_", "instance id", "container id", "root hub",
        "device path",
    };
    return std::any_of(blocked.begin(), blocked.end(),
                       [&lower](std::string_view marker) {
                           return lower.find(marker) != std::string::npos;
                       });
}

std::string FormatFixed(double value, int precision) {
    std::ostringstream output;
    output << std::fixed << std::setprecision(precision) << value;
    return output.str();
}

std::string FormatClock(double seconds) {
    const auto whole_seconds = static_cast<std::int64_t>(
        std::max(0.0, std::floor(std::isfinite(seconds) ? seconds : 0.0)));
    const auto minutes = whole_seconds / 60;
    const auto remainder = whole_seconds % 60;
    std::ostringstream output;
    output << minutes << ':' << std::setw(2) << std::setfill('0') << remainder;
    return output.str();
}

std::string SelectedMouseLabel(const ParticipantUiInput& input) {
    if (!input.selected_mouse.has_value() ||
        *input.selected_mouse >= input.mice.size()) {
        return "YOUR SELECTED MOUSE";
    }
    return SanitizeParticipantLabel(
        input.mice[*input.selected_mouse].product_name,
        "YOUR SELECTED MOUSE");
}

class UiBuilder final {
public:
    ParticipantUiResult result;

    void Background() {
        Rect({-1.0F, 1.0F, 1.0F, -1.0F}, kBackground);
        Rect({-1.0F, 0.88F, 1.0F, 0.84F}, Color(0.08F, 0.32F, 0.36F));
        Rect({-1.0F, -0.84F, 1.0F, -0.88F}, Color(0.08F, 0.32F, 0.36F));
    }

    void Rect(UiRect rect, RenderColor color) {
        result.layer.rects.push_back(
            {rect.left, rect.top, rect.right, rect.bottom, color});
    }

    void Outline(UiRect rect, float thickness, RenderColor color) {
        Rect({rect.left, rect.top, rect.right, rect.top - thickness}, color);
        Rect({rect.left, rect.bottom + thickness, rect.right, rect.bottom}, color);
        Rect({rect.left, rect.top, rect.left + thickness, rect.bottom}, color);
        Rect({rect.right - thickness, rect.top, rect.right, rect.bottom}, color);
    }

    void Text(std::string text, float x, float y, double scale,
              RenderColor color = kText,
              RenderTextAlign align = RenderTextAlign::Left) {
        if (text.empty()) {
            return;
        }
        result.layer.texts.push_back(
            {std::move(text), x, y, scale, color, align});
    }

    void Button(UiRect rect, std::string label, ParticipantUiAction action,
                RenderColor accent = kCyan, bool enabled = true,
                double scale = 0.62,
                std::size_t item_index = kNoItem,
                ParticipantUiControlRole role =
                    ParticipantUiControlRole::Button) {
        const RenderColor fill = enabled ? Color(accent.r * 0.12F,
                                                 accent.g * 0.12F,
                                                 accent.b * 0.12F, 0.98F)
                                         : Color(0.035F, 0.041F, 0.050F, 0.92F);
        const RenderColor edge = enabled ? accent : kMuted;
        Rect(rect, fill);
        Outline(rect, 0.005F, edge);
        Text(label, (rect.left + rect.right) * 0.5F,
             (rect.top + rect.bottom) * 0.5F + 0.018F, scale,
             enabled ? kText : kMuted, RenderTextAlign::Center);
        result.hitboxes.push_back({action, role, rect.left, rect.top,
                                   rect.right, rect.bottom, enabled,
                                   item_index, std::move(label)});
    }

    void Slider(UiRect hit_rect, float track_left, float track_right,
                float track_y, double normalized, std::string label,
                ParticipantUiAction action, RenderColor accent,
                bool enabled = true) {
        const double clamped = std::clamp(
            std::isfinite(normalized) ? normalized : 0.0, 0.0, 1.0);
        const float knob_x = track_left +
            static_cast<float>(clamped) * (track_right - track_left);
        Rect({track_left, track_y + 0.010F, track_right, track_y - 0.010F},
             enabled ? Color(0.16F, 0.22F, 0.26F) :
                       Color(0.10F, 0.12F, 0.14F));
        Rect({track_left, track_y + 0.010F, knob_x, track_y - 0.010F},
             enabled ? accent : kMuted);
        Rect({knob_x - 0.014F, track_y + 0.030F, knob_x + 0.014F,
              track_y - 0.030F}, enabled ? kText : kMuted);
        result.hitboxes.push_back(
            {action, ParticipantUiControlRole::Slider,
             hit_rect.left, hit_rect.top, hit_rect.right, hit_rect.bottom,
             enabled, kNoItem, std::move(label)});
    }

    ParticipantUiResult Finish() {
        std::ostringstream accessibility;
        bool first = true;
        for (const RenderText& text : result.layer.texts) {
            if (text.text.empty()) {
                continue;
            }
            if (!first) {
                accessibility << '\n';
            }
            first = false;
            accessibility << text.text;
        }
        result.accessible_text = accessibility.str();
        return std::move(result);
    }
};

void AddTitle(UiBuilder& ui, std::string_view title,
              std::string_view detail = {}) {
    ui.Text("ABCURVES AIM TRAINER", 0.0F, 0.94F, 1.04, kText,
            RenderTextAlign::Center);
    ui.Text(std::string(title), 0.0F, 0.76F, 0.91, kCyan,
            RenderTextAlign::Center);
    if (!detail.empty()) {
        ui.Text(std::string(detail), 0.0F, 0.63F, 0.50, kSoft,
                RenderTextAlign::Center);
    }
}

void AddFooterHints(UiBuilder& ui, bool escape_pauses) {
    ui.Text(escape_pauses ? "ESC PAUSES    F11 FULLSCREEN"
                          : "F11 FULLSCREEN",
            0.0F, -0.94F, 0.46, kMuted, RenderTextAlign::Center);
}

void AddCenteredPanel(UiBuilder& ui, float top = 0.50F,
                      float bottom = -0.68F) {
    const UiRect panel{-0.72F, top, 0.72F, bottom};
    ui.Rect(panel, kPanel);
    ui.Outline(panel, 0.006F, kCyan);
}

void AddProgress(UiBuilder& ui, float y, double normalized,
                 RenderColor accent = kGreen) {
    const double value = std::clamp(
        std::isfinite(normalized) ? normalized : 0.0, 0.0, 1.0);
    ui.Rect({-0.55F, y + 0.025F, 0.55F, y - 0.025F},
            Color(0.10F, 0.14F, 0.18F));
    ui.Rect({-0.55F, y + 0.025F,
             -0.55F + static_cast<float>(value) * 1.10F, y - 0.025F},
            accent);
}

void AddRunLengthButtons(UiBuilder& ui, const ParticipantSettings& settings,
                         bool enabled) {
    const bool full = settings.protocol == ProtocolPreference::FullResearch;
    ui.Text("SESSION", 0.0F, 0.50F, 0.58, kSoft, RenderTextAlign::Center);
    ui.Button({-0.23F, 0.41F, 0.23F, 0.25F}, "FULL RESEARCH",
              ParticipantUiAction::ChooseFullResearch,
              full ? kGreen : kMuted, enabled, 0.50);
    ui.Button({-0.23F, 0.20F, 0.23F, 0.04F}, "QUICK TEST",
              ParticipantUiAction::ChooseQuickPractice,
              full ? kMuted : kGreen, enabled, 0.50);
    ui.Text(full ? "COMPLETE 21 BLOCK ROUTINE" : "10 SECONDS PER CHALLENGE",
            0.0F, -0.02F, 0.38, kMuted, RenderTextAlign::Center);
}

void AddSettingsPanel(UiBuilder& ui, const ParticipantSettings& settings,
                      bool sensitivity_enabled) {
    ui.Text("AIM SETTINGS", -0.645F, 0.61F, 0.72, kCyan,
            RenderTextAlign::Center);
    ui.Text("CROSSHAIR", -0.90F, 0.45F, 0.48, kSoft);
    ui.Text(FormatFixed(settings.crosshair_scale, 2) + "X", -0.39F, 0.45F,
            0.48, kText, RenderTextAlign::Right);
    ui.Slider({-0.91F, 0.40F, -0.38F, 0.25F}, -0.88F, -0.43F, 0.32F,
              (settings.crosshair_scale - kMinimumCrosshairScale) /
                  (kMaximumCrosshairScale - kMinimumCrosshairScale),
              "Crosshair size", ParticipantUiAction::SetCrosshairScale,
              kCyan);
    ui.result.layer.crosshair_previews.push_back(
        {-0.405F, 0.43F, settings.crosshair_scale});

    ui.Text("SENSITIVITY", -0.90F, 0.15F, 0.48, kSoft);
    ui.Text(sensitivity_enabled
                ? FormatFixed(settings.trainer_sensitivity, 2)
                : "SET FOR SESSION",
            -0.39F, 0.15F, 0.46,
            sensitivity_enabled ? kText : kMuted, RenderTextAlign::Right);
    ui.Slider({-0.91F, 0.10F, -0.38F, -0.05F}, -0.88F, -0.43F, 0.02F,
              (settings.trainer_sensitivity - kMinimumTrainerSensitivity) /
                  (kMaximumTrainerSensitivity - kMinimumTrainerSensitivity),
              "Sensitivity", ParticipantUiAction::SetSensitivity,
              kGreen, sensitivity_enabled);

    ui.Button({-0.88F, -0.17F, -0.41F, -0.35F},
              settings.target_highlight_enabled ? "HIGHLIGHT ON"
                                                : "HIGHLIGHT OFF",
              ParticipantUiAction::ToggleTargetHighlight,
              settings.target_highlight_enabled ? kGreen : kMuted,
              true, 0.50);
}

void AddSoundPanel(UiBuilder& ui, const ParticipantUiInput& input) {
    const ParticipantSettings& settings = input.settings;
    const RenderColor accent = settings.audio_enabled ? kPurple : kMuted;
    ui.Text("SOUND", 0.645F, 0.61F, 0.72, accent,
            RenderTextAlign::Center);
    ui.Button({0.40F, 0.51F, 0.90F, 0.36F},
              settings.audio_enabled ? "AUDIO ON" : "AUDIO OFF",
              ParticipantUiAction::ToggleAudio, accent, true, 0.50);
    ui.Text("TARGET HIT SOUND", 0.65F, 0.22F, 0.42, kSoft,
            RenderTextAlign::Center);
    const std::array actions{ParticipantUiAction::SelectPop1,
                             ParticipantUiAction::SelectPop2,
                             ParticipantUiAction::SelectPop3};
    constexpr std::array<UiRect, 3U> boxes{
        UiRect{0.39F, 0.15F, 0.54F, -0.02F},
        UiRect{0.575F, 0.15F, 0.725F, -0.02F},
        UiRect{0.76F, 0.15F, 0.91F, -0.02F},
    };
    for (std::size_t index = 0U; index < boxes.size(); ++index) {
        const bool selected = static_cast<std::size_t>(settings.hit_sound) == index;
        ui.Button(boxes[index], "POP " + std::to_string(index + 1U),
                  actions[index], selected ? kGreen : accent,
                  settings.audio_enabled, 0.40);
    }
    ui.Text("SOUND FEEDBACK IS OPTIONAL", 0.65F, -0.16F, 0.38, kMuted,
            RenderTextAlign::Center);
}

ParticipantUiResult BuildThreePanel(const ParticipantUiInput& input,
                                    bool paused) {
    UiBuilder ui;
    ui.Background();
    ui.Text("ABCURVES AIM TRAINER", 0.0F, 0.94F, 1.04, kText,
            RenderTextAlign::Center);
    ui.Text(paused ? "SESSION PAUSED" : "CHOOSE YOUR SESSION", 0.0F, 0.80F,
            0.70, paused ? kAmber : kCyan, RenderTextAlign::Center);
    ui.Rect(kLeftPanel, kPanel);
    ui.Rect(kCenterPanel, kPanelAlt);
    ui.Rect(kRightPanel, kPanel);
    ui.Outline(kLeftPanel, 0.005F, kCyan);
    ui.Outline(kCenterPanel, 0.005F, paused ? kAmber : kGreen);
    ui.Outline(kRightPanel, 0.005F, kPurple);

    AddSettingsPanel(ui, input.settings, !paused);
    AddRunLengthButtons(ui, input.settings, !paused);
    if (paused) {
        ui.Button({-0.23F, 0.00F, 0.23F, -0.23F}, "RESUME",
                  ParticipantUiAction::Resume, kGreen, true, 0.85);
        ui.Text("CURRENT EVENT SKIPPED", 0.0F, -0.31F, 0.40, kAmber,
                RenderTextAlign::Center);
    } else {
        ui.Button({-0.23F, -0.10F, 0.23F, -0.33F}, "START",
                  ParticipantUiAction::ConfirmConfiguration, kGreen, true,
                  0.85);
    }
    ui.Button({-0.23F, -0.42F, 0.23F, -0.63F},
              paused ? "FINISH AND SAVE" : "QUIT",
              paused ? ParticipantUiAction::FinishAndSave
                     : ParticipantUiAction::Cancel,
              paused ? kAmber : kRed, true, paused ? 0.48 : 0.72);

    AddSoundPanel(ui, input);
    AddFooterHints(ui, true);
    return ui.Finish();
}

ParticipantUiResult BuildWelcome(const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, "HELP IMPROVE MOUSE RESEARCH",
             "A SHORT AIM TRAINER THAT SAVES A STUDY SESSION");
    AddCenteredPanel(ui, 0.49F, -0.80F);
    ui.Text("WHAT IS SAVED", -0.58F, 0.35F, 0.64, kGreen);
    ui.Text("RAW USB TRAFFIC FROM THE MOUSE OR RECEIVER YOU CHOOSE", -0.58F,
            0.22F, 0.39,
            kText);
    ui.Text("TARGETS, CLICKS, TIMING, AND GAME RESULTS", -0.58F, 0.10F,
            0.49, kText);
    ui.Text("YOUR SETTINGS AND A RANDOM PARTICIPANT CODE", -0.58F, -0.02F,
            0.49, kText);
    ui.Text("SHARED-RECEIVER KEYS MAY BE CAPTURED - AVOID PRIVATE TYPING",
            -0.58F, -0.13F, 0.34, kAmber);
    ui.Text("NOT SAVED", -0.58F, -0.24F, 0.59, kAmber);
    ui.Text("SCREEN CONTENT, NAMES, MICROPHONE, OR PERSONAL FILES", -0.58F,
            -0.35F, 0.43, kText);

    const auto& recovery = input.startup_recovery;
    std::string notice = "YOU CAN EXIT BEFORE STARTING";
    std::string archive_notice;
    std::string review_notice;
    RenderColor notice_color = kSoft;
    if (recovery.in_progress) {
        notice = recovery.close_requested
            ? "CLOSE REQUESTED - FINISHING THE FILE CHECK SAFELY"
            : "CHECKING FOR AN EARLIER INTERRUPTED SESSION";
        archive_notice = recovery.close_requested
            ? "THIS WINDOW WILL CLOSE WHEN THE CHECK FINISHES"
            : "CONTINUE UNLOCKS WHEN THIS CHECK FINISHES";
        notice_color = kAmber;
    } else if (recovery.recovered_archive_count > 0U) {
        notice = std::to_string(recovery.recovered_archive_count) +
            (recovery.recovered_archive_count == 1U
                 ? " PREVIOUS SESSION FILE RECOVERED"
                 : " PREVIOUS SESSION FILES RECOVERED");
        if (recovery.recovered_archive_count == 1U &&
            !recovery.recovered_archive_filename.empty()) {
            std::string filename = SanitizeParticipantLabel(
                recovery.recovered_archive_filename,
                "RECOVERED SESSION FILE");
            if (filename.size() > 42U) {
                filename.resize(39U);
                filename += "...";
            }
            archive_notice = "FILE: " + filename;
        } else {
            archive_notice = "FILES ARE IN ABCURVES RESEARCH SESSIONS";
        }
        if (recovery.check_failed) {
            review_notice = "THE STARTUP FILE CHECK ALSO NEEDS TECHNICAL REVIEW";
        } else if (recovery.review_archive_count > 0U &&
            recovery.failed_workspace_count > 0U) {
            review_notice =
                "RECOVERED AND ORIGINAL FILES REQUIRE RESEARCHER REVIEW";
        } else if (recovery.review_archive_count > 0U) {
            review_notice = std::to_string(recovery.review_archive_count) +
                (recovery.review_archive_count == 1U
                     ? " RECOVERED FILE REQUIRES RESEARCHER REVIEW"
                     : " RECOVERED FILES REQUIRE RESEARCHER REVIEW");
        } else if (recovery.failed_workspace_count > 0U) {
            review_notice =
                "EARLIER SESSION FILES STILL REQUIRE TECHNICAL REVIEW";
        } else if (recovery.active_writer_count > 0U) {
            review_notice =
                "ANOTHER ACTIVE SESSION WAS LEFT UNCHANGED";
        }
        notice_color = review_notice.empty() ? kGreen : kAmber;
    } else if (recovery.check_failed) {
        notice = "PREVIOUS SESSION FILES COULD NOT BE CHECKED";
        archive_notice = "NO EARLIER FILE WAS CALLED RECOVERED";
        review_notice = "CONTACT THE RESEARCH TEAM IF YOU EXPECTED A FILE";
        notice_color = kAmber;
    } else if (recovery.failed_workspace_count > 0U) {
        notice = recovery.failed_workspace_count == 1U
            ? "AN EARLIER SESSION NEEDS TECHNICAL REVIEW"
            : "EARLIER SESSIONS NEED TECHNICAL REVIEW";
        archive_notice = "THE ORIGINAL FILES WERE LEFT UNCHANGED";
        if (recovery.active_writer_count > 0U) {
            review_notice = "ANOTHER ACTIVE SESSION WAS ALSO LEFT UNCHANGED";
        }
        notice_color = kAmber;
    } else if (recovery.active_writer_count > 0U) {
        notice = recovery.active_writer_count == 1U
            ? "ANOTHER SESSION MAY STILL BE ACTIVE"
            : "OTHER SESSIONS MAY STILL BE ACTIVE";
        archive_notice = "THEIR FILES WERE LEFT UNCHANGED";
        notice_color = kAmber;
    }
    ui.Text(std::move(notice), 0.0F, -0.43F, 0.40, notice_color,
            RenderTextAlign::Center);
    ui.Text(std::move(archive_notice), 0.0F, -0.50F, 0.31, kSoft,
            RenderTextAlign::Center);
    ui.Text(std::move(review_notice), 0.0F, -0.56F, 0.30, kAmber,
            RenderTextAlign::Center);

    const bool welcome_enabled = !recovery.in_progress &&
                                 !recovery.close_requested;
    ui.Button({-0.38F, -0.60F, 0.34F, -0.79F},
              recovery.close_requested
                  ? "FINISHING..."
                  : recovery.in_progress ? "CHECKING FILES..."
                                         : "I UNDERSTAND - CONTINUE",
              ParticipantUiAction::AcceptPrivacy, kGreen, welcome_enabled,
              recovery.in_progress || recovery.close_requested ? 0.48 : 0.57);
    ui.Button({0.51F, -0.60F, 0.69F, -0.79F},
              recovery.close_requested ? "CLOSING" : "EXIT",
              ParticipantUiAction::Exit, kRed, !recovery.close_requested,
              0.50);
    AddFooterHints(ui, false);
    return ui.Finish();
}

ParticipantUiResult BuildMouseList(const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, "CHOOSE YOUR MOUSE",
             "SELECT THE PHYSICAL MOUSE YOU WILL USE TO PLAY");
    ui.Rect({-0.72F, 0.51F, 0.72F, -0.57F}, kPanel);
    ui.Outline({-0.72F, 0.51F, 0.72F, -0.57F}, 0.006F, kCyan);

    constexpr std::size_t kVisibleRows = 5U;
    if (input.mice.empty()) {
        ui.Text(input.mouse_scan_in_progress ? "LOOKING FOR MICE..."
                                             : "NO MICE FOUND",
                0.0F, 0.17F, 0.72, kAmber,
                RenderTextAlign::Center);
        ui.Text(input.mouse_scan_in_progress ? "THIS SHOULD ONLY TAKE A MOMENT"
                                             : "CONNECT YOUR MOUSE, THEN REFRESH",
                0.0F, 0.01F, 0.49,
                kSoft, RenderTextAlign::Center);
    } else {
        const std::size_t count = std::min(kVisibleRows, input.mice.size());
        for (std::size_t index = 0U; index < count; ++index) {
            const ParticipantMouseOption& mouse = input.mice[index];
            const float top = 0.42F - static_cast<float>(index) * 0.19F;
            const UiRect row{-0.64F, top, 0.64F, top - 0.15F};
            std::string label = SanitizeParticipantLabel(
                mouse.product_name, "MOUSE " + std::to_string(index + 1U));
            if (label.size() > 34U) {
                label.resize(31U);
                label += "...";
            }
            const bool selected = input.selected_mouse == index;
            const RenderColor accent = mouse.available
                                           ? (selected ? kGreen : kCyan)
                                           : kMuted;
            ui.Button(row, label, ParticipantUiAction::SelectMouse, accent,
                      mouse.available, 0.52, index,
                      ParticipantUiControlRole::ListRow);
            ui.Text(mouse.available ? (selected ? "SELECTED" : "READY")
                                    : "NOT AVAILABLE",
                    0.60F, top - 0.055F, 0.36,
                    mouse.available ? accent : kMuted,
                    RenderTextAlign::Right);
        }
        if (input.mice.size() > kVisibleRows) {
            ui.Text("MORE MICE FOUND - DISCONNECT UNUSED DEVICES",
                    0.0F, -0.53F, 0.38, kAmber, RenderTextAlign::Center);
        }
    }

    ui.Button({-0.50F, -0.66F, -0.08F, -0.82F}, "REFRESH",
              ParticipantUiAction::RefreshMouseList, kCyan, true, 0.53);
    ui.Button({0.08F, -0.66F, 0.50F, -0.82F}, "CANCEL",
              ParticipantUiAction::Cancel, kRed, true, 0.53);
    AddFooterHints(ui, false);
    return ui.Finish();
}

ParticipantUiResult BuildCertificationReady(const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, "CHECK THIS MOUSE",
             "ONE QUICK CHECK MAKES SURE WE FOLLOW THE MOUSE YOU CHOSE");
    AddCenteredPanel(ui);
    ui.Text(SelectedMouseLabel(input), 0.0F, 0.32F, 0.70, kGreen,
            RenderTextAlign::Center);
    ui.Text("WHEN THE CHECK STARTS", 0.0F, 0.14F, 0.48, kSoft,
            RenderTextAlign::Center);
    ui.Text("MOVE THIS MOUSE IN A FEW CIRCLES", 0.0F, 0.01F, 0.61, kText,
            RenderTextAlign::Center);
    ui.Text("THEN CLICK ITS LEFT BUTTON ONCE", 0.0F, -0.12F, 0.61, kText,
            RenderTextAlign::Center);
    ui.Text("THE CHECK ENDS ON ITS OWN", 0.0F, -0.25F, 0.44, kMuted,
            RenderTextAlign::Center);
    ui.Text("WINDOWS MAY ASK PERMISSION FOR THIS CHECK", 0.0F, -0.33F,
            0.36, kSoft, RenderTextAlign::Center);
    ui.Button({-0.29F, -0.40F, 0.29F, -0.59F}, "BEGIN CHECK",
              ParticipantUiAction::BeginCertification, kGreen, true, 0.66);
    ui.Button({-0.62F, -0.65F, -0.10F, -0.81F}, "CHOOSE ANOTHER",
              ParticipantUiAction::ChooseDifferentMouse, kCyan, true, 0.48);
    ui.Button({0.10F, -0.65F, 0.62F, -0.81F}, "CANCEL",
              ParticipantUiAction::Cancel, kRed, true, 0.48);
    AddFooterHints(ui, false);
    return ui.Finish();
}

ParticipantUiResult BuildCertifying(const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, "CHECKING YOUR MOUSE",
             "KEEP USING ONLY THE MOUSE YOU SELECTED FOR THIS SHORT STEP");
    AddCenteredPanel(ui);
    ui.Text("MOVE IN A FEW CIRCLES", 0.0F, 0.27F, 0.76, kCyan,
            RenderTextAlign::Center);
    ui.Text("CLICK LEFT ONCE", 0.0F, 0.08F, 0.76, kGreen,
            RenderTextAlign::Center);
    AddProgress(ui, -0.09F, input.certification_progress);
    ui.Text("CHECKING...", 0.0F, -0.21F, 0.52, kSoft,
            RenderTextAlign::Center);
    ui.Button({-0.24F, -0.38F, 0.24F, -0.57F}, "CANCEL CHECK",
              ParticipantUiAction::Cancel, kRed, true, 0.54);
    AddFooterHints(ui, false);
    return ui.Finish();
}

ParticipantUiResult BuildCertificationNeedsAction(
    const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    AddCenteredPanel(ui, 0.58F, -0.69F);
    std::string title = "LET US TRY THAT ONCE MORE";
    std::string detail = "MOVE THE SELECTED MOUSE MORE CLEARLY AND CLICK ONCE";
    if (input.flow.certification_problem == CertificationProblem::Ambiguous) {
        title = "WE COULD NOT PICK ONE MOUSE";
        detail = "USE ONLY YOUR SELECTED MOUSE DURING THE NEXT CHECK";
    } else if (input.flow.certification_problem ==
               CertificationProblem::NoActivity) {
        title = "MOUSE DATA WAS NOT SEEN";
        detail = "MOVE THE SELECTED MOUSE IN CIRCLES AND CLICK ONCE";
    } else if (input.flow.certification_problem ==
               CertificationProblem::PermissionDenied) {
        title = "PERMISSION IS NEEDED";
        detail = "ALLOW THE MOUSE CHECK, THEN CHOOSE TRY AGAIN";
    }
    AddTitle(ui, title, detail);
    ui.Text("NOTHING WILL RETRY UNTIL YOU CHOOSE", 0.0F, 0.27F, 0.47,
            kSoft, RenderTextAlign::Center);
    ui.Button({-0.29F, 0.10F, 0.29F, -0.10F}, "TRY AGAIN",
              ParticipantUiAction::RetryCertification, kGreen, true, 0.65);
    ui.Button({-0.29F, -0.17F, 0.29F, -0.37F}, "CHOOSE ANOTHER MOUSE",
              ParticipantUiAction::ChooseDifferentMouse, kCyan, true, 0.49);
    ui.Button({-0.29F, -0.44F, 0.29F, -0.62F}, "CANCEL",
              ParticipantUiAction::Cancel, kRed, true, 0.54);
    AddFooterHints(ui, false);
    return ui.Finish();
}

ParticipantUiResult BuildReadyToStart(const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, "READY TO BEGIN",
             "YOUR MOUSE AND AIM TRAINER SETTINGS ARE READY");
    AddCenteredPanel(ui);
    ui.Text(SelectedMouseLabel(input), 0.0F, 0.29F, 0.68, kGreen,
            RenderTextAlign::Center);
    ui.Text(input.settings.protocol == ProtocolPreference::FullResearch
                ? "FULL RESEARCH SESSION"
                : "QUICK TEST - 10 SECONDS PER CHALLENGE",
            0.0F, 0.10F, 0.58, kText, RenderTextAlign::Center);
    ui.Text("SENSITIVITY " +
                FormatFixed(input.settings.trainer_sensitivity, 2),
            0.0F, -0.04F, 0.50, kSoft, RenderTextAlign::Center);
    ui.Button({-0.30F, -0.20F, 0.30F, -0.43F}, "START COLLECTION",
              ParticipantUiAction::StartCapture, kGreen, true, 0.67);
    ui.Button({-0.30F, -0.49F, 0.30F, -0.65F}, "EDIT SETTINGS",
              ParticipantUiAction::EditConfiguration, kCyan, true, 0.48);
    AddFooterHints(ui, false);
    return ui.Finish();
}

ParticipantUiResult BuildBusyScreen(std::string_view title,
                                    std::string_view detail,
                                    std::string_view status,
                                    RenderColor accent) {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, title, detail);
    AddCenteredPanel(ui);
    ui.Text(std::string(status), 0.0F, 0.11F, 0.72, accent,
            RenderTextAlign::Center);
    ui.Text("PLEASE KEEP THIS WINDOW OPEN", 0.0F, -0.10F, 0.47, kSoft,
            RenderTextAlign::Center);
    AddProgress(ui, -0.26F, 0.58, accent);
    AddFooterHints(ui, false);
    return ui.Finish();
}

ParticipantUiResult BuildReady(const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, "COLLECTION IS READY",
             "GET COMFORTABLE AND BEGIN WHEN YOU ARE READY TO AIM");
    AddCenteredPanel(ui);
    ui.Text(input.flow.WaitingForGameplayInput()
                ? "WAITING FOR YOUR SELECTED MOUSE"
                : "THE TRAINER WILL START AFTER A SHORT COUNTDOWN",
            0.0F, 0.19F, 0.53,
            input.flow.WaitingForGameplayInput() ? kAmber : kText,
            RenderTextAlign::Center);
    ui.Text("ALT-TAB OR ESC WILL PAUSE SAFELY", 0.0F, 0.03F, 0.50, kSoft,
            RenderTextAlign::Center);
    ui.Button({-0.30F, -0.16F, 0.30F, -0.39F}, "START COUNTDOWN",
              ParticipantUiAction::BeginCountdown, kGreen,
              input.flow.CanBeginCountdown(), 0.62);
    ui.Button({-0.30F, -0.47F, 0.30F, -0.64F}, "FINISH AND SAVE",
              ParticipantUiAction::FinishAndSave, kAmber, true, 0.48);
    AddFooterHints(ui, true);
    return ui.Finish();
}

ParticipantUiResult BuildCountdown(int number, bool resume) {
    UiBuilder ui;
    ui.Background();
    ui.Text(resume ? "RESUMING" : "GET READY", 0.0F, 0.48F, 1.10,
            kCyan, RenderTextAlign::Center);
    ui.Text(std::to_string(std::max(1, number)), 0.0F, 0.12F, 2.20,
            kGreen, RenderTextAlign::Center);
    ui.Text("ESC TO PAUSE", 0.0F, -0.32F, 0.52, kSoft,
            RenderTextAlign::Center);
    ui.Button({-0.19F, -0.48F, 0.19F, -0.64F}, "PAUSE",
              ParticipantUiAction::Pause, kAmber, true, 0.52);
    AddFooterHints(ui, true);
    return ui.Finish();
}

ParticipantUiResult BuildEnvironmentPause(const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, "PAUSED",
             input.flow.WaitingForGameplayInput()
                 ? "WAITING FOR YOUR SELECTED MOUSE TO RECONNECT"
                 : "RETURN TO THIS WINDOW AND THE TRAINER WILL RESUME SAFELY");
    AddCenteredPanel(ui);
    ui.Text("THE CURRENT TARGET WAS SKIPPED", 0.0F, 0.17F, 0.61, kAmber,
            RenderTextAlign::Center);
    ui.Text("YOUR SAVED SESSION IS STILL SAFE", 0.0F, -0.01F, 0.54, kGreen,
            RenderTextAlign::Center);
    ui.Button({-0.29F, -0.23F, 0.29F, -0.43F}, "FINISH AND SAVE",
              ParticipantUiAction::FinishAndSave, kAmber, true, 0.50);
    AddFooterHints(ui, true);
    return ui.Finish();
}

ParticipantUiResult BuildComplete(const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, "SESSION SAVED",
             "THANK YOU - YOUR TIME AND EFFORT MATTER");
    AddCenteredPanel(ui);
    ui.Text("SEND_THIS", 0.0F, 0.20F, 1.34, kGreen,
            RenderTextAlign::Center);
    ui.Text(input.send_this_filename.empty()
                ? "SEND THE FILE WITH THIS LABEL TO THE RESEARCH TEAM"
                : input.send_this_filename,
            0.0F, 0.00F, input.send_this_filename.empty() ? 0.48 : 0.34,
            kText, RenderTextAlign::Center);
    if (!input.flow.warnings.empty()) {
        ui.Text("A FEW MOMENTS ARE MARKED FOR REVIEW", 0.0F, -0.14F, 0.45,
                kAmber, RenderTextAlign::Center);
    }
    ui.Button({-0.34F, -0.28F, 0.34F, -0.48F}, "OPEN SEND_THIS FOLDER",
              ParticipantUiAction::OpenSendThisFolder, kGreen,
              input.flow.send_this_available, 0.52);
    ui.Button({-0.22F, -0.54F, 0.22F, -0.69F}, "DONE",
              ParticipantUiAction::Done, kCyan, true, 0.55);
    AddFooterHints(ui, false);
    return ui.Finish();
}

ParticipantUiResult BuildError(const ParticipantUiInput& input) {
    UiBuilder ui;
    ui.Background();
    const bool preserved = input.flow.preserved_prefix ==
                           PreservedPrefixOutcome::Preserved;
    const bool diagnostic = input.flow.preserved_prefix ==
        PreservedPrefixOutcome::ArchiveWithoutVerifiedSource;
    AddTitle(ui, preserved ? "COLLECTION STOPPED SAFELY"
                           : diagnostic ? "COLLECTION NEEDS REVIEW"
                                        : "COLLECTION COULD NOT FINISH",
             preserved ? "THE USABLE PART OF YOUR SESSION WAS SAVED"
                       : diagnostic
                           ? "A REVIEW FILE WAS SAVED, BUT MOUSE DATA COULD NOT BE VERIFIED"
                       : "PLEASE CONTACT THE RESEARCH TEAM BEFORE TRYING AGAIN");
    AddCenteredPanel(ui);
    if (preserved || diagnostic) {
        ui.Text("SEND_THIS", 0.0F, 0.16F, 1.20, kGreen,
                RenderTextAlign::Center);
        ui.Text(preserved ? "THIS FILE STILL CONTAINS USEFUL WORK"
                          : "SEND THIS FILE FOR TECHNICAL REVIEW",
                0.0F, -0.04F, 0.52, kText, RenderTextAlign::Center);
        ui.Button({-0.34F, -0.23F, 0.34F, -0.43F},
                  "OPEN SEND_THIS FOLDER",
                  ParticipantUiAction::OpenSendThisFolder, kGreen, true,
                  0.52);
    } else {
        ui.Text("NO FINISHED FILE IS AVAILABLE", 0.0F, 0.10F, 0.62, kRed,
                RenderTextAlign::Center);
        ui.Text("YOUR PREVIOUS FILES WERE NOT CHANGED", 0.0F, -0.09F, 0.48,
                kSoft, RenderTextAlign::Center);
    }
    ui.Button({-0.22F, -0.52F, 0.22F, -0.68F}, "DONE",
              ParticipantUiAction::Done, kCyan, true, 0.55);
    AddFooterHints(ui, false);
    return ui.Finish();
}

ParticipantUiResult BuildCancelled() {
    UiBuilder ui;
    ui.Background();
    AddTitle(ui, "SESSION CANCELLED", "NO STUDY SESSION WAS STARTED");
    AddCenteredPanel(ui);
    ui.Text("YOU CAN CLOSE THIS WINDOW SAFELY", 0.0F, 0.05F, 0.60, kSoft,
            RenderTextAlign::Center);
    ui.Button({-0.22F, -0.25F, 0.22F, -0.44F}, "CLOSE",
              ParticipantUiAction::Done, kCyan, true, 0.57);
    AddFooterHints(ui, false);
    return ui.Finish();
}

}  // namespace

bool ParticipantUiHitbox::Contains(float ndc_x, float ndc_y) const noexcept {
    return IsFinite(ndc_x) && IsFinite(ndc_y) && ndc_x >= left &&
           ndc_x <= right && ndc_y <= top && ndc_y >= bottom;
}

std::string SanitizeParticipantLabel(std::string_view text,
                                     std::string_view fallback_text) {
    const auto safe_fallback = [&fallback_text]() {
        std::string fallback;
        fallback.reserve(fallback_text.size());
        for (const unsigned char character : fallback_text) {
            if (character >= 0x20U && character <= 0x7EU) {
                fallback.push_back(static_cast<char>(character));
            }
        }
        return fallback.empty() ? std::string("Mouse") : fallback;
    };

    if (LooksLikePrivateOrInternalText(text)) {
        return safe_fallback();
    }

    std::string cleaned;
    cleaned.reserve(std::min<std::size_t>(text.size(), 48U));
    bool pending_space = false;
    for (const unsigned char character : text) {
        const bool whitespace = character == static_cast<unsigned char>(' ') ||
                                character == static_cast<unsigned char>('\t') ||
                                character == static_cast<unsigned char>('\r') ||
                                character == static_cast<unsigned char>('\n');
        if (whitespace) {
            pending_space = !cleaned.empty();
            continue;
        }
        if (character < 0x20U || character > 0x7EU) {
            pending_space = !cleaned.empty();
            continue;
        }
        if (pending_space && cleaned.size() < 48U) {
            cleaned.push_back(' ');
        }
        pending_space = false;
        if (cleaned.size() < 48U) {
            cleaned.push_back(static_cast<char>(character));
        }
    }
    while (!cleaned.empty() && cleaned.back() == ' ') {
        cleaned.pop_back();
    }
    return cleaned.empty() ? safe_fallback() : cleaned;
}

std::optional<double> ParticipantSliderNormalizedValue(
    const ParticipantUiHitbox& hitbox, float ndc_x) noexcept {
    if (hitbox.role != ParticipantUiControlRole::Slider ||
        !IsFinite(ndc_x) || !IsFinite(hitbox.left) ||
        !IsFinite(hitbox.right) || hitbox.right <= hitbox.left) {
        return std::nullopt;
    }
    const double value =
        (static_cast<double>(ndc_x) - static_cast<double>(hitbox.left)) /
        (static_cast<double>(hitbox.right) - static_cast<double>(hitbox.left));
    return std::clamp(value, 0.0, 1.0);
}

std::optional<ParticipantUiHit> HitTestParticipantUi(
    std::span<const ParticipantUiHitbox> hitboxes, float ndc_x,
    float ndc_y) noexcept {
    if (!IsFinite(ndc_x) || !IsFinite(ndc_y)) {
        return std::nullopt;
    }
    for (const ParticipantUiHitbox& hitbox : hitboxes) {
        if (!hitbox.enabled || !hitbox.Contains(ndc_x, ndc_y)) {
            continue;
        }
        ParticipantUiHit hit;
        hit.action = hitbox.action;
        hit.item_index = hitbox.item_index;
        hit.normalized_value = ParticipantSliderNormalizedValue(hitbox, ndc_x);
        return hit;
    }
    return std::nullopt;
}

ParticipantUiResult BuildGameplayHud(
    const ParticipantGameplayHudInput& input) {
    UiBuilder ui;
    const RenderColor shadow = Color(0.010F, 0.014F, 0.020F, 0.84F);

    ui.Rect({-0.22F, 0.97F, 0.22F, 0.82F}, shadow);
    ui.Text(FormatClock(input.remaining_seconds), 0.0F, 0.93F, 0.78, kText,
            RenderTextAlign::Center);

    std::string challenge = SanitizeParticipantLabel(
        input.challenge_name, "AIM CHALLENGE");
    if (challenge.size() > 24U) {
        challenge.resize(21U);
        challenge += "...";
    }
    ui.Rect({0.35F, 0.97F, 0.98F, 0.82F}, shadow);
    ui.Text(challenge, 0.95F, 0.93F, 0.48, kText,
            RenderTextAlign::Right);
    ui.Text(std::to_string(input.block_index) + "/" +
                std::to_string(input.block_count),
            0.95F, 0.85F, 0.36, kSoft, RenderTextAlign::Right);

    ui.Rect({-0.98F, 0.97F, -0.56F, 0.82F}, shadow);
    ui.Text("SCORE " + std::to_string(input.score), -0.95F, 0.93F, 0.55,
            kText);
    ui.Text("HIGH " + std::to_string(input.highscore), -0.95F, 0.85F,
            0.40, kSoft);

    float warning_y = 0.72F;
    for (const ParticipantHudWarning warning : input.warnings) {
        std::string text;
        switch (warning) {
        case ParticipantHudWarning::MomentSkipped:
            text = "ONE MOMENT WAS SKIPPED";
            break;
        case ParticipantHudWarning::MomentMarkedForReview:
            text = "ONE MOMENT WAS MARKED FOR REVIEW";
            break;
        case ParticipantHudWarning::ReturnToWindow:
            text = "RETURN TO THE TRAINER TO CONTINUE";
            break;
        }
        ui.Rect({-0.98F, warning_y + 0.04F, -0.42F, warning_y - 0.07F},
                shadow);
        ui.Text(text, -0.95F, warning_y, 0.38, kAmber);
        warning_y -= 0.10F;
    }

    if (input.countdown.has_value()) {
        ui.Rect({-0.25F, 0.33F, 0.25F, -0.31F},
                Color(0.01F, 0.02F, 0.03F, 0.88F));
        ui.Text("GET READY", 0.0F, 0.20F, 0.72, kCyan,
                RenderTextAlign::Center);
        ui.Text(std::to_string(std::max(1, *input.countdown)), 0.0F, -0.02F,
                2.10, kGreen, RenderTextAlign::Center);
    }
    ui.Text("ESC PAUSES    F11 FULLSCREEN", 0.0F, -0.93F, 0.38, kMuted,
            RenderTextAlign::Center);
    ui.Text("ABCURVES", 0.95F, -0.85F, 0.50, kCyan,
            RenderTextAlign::Right);
    ui.Text("AIM TRAINER", 0.95F, -0.93F, 0.38, kGreen,
            RenderTextAlign::Right);
    return ui.Finish();
}

ParticipantUiResult BuildParticipantUi(const ParticipantUiInput& input) {
    switch (input.flow.stage) {
    case ParticipantStage::WelcomePrivacy:
        return BuildWelcome(input);
    case ParticipantStage::ChooseMouse:
        return BuildMouseList(input);
    case ParticipantStage::CertificationReady:
        return BuildCertificationReady(input);
    case ParticipantStage::Certifying:
        return BuildCertifying(input);
    case ParticipantStage::CertificationNeedsAction:
        return BuildCertificationNeedsAction(input);
    case ParticipantStage::ConfigureSession:
        return BuildThreePanel(input, false);
    case ParticipantStage::ReadyToStart:
        return BuildReadyToStart(input);
    case ParticipantStage::StartingCapture:
        return BuildBusyScreen("STARTING COLLECTION",
                               "THIS SHOULD ONLY TAKE A MOMENT",
                               "GETTING READY", kCyan);
    case ParticipantStage::Ready:
        return BuildReady(input);
    case ParticipantStage::Countdown:
        return BuildCountdown(input.countdown_number, false);
    case ParticipantStage::Playing: {
        ParticipantGameplayHudInput gameplay = input.gameplay;
        if (!input.flow.warnings.empty() && gameplay.warnings.empty()) {
            gameplay.warnings.push_back(
                ParticipantHudWarning::MomentMarkedForReview);
        }
        return BuildGameplayHud(gameplay);
    }
    case ParticipantStage::Paused:
        return input.flow.CanResume() ? BuildThreePanel(input, true)
                                      : BuildEnvironmentPause(input);
    case ParticipantStage::ResumeCountdown:
        return BuildCountdown(input.countdown_number, true);
    case ParticipantStage::StoppingAndSaving:
        return BuildBusyScreen("SAVING YOUR SESSION",
                               "YOUR AIM TRAINER SESSION IS COMPLETE",
                               "SAVING", kGreen);
    case ParticipantStage::StoppingAndPreserving:
        return BuildBusyScreen("SAVING USABLE WORK",
                               "COLLECTION STOPPED AND YOUR SAVED WORK IS BEING PROTECTED",
                               "PLEASE WAIT", kAmber);
    case ParticipantStage::Complete:
        return BuildComplete(input);
    case ParticipantStage::Error:
        return BuildError(input);
    case ParticipantStage::Cancelled:
        return BuildCancelled();
    }
    return BuildCancelled();
}

}  // namespace abdc::app
