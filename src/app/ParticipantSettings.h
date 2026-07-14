#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace abdc::app {

inline constexpr std::string_view kParticipantSettingsSchema =
    "abcurves.participant-settings";
inline constexpr int kParticipantSettingsSchemaVersion = 2;

inline constexpr double kMinimumTrainerSensitivity = 0.01;
inline constexpr double kMaximumTrainerSensitivity = 3.0;
inline constexpr double kMinimumCrosshairScale = 0.25;
inline constexpr double kMaximumCrosshairScale = 2.0;
enum class HitSound {
    Pop1,
    Pop2,
    Pop3,
};

// Quick practice is intentionally not research-equivalent. The session manifest
// remains responsible for recording the protocol that was actually run.
enum class ProtocolPreference {
    FullResearch,
    QuickPractice,
};

struct ParticipantSettings {
    double trainer_sensitivity = 1.0;
    double crosshair_scale = 0.75;
    bool target_highlight_enabled = true;
    bool fullscreen = false;

    bool audio_enabled = true;
    HitSound hit_sound = HitSound::Pop1;

    ProtocolPreference protocol = ProtocolPreference::FullResearch;

    bool operator==(const ParticipantSettings&) const = default;
};

enum class ParticipantSettingsLoadStatus {
    DefaultsBecauseMissing,
    Loaded,
    LoadedWithWarnings,
    DefaultsAfterMalformedFile,
    DefaultsAfterIoError,
};

struct ParticipantSettingsLoadResult {
    ParticipantSettings settings{};
    ParticipantSettingsLoadStatus status =
        ParticipantSettingsLoadStatus::DefaultsBecauseMissing;
    std::vector<std::string> warnings;
    std::filesystem::path quarantined_file;
};

struct ParticipantSettingsSaveResult {
    bool saved = false;
    std::string error;

    [[nodiscard]] explicit operator bool() const noexcept { return saved; }
};

[[nodiscard]] std::string_view ConfigValue(HitSound sound) noexcept;
[[nodiscard]] std::string_view ConfigValue(ProtocolPreference protocol) noexcept;
[[nodiscard]] int ParticipantBlockDurationMs(
    ProtocolPreference protocol) noexcept;

// Invalid individual fields are ignored in favor of safe defaults. A malformed
// document is quarantined when possible. Ordinary file and parse failures are
// returned as status/warnings and never need to block capture startup.
[[nodiscard]] ParticipantSettingsLoadResult LoadParticipantSettings(
    const std::filesystem::path& path);

// Saving is atomic and refuses out-of-range or invalid enum values. The previous
// settings file is left untouched when validation or writing fails.
[[nodiscard]] ParticipantSettingsSaveResult SaveParticipantSettings(
    const std::filesystem::path& path,
    const ParticipantSettings& settings);

}  // namespace abdc::app
