#include "TestHarness.h"

#include "app/ParticipantSettings.h"
#include "base/AtomicFile.h"
#include "base/Json.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <string>

namespace {

class TemporaryDirectory final {
public:
    TemporaryDirectory() {
        static std::atomic<unsigned long long> sequence{0U};
        const auto tick = std::chrono::steady_clock::now()
                              .time_since_epoch()
                              .count();
        path_ = std::filesystem::temp_directory_path() /
            ("abcurves_participant_settings_" + std::to_string(tick) + "_" +
             std::to_string(sequence.fetch_add(1U)));
        std::filesystem::create_directories(path_);
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    [[nodiscard]] const std::filesystem::path& Path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_;
};

}  // namespace

TEST_CASE("participant settings defaults preserve the trainer-facing baseline") {
    const abdc::app::ParticipantSettings settings;
    EXPECT_EQ(settings.trainer_sensitivity, 1.0);
    EXPECT_EQ(settings.crosshair_scale, 0.75);
    EXPECT_TRUE(settings.target_highlight_enabled);
    EXPECT_TRUE(!settings.fullscreen);
    EXPECT_TRUE(settings.audio_enabled);
    EXPECT_EQ(settings.hit_sound, abdc::app::HitSound::Pop1);
    EXPECT_EQ(settings.protocol, abdc::app::ProtocolPreference::FullResearch);
    EXPECT_EQ(abdc::app::ParticipantBlockDurationMs(settings.protocol),
              60'000);
    EXPECT_EQ(abdc::app::ParticipantBlockDurationMs(
                  abdc::app::ProtocolPreference::QuickPractice),
              10'000);
}

TEST_CASE("participant settings round trip atomically without identity or session state") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "participant-settings.json";

    abdc::app::ParticipantSettings expected;
    expected.trainer_sensitivity = 0.713;
    expected.crosshair_scale = 0.55;
    expected.target_highlight_enabled = false;
    expected.fullscreen = true;
    expected.audio_enabled = false;
    expected.hit_sound = abdc::app::HitSound::Pop3;
    expected.protocol = abdc::app::ProtocolPreference::QuickPractice;

    const auto saved = abdc::app::SaveParticipantSettings(path, expected);
    EXPECT_TRUE(saved.saved);
    EXPECT_TRUE(saved.error.empty());
    const auto loaded = abdc::app::LoadParticipantSettings(path);
    EXPECT_EQ(loaded.status, abdc::app::ParticipantSettingsLoadStatus::Loaded);
    EXPECT_EQ(loaded.settings, expected);

    const std::string text = abdc::ReadUtf8File(path);
    const auto document = abdc::json::Parse(text);
    EXPECT_EQ(document.At("schema").AsString(),
              std::string(abdc::app::kParticipantSettingsSchema));
    EXPECT_EQ(document.At("schema_version").AsInt(),
              static_cast<std::int64_t>(abdc::app::kParticipantSettingsSchemaVersion));
    EXPECT_TRUE(text.find("user_id") == std::string::npos);
    EXPECT_TRUE(text.find("session_id") == std::string::npos);
    EXPECT_TRUE(text.find("output_directory") == std::string::npos);
    EXPECT_TRUE(text.find("device") == std::string::npos);
}

TEST_CASE("missing participant settings quietly use defaults") {
    TemporaryDirectory temporary;
    const auto loaded = abdc::app::LoadParticipantSettings(
        temporary.Path() / "does-not-exist.json");
    EXPECT_EQ(loaded.status,
              abdc::app::ParticipantSettingsLoadStatus::DefaultsBecauseMissing);
    EXPECT_EQ(loaded.settings, abdc::app::ParticipantSettings{});
    EXPECT_TRUE(loaded.warnings.empty());
    EXPECT_TRUE(loaded.quarantined_file.empty());
}

TEST_CASE("newer settings schemas load known fields and ignore extensions") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "participant-settings.json";
    abdc::AtomicWriteFile(path, R"json({
  "schema": "abcurves.participant-settings",
  "schema_version": 27,
  "future_top_level": {"anything": true},
  "preferences": {
    "trainer_sensitivity": 2,
    "crosshair_scale": 1.25,
    "target_highlight_enabled": false,
    "fullscreen": true,
    "protocol": "quick_practice",
    "future_preference": "ignored",
    "audio": {
      "enabled": true,
      "hit_sound": "pop_2",
      "future_audio_option": 123
    }
  }
})json");

    const auto loaded = abdc::app::LoadParticipantSettings(path);
    EXPECT_EQ(loaded.status,
              abdc::app::ParticipantSettingsLoadStatus::LoadedWithWarnings);
    EXPECT_EQ(loaded.settings.trainer_sensitivity, 2.0);
    EXPECT_EQ(loaded.settings.crosshair_scale, 1.25);
    EXPECT_TRUE(!loaded.settings.target_highlight_enabled);
    EXPECT_TRUE(loaded.settings.fullscreen);
    EXPECT_EQ(loaded.settings.protocol,
              abdc::app::ProtocolPreference::QuickPractice);
    EXPECT_EQ(loaded.settings.hit_sound, abdc::app::HitSound::Pop2);
    EXPECT_EQ(loaded.warnings.size(), 1U);
}

TEST_CASE("bad individual preferences fall back while valid preferences survive") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "participant-settings.json";
    abdc::AtomicWriteFile(path, R"json({
  "schema": "abcurves.participant-settings",
  "schema_version": 1,
  "preferences": {
    "trainer_sensitivity": 99,
    "crosshair_scale": "large",
    "target_highlight_enabled": false,
    "fullscreen": "yes",
    "protocol": "unknown_protocol",
    "audio": {
      "enabled": false,
      "hit_sound": "pop_3"
    }
  }
})json");

    const auto loaded = abdc::app::LoadParticipantSettings(path);
    EXPECT_EQ(loaded.status,
              abdc::app::ParticipantSettingsLoadStatus::LoadedWithWarnings);
    EXPECT_EQ(loaded.settings.trainer_sensitivity, 1.0);
    EXPECT_EQ(loaded.settings.crosshair_scale, 0.75);
    EXPECT_TRUE(!loaded.settings.target_highlight_enabled);
    EXPECT_TRUE(!loaded.settings.fullscreen);
    EXPECT_EQ(loaded.settings.protocol,
              abdc::app::ProtocolPreference::FullResearch);
    EXPECT_TRUE(!loaded.settings.audio_enabled);
    EXPECT_EQ(loaded.settings.hit_sound, abdc::app::HitSound::Pop3);
    EXPECT_EQ(loaded.warnings.size(), 4U);
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_TRUE(loaded.quarantined_file.empty());
}

TEST_CASE("malformed settings are quarantined and cannot block startup") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "participant-settings.json";
    abdc::AtomicWriteFile(path, "{ this is not json");

    const auto loaded = abdc::app::LoadParticipantSettings(path);
    EXPECT_EQ(loaded.status,
              abdc::app::ParticipantSettingsLoadStatus::DefaultsAfterMalformedFile);
    EXPECT_EQ(loaded.settings, abdc::app::ParticipantSettings{});
    EXPECT_TRUE(!loaded.warnings.empty());
    EXPECT_TRUE(!loaded.quarantined_file.empty());
    EXPECT_TRUE(std::filesystem::exists(loaded.quarantined_file));
    EXPECT_TRUE(!std::filesystem::exists(path));

    const auto second = abdc::app::LoadParticipantSettings(path);
    EXPECT_EQ(second.status,
              abdc::app::ParticipantSettingsLoadStatus::DefaultsBecauseMissing);
}

TEST_CASE("invalid settings are not saved over a valid atomic file") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "participant-settings.json";
    abdc::app::ParticipantSettings valid;
    EXPECT_TRUE(abdc::app::SaveParticipantSettings(path, valid).saved);
    const std::string original = abdc::ReadUtf8File(path);

    auto invalid = valid;
    invalid.trainer_sensitivity = 0.0;
    const auto rejected = abdc::app::SaveParticipantSettings(path, invalid);
    EXPECT_TRUE(!rejected.saved);
    EXPECT_TRUE(!rejected.error.empty());
    EXPECT_EQ(abdc::ReadUtf8File(path), original);

    invalid = valid;
    invalid.hit_sound = static_cast<abdc::app::HitSound>(999);
    EXPECT_TRUE(!abdc::app::SaveParticipantSettings(path, invalid).saved);
    EXPECT_EQ(abdc::ReadUtf8File(path), original);
}
