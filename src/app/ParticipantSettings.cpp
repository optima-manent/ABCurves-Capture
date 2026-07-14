#include "app/ParticipantSettings.h"

#include "base/AtomicFile.h"
#include "base/Json.h"
#include "protocol/protocol_v1.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <exception>
#include <optional>
#include <system_error>
#include <utility>
#include <variant>

namespace abdc::app {
namespace {

constexpr std::uint64_t kMaximumSettingsBytes = 256U << 10U;

using Object = json::Value::Object;

const json::Value* Find(const Object& object, const std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &found->second;
}

void Warn(std::vector<std::string>& warnings,
          const std::string_view field,
          const std::string_view message) {
    warnings.emplace_back(std::string(field) + ": " + std::string(message));
}

const Object* ObjectValue(const json::Value& value) noexcept {
    return std::get_if<Object>(&value.Data());
}

std::optional<double> NumberValue(const json::Value& value) noexcept {
    if (const auto* floating = std::get_if<double>(&value.Data())) {
        return *floating;
    }
    if (const auto* integer = std::get_if<std::int64_t>(&value.Data())) {
        return static_cast<double>(*integer);
    }
    return std::nullopt;
}

void ReadBoundedNumber(const Object& object,
                       const std::string_view field,
                       const double minimum,
                       const double maximum,
                       double& destination,
                       std::vector<std::string>& warnings) {
    const json::Value* value = Find(object, field);
    if (value == nullptr) return;
    const auto number = NumberValue(*value);
    if (!number.has_value() || !std::isfinite(*number) ||
        *number < minimum || *number > maximum) {
        Warn(warnings, field, "invalid or out of range; using the default");
        return;
    }
    destination = *number;
}

void ReadBool(const Object& object,
              const std::string_view field,
              bool& destination,
              std::vector<std::string>& warnings) {
    const json::Value* value = Find(object, field);
    if (value == nullptr) return;
    if (const auto* boolean = std::get_if<bool>(&value->Data())) {
        destination = *boolean;
        return;
    }
    Warn(warnings, field, "must be true or false; using the default");
}

std::optional<std::string_view> StringValue(const json::Value& value) noexcept {
    if (const auto* text = std::get_if<std::string>(&value.Data())) {
        return *text;
    }
    return std::nullopt;
}

std::optional<HitSound> ParseHitSound(const std::string_view value) noexcept {
    if (value == "pop_1") return HitSound::Pop1;
    if (value == "pop_2") return HitSound::Pop2;
    if (value == "pop_3") return HitSound::Pop3;
    return std::nullopt;
}

std::optional<ProtocolPreference> ParseProtocol(
    const std::string_view value) noexcept {
    if (value == "full_research") return ProtocolPreference::FullResearch;
    if (value == "quick_practice") return ProtocolPreference::QuickPractice;
    return std::nullopt;
}

template <typename Enum, typename Parser>
void ReadEnum(const Object& object,
              const std::string_view field,
              Enum& destination,
              Parser&& parser,
              std::vector<std::string>& warnings) {
    const json::Value* value = Find(object, field);
    if (value == nullptr) return;
    const auto text = StringValue(*value);
    const auto parsed = text.has_value() ? parser(*text) : std::optional<Enum>{};
    if (!parsed.has_value()) {
        Warn(warnings, field, "unknown value; using the default");
        return;
    }
    destination = *parsed;
}

bool ValidEnum(const HitSound sound) noexcept {
    switch (sound) {
    case HitSound::Pop1:
    case HitSound::Pop2:
    case HitSound::Pop3:
        return true;
    }
    return false;
}

bool ValidEnum(const ProtocolPreference protocol) noexcept {
    switch (protocol) {
    case ProtocolPreference::FullResearch:
    case ProtocolPreference::QuickPractice:
        return true;
    }
    return false;
}

std::optional<std::string> ValidationError(
    const ParticipantSettings& settings) {
    const auto bounded = [](const double value,
                            const double minimum,
                            const double maximum) noexcept {
        return std::isfinite(value) && value >= minimum && value <= maximum;
    };
    if (!bounded(settings.trainer_sensitivity,
                 kMinimumTrainerSensitivity,
                 kMaximumTrainerSensitivity)) {
        return "trainer_sensitivity must be finite and between 0.01 and 3.0";
    }
    if (!bounded(settings.crosshair_scale,
                 kMinimumCrosshairScale,
                 kMaximumCrosshairScale)) {
        return "crosshair_scale must be finite and between 0.25 and 2.0";
    }
    if (!ValidEnum(settings.hit_sound)) return "hit_sound is invalid";
    if (!ValidEnum(settings.protocol)) return "protocol is invalid";
    return std::nullopt;
}

std::filesystem::path QuarantineMalformedFile(
    const std::filesystem::path& path) noexcept {
    try {
        std::error_code error;
        if (!std::filesystem::is_regular_file(path, error) || error) return {};

        const auto stamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        for (unsigned attempt = 0U; attempt < 100U; ++attempt) {
            const auto filename = path.filename().wstring() + L".invalid." +
                std::to_wstring(stamp) + L"." + std::to_wstring(attempt);
            const auto candidate = path.parent_path() / filename;
            error.clear();
            if (std::filesystem::exists(candidate, error) || error) continue;
            std::filesystem::rename(path, candidate, error);
            if (!error) return candidate;
        }
    } catch (...) {
        // Loading preferences is best effort. Capture startup must remain usable.
    }
    return {};
}

ParticipantSettingsLoadResult MalformedResult(
    const std::filesystem::path& path,
    const std::string_view reason) {
    ParticipantSettingsLoadResult result;
    result.status = ParticipantSettingsLoadStatus::DefaultsAfterMalformedFile;
    result.warnings.emplace_back("settings file ignored: " + std::string(reason));
    result.quarantined_file = QuarantineMalformedFile(path);
    if (result.quarantined_file.empty()) {
        result.warnings.emplace_back("malformed settings file could not be quarantined");
    }
    return result;
}

json::Value Serialize(const ParticipantSettings& settings) {
    json::Value audio = Object{};
    audio["enabled"] = settings.audio_enabled;
    audio["hit_sound"] = std::string(ConfigValue(settings.hit_sound));

    json::Value preferences = Object{};
    preferences["audio"] = std::move(audio);
    preferences["crosshair_scale"] = settings.crosshair_scale;
    preferences["fullscreen"] = settings.fullscreen;
    preferences["protocol"] = std::string(ConfigValue(settings.protocol));
    preferences["target_highlight_enabled"] = settings.target_highlight_enabled;
    preferences["trainer_sensitivity"] = settings.trainer_sensitivity;

    json::Value root = Object{};
    root["preferences"] = std::move(preferences);
    root["schema"] = std::string(kParticipantSettingsSchema);
    root["schema_version"] = kParticipantSettingsSchemaVersion;
    return root;
}

}  // namespace

std::string_view ConfigValue(const HitSound sound) noexcept {
    switch (sound) {
    case HitSound::Pop1: return "pop_1";
    case HitSound::Pop2: return "pop_2";
    case HitSound::Pop3: return "pop_3";
    }
    return {};
}

std::string_view ConfigValue(const ProtocolPreference protocol) noexcept {
    switch (protocol) {
    case ProtocolPreference::FullResearch: return "full_research";
    case ProtocolPreference::QuickPractice: return "quick_practice";
    }
    return {};
}

int ParticipantBlockDurationMs(const ProtocolPreference preference) noexcept {
    return preference == ProtocolPreference::QuickPractice
        ? protocol::V1Constants::quick_test_block_duration_ms
        : protocol::V1Constants::block_duration_ms;
}

ParticipantSettingsLoadResult LoadParticipantSettings(
    const std::filesystem::path& path) {
    ParticipantSettingsLoadResult result;

    std::error_code error;
    const bool exists = std::filesystem::exists(path, error);
    if (error) {
        result.status = ParticipantSettingsLoadStatus::DefaultsAfterIoError;
        result.warnings.emplace_back("settings path could not be inspected: " +
                                     error.message());
        return result;
    }
    if (!exists) return result;

    const bool regular = std::filesystem::is_regular_file(path, error);
    if (error || !regular) {
        result.status = ParticipantSettingsLoadStatus::DefaultsAfterIoError;
        result.warnings.emplace_back("settings path is not a readable regular file");
        return result;
    }

    const auto file_size = std::filesystem::file_size(path, error);
    if (error) {
        result.status = ParticipantSettingsLoadStatus::DefaultsAfterIoError;
        result.warnings.emplace_back("settings file size could not be read: " +
                                     error.message());
        return result;
    }
    if (file_size > kMaximumSettingsBytes) {
        return MalformedResult(path, "file exceeds the 256 KiB safety limit");
    }

    std::string text;
    try {
        text = ReadUtf8File(path, kMaximumSettingsBytes);
    } catch (const std::exception& exception) {
        result.status = ParticipantSettingsLoadStatus::DefaultsAfterIoError;
        result.warnings.emplace_back(std::string("settings file could not be read: ") +
                                     exception.what());
        return result;
    } catch (...) {
        result.status = ParticipantSettingsLoadStatus::DefaultsAfterIoError;
        result.warnings.emplace_back("settings file could not be read");
        return result;
    }

    json::Value root;
    try {
        root = json::Parse(text);
    } catch (const std::exception& exception) {
        return MalformedResult(path, exception.what());
    } catch (...) {
        return MalformedResult(path, "invalid JSON");
    }

    const Object* root_object = ObjectValue(root);
    if (root_object == nullptr) {
        return MalformedResult(path, "root must be an object");
    }

    const json::Value* schema_value = Find(*root_object, "schema");
    const auto schema = schema_value == nullptr
        ? std::optional<std::string_view>{}
        : StringValue(*schema_value);
    if (!schema.has_value() || *schema != kParticipantSettingsSchema) {
        return MalformedResult(path, "schema identifier is missing or incompatible");
    }

    const json::Value* version_value = Find(*root_object, "schema_version");
    const auto* version = version_value == nullptr
        ? nullptr
        : std::get_if<std::int64_t>(&version_value->Data());
    if (version == nullptr || *version < 1) {
        return MalformedResult(path, "schema_version must be a positive integer");
    }

    const json::Value* preferences_value = Find(*root_object, "preferences");
    const Object* preferences = preferences_value == nullptr
        ? nullptr
        : ObjectValue(*preferences_value);
    if (preferences == nullptr) {
        return MalformedResult(path, "preferences must be an object");
    }

    if (*version > kParticipantSettingsSchemaVersion) {
        result.warnings.emplace_back(
            "settings were written by a newer schema version; known fields were loaded");
    }

    ReadBoundedNumber(*preferences, "trainer_sensitivity",
                      kMinimumTrainerSensitivity, kMaximumTrainerSensitivity,
                      result.settings.trainer_sensitivity, result.warnings);
    ReadBoundedNumber(*preferences, "crosshair_scale",
                      kMinimumCrosshairScale, kMaximumCrosshairScale,
                      result.settings.crosshair_scale, result.warnings);
    ReadBool(*preferences, "target_highlight_enabled",
             result.settings.target_highlight_enabled, result.warnings);
    ReadBool(*preferences, "fullscreen", result.settings.fullscreen,
             result.warnings);
    ReadEnum(*preferences, "protocol", result.settings.protocol,
             ParseProtocol, result.warnings);

    if (const json::Value* audio_value = Find(*preferences, "audio")) {
        if (const Object* audio = ObjectValue(*audio_value)) {
            ReadBool(*audio, "enabled", result.settings.audio_enabled,
                     result.warnings);
            ReadEnum(*audio, "hit_sound", result.settings.hit_sound,
                     ParseHitSound, result.warnings);
        } else {
            Warn(result.warnings, "audio",
                 "must be an object; using audio defaults");
        }
    }

    result.status = result.warnings.empty()
        ? ParticipantSettingsLoadStatus::Loaded
        : ParticipantSettingsLoadStatus::LoadedWithWarnings;
    return result;
}

ParticipantSettingsSaveResult SaveParticipantSettings(
    const std::filesystem::path& path,
    const ParticipantSettings& settings) {
    ParticipantSettingsSaveResult result;
    if (path.empty() || path.filename().empty()) {
        result.error = "settings path is empty";
        return result;
    }
    if (const auto error = ValidationError(settings)) {
        result.error = *error;
        return result;
    }

    try {
        AtomicWriteFile(path, json::DumpCanonical(Serialize(settings), true));
        result.saved = true;
    } catch (const std::exception& exception) {
        result.error = exception.what();
    } catch (...) {
        result.error = "unknown settings write failure";
    }
    return result;
}

}  // namespace abdc::app
