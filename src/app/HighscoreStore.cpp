#include "app/HighscoreStore.h"

#include "base/AtomicFile.h"
#include "base/Json.h"

#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <variant>

namespace abdc::app {
namespace {

constexpr std::uint64_t kMaximumHighscoreBytes = 1U << 20U;
constexpr std::size_t kMaximumHighscoreEntries = 4'096U;
constexpr std::size_t kMaximumIdentifierBytes = 128U;

using Array = json::Value::Array;
using Object = json::Value::Object;

const Object* ObjectValue(const json::Value& value) noexcept {
    return std::get_if<Object>(&value.Data());
}

const Array* ArrayValue(const json::Value& value) noexcept {
    return std::get_if<Array>(&value.Data());
}

const json::Value* Find(const Object& object, const std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &found->second;
}

const std::string* StringValue(const json::Value* value) noexcept {
    return value == nullptr ? nullptr
                            : std::get_if<std::string>(&value->Data());
}

const std::int64_t* IntegerValue(const json::Value* value) noexcept {
    return value == nullptr ? nullptr
                            : std::get_if<std::int64_t>(&value->Data());
}

bool IsLowerHexDigest(const std::string_view value) noexcept {
    if (value.size() != 64U) return false;
    for (const char character : value) {
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool IsCanonicalIdentifier(const std::string_view value) noexcept {
    if (value.empty() || value.size() > kMaximumIdentifierBytes) return false;
    for (const char character : value) {
        const bool lower = character >= 'a' && character <= 'z';
        const bool digit = character >= '0' && character <= '9';
        if (!lower && !digit && character != '_' && character != '-' &&
            character != '.') {
            return false;
        }
    }
    return true;
}

std::optional<std::string> ValidateKey(const HighscoreKey& key) {
    if (!IsLowerHexDigest(key.protocol_sha256)) {
        return "protocol_sha256 must be a 64-character lowercase hexadecimal digest";
    }
    if (!IsCanonicalIdentifier(key.challenge_id)) {
        return "challenge_id is not a canonical identifier";
    }
    if (!IsCanonicalIdentifier(key.block_id)) {
        return "block_id is not a canonical identifier";
    }
    return std::nullopt;
}

json::Value Serialize(const std::map<HighscoreKey, int>& scores) {
    Array entries;
    entries.reserve(scores.size());
    for (const auto& [key, score] : scores) {
        entries.emplace_back(Object{
            {"best_score", score},
            {"block_id", key.block_id},
            {"challenge_id", key.challenge_id},
            {"protocol_sha256", key.protocol_sha256},
        });
    }

    return Object{
        {"entries", std::move(entries)},
        {"schema", std::string(kHighscoreSchema)},
        {"schema_version", kHighscoreSchemaVersion},
    };
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
        // Highscores are disposable UI state and never capture state.
    }
    return {};
}

class MalformedHighscore final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[noreturn]] void Malformed(const std::string_view reason) {
    throw MalformedHighscore("malformed highscore file: " +
                             std::string(reason));
}

HighscoreKey ParseKey(const Object& entry) {
    const auto* protocol_sha256 = StringValue(Find(entry, "protocol_sha256"));
    const auto* challenge_id = StringValue(Find(entry, "challenge_id"));
    const auto* block_id = StringValue(Find(entry, "block_id"));
    if (protocol_sha256 == nullptr || challenge_id == nullptr ||
        block_id == nullptr) {
        Malformed("an entry is missing its canonical identity");
    }

    HighscoreKey key{*protocol_sha256, *challenge_id, *block_id};
    if (const auto error = ValidateKey(key)) Malformed(*error);
    return key;
}

}  // namespace

HighscoreKey CanonicalHighscoreKey(
    const protocol::BlockDefinition& block) {
    const auto& canonical_blocks = protocol::OrderedBlocksV1();
    if (block.ordinal >= canonical_blocks.size()) {
        throw std::invalid_argument(
            "canonical highscore block ordinal is out of range");
    }
    const auto& canonical = canonical_blocks[block.ordinal];
    if (block.challenge_id != canonical.challenge_id ||
        block.block_id != canonical.block_id) {
        throw std::invalid_argument(
            "highscore block identity does not match its canonical ordinal");
    }
    HighscoreKey key{protocol::ProtocolSha256(), block.challenge_id,
                     block.block_id};
    if (const auto error = ValidateKey(key)) {
        throw std::invalid_argument("invalid canonical highscore key: " + *error);
    }
    return key;
}

HighscoreStore::HighscoreStore(std::filesystem::path path)
    : path_(std::move(path)) {
    Load();
}

std::optional<int> HighscoreStore::BestScore(
    const HighscoreKey& key) const noexcept {
    const auto found = scores_.find(key);
    if (found == scores_.end()) return std::nullopt;
    return found->second;
}

void HighscoreStore::Load() {
    scores_.clear();
    load_report_ = {};
    writes_enabled_ = true;

    if (path_.empty() || path_.filename().empty()) {
        load_report_.status = HighscoreLoadStatus::EmptyAfterIoError;
        load_report_.warnings.emplace_back("highscore path is empty");
        writes_enabled_ = false;
        return;
    }

    std::error_code error;
    const bool exists = std::filesystem::exists(path_, error);
    if (error) {
        load_report_.status = HighscoreLoadStatus::EmptyAfterIoError;
        load_report_.warnings.emplace_back(
            "highscore path could not be inspected: " + error.message());
        writes_enabled_ = false;
        return;
    }
    if (!exists) return;

    if (!std::filesystem::is_regular_file(path_, error) || error) {
        load_report_.status = HighscoreLoadStatus::EmptyAfterIoError;
        load_report_.warnings.emplace_back(
            "highscore path is not a readable regular file");
        writes_enabled_ = false;
        return;
    }

    const auto file_size = std::filesystem::file_size(path_, error);
    if (error) {
        load_report_.status = HighscoreLoadStatus::EmptyAfterIoError;
        load_report_.warnings.emplace_back(
            "highscore file size could not be read: " + error.message());
        writes_enabled_ = false;
        return;
    }

    try {
        if (file_size > kMaximumHighscoreBytes) {
            Malformed("file exceeds the 1 MiB safety limit");
        }

        std::string text;
        try {
            text = ReadUtf8File(path_, kMaximumHighscoreBytes);
        } catch (const std::exception& exception) {
            load_report_.status = HighscoreLoadStatus::EmptyAfterIoError;
            load_report_.warnings.emplace_back(
                "highscore file could not be read: " +
                std::string(exception.what()));
            writes_enabled_ = false;
            return;
        }

        json::Value document;
        try {
            document = json::Parse(text);
        } catch (const std::exception& exception) {
            Malformed(exception.what());
        }
        const Object* root = ObjectValue(document);
        if (root == nullptr) Malformed("root must be an object");

        const auto* schema = StringValue(Find(*root, "schema"));
        if (schema == nullptr || *schema != kHighscoreSchema) {
            Malformed("schema identifier is missing or incompatible");
        }

        const auto* version = IntegerValue(Find(*root, "schema_version"));
        if (version == nullptr || *version < 1) {
            Malformed("schema_version must be a positive integer");
        }
        if (*version > kHighscoreSchemaVersion) {
            load_report_.status =
                HighscoreLoadStatus::EmptyAfterIncompatibleSchema;
            load_report_.warnings.emplace_back(
                "highscore file uses a newer schema and was left untouched");
            writes_enabled_ = false;
            return;
        }

        const json::Value* entries_value = Find(*root, "entries");
        const Array* entries = entries_value == nullptr
            ? nullptr
            : ArrayValue(*entries_value);
        if (entries == nullptr) Malformed("entries must be an array");
        if (entries->size() > kMaximumHighscoreEntries) {
            Malformed("entry count exceeds the safety limit");
        }

        std::map<HighscoreKey, int> parsed;
        for (const json::Value& value : *entries) {
            const Object* entry = ObjectValue(value);
            if (entry == nullptr) Malformed("each entry must be an object");

            HighscoreKey key = ParseKey(*entry);
            const auto* score = IntegerValue(Find(*entry, "best_score"));
            if (score == nullptr || *score < 0 ||
                *score > std::numeric_limits<int>::max()) {
                Malformed("best_score must be a nonnegative integer");
            }
            const auto [unused, inserted] = parsed.emplace(
                std::move(key), static_cast<int>(*score));
            static_cast<void>(unused);
            if (!inserted) Malformed("duplicate canonical score identity");
        }

        scores_ = std::move(parsed);
        load_report_.status = HighscoreLoadStatus::Loaded;
    } catch (const MalformedHighscore& exception) {
        scores_.clear();
        load_report_.status = HighscoreLoadStatus::EmptyAfterMalformedFile;
        load_report_.warnings.emplace_back(exception.what());
        load_report_.quarantined_file = QuarantineMalformedFile(path_);
        if (load_report_.quarantined_file.empty()) {
            load_report_.warnings.emplace_back(
                "malformed highscore file could not be quarantined");
            writes_enabled_ = false;
        }
    } catch (const std::exception& exception) {
        scores_.clear();
        load_report_.status = HighscoreLoadStatus::EmptyAfterIoError;
        load_report_.warnings.emplace_back(
            "highscore file could not be loaded: " +
            std::string(exception.what()));
        writes_enabled_ = false;
    } catch (...) {
        scores_.clear();
        load_report_.status = HighscoreLoadStatus::EmptyAfterIoError;
        load_report_.warnings.emplace_back("highscore file could not be loaded");
        writes_enabled_ = false;
    }
}

HighscoreUpdateResult HighscoreStore::RecordScore(
    const HighscoreKey& key,
    const int current_score) {
    HighscoreUpdateResult result;
    result.current_score = current_score;
    result.best_score = BestScore(key);

    if (current_score < 0) {
        result.save_status = HighscoreSaveStatus::Failed;
        result.warnings.emplace_back("current score must be nonnegative");
        return result;
    }
    if (const auto error = ValidateKey(key)) {
        result.save_status = HighscoreSaveStatus::Failed;
        result.warnings.push_back(*error);
        return result;
    }
    if (result.best_score.has_value() &&
        current_score <= *result.best_score) {
        return result;
    }
    if (!writes_enabled_) {
        result.save_status = HighscoreSaveStatus::Failed;
        result.warnings.emplace_back(
            "highscore saving is disabled because the existing file could not be safely loaded");
        return result;
    }
    if (!result.best_score.has_value() &&
        scores_.size() >= kMaximumHighscoreEntries) {
        result.save_status = HighscoreSaveStatus::Failed;
        result.warnings.emplace_back(
            "highscore entry safety limit has been reached");
        return result;
    }

    try {
        auto updated = scores_;
        updated[key] = current_score;
        const std::string encoded =
            json::DumpCanonical(Serialize(updated), true);
        if (encoded.size() > kMaximumHighscoreBytes) {
            result.save_status = HighscoreSaveStatus::Failed;
            result.warnings.emplace_back(
                "highscore file safety limit would be exceeded");
            return result;
        }
        AtomicWriteFile(path_, encoded);
        scores_.swap(updated);
        result.best_score = current_score;
        result.new_best = true;
        result.save_status = HighscoreSaveStatus::Saved;
    } catch (const std::exception& exception) {
        result.save_status = HighscoreSaveStatus::Failed;
        result.warnings.emplace_back(
            "highscore was not saved: " + std::string(exception.what()));
    } catch (...) {
        result.save_status = HighscoreSaveStatus::Failed;
        result.warnings.emplace_back(
            "highscore was not saved because of an unknown write failure");
    }
    return result;
}

}  // namespace abdc::app
