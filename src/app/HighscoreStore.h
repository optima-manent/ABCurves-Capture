#pragma once

#include "protocol/protocol_v1.hpp"

#include <compare>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace abdc::app {

inline constexpr std::string_view kHighscoreSchema =
    "abcurves.local-highscores";
inline constexpr int kHighscoreSchemaVersion = 1;

// A score belongs to one exact scientific protocol and one canonical block.
// block_id contains the repeat identity (for example, default_static_r2), while
// protocol_sha256 prevents a later, incompatible protocol from sharing scores
// merely because it reused the same human-readable challenge or block name.
struct HighscoreKey final {
    std::string protocol_sha256;
    std::string challenge_id;
    std::string block_id;

    auto operator<=>(const HighscoreKey&) const = default;
};

// Convenience for the audited built-in protocol. Callers running another
// version may construct HighscoreKey directly from that protocol's canonical
// identifiers and digest.
[[nodiscard]] HighscoreKey CanonicalHighscoreKey(
    const protocol::BlockDefinition& block);

enum class HighscoreLoadStatus {
    EmptyBecauseMissing,
    Loaded,
    EmptyAfterMalformedFile,
    EmptyAfterIoError,
    EmptyAfterIncompatibleSchema,
};

struct HighscoreLoadReport final {
    HighscoreLoadStatus status = HighscoreLoadStatus::EmptyBecauseMissing;
    std::vector<std::string> warnings;
    std::filesystem::path quarantined_file;
};

enum class HighscoreSaveStatus {
    // The submitted score did not exceed the existing best, so no write was
    // necessary and the prior durable file remains authoritative.
    NotNeeded,
    Saved,
    Failed,
};

struct HighscoreUpdateResult final {
    int current_score = 0;
    std::optional<int> best_score;
    bool new_best = false;
    HighscoreSaveStatus save_status = HighscoreSaveStatus::NotNeeded;
    std::vector<std::string> warnings;
};

// Local highscores are presentation-only preferences. Every filesystem and
// parse failure is converted to a report or update warning; callers must never
// use these results to accept, reject, pause, or invalidate capture data.
class HighscoreStore final {
public:
    explicit HighscoreStore(std::filesystem::path path);

    [[nodiscard]] const HighscoreLoadReport& load_report() const noexcept {
        return load_report_;
    }
    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }
    [[nodiscard]] std::size_t size() const noexcept { return scores_.size(); }
    [[nodiscard]] std::optional<int> BestScore(
        const HighscoreKey& key) const noexcept;

    // Only a strictly greater score is committed. The disk write is atomic and
    // the in-memory best is updated only after that write succeeds, so a failed
    // save preserves both the previous durable file and the previous best.
    [[nodiscard]] HighscoreUpdateResult RecordScore(
        const HighscoreKey& key,
        int current_score);

private:
    void Load();

    std::filesystem::path path_;
    std::map<HighscoreKey, int> scores_;
    HighscoreLoadReport load_report_;
    bool writes_enabled_ = true;
};

}  // namespace abdc::app
