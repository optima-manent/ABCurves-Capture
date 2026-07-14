#include "TestHarness.h"

#include "app/HighscoreStore.h"
#include "base/AtomicFile.h"
#include "base/Json.h"

#include <windows.h>

#include <atomic>
#include <chrono>
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
            ("abcurves_highscores_" + std::to_string(tick) + "_" +
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

abdc::app::HighscoreKey Key(
    const char digest_character = 'a',
    const std::string& challenge = "default_static",
    const std::string& block = "default_static_r1") {
    return {std::string(64U, digest_character), challenge, block};
}

}  // namespace

TEST_CASE("missing highscore file opens as an empty noncritical store") {
    TemporaryDirectory temporary;
    abdc::app::HighscoreStore store(temporary.Path() / "highscores.json");

    EXPECT_EQ(store.load_report().status,
              abdc::app::HighscoreLoadStatus::EmptyBecauseMissing);
    EXPECT_TRUE(store.load_report().warnings.empty());
    EXPECT_EQ(store.size(), 0U);
    EXPECT_TRUE(!store.BestScore(Key()).has_value());
}

TEST_CASE("highscores save and load with an anonymous versioned schema") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "highscores.json";
    const auto key = Key();

    abdc::app::HighscoreStore store(path);
    const auto update = store.RecordScore(key, 37);
    EXPECT_EQ(update.current_score, 37);
    EXPECT_EQ(update.best_score, 37);
    EXPECT_TRUE(update.new_best);
    EXPECT_EQ(update.save_status, abdc::app::HighscoreSaveStatus::Saved);

    abdc::app::HighscoreStore loaded(path);
    EXPECT_EQ(loaded.load_report().status,
              abdc::app::HighscoreLoadStatus::Loaded);
    EXPECT_EQ(loaded.BestScore(key), 37);

    const std::string text = abdc::ReadUtf8File(path);
    const auto document = abdc::json::Parse(text);
    EXPECT_EQ(document.At("schema").AsString(),
              std::string(abdc::app::kHighscoreSchema));
    EXPECT_EQ(document.At("schema_version").AsInt(),
              static_cast<std::int64_t>(abdc::app::kHighscoreSchemaVersion));
    EXPECT_TRUE(text.find("participant") == std::string::npos);
    EXPECT_TRUE(text.find("user_id") == std::string::npos);
    EXPECT_TRUE(text.find("session") == std::string::npos);
    EXPECT_TRUE(text.find("device") == std::string::npos);
}

TEST_CASE("equal and lower scores do not rewrite or replace the best") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "highscores.json";
    const auto key = Key();
    abdc::app::HighscoreStore store(path);
    EXPECT_TRUE(store.RecordScore(key, 20).new_best);
    const std::string original = abdc::ReadUtf8File(path);

    const auto lower = store.RecordScore(key, 19);
    EXPECT_EQ(lower.current_score, 19);
    EXPECT_EQ(lower.best_score, 20);
    EXPECT_TRUE(!lower.new_best);
    EXPECT_EQ(lower.save_status,
              abdc::app::HighscoreSaveStatus::NotNeeded);
    EXPECT_EQ(abdc::ReadUtf8File(path), original);

    const auto equal = store.RecordScore(key, 20);
    EXPECT_EQ(equal.best_score, 20);
    EXPECT_TRUE(!equal.new_best);
    EXPECT_EQ(equal.save_status,
              abdc::app::HighscoreSaveStatus::NotNeeded);
    EXPECT_EQ(abdc::ReadUtf8File(path), original);
}

TEST_CASE("a strictly greater score becomes the new durable best") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "highscores.json";
    const auto key = Key();
    abdc::app::HighscoreStore store(path);
    EXPECT_TRUE(store.RecordScore(key, 12).new_best);

    const auto greater = store.RecordScore(key, 13);
    EXPECT_EQ(greater.current_score, 13);
    EXPECT_EQ(greater.best_score, 13);
    EXPECT_TRUE(greater.new_best);
    EXPECT_EQ(greater.save_status, abdc::app::HighscoreSaveStatus::Saved);
    EXPECT_EQ(abdc::app::HighscoreStore(path).BestScore(key), 13);
}

TEST_CASE("protocol hashes and repeated canonical blocks have separate scores") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "highscores.json";
    const auto protocol_a_repeat_1 = Key('a');
    const auto protocol_b_repeat_1 = Key('b');
    const auto protocol_a_repeat_2 =
        Key('a', "default_static", "default_static_r2");

    abdc::app::HighscoreStore store(path);
    EXPECT_TRUE(store.RecordScore(protocol_a_repeat_1, 10).new_best);
    EXPECT_TRUE(store.RecordScore(protocol_b_repeat_1, 20).new_best);
    EXPECT_TRUE(store.RecordScore(protocol_a_repeat_2, 30).new_best);
    EXPECT_EQ(store.BestScore(protocol_a_repeat_1), 10);
    EXPECT_EQ(store.BestScore(protocol_b_repeat_1), 20);
    EXPECT_EQ(store.BestScore(protocol_a_repeat_2), 30);

    const auto& blocks = abdc::protocol::OrderedBlocksV1();
    const auto canonical_repeat_1 = abdc::app::CanonicalHighscoreKey(blocks[0]);
    const auto canonical_repeat_2 = abdc::app::CanonicalHighscoreKey(blocks[1]);
    EXPECT_EQ(canonical_repeat_1.protocol_sha256,
              abdc::protocol::ProtocolSha256());
    EXPECT_EQ(canonical_repeat_1.challenge_id,
              canonical_repeat_2.challenge_id);
    EXPECT_TRUE(canonical_repeat_1.block_id != canonical_repeat_2.block_id);
}

TEST_CASE("malformed highscores fall back to empty and are quarantined") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "highscores.json";
    abdc::AtomicWriteFile(path, "{ definitely not json");

    abdc::app::HighscoreStore store(path);
    EXPECT_EQ(store.load_report().status,
              abdc::app::HighscoreLoadStatus::EmptyAfterMalformedFile);
    EXPECT_EQ(store.size(), 0U);
    EXPECT_TRUE(!store.load_report().warnings.empty());
    EXPECT_TRUE(!store.load_report().quarantined_file.empty());
    EXPECT_TRUE(std::filesystem::exists(
        store.load_report().quarantined_file));
    EXPECT_TRUE(!std::filesystem::exists(path));

    // A quarantined preference file does not prevent a fresh score file.
    EXPECT_TRUE(store.RecordScore(Key(), 4).new_best);
    EXPECT_TRUE(std::filesystem::exists(path));
}

TEST_CASE("failed atomic highscore save preserves the old file and old best") {
    TemporaryDirectory temporary;
    const auto path = temporary.Path() / "highscores.json";
    const auto key = Key();
    abdc::app::HighscoreStore store(path);
    EXPECT_TRUE(store.RecordScore(key, 8).new_best);
    const std::string original = abdc::ReadUtf8File(path);

    const HANDLE lock = CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    EXPECT_TRUE(lock != INVALID_HANDLE_VALUE);

    const auto failed = store.RecordScore(key, 99);
    EXPECT_EQ(failed.current_score, 99);
    EXPECT_EQ(failed.best_score, 8);
    EXPECT_TRUE(!failed.new_best);
    EXPECT_EQ(failed.save_status, abdc::app::HighscoreSaveStatus::Failed);
    EXPECT_TRUE(!failed.warnings.empty());
    EXPECT_EQ(store.BestScore(key), 8);
    EXPECT_EQ(abdc::ReadUtf8File(path), original);

    EXPECT_TRUE(CloseHandle(lock) != FALSE);
    EXPECT_EQ(abdc::app::HighscoreStore(path).BestScore(key), 8);
}
