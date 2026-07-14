#include "TestHarness.h"

#include "base/Json.h"
#include "session/AppendOnlyJsonl.h"
#include "session/FailurePolicy.h"

#include <chrono>
#include <filesystem>
#include <fstream>

namespace {

std::filesystem::path TempDirectory() {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
        ("abcurves_journal_" + std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

}  // namespace

TEST_CASE("optional witness differences never control capture life") {
    using namespace abdc::session;
    EXPECT_EQ(ActionFor(RuntimeIssue::RawInputUsbDifference),
              RuntimeAction::ContinueWithAnnotation);
    EXPECT_EQ(ActionFor(RuntimeIssue::RawInputUnavailable),
              RuntimeAction::ContinueWithAnnotation);
    EXPECT_EQ(ActionFor(RuntimeIssue::GameplayInputUnavailable),
              RuntimeAction::PauseGameplayAndDiscardActiveEvent);
    EXPECT_EQ(ActionFor(RuntimeIssue::OtherMouseActivity),
              RuntimeAction::ContinueWithAnnotation);
    EXPECT_EQ(ActionFor(RuntimeIssue::FocusLost),
              RuntimeAction::PauseGameplayAndDiscardActiveEvent);
    EXPECT_EQ(ActionFor(RuntimeIssue::NativeQueueOverflow),
              RuntimeAction::StopCaptureAndPreservePrefix);
}

TEST_CASE("append journal validates sequence schema and CRC") {
    using namespace abdc::session;
    const auto directory = TempDirectory();
    const auto partial = directory / "events.jsonl.partial";
    const auto final = directory / "events.jsonl";
    {
        AppendOnlyJsonlWriter writer(partial, "abcurves.gameplay.event.v1");
        abdc::json::Value event = abdc::json::Value::Object{};
        event["kind"] = "target_presented";
        event["qpc"] = static_cast<std::int64_t>(1234);
        writer.Append(std::move(event));
        writer.Finalize(final);
    }
    {
        AppendOnlyJsonlReader reader(final, "abcurves.gameplay.event.v1");
        const auto event = reader.Next();
        EXPECT_TRUE(event.has_value());
        EXPECT_EQ(event->At("kind").AsString(), std::string("target_presented"));
        EXPECT_EQ(event->At("sequence").AsInt(), 0);
        EXPECT_TRUE(!reader.Next().has_value());
    }
    std::filesystem::remove_all(directory);
}
