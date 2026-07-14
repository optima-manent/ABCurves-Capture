#include "TestHarness.h"

#include "session/ClockJournal.h"

#include <chrono>
#include <filesystem>

namespace {

std::filesystem::path ClockTempDirectory() {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
        ("abcurves_clocks_" + std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

abdc::platform::ClockAnchor Anchor(const std::int64_t qpc,
                                   const std::int64_t utc,
                                   const char* source) {
    abdc::platform::ClockAnchor result;
    result.qpc_before = qpc;
    result.qpc_after = qpc + 4;
    result.qpc_midpoint = qpc + 2;
    result.bracket_ticks = 4;
    result.utc_unix_ns = utc;
    result.source = source;
    return result;
}

}  // namespace

TEST_CASE("clock journal retains bracketed QPC and precise UTC anchors") {
    const auto directory = ClockTempDirectory();
    {
        abdc::session::ClockJournal writer(directory, 10'000'000);
        writer.Append(Anchor(100, 1'700'000'000'000'000'000LL, "session_start"));
        writer.Append(Anchor(200, 1'700'000'000'000'010'000LL, "periodic"));
        writer.Finalize();
    }
    const auto records =
        abdc::session::ReadClockJournal(directory / "anchors.jsonl");
    EXPECT_EQ(records.size(), 2U);
    EXPECT_EQ(records.front().qpc_frequency, 10'000'000);
    EXPECT_EQ(records.back().anchor.source, std::string("periodic"));
    EXPECT_EQ(records.back().anchor.qpc_midpoint, 202);
    EXPECT_TRUE(!std::filesystem::exists(directory / "anchors.jsonl.partial"));
    std::filesystem::remove_all(directory);
}
