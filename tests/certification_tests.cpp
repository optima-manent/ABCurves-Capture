#include "TestHarness.h"

#include "device/ActivityCorrelation.h"

#include <array>
#include <vector>

TEST_CASE("certification tolerates batching scale timing and unrelated mice") {
    using namespace abdc::device;
    const std::vector<GestureSample> usb{
        {0, 90, 0, false, false},
        {40'000'000, 0, 100, false, false},
        {80'000'000, -110, 0, true, false},
        {120'000'000, 0, -95, false, true},
    };
    // Delayed, differently scaled, and split/batched Raw Input witness.
    const std::vector<GestureSample> raw{
        {30'000'000, 40, 0, false, false},
        {35'000'000, 35, 0, false, false},
        {70'000'000, 0, 82, false, false},
        {110'000'000, -83, 0, true, false},
        {150'000'000, 0, -72, false, true},
    };
    const std::array<std::int64_t, 3> slow_intervals{
        4'000'000, 4'100'000, 3'900'000};  // about 250 Hz: still certified.
    const auto result = EvaluateGestureCorrelation(usb, raw, slow_intervals);
    EXPECT_EQ(result.status, ActivityCorrelationStatus::Ready);
    EXPECT_TRUE(result.identity_proven);
    EXPECT_TRUE(result.correlation_score > 0.8);
    EXPECT_TRUE(result.measured_polling_hz < 600.0);

    ActivityTotals usb_totals{10, -4, 1, 1, 4, 395};
    ActivityTotals raw_totals{99, 42, 2, 1, 7, 311};
    ActivityTotals other_totals{500, 500, 3, 3, 12, 1'000};
    const auto topology_unique = EvaluateActivityCorrelation(
        usb_totals, raw_totals, other_totals, slow_intervals);
    EXPECT_TRUE(topology_unique.identity_proven);
    EXPECT_EQ(topology_unique.status, ActivityCorrelationStatus::Ready);
}

TEST_CASE("certification chooses a clear score and reports close routes ambiguous") {
    using namespace abdc::device;
    ActivityProofCandidateResult weak;
    weak.pair_token = "weak";
    weak.source_capture_intact = true;
    weak.correlation.identity_proven = true;
    weak.correlation.correlation_score = 0.62;
    ActivityProofCandidateResult strong = weak;
    strong.pair_token = "strong";
    strong.correlation.correlation_score = 0.91;
    std::array<ActivityProofCandidateResult, 2> candidates{weak, strong};
    const auto selected = SelectUniqueActivityWinner(candidates);
    EXPECT_EQ(selected.status, UniqueActivityWinnerStatus::Accepted);
    EXPECT_EQ(selected.winning_index, 1U);

    candidates[0].correlation.correlation_score = 0.87;
    const auto ambiguous = SelectUniqueActivityWinner(candidates);
    EXPECT_EQ(ambiguous.status, UniqueActivityWinnerStatus::Ambiguous);
}

TEST_CASE("collection decoders sharing one USB source do not create false ambiguity") {
    using namespace abdc::device;
    ActivityProofCandidateResult first;
    first.pair_token = "collection-a";
    first.source_stream_token = "physical-endpoint-1";
    first.source_capture_intact = true;
    first.correlation.identity_proven = true;
    first.correlation.correlation_score = 0.87;

    ActivityProofCandidateResult second = first;
    second.pair_token = "collection-b";
    second.correlation.correlation_score = 0.89;

    const std::array<ActivityProofCandidateResult, 2> candidates{first, second};
    const auto selected = SelectUniqueActivityWinner(candidates);
    EXPECT_EQ(selected.status, UniqueActivityWinnerStatus::Accepted);
    EXPECT_EQ(selected.winning_index, 1U);
    EXPECT_EQ(selected.passing_indices.size(), 2U);
}
