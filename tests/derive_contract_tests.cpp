#include "TestHarness.h"

#include "derive/AxisConvention.h"
#include "derive/ClockAnchorFit.h"
#include "derive/MillisecondDeriver.h"

#include <cmath>
#include <cstdint>
#include <string_view>
#include <vector>

namespace {

namespace derive = abdc::derive;

abdc::capture::AuthoritativeReport Report(
    const std::uint64_t sequence,
    const std::int64_t unix_ns,
    const std::int32_t dx,
    const std::int32_t dy,
    const std::uint32_t buttons = 0U,
    const std::int32_t wheel = 0,
    const std::uint32_t quality = 0U) {
    abdc::capture::AuthoritativeReport report{};
    report.capture_sequence = sequence;
    report.capture_unix_ns = unix_ns;
    report.hid_dx = dx;
    report.hid_dy = dy;
    report.hid_wheel = wheel;
    report.buttons = buttons;
    report.quality_flags = quality;
    return report;
}

TEST_CASE("derive axis conventions preserve device counts and version Y semantics") {
    const auto canonical = derive::DeriveAxes(
        7,
        -4,
        derive::AxisConventionVersion::PhalmM16CountSpaceXRightYUpV2);
    EXPECT_EQ(canonical.device_dx, 7);
    EXPECT_EQ(canonical.device_dy, -4);
    EXPECT_EQ(canonical.derived_dx, 7);
    EXPECT_EQ(canonical.derived_dy, 4);

    const auto legacy = derive::DeriveAxes(
        7,
        -4,
        derive::AxisConventionVersion::LegacyDeviceNativeYV1);
    EXPECT_EQ(legacy.device_dx, 7);
    EXPECT_EQ(legacy.device_dy, -4);
    EXPECT_EQ(legacy.derived_dx, 7);
    EXPECT_EQ(legacy.derived_dy, -4);

    const auto info = derive::DescribeAxisConvention(
        derive::AxisConventionVersion::PhalmM16CountSpaceXRightYUpV2);
    EXPECT_EQ(
        info.stable_name,
        std::string_view("phalm_m16_count_space_x_right_y_up_v2"));
    EXPECT_EQ(info.derived_y_positive, std::string_view("up"));
}

TEST_CASE("derive millisecond grid is floor aligned and half open") {
    const derive::MillisecondGrid grid(10'000'000);
    EXPECT_EQ(grid.IndexOf(9'999'999), -1);
    EXPECT_EQ(grid.IndexOf(10'000'000), 0);
    EXPECT_EQ(grid.IndexOf(10'999'999), 0);
    EXPECT_EQ(grid.IndexOf(11'000'000), 1);
    EXPECT_TRUE(grid.Interval(0).Contains(10'000'000));
    EXPECT_TRUE(grid.Interval(0).Contains(10'999'999));
    EXPECT_TRUE(!grid.Interval(0).Contains(11'000'000));
    EXPECT_EQ(derive::MillisecondGrid::FloorToMillisecond(12'345'678),
              12'000'000);
    EXPECT_EQ(derive::MillisecondGrid::FloorToMillisecond(-1), -1'000'000);
}

TEST_CASE("derive bins sum every report and retain empty bins buttons and wheels") {
    const std::vector reports{
        Report(1, 100'000, 1, 2, 0U, 0, 0x02U),
        Report(2, 900'000, 3, -1, 0x01U, 1),
        // An exact boundary belongs to bin 1.
        Report(3, 1'000'000, 2, 3, 0x01U),
        Report(4, 3'100'000, 0, 0, 0U, -1),
    };
    derive::MillisecondBinningOptions options{};
    options.initial_crosshair = {10, 20};
    const auto result = derive::DeriveMillisecondBins(
        reports,
        derive::MillisecondGrid(0),
        {0, 4},
        options);

    EXPECT_EQ(result.bins.size(), std::size_t{4});
    const auto& bin0 = result.bins[0];
    EXPECT_EQ(bin0.report_count, 2U);
    EXPECT_EQ(bin0.zero_delta_report_count, 0U);
    EXPECT_EQ(bin0.delta.device_dx, 4);
    EXPECT_EQ(bin0.delta.device_dy, 1);
    EXPECT_EQ(bin0.delta.derived_dx, 4);
    EXPECT_EQ(bin0.delta.derived_dy, -1);
    EXPECT_EQ(bin0.wheel_sum, 1);
    EXPECT_EQ(bin0.buttons_at_start, 0U);
    EXPECT_EQ(bin0.buttons_at_end, 0x01U);
    EXPECT_EQ(bin0.buttons_down_mask, 0x01U);
    EXPECT_EQ(bin0.buttons_up_mask, 0U);
    EXPECT_EQ(bin0.ordered_button_edges.size(), std::size_t{1});
    EXPECT_EQ(bin0.ordered_button_edges[0].report_ordinal_in_bin, 1U);
    EXPECT_EQ(bin0.quality_mask & derive::kSourceReportQualityMask, 0x02ULL);

    EXPECT_EQ(result.bins[1].report_count, 1U);
    EXPECT_EQ(result.bins[1].begin_unix_ns, 1'000'000);
    EXPECT_EQ(result.bins[2].report_count, 0U);
    EXPECT_TRUE(!result.bins[2].ReportPresent());
    EXPECT_EQ(result.bins[2].buttons_at_start, 0x01U);
    EXPECT_EQ(result.bins[2].buttons_at_end, 0x01U);
    EXPECT_EQ(result.bins[2].delta.derived_dx, 0);
    EXPECT_EQ(result.bins[2].delta.derived_dy, 0);
    EXPECT_EQ(result.bins[3].zero_delta_report_count, 1U);
    EXPECT_EQ(result.bins[3].wheel_sum, -1);
    EXPECT_EQ(result.bins[3].buttons_up_mask, 0x01U);
}

TEST_CASE("derive crosshair rows expose pre delta state with dense continuity") {
    const std::vector reports{
        Report(1, 100'000, 3, -2),
        Report(2, 2'100'000, -1, 4),
    };
    derive::MillisecondBinningOptions options{};
    options.initial_crosshair = {10, 20};
    const auto result = derive::DeriveMillisecondBins(
        reports,
        derive::MillisecondGrid(0),
        {0, 3},
        options);

    EXPECT_EQ(result.bins[0].crosshair_pre_delta,
              (derive::CountPosition{10, 20}));
    EXPECT_EQ(result.bins[0].crosshair_post_delta,
              (derive::CountPosition{13, 22}));
    EXPECT_EQ(result.bins[1].crosshair_pre_delta,
              result.bins[0].crosshair_post_delta);
    EXPECT_EQ(result.bins[1].crosshair_post_delta,
              result.bins[1].crosshair_pre_delta);
    EXPECT_EQ(result.bins[2].crosshair_pre_delta,
              result.bins[1].crosshair_post_delta);
    EXPECT_EQ(result.bins[2].crosshair_post_delta,
              (derive::CountPosition{12, 18}));
}

TEST_CASE("derive timestamp regression is retained in original bins and annotated") {
    const std::vector reports{
        Report(1, 1'200'000, 2, 0, 0x01U),
        Report(2, 800'000, 3, 0, 0U),
    };
    const auto result = derive::DeriveMillisecondBins(
        reports,
        derive::MillisecondGrid(0),
        {0, 2});

    EXPECT_EQ(result.timestamp_regression_count, 1ULL);
    EXPECT_EQ(result.bins[0].delta.device_dx, 3);
    EXPECT_EQ(result.bins[1].delta.device_dx, 2);
    const auto regression = derive::QualityMask(
        derive::BinQualityFlag::TimestampRegressionDetected);
    const auto uncertain = derive::QualityMask(
        derive::BinQualityFlag::ButtonChronologyUncertain);
    EXPECT_TRUE((result.bins[0].quality_mask & regression) != 0U);
    EXPECT_TRUE((result.bins[1].quality_mask & regression) != 0U);
    EXPECT_TRUE((result.quality_mask & uncertain) != 0U);
}

TEST_CASE("derive clock fit warns on UTC step but keeps coherent mapping") {
    constexpr std::int64_t base_qpc = 1'000'000;
    constexpr std::int64_t base_utc = 1'700'000'000'000'000'000;
    std::vector<derive::ClockAnchor> anchors;
    for (std::int64_t index = 0; index < 5; ++index) {
        anchors.push_back({
            base_qpc + index * 1'000'000,
            base_utc + index * 1'000'000'000 +
                (index >= 3 ? 20'000'000 : 0),
            1'000,
        });
    }
    derive::ClockFitConfig config{};
    config.qpc_frequency_hz = 1'000'000;
    config.residual_warning_ns = 100'000;
    config.clock_step_warning_ns = 5'000'000;
    config.anchor_uncertainty_warning_ns = 500'000;
    const auto fit = derive::FitQpcUtcClockAnchors(anchors, config);

    EXPECT_TRUE(fit.mapping_available);
    EXPECT_TRUE(fit.HasWarning(derive::ClockFitWarning::UtcClockStepDetected));
    EXPECT_TRUE(fit.HasWarning(derive::ClockFitWarning::HighResidual));
    EXPECT_TRUE(fit.HasWarning(derive::ClockFitWarning::OutliersExcluded));
    EXPECT_EQ(fit.detected_clock_step_count, std::size_t{1});
    EXPECT_EQ(fit.fitted_anchor_count, std::size_t{3});
    const auto mapped = fit.QpcToUtcUnixNs(base_qpc + 2'000'000);
    EXPECT_TRUE(mapped.has_value());
    EXPECT_TRUE(std::llabs(*mapped - (base_utc + 2'000'000'000)) <= 1);
    const auto inverse = fit.UtcUnixNsToQpc(base_utc + 2'000'000'000);
    EXPECT_TRUE(inverse.has_value());
    EXPECT_TRUE(std::llabs(*inverse - (base_qpc + 2'000'000)) <= 1);
}

TEST_CASE("derive clock fit reports bracket uncertainty without quality exception") {
    constexpr std::int64_t base_utc = 1'700'000'000'000'000'000;
    const std::vector<derive::ClockAnchor> anchors{
        {1'000'000, base_utc, 2'000'000},
        {2'000'000, base_utc + 1'000'000'000, 2'000'000},
        {3'000'000, base_utc + 2'000'000'000, 2'000'000},
    };
    derive::ClockFitConfig config{};
    config.qpc_frequency_hz = 1'000'000;
    config.anchor_uncertainty_warning_ns = 500'000;
    const auto fit = derive::FitQpcUtcClockAnchors(anchors, config);
    EXPECT_TRUE(fit.mapping_available);
    EXPECT_TRUE(fit.HasWarning(
        derive::ClockFitWarning::HighAnchorUncertainty));
    EXPECT_TRUE(fit.estimated_mapping_uncertainty_ns >= 2'000'000.0L);

    const auto bracket = derive::MakeBracketedClockAnchor(
        100,
        123'456,
        120,
        10'000'000);
    EXPECT_EQ(bracket.qpc_ticks, 110);
    EXPECT_EQ(bracket.uncertainty_ns, 1'000);
}

TEST_CASE("derive clock fit distinguishes consistent drift from UTC step") {
    constexpr std::int64_t base_utc = 1'700'000'000'000'000'000;
    // A deliberately exaggerated, but consistent, +2,000 ppm mapping over
    // long anchor gaps.  It is poor clock-rate agreement, not a discontinuity.
    const std::vector<derive::ClockAnchor> anchors{
        {1'000'000, base_utc, 0},
        {1'001'000'000, base_utc + 1'002'000'000'000, 0},
        {2'001'000'000, base_utc + 2'004'000'000'000, 0},
    };
    derive::ClockFitConfig config{};
    config.qpc_frequency_hz = 1'000'000;
    config.drift_warning_ppm = 1'000.0L;
    const auto fit = derive::FitQpcUtcClockAnchors(anchors, config);
    EXPECT_TRUE(fit.mapping_available);
    EXPECT_TRUE(fit.HasWarning(derive::ClockFitWarning::ExcessiveDrift));
    EXPECT_TRUE(!fit.HasWarning(
        derive::ClockFitWarning::UtcClockStepDetected));
    EXPECT_TRUE(std::fabs(fit.fitted_drift_ppm - 2'000.0L) < 0.01L);
}

}  // namespace
