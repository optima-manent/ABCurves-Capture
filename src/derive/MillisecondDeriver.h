#pragma once

#include "capture/ReportStream.h"
#include "derive/AxisConvention.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace abdc::derive {

inline constexpr std::int64_t kNanosecondsPerMillisecond = 1'000'000;

struct MillisecondBinInterval {
    std::int64_t index{};
    std::int64_t begin_unix_ns{};
    std::int64_t end_unix_ns{};

    [[nodiscard]] bool Contains(const std::int64_t unix_ns) const noexcept {
        return begin_unix_ns <= unix_ns && unix_ns < end_unix_ns;
    }
};

// Bin i is always [origin + i ms, origin + (i + 1) ms).  Callers must persist
// origin_unix_ns; silently selecting a new phase during reprocessing is not
// allowed by this API.
class MillisecondGrid final {
public:
    explicit MillisecondGrid(std::int64_t origin_unix_ns)
        : origin_unix_ns_(origin_unix_ns) {}

    // Integer floor, including before the Unix epoch.  An input in the tiny
    // sub-millisecond tail below INT64_MIN's first representable edge is a
    // structural overflow and is rejected.
    [[nodiscard]] static std::int64_t FloorToMillisecond(std::int64_t unix_ns);
    [[nodiscard]] static MillisecondGrid FloorAligned(std::int64_t unix_ns) {
        return MillisecondGrid(FloorToMillisecond(unix_ns));
    }

    [[nodiscard]] std::int64_t OriginUnixNs() const noexcept {
        return origin_unix_ns_;
    }
    [[nodiscard]] std::int64_t IndexOf(std::int64_t unix_ns) const noexcept;
    [[nodiscard]] std::int64_t EdgeUnixNs(std::int64_t edge_index) const;
    [[nodiscard]] MillisecondBinInterval Interval(std::int64_t index) const;

private:
    std::int64_t origin_unix_ns_{};
};

struct DenseBinRange {
    std::int64_t first{};
    std::int64_t end_exclusive{};

    [[nodiscard]] std::uint64_t Size() const;
    [[nodiscard]] bool Contains(const std::int64_t index) const noexcept {
        return first <= index && index < end_exclusive;
    }
};

[[nodiscard]] std::optional<DenseBinRange> CoveringBinRange(
    std::span<const capture::AuthoritativeReport> reports,
    const MillisecondGrid& grid);

enum class BinQualityFlag : std::uint64_t {
    None = 0,

    // Bits 0..31 are a lossless OR of AuthoritativeReport::quality_flags.
    TimestampRegressionDetected = std::uint64_t{1} << 32U,
    CaptureSequenceNotIncreasing = std::uint64_t{1} << 33U,
    ButtonChronologyUncertain = std::uint64_t{1} << 34U,
};

inline constexpr std::uint64_t kSourceReportQualityMask = 0xFFFF'FFFFULL;

[[nodiscard]] constexpr std::uint64_t QualityMask(
    const BinQualityFlag flag) noexcept {
    return static_cast<std::uint64_t>(flag);
}

struct CountPosition {
    std::int64_t x{};
    std::int64_t y{};

    bool operator==(const CountPosition&) const = default;
};

struct OrderedButtonEdge {
    std::uint64_t capture_sequence{};
    std::int64_t capture_unix_ns{};
    std::uint32_t report_ordinal_in_bin{};
    std::uint32_t buttons_before{};
    std::uint32_t buttons_after{};
    std::uint32_t down_mask{};
    std::uint32_t up_mask{};

    bool operator==(const OrderedButtonEdge&) const = default;
};

struct DerivedMillisecondBin {
    std::int64_t bin_index{};
    std::int64_t begin_unix_ns{};
    std::int64_t end_unix_ns{};
    DeviceAndDerivedDelta delta{};
    std::int64_t wheel_sum{};
    std::int64_t horizontal_wheel_sum{};
    std::uint32_t report_count{};

    // A zero-delta report has device dx == 0 and device dy == 0.  Wheel and
    // button activity remain independently available on the same record.
    std::uint32_t zero_delta_report_count{};
    std::optional<std::uint64_t> first_report_sequence;
    std::optional<std::uint64_t> last_report_sequence;
    std::uint32_t buttons_at_start{};
    std::uint32_t buttons_at_end{};
    std::uint32_t buttons_down_mask{};
    std::uint32_t buttons_up_mask{};
    std::vector<OrderedButtonEdge> ordered_button_edges;

    // The row's position is sampled before applying this row's delta.  This is
    // the PHALM-M16 adapter invariant: next.pre == current.post.
    CountPosition crosshair_pre_delta{};
    CountPosition crosshair_post_delta{};
    std::uint64_t quality_mask{};

    [[nodiscard]] bool ReportPresent() const noexcept {
        return report_count != 0U;
    }
};

struct MillisecondBinningOptions {
    AxisConventionVersion axis_convention{kCurrentResearchAxisConvention};
    CountPosition initial_crosshair{};
    std::uint32_t initial_buttons{};
};

struct DenseBinningResult {
    std::int64_t grid_origin_unix_ns{};
    DenseBinRange range{};
    AxisConventionVersion axis_convention{kCurrentResearchAxisConvention};
    std::vector<DerivedMillisecondBin> bins;
    std::uint64_t quality_mask{};
    std::uint64_t timestamp_regression_count{};
    std::uint64_t capture_sequence_regression_count{};
};

// Offline, deterministic replay over the selected mouse's authoritative USB
// reports.  Every report must fall inside range.  Reports are assigned solely
// by their original capture_unix_ns; exact edges enter the following bin.
// Timestamp regression marks every crossed bin and remains usable instead of
// terminating derivation.  Arithmetic/range overflow and omitted reports are
// structural contract violations and may throw.
[[nodiscard]] DenseBinningResult DeriveMillisecondBins(
    std::span<const capture::AuthoritativeReport> reports,
    const MillisecondGrid& grid,
    DenseBinRange range,
    MillisecondBinningOptions options = {});

}  // namespace abdc::derive
