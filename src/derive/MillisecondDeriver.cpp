#include "derive/MillisecondDeriver.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace abdc::derive {
namespace {

struct QuotientRemainder {
    std::int64_t quotient{};
    std::int64_t remainder{};
};

[[nodiscard]] QuotientRemainder FloorParts(const std::int64_t value) noexcept {
    auto quotient = value / kNanosecondsPerMillisecond;
    auto remainder = value % kNanosecondsPerMillisecond;
    if (remainder < 0) {
        --quotient;
        remainder += kNanosecondsPerMillisecond;
    }
    return {quotient, remainder};
}

[[nodiscard]] std::int64_t CheckedAdd(
    const std::int64_t left,
    const std::int64_t right,
    const char* message) {
    if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
        throw std::overflow_error(message);
    }
    return left + right;
}

[[nodiscard]] std::int64_t CheckedMultiply(
    const std::int64_t left,
    const std::int64_t right,
    const char* message) {
    if (left == 0 || right == 0) return 0;
    const auto minimum = std::numeric_limits<std::int64_t>::min();
    const auto maximum = std::numeric_limits<std::int64_t>::max();
    const bool overflow = left > 0
        ? (right > 0 ? left > maximum / right : right < minimum / left)
        : (right > 0 ? left < minimum / right
                     : left != 0 && right < maximum / left);
    if (overflow) throw std::overflow_error(message);
    return left * right;
}

[[nodiscard]] std::uint32_t CheckedIncrement(
    const std::uint32_t value,
    const char* message) {
    if (value == std::numeric_limits<std::uint32_t>::max()) {
        throw std::overflow_error(message);
    }
    return value + 1U;
}

[[nodiscard]] std::size_t BinOffset(
    const DenseBinRange range,
    const std::int64_t index) {
    if (!range.Contains(index)) {
        throw std::invalid_argument(
            "authoritative report lies outside requested dense bin range");
    }
    const auto difference = static_cast<std::uint64_t>(index) -
                            static_cast<std::uint64_t>(range.first);
    if (difference > std::numeric_limits<std::size_t>::max()) {
        throw std::length_error("dense bin offset exceeds addressable memory");
    }
    return static_cast<std::size_t>(difference);
}

struct IndexedReport {
    const capture::AuthoritativeReport* report{};
    std::size_t input_ordinal{};
};

void MarkInclusiveBinSpan(
    DenseBinningResult& result,
    std::int64_t first,
    std::int64_t last,
    const std::uint64_t mask) {
    if (last < first) std::swap(first, last);
    for (auto index = first;; ++index) {
        result.bins[BinOffset(result.range, index)].quality_mask |= mask;
        if (index == last) break;
        if (index == std::numeric_limits<std::int64_t>::max()) {
            throw std::overflow_error("quality annotation bin span overflow");
        }
    }
    result.quality_mask |= mask;
}

}  // namespace

std::int64_t MillisecondGrid::FloorToMillisecond(const std::int64_t unix_ns) {
    const auto parts = FloorParts(unix_ns);
    return CheckedMultiply(
        parts.quotient,
        kNanosecondsPerMillisecond,
        "floor-aligned millisecond origin overflow");
}

std::int64_t MillisecondGrid::IndexOf(const std::int64_t unix_ns) const noexcept {
    const auto timestamp = FloorParts(unix_ns);
    const auto origin = FloorParts(origin_unix_ns_);

    // Dividing first keeps the difference representable even for timestamps at
    // opposite ends of int64.  Quotients are bounded to about +/-9.3e12.
    auto index = timestamp.quotient - origin.quotient;
    if (timestamp.remainder < origin.remainder) --index;
    return index;
}

std::int64_t MillisecondGrid::EdgeUnixNs(const std::int64_t edge_index) const {
    return CheckedAdd(
        origin_unix_ns_,
        CheckedMultiply(
            edge_index,
            kNanosecondsPerMillisecond,
            "millisecond-grid edge multiplication overflow"),
        "millisecond-grid edge addition overflow");
}

MillisecondBinInterval MillisecondGrid::Interval(const std::int64_t index) const {
    const auto begin = EdgeUnixNs(index);
    return {
        index,
        begin,
        CheckedAdd(
            begin,
            kNanosecondsPerMillisecond,
            "millisecond-grid interval end overflow"),
    };
}

std::uint64_t DenseBinRange::Size() const {
    if (end_exclusive < first) {
        throw std::invalid_argument("dense bin range ends before it begins");
    }
    return static_cast<std::uint64_t>(end_exclusive) -
           static_cast<std::uint64_t>(first);
}

std::optional<DenseBinRange> CoveringBinRange(
    const std::span<const capture::AuthoritativeReport> reports,
    const MillisecondGrid& grid) {
    if (reports.empty()) return std::nullopt;

    auto minimum = grid.IndexOf(reports.front().capture_unix_ns);
    auto maximum = minimum;
    for (const auto& report : reports.subspan(1)) {
        const auto index = grid.IndexOf(report.capture_unix_ns);
        minimum = std::min(minimum, index);
        maximum = std::max(maximum, index);
    }
    if (maximum == std::numeric_limits<std::int64_t>::max()) {
        throw std::overflow_error("covering bin range end overflow");
    }
    return DenseBinRange{minimum, maximum + 1};
}

DenseBinningResult DeriveMillisecondBins(
    const std::span<const capture::AuthoritativeReport> reports,
    const MillisecondGrid& grid,
    const DenseBinRange range,
    const MillisecondBinningOptions options) {
    static_cast<void>(DescribeAxisConvention(options.axis_convention));

    DenseBinningResult result{};
    result.grid_origin_unix_ns = grid.OriginUnixNs();
    result.range = range;
    result.axis_convention = options.axis_convention;

    const auto bin_count = range.Size();
    if (bin_count > static_cast<std::uint64_t>(result.bins.max_size()) ||
        bin_count > std::numeric_limits<std::size_t>::max()) {
        throw std::length_error("dense millisecond range is too large");
    }
    result.bins.resize(static_cast<std::size_t>(bin_count));
    std::vector<std::vector<IndexedReport>> grouped(result.bins.size());

    for (std::size_t offset = 0; offset < result.bins.size(); ++offset) {
        if (offset > static_cast<std::size_t>(
                         std::numeric_limits<std::int64_t>::max())) {
            throw std::overflow_error("dense bin index offset overflow");
        }
        const auto index = CheckedAdd(
            range.first,
            static_cast<std::int64_t>(offset),
            "dense bin index overflow");
        const auto interval = grid.Interval(index);
        auto& bin = result.bins[offset];
        bin.bin_index = index;
        bin.begin_unix_ns = interval.begin_unix_ns;
        bin.end_unix_ns = interval.end_unix_ns;
    }

    std::optional<std::int64_t> previous_timestamp;
    std::optional<std::int64_t> previous_bin;
    std::optional<std::uint64_t> previous_capture_sequence;
    for (std::size_t input_ordinal = 0; input_ordinal < reports.size();
         ++input_ordinal) {
        const auto& report = reports[input_ordinal];
        const auto report_bin = grid.IndexOf(report.capture_unix_ns);
        const auto offset = BinOffset(range, report_bin);
        auto& bin = result.bins[offset];
        grouped[offset].push_back({&report, input_ordinal});

        bin.delta.device_dx = CheckedAdd(
            bin.delta.device_dx, report.hid_dx, "binned device X sum overflow");
        bin.delta.device_dy = CheckedAdd(
            bin.delta.device_dy, report.hid_dy, "binned device Y sum overflow");
        bin.wheel_sum = CheckedAdd(
            bin.wheel_sum, report.hid_wheel, "binned wheel sum overflow");
        bin.horizontal_wheel_sum = CheckedAdd(
            bin.horizontal_wheel_sum,
            report.hid_horizontal_wheel,
            "binned horizontal wheel sum overflow");
        bin.report_count = CheckedIncrement(
            bin.report_count, "millisecond report count overflow");
        if (report.hid_dx == 0 && report.hid_dy == 0) {
            bin.zero_delta_report_count = CheckedIncrement(
                bin.zero_delta_report_count,
                "millisecond zero-delta report count overflow");
        }
        bin.quality_mask |= static_cast<std::uint64_t>(report.quality_flags);
        result.quality_mask |= static_cast<std::uint64_t>(report.quality_flags);

        if (previous_timestamp && report.capture_unix_ns < *previous_timestamp) {
            if (result.timestamp_regression_count ==
                std::numeric_limits<std::uint64_t>::max()) {
                throw std::overflow_error("timestamp regression count overflow");
            }
            ++result.timestamp_regression_count;
            MarkInclusiveBinSpan(
                result,
                *previous_bin,
                report_bin,
                QualityMask(BinQualityFlag::TimestampRegressionDetected) |
                    QualityMask(BinQualityFlag::ButtonChronologyUncertain));
        }
        if (previous_capture_sequence &&
            report.capture_sequence <= *previous_capture_sequence) {
            if (result.capture_sequence_regression_count ==
                std::numeric_limits<std::uint64_t>::max()) {
                throw std::overflow_error("capture sequence regression count overflow");
            }
            ++result.capture_sequence_regression_count;
            MarkInclusiveBinSpan(
                result,
                *previous_bin,
                report_bin,
                QualityMask(BinQualityFlag::CaptureSequenceNotIncreasing) |
                    QualityMask(BinQualityFlag::ButtonChronologyUncertain));
        }
        previous_timestamp = report.capture_unix_ns;
        previous_bin = report_bin;
        previous_capture_sequence = report.capture_sequence;
    }

    std::uint32_t current_buttons = options.initial_buttons;
    auto crosshair = options.initial_crosshair;
    for (std::size_t offset = 0; offset < result.bins.size(); ++offset) {
        auto& bin = result.bins[offset];
        auto& report_group = grouped[offset];
        std::stable_sort(
            report_group.begin(),
            report_group.end(),
            [](const IndexedReport& left, const IndexedReport& right) {
                if (left.report->capture_sequence !=
                    right.report->capture_sequence) {
                    return left.report->capture_sequence <
                           right.report->capture_sequence;
                }
                return left.input_ordinal < right.input_ordinal;
            });

        bin.delta = DeriveAxes(
            bin.delta.device_dx,
            bin.delta.device_dy,
            options.axis_convention);
        bin.buttons_at_start = current_buttons;
        for (std::size_t ordinal = 0; ordinal < report_group.size(); ++ordinal) {
            const auto& report = *report_group[ordinal].report;
            if (!bin.first_report_sequence) {
                bin.first_report_sequence = report.capture_sequence;
            }
            bin.last_report_sequence = report.capture_sequence;
            const auto down = (~current_buttons) & report.buttons;
            const auto up = current_buttons & (~report.buttons);
            bin.buttons_down_mask |= down;
            bin.buttons_up_mask |= up;
            if (down != 0U || up != 0U) {
                if (ordinal > std::numeric_limits<std::uint32_t>::max()) {
                    throw std::overflow_error("button edge ordinal overflow");
                }
                bin.ordered_button_edges.push_back({
                    report.capture_sequence,
                    report.capture_unix_ns,
                    static_cast<std::uint32_t>(ordinal),
                    current_buttons,
                    report.buttons,
                    down,
                    up,
                });
            }
            current_buttons = report.buttons;
        }
        bin.buttons_at_end = current_buttons;

        bin.crosshair_pre_delta = crosshair;
        bin.crosshair_post_delta = {
            CheckedAdd(
                crosshair.x,
                bin.delta.derived_dx,
                "integrated crosshair X overflow"),
            CheckedAdd(
                crosshair.y,
                bin.delta.derived_dy,
                "integrated crosshair Y overflow"),
        };
        crosshair = bin.crosshair_post_delta;
        result.quality_mask |= bin.quality_mask;
    }

    return result;
}

}  // namespace abdc::derive
