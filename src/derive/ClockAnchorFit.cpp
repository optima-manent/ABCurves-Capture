#include "derive/ClockAnchorFit.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <utility>

namespace abdc::derive {
namespace {

[[nodiscard]] long double Absolute(const long double value) noexcept {
    return value < 0.0L ? -value : value;
}

[[nodiscard]] long double IntegerDifference(
    const std::int64_t left,
    const std::int64_t right) noexcept {
    if (left >= right) {
        return static_cast<long double>(
            static_cast<std::uint64_t>(left) -
            static_cast<std::uint64_t>(right));
    }
    return -static_cast<long double>(
        static_cast<std::uint64_t>(right) -
        static_cast<std::uint64_t>(left));
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

[[nodiscard]] std::int64_t CheckedRound(
    const long double value,
    const char* message) {
    constexpr long double kInt64Lower = -9'223'372'036'854'775'808.0L;
    constexpr long double kInt64UpperExclusive =
        9'223'372'036'854'775'808.0L;
    if (!std::isfinite(value)) {
        throw std::overflow_error(message);
    }
    const auto rounded = std::round(value);
    if (rounded < kInt64Lower || rounded >= kInt64UpperExclusive) {
        throw std::overflow_error(message);
    }
    return static_cast<std::int64_t>(rounded);
}

[[nodiscard]] long double Median(std::vector<long double> values) {
    if (values.empty()) throw std::invalid_argument("median of empty values");
    const auto middle = values.begin() +
                        static_cast<std::ptrdiff_t>(values.size() / 2U);
    std::nth_element(values.begin(), middle, values.end());
    const auto upper = *middle;
    if ((values.size() & 1U) != 0U) return upper;
    const auto lower = *std::max_element(values.begin(), middle);
    return lower / 2.0L + upper / 2.0L;
}

struct IndexedAnchor {
    ClockAnchor anchor{};
    std::size_t input_index{};
};

struct RelativeFit {
    bool available{};
    bool drift_measured{};
    std::int64_t reference_qpc{};
    std::int64_t reference_utc{};
    long double intercept_ns{};
    long double slope_ns_per_tick{};
    std::vector<std::size_t> used_input_indices;
};

[[nodiscard]] long double PredictRelative(
    const RelativeFit& fit,
    const std::int64_t qpc_ticks) noexcept {
    return fit.intercept_ns + fit.slope_ns_per_tick *
        IntegerDifference(qpc_ticks, fit.reference_qpc);
}

[[nodiscard]] RelativeFit RobustFitSegment(
    const std::vector<IndexedAnchor>& sorted,
    const std::size_t begin,
    const std::size_t end,
    const long double nominal_slope,
    const ClockFitConfig& config) {
    RelativeFit fit{};
    if (begin >= end) return fit;

    const auto reference_index = begin + (end - begin) / 2U;
    fit.reference_qpc = sorted[reference_index].anchor.qpc_ticks;
    fit.reference_utc = sorted[reference_index].anchor.utc_unix_ns;
    fit.slope_ns_per_tick = nominal_slope;
    fit.available = true;

    if (end - begin == 1U) {
        fit.used_input_indices.push_back(sorted[begin].input_index);
        return fit;
    }

    std::vector<long double> slopes;
    const auto count = end - begin;
    slopes.reserve(count * (count - 1U) / 2U);
    for (auto left = begin; left < end; ++left) {
        for (auto right = left + 1U; right < end; ++right) {
            const auto dx = IntegerDifference(
                sorted[right].anchor.qpc_ticks,
                sorted[left].anchor.qpc_ticks);
            if (!(dx > 0.0L)) continue;
            slopes.push_back(IntegerDifference(
                sorted[right].anchor.utc_unix_ns,
                sorted[left].anchor.utc_unix_ns) / dx);
        }
    }
    if (slopes.empty()) return fit;
    fit.slope_ns_per_tick = Median(std::move(slopes));
    fit.drift_measured = true;
    if (!(fit.slope_ns_per_tick > 0.0L) ||
        !std::isfinite(fit.slope_ns_per_tick)) {
        fit.available = false;
        return fit;
    }

    std::vector<long double> intercepts;
    intercepts.reserve(count);
    for (auto index = begin; index < end; ++index) {
        intercepts.push_back(
            IntegerDifference(
                sorted[index].anchor.utc_unix_ns,
                fit.reference_utc) -
            fit.slope_ns_per_tick * IntegerDifference(
                sorted[index].anchor.qpc_ticks,
                fit.reference_qpc));
    }
    fit.intercept_ns = Median(std::move(intercepts));

    std::vector<long double> initial_absolute_residuals;
    initial_absolute_residuals.reserve(count);
    for (auto index = begin; index < end; ++index) {
        const auto residual = IntegerDifference(
            sorted[index].anchor.utc_unix_ns,
            fit.reference_utc) - PredictRelative(fit, sorted[index].anchor.qpc_ticks);
        initial_absolute_residuals.push_back(Absolute(residual));
    }
    const auto robust_sigma = 1.4826L * Median(initial_absolute_residuals);
    const auto robust_limit = std::max(
        static_cast<long double>(config.residual_warning_ns),
        6.0L * robust_sigma);

    std::vector<std::size_t> inliers;
    for (auto index = begin; index < end; ++index) {
        const auto residual = IntegerDifference(
            sorted[index].anchor.utc_unix_ns,
            fit.reference_utc) - PredictRelative(fit, sorted[index].anchor.qpc_ticks);
        const auto limit = robust_limit + static_cast<long double>(
            sorted[index].anchor.uncertainty_ns);
        if (Absolute(residual) <= limit) inliers.push_back(index);
    }
    if (inliers.size() < 2U) {
        inliers.clear();
        for (auto index = begin; index < end; ++index) inliers.push_back(index);
    }

    // Refine the robust selection with centered least squares.  All arithmetic
    // is relative to a real anchor so contemporary Unix epochs retain ns-scale
    // precision even where long double aliases double on MSVC.
    long double mean_x = 0.0L;
    long double mean_y = 0.0L;
    for (const auto index : inliers) {
        mean_x += IntegerDifference(
            sorted[index].anchor.qpc_ticks, fit.reference_qpc);
        mean_y += IntegerDifference(
            sorted[index].anchor.utc_unix_ns, fit.reference_utc);
    }
    mean_x /= static_cast<long double>(inliers.size());
    mean_y /= static_cast<long double>(inliers.size());

    long double covariance = 0.0L;
    long double variance = 0.0L;
    for (const auto index : inliers) {
        const auto x = IntegerDifference(
            sorted[index].anchor.qpc_ticks, fit.reference_qpc);
        const auto y = IntegerDifference(
            sorted[index].anchor.utc_unix_ns, fit.reference_utc);
        covariance += (x - mean_x) * (y - mean_y);
        variance += (x - mean_x) * (x - mean_x);
    }
    if (variance > 0.0L) {
        const auto refined_slope = covariance / variance;
        if (refined_slope > 0.0L && std::isfinite(refined_slope)) {
            fit.slope_ns_per_tick = refined_slope;
            fit.intercept_ns = mean_y - refined_slope * mean_x;
        }
    }
    for (const auto index : inliers) {
        fit.used_input_indices.push_back(sorted[index].input_index);
    }
    return fit;
}

[[nodiscard]] bool ContainsIndex(
    const std::vector<std::size_t>& values,
    const std::size_t value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

}  // namespace

std::optional<std::int64_t> QpcUtcClockFit::QpcToUtcUnixNs(
    const std::int64_t qpc_ticks) const {
    if (!mapping_available) return std::nullopt;
    const auto relative = relative_intercept_ns + fitted_ns_per_qpc_tick *
        IntegerDifference(qpc_ticks, reference_qpc);
    return CheckedAdd(
        reference_utc_unix_ns,
        CheckedRound(relative, "QPC-to-UTC relative mapping overflow"),
        "QPC-to-UTC mapping overflow");
}

std::optional<std::int64_t> QpcUtcClockFit::UtcUnixNsToQpc(
    const std::int64_t utc_unix_ns) const {
    if (!mapping_available) return std::nullopt;
    if (!(fitted_ns_per_qpc_tick > 0.0L)) {
        throw std::logic_error("available QPC-to-UTC fit has non-positive slope");
    }
    const auto relative_utc = IntegerDifference(
        utc_unix_ns, reference_utc_unix_ns) - relative_intercept_ns;
    const auto relative_qpc = relative_utc / fitted_ns_per_qpc_tick;
    return CheckedAdd(
        reference_qpc,
        CheckedRound(relative_qpc, "UTC-to-QPC relative mapping overflow"),
        "UTC-to-QPC mapping overflow");
}

ClockAnchor MakeBracketedClockAnchor(
    const std::int64_t qpc_before,
    const std::int64_t utc_unix_ns,
    const std::int64_t qpc_after,
    const std::int64_t qpc_frequency_hz) {
    if (qpc_frequency_hz <= 0) {
        throw std::invalid_argument("QPC frequency must be positive");
    }
    if (qpc_before < 0 || qpc_after < qpc_before) {
        throw std::invalid_argument("QPC bracket must be non-negative and ordered");
    }
    const auto width_ticks = static_cast<std::uint64_t>(qpc_after) -
                             static_cast<std::uint64_t>(qpc_before);
    const auto midpoint_offset = width_ticks / 2U;
    if (midpoint_offset > static_cast<std::uint64_t>(
                              std::numeric_limits<std::int64_t>::max() -
                              qpc_before)) {
        throw std::overflow_error("QPC bracket midpoint overflow");
    }
    const auto midpoint = qpc_before +
        static_cast<std::int64_t>(midpoint_offset);
    const auto uncertainty = std::ceil(
        static_cast<long double>(width_ticks) * 1'000'000'000.0L /
        static_cast<long double>(qpc_frequency_hz) / 2.0L);
    return {
        midpoint,
        utc_unix_ns,
        CheckedRound(uncertainty, "QPC bracket uncertainty overflow"),
    };
}

QpcUtcClockFit FitQpcUtcClockAnchors(
    const std::span<const ClockAnchor> anchors,
    const ClockFitConfig config) {
    if (config.qpc_frequency_hz <= 0) {
        throw std::invalid_argument("QPC frequency must be positive");
    }
    if (config.residual_warning_ns < 0 ||
        config.clock_step_warning_ns <= 0 ||
        config.anchor_uncertainty_warning_ns < 0 ||
        !(config.drift_warning_ppm > 0.0L) ||
        !std::isfinite(config.drift_warning_ppm) ||
        config.max_anchors == 0U) {
        throw std::invalid_argument("invalid QPC-to-UTC fit configuration");
    }
    if (anchors.size() > config.max_anchors) {
        throw std::length_error("clock anchor count exceeds configured limit");
    }

    QpcUtcClockFit result{};
    result.anchor_count = anchors.size();
    result.nominal_ns_per_qpc_tick =
        1'000'000'000.0L /
        static_cast<long double>(config.qpc_frequency_hz);
    result.fitted_ns_per_qpc_tick = result.nominal_ns_per_qpc_tick;
    result.residuals.resize(anchors.size());
    for (std::size_t index = 0; index < anchors.size(); ++index) {
        result.residuals[index].input_index = index;
        if (anchors[index].qpc_ticks < 0 || anchors[index].uncertainty_ns < 0) {
            throw std::invalid_argument(
                "clock anchors require non-negative QPC and uncertainty");
        }
        if (anchors[index].uncertainty_ns >
            config.anchor_uncertainty_warning_ns) {
            result.warning_mask |=
                WarningMask(ClockFitWarning::HighAnchorUncertainty);
        }
        if (index != 0U &&
            anchors[index].qpc_ticks <= anchors[index - 1U].qpc_ticks) {
            result.warning_mask |= WarningMask(ClockFitWarning::NonIncreasingQpc);
        }
    }
    if (anchors.empty()) {
        result.warning_mask |= WarningMask(ClockFitWarning::InsufficientAnchors);
        return result;
    }

    std::vector<IndexedAnchor> sorted;
    sorted.reserve(anchors.size());
    for (std::size_t index = 0; index < anchors.size(); ++index) {
        sorted.push_back({anchors[index], index});
    }
    std::stable_sort(
        sorted.begin(),
        sorted.end(),
        [](const IndexedAnchor& left, const IndexedAnchor& right) {
            if (left.anchor.qpc_ticks != right.anchor.qpc_ticks) {
                return left.anchor.qpc_ticks < right.anchor.qpc_ticks;
            }
            if (left.anchor.uncertainty_ns != right.anchor.uncertainty_ns) {
                return left.anchor.uncertainty_ns < right.anchor.uncertainty_ns;
            }
            return left.input_index < right.input_index;
        });

    // Only one observation can constrain a given QPC instant.  Retain the
    // narrowest bracket and report the others as non-increasing/outliers.
    std::vector<IndexedAnchor> unique;
    unique.reserve(sorted.size());
    for (const auto& anchor : sorted) {
        if (!unique.empty() &&
            unique.back().anchor.qpc_ticks == anchor.anchor.qpc_ticks) {
            result.warning_mask |= WarningMask(ClockFitWarning::NonIncreasingQpc) |
                                   WarningMask(ClockFitWarning::OutliersExcluded);
            continue;
        }
        unique.push_back(anchor);
    }

    // Estimate the ordinary clock rate before looking for discontinuities.  A
    // consistent large drift is a drift warning, not a series of false UTC
    // steps.  For an even number of adjacent slopes, choose the central value
    // nearer the known QPC nominal rate instead of averaging across a possible
    // single step.
    auto step_baseline_slope = result.nominal_ns_per_qpc_tick;
    if (unique.size() >= 2U) {
        std::vector<long double> adjacent_slopes;
        adjacent_slopes.reserve(unique.size() - 1U);
        for (std::size_t index = 1; index < unique.size(); ++index) {
            const auto qpc_delta = IntegerDifference(
                unique[index].anchor.qpc_ticks,
                unique[index - 1U].anchor.qpc_ticks);
            adjacent_slopes.push_back(IntegerDifference(
                unique[index].anchor.utc_unix_ns,
                unique[index - 1U].anchor.utc_unix_ns) / qpc_delta);
        }
        std::sort(adjacent_slopes.begin(), adjacent_slopes.end());
        const auto middle = adjacent_slopes.size() / 2U;
        if ((adjacent_slopes.size() & 1U) != 0U) {
            step_baseline_slope = adjacent_slopes[middle];
        } else {
            const auto lower = adjacent_slopes[middle - 1U];
            const auto upper = adjacent_slopes[middle];
            step_baseline_slope =
                Absolute(lower - result.nominal_ns_per_qpc_tick) <=
                        Absolute(upper - result.nominal_ns_per_qpc_tick)
                    ? lower
                    : upper;
        }
    }

    std::vector<std::size_t> segment_starts{0U};
    for (std::size_t index = 1; index < unique.size(); ++index) {
        const auto qpc_delta = IntegerDifference(
            unique[index].anchor.qpc_ticks,
            unique[index - 1U].anchor.qpc_ticks);
        const auto utc_delta = IntegerDifference(
            unique[index].anchor.utc_unix_ns,
            unique[index - 1U].anchor.utc_unix_ns);
        const auto baseline_elapsed = qpc_delta * step_baseline_slope;
        const auto step_bound =
            static_cast<long double>(config.clock_step_warning_ns) +
            static_cast<long double>(unique[index].anchor.uncertainty_ns) +
            static_cast<long double>(unique[index - 1U].anchor.uncertainty_ns);
        if (Absolute(utc_delta - baseline_elapsed) > step_bound) {
            segment_starts.push_back(index);
            ++result.detected_clock_step_count;
        }
    }
    if (result.detected_clock_step_count != 0U) {
        result.warning_mask |= WarningMask(ClockFitWarning::UtcClockStepDetected);
    }
    segment_starts.push_back(unique.size());

    std::size_t best_begin = 0U;
    std::size_t best_end = unique.size();
    std::size_t best_size = 0U;
    long double best_uncertainty = std::numeric_limits<long double>::infinity();
    for (std::size_t segment = 0; segment + 1U < segment_starts.size();
         ++segment) {
        const auto begin = segment_starts[segment];
        const auto end = segment_starts[segment + 1U];
        const auto size = end - begin;
        long double uncertainty = 0.0L;
        for (auto index = begin; index < end; ++index) {
            uncertainty += static_cast<long double>(
                unique[index].anchor.uncertainty_ns);
        }
        if (size > best_size ||
            (size == best_size && uncertainty < best_uncertainty)) {
            best_begin = begin;
            best_end = end;
            best_size = size;
            best_uncertainty = uncertainty;
        }
    }

    const auto fit = RobustFitSegment(
        unique,
        best_begin,
        best_end,
        result.nominal_ns_per_qpc_tick,
        config);
    result.mapping_available = fit.available;
    result.drift_measured = fit.drift_measured;
    result.reference_qpc = fit.reference_qpc;
    result.reference_utc_unix_ns = fit.reference_utc;
    result.relative_intercept_ns = fit.intercept_ns;
    result.fitted_ns_per_qpc_tick = fit.slope_ns_per_tick;
    result.fitted_anchor_count = fit.used_input_indices.size();

    if (result.fitted_anchor_count < 2U) {
        result.warning_mask |= WarningMask(ClockFitWarning::InsufficientAnchors);
    }
    if (!fit.available) {
        result.warning_mask |= WarningMask(ClockFitWarning::NonPositiveSlope);
        return result;
    }
    if (result.fitted_anchor_count < anchors.size()) {
        result.warning_mask |= WarningMask(ClockFitWarning::OutliersExcluded);
    }

    result.fitted_drift_ppm =
        (result.fitted_ns_per_qpc_tick /
             result.nominal_ns_per_qpc_tick -
         1.0L) *
        1'000'000.0L;
    if (Absolute(result.fitted_drift_ppm) > config.drift_warning_ppm) {
        result.warning_mask |= WarningMask(ClockFitWarning::ExcessiveDrift);
    }

    long double fitted_squared_residual_sum = 0.0L;
    long double fitted_uncertainty_squared_sum = 0.0L;
    for (std::size_t index = 0; index < anchors.size(); ++index) {
        const auto used = ContainsIndex(fit.used_input_indices, index);
        const auto residual = IntegerDifference(
            anchors[index].utc_unix_ns,
            fit.reference_utc) - PredictRelative(fit, anchors[index].qpc_ticks);
        const auto absolute_residual = Absolute(residual);
        const auto uncertainty = static_cast<long double>(
            anchors[index].uncertainty_ns);
        const auto beyond_uncertainty =
            std::max(0.0L, absolute_residual - uncertainty);
        const bool exceeds =
            beyond_uncertainty >
            static_cast<long double>(config.residual_warning_ns);
        result.residuals[index] = {
            index,
            residual,
            beyond_uncertainty,
            used,
            exceeds,
        };
        result.max_abs_residual_ns = std::max(
            result.max_abs_residual_ns, absolute_residual);
        if (exceeds) {
            result.warning_mask |= WarningMask(ClockFitWarning::HighResidual);
        }
        if (used) {
            fitted_squared_residual_sum += residual * residual;
            fitted_uncertainty_squared_sum += uncertainty * uncertainty;
        }
    }
    if (result.fitted_anchor_count != 0U) {
        const auto divisor = static_cast<long double>(
            result.fitted_anchor_count);
        result.rms_fitted_residual_ns = std::sqrt(
            fitted_squared_residual_sum / divisor);
        result.estimated_mapping_uncertainty_ns = std::sqrt(
            (fitted_squared_residual_sum + fitted_uncertainty_squared_sum) /
            divisor);
    }
    return result;
}

}  // namespace abdc::derive
