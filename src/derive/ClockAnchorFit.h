#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace abdc::derive {

struct ClockAnchor {
    std::int64_t qpc_ticks{};
    std::int64_t utc_unix_ns{};

    // Half-width of the QPC bracket around the UTC read, expressed in ns.
    std::int64_t uncertainty_ns{};
};

struct ClockFitConfig {
    std::int64_t qpc_frequency_hz{};
    std::int64_t residual_warning_ns{1'000'000};
    std::int64_t clock_step_warning_ns{10'000'000};
    std::int64_t anchor_uncertainty_warning_ns{1'000'000};
    long double drift_warning_ppm{1'000.0L};
    std::size_t max_anchors{512};
};

enum class ClockFitWarning : std::uint32_t {
    None = 0,
    InsufficientAnchors = 1U << 0U,
    NonIncreasingQpc = 1U << 1U,
    UtcClockStepDetected = 1U << 2U,
    HighResidual = 1U << 3U,
    HighAnchorUncertainty = 1U << 4U,
    ExcessiveDrift = 1U << 5U,
    OutliersExcluded = 1U << 6U,
    NonPositiveSlope = 1U << 7U,
};

[[nodiscard]] constexpr std::uint32_t WarningMask(
    const ClockFitWarning warning) noexcept {
    return static_cast<std::uint32_t>(warning);
}

struct ClockAnchorResidual {
    std::size_t input_index{};
    long double residual_ns{};
    long double absolute_residual_beyond_uncertainty_ns{};
    bool used_in_fit{};
    bool exceeds_warning_limit{};
};

struct QpcUtcClockFit {
    bool mapping_available{};
    bool drift_measured{};
    std::uint32_t warning_mask{};
    std::size_t anchor_count{};
    std::size_t fitted_anchor_count{};
    std::size_t detected_clock_step_count{};
    std::int64_t reference_qpc{};
    std::int64_t reference_utc_unix_ns{};
    long double relative_intercept_ns{};
    long double nominal_ns_per_qpc_tick{};
    long double fitted_ns_per_qpc_tick{};
    long double fitted_drift_ppm{};
    long double rms_fitted_residual_ns{};
    long double max_abs_residual_ns{};
    long double estimated_mapping_uncertainty_ns{};
    std::vector<ClockAnchorResidual> residuals;

    [[nodiscard]] bool HasWarning(ClockFitWarning warning) const noexcept {
        return (warning_mask & WarningMask(warning)) != 0U;
    }

    // Missing mappings return nullopt.  A representable fit whose requested
    // conversion exceeds int64 is a structural overflow and throws.
    [[nodiscard]] std::optional<std::int64_t> QpcToUtcUnixNs(
        std::int64_t qpc_ticks) const;
    [[nodiscard]] std::optional<std::int64_t> UtcUnixNsToQpc(
        std::int64_t utc_unix_ns) const;
};

// Samples UTC between qpc_before/qpc_after and preserves half the bracket as
// uncertainty.  Reversed/negative QPC brackets and numeric overflow reject.
[[nodiscard]] ClockAnchor MakeBracketedClockAnchor(
    std::int64_t qpc_before,
    std::int64_t utc_unix_ns,
    std::int64_t qpc_after,
    std::int64_t qpc_frequency_hz);

// Robust offline affine fit UTC = a + b*QPC.  A detected UTC step partitions
// the observations and fits the longest coherent segment; every anchor still
// receives a residual.  Poor residuals, drift, steps, and wide brackets are
// warnings in the result, never fit-quality exceptions.  Invalid configuration,
// negative uncertainties, impossible numeric conversions, and configured size
// limits remain structural errors.
[[nodiscard]] QpcUtcClockFit FitQpcUtcClockAnchors(
    std::span<const ClockAnchor> anchors,
    ClockFitConfig config);

}  // namespace abdc::derive
