#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abdc::device {

struct ActivityTotals {
    std::int64_t canonical_dx = 0;
    std::int64_t canonical_dy = 0;
    std::uint64_t left_down_edges = 0;
    std::uint64_t left_up_edges = 0;
    std::uint64_t packet_count = 0;
    std::uint64_t absolute_motion_counts = 0;
};

// Relative probe time makes correlation independent of the USBPcap/QPC epoch.
struct GestureSample {
    std::int64_t relative_time_ns = 0;
    std::int32_t canonical_dx = 0;
    std::int32_t canonical_dy = 0;
    bool left_down = false;
    bool left_up = false;
};

struct ActivityCorrelationPolicy {
    std::uint64_t minimum_movement_counts = 64U;
    std::int64_t bin_width_ns = 10'000'000LL;
    std::int64_t maximum_lag_ns = 120'000'000LL;
    double minimum_directional_correlation = 0.55;
    double unique_winner_margin = 0.08;
};

enum class ActivityCorrelationStatus {
    Ready,
    InsufficientMovement,
    ClickNotObserved,
    TemporalCorrelationUnavailable,
    WeakTemporalCorrelation,
};

[[nodiscard]] const char* ToString(ActivityCorrelationStatus status) noexcept;

struct ActivityCorrelationDecision {
    ActivityCorrelationStatus status = ActivityCorrelationStatus::InsufficientMovement;
    std::string explanation;
    bool identity_proven = false;
    double correlation_score = 0.0;
    std::int64_t best_lag_ns = 0;
    std::uint64_t polling_interval_count = 0;
    std::int64_t median_polling_interval_ns = 0;
    std::int64_t p95_polling_interval_ns = 0;
    double measured_polling_hz = 0.0;
};

// Preferred route: tolerant, lag-searching temporal correlation. Scale and
// packet batching may differ. The gesture only needs enough direction-changing
// motion and a click in both channels.
[[nodiscard]] ActivityCorrelationDecision EvaluateGestureCorrelation(
    std::span<const GestureSample> usb,
    std::span<const GestureSample> selected_raw_input,
    std::span<const std::int64_t> positive_usb_transfer_intervals_ns,
    const ActivityCorrelationPolicy& policy = {});

// Totals-only fallback for a topology-unique endpoint. It proves activity and
// button presence without requiring exact counts, exact edge totals, stillness,
// another mouse to remain idle, or a polling-rate threshold.
[[nodiscard]] ActivityCorrelationDecision EvaluateActivityCorrelation(
    const ActivityTotals& usb,
    const ActivityTotals& selected_raw_input,
    const ActivityTotals& other_raw_input,
    std::span<const std::int64_t> positive_usb_transfer_intervals_ns,
    std::uint64_t minimum_movement_counts = 64U);

struct ActivityProofCandidateResult {
    std::string pair_token;

    // Several Windows HID top-level collections can decode the same physical
    // USB endpoint. They are alternative witnesses for one source stream, not
    // competing mice. Empty retains the legacy one-pair-per-stream behavior.
    std::string source_stream_token;
    ActivityCorrelationDecision correlation;
    bool source_capture_intact = false;
    std::uint64_t decode_failures = 0;
    std::uint64_t failed_transfers = 0;
};

enum class UniqueActivityWinnerStatus {
    Accepted,
    NoWinner,
    Ambiguous,
};

struct UniqueActivityWinnerDecision {
    UniqueActivityWinnerStatus status = UniqueActivityWinnerStatus::NoWinner;
    std::string explanation;
    std::size_t winning_index = 0;
    std::vector<std::size_t> passing_indices;
};

[[nodiscard]] const char* ToString(UniqueActivityWinnerStatus status) noexcept;

// Decoder warnings do not disqualify preserved source capture. When several
// endpoints move, a clear correlation margin selects the winner; otherwise the
// finite probe returns Ambiguous and lets the participant explicitly retry.
[[nodiscard]] UniqueActivityWinnerDecision SelectUniqueActivityWinner(
    std::span<const ActivityProofCandidateResult> candidates,
    double minimum_margin = ActivityCorrelationPolicy{}.unique_winner_margin);

}  // namespace abdc::device
