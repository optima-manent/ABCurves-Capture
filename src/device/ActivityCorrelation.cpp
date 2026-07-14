#include "device/ActivityCorrelation.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <utility>
#include <vector>

namespace abdc::device {
namespace {

struct Bin {
    double dx = 0.0;
    double dy = 0.0;
};

std::int64_t NearestRank(std::vector<std::int64_t> values,
                         const std::size_t numerator,
                         const std::size_t denominator) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const auto rank = std::max<std::size_t>(
        1U, (values.size() * numerator + denominator - 1U) / denominator);
    return values[std::min(rank - 1U, values.size() - 1U)];
}

void AddPollingEvidence(ActivityCorrelationDecision& result,
                        const std::span<const std::int64_t> input) {
    std::vector<std::int64_t> intervals;
    intervals.reserve(input.size());
    for (const auto interval : input) {
        if (interval > 0) intervals.push_back(interval);
    }
    result.polling_interval_count = intervals.size();
    if (intervals.empty()) return;
    result.median_polling_interval_ns = NearestRank(intervals, 1U, 2U);
    result.p95_polling_interval_ns = NearestRank(intervals, 95U, 100U);
    if (result.median_polling_interval_ns > 0) {
        result.measured_polling_hz = 1'000'000'000.0 /
            static_cast<double>(result.median_polling_interval_ns);
    }
}

ActivityCorrelationDecision Failure(const ActivityCorrelationStatus status,
                                    std::string explanation,
                                    const std::span<const std::int64_t> intervals) {
    ActivityCorrelationDecision result;
    result.status = status;
    result.explanation = std::move(explanation);
    AddPollingEvidence(result, intervals);
    return result;
}

ActivityTotals Totals(const std::span<const GestureSample> samples) {
    ActivityTotals totals;
    totals.packet_count = samples.size();
    for (const auto& sample : samples) {
        totals.canonical_dx += sample.canonical_dx;
        totals.canonical_dy += sample.canonical_dy;
        totals.absolute_motion_counts += static_cast<std::uint64_t>(
            std::abs(static_cast<std::int64_t>(sample.canonical_dx)) +
            std::abs(static_cast<std::int64_t>(sample.canonical_dy)));
        totals.left_down_edges += sample.left_down ? 1U : 0U;
        totals.left_up_edges += sample.left_up ? 1U : 0U;
    }
    return totals;
}

std::vector<Bin> BinSamples(const std::span<const GestureSample> samples,
                            const std::int64_t origin,
                            const std::int64_t bin_width,
                            const std::size_t count) {
    std::vector<Bin> bins(count);
    for (const auto& sample : samples) {
        if (sample.relative_time_ns < origin) continue;
        const auto index = static_cast<std::uint64_t>(
            (sample.relative_time_ns - origin) / bin_width);
        if (index >= bins.size()) continue;
        bins[static_cast<std::size_t>(index)].dx += sample.canonical_dx;
        bins[static_cast<std::size_t>(index)].dy += sample.canonical_dy;
    }
    return bins;
}

double DirectionalCorrelation(const std::span<const Bin> left,
                              const std::span<const Bin> right,
                              const int lag) {
    double dot = 0.0;
    double left_energy = 0.0;
    double right_energy = 0.0;
    for (std::size_t left_index = 0; left_index < left.size(); ++left_index) {
        const auto right_index = static_cast<std::int64_t>(left_index) + lag;
        if (right_index < 0 || right_index >= static_cast<std::int64_t>(right.size())) {
            continue;
        }
        const auto& a = left[left_index];
        const auto& b = right[static_cast<std::size_t>(right_index)];
        dot += a.dx * b.dx + a.dy * b.dy;
        left_energy += a.dx * a.dx + a.dy * a.dy;
        right_energy += b.dx * b.dx + b.dy * b.dy;
    }
    if (left_energy <= 0.0 || right_energy <= 0.0) return -1.0;
    return dot / std::sqrt(left_energy * right_energy);
}

}  // namespace

const char* ToString(const ActivityCorrelationStatus status) noexcept {
    switch (status) {
    case ActivityCorrelationStatus::Ready: return "ready";
    case ActivityCorrelationStatus::InsufficientMovement: return "insufficient_movement";
    case ActivityCorrelationStatus::ClickNotObserved: return "click_not_observed";
    case ActivityCorrelationStatus::TemporalCorrelationUnavailable:
        return "temporal_correlation_unavailable";
    case ActivityCorrelationStatus::WeakTemporalCorrelation:
        return "weak_temporal_correlation";
    }
    return "unknown";
}

ActivityCorrelationDecision EvaluateGestureCorrelation(
    const std::span<const GestureSample> usb,
    const std::span<const GestureSample> selected_raw_input,
    const std::span<const std::int64_t> positive_usb_transfer_intervals_ns,
    const ActivityCorrelationPolicy& policy) {
    if (policy.minimum_movement_counts == 0U || policy.bin_width_ns <= 0 ||
        policy.maximum_lag_ns < 0 ||
        !(policy.minimum_directional_correlation >= -1.0 &&
          policy.minimum_directional_correlation <= 1.0)) {
        return Failure(ActivityCorrelationStatus::TemporalCorrelationUnavailable,
                       "certification correlation policy is invalid",
                       positive_usb_transfer_intervals_ns);
    }
    const auto usb_totals = Totals(usb);
    const auto raw_totals = Totals(selected_raw_input);
    if (usb_totals.absolute_motion_counts < policy.minimum_movement_counts ||
        raw_totals.absolute_motion_counts < policy.minimum_movement_counts) {
        return Failure(ActivityCorrelationStatus::InsufficientMovement,
                       "move the selected mouse through a wider changing path",
                       positive_usb_transfer_intervals_ns);
    }
    if (usb_totals.left_down_edges == 0U || usb_totals.left_up_edges == 0U ||
        raw_totals.left_down_edges == 0U || raw_totals.left_up_edges == 0U) {
        return Failure(ActivityCorrelationStatus::ClickNotObserved,
                       "one complete left click was not visible in both channels",
                       positive_usb_transfer_intervals_ns);
    }
    if (usb.empty() || selected_raw_input.empty()) {
        return Failure(ActivityCorrelationStatus::TemporalCorrelationUnavailable,
                       "the gesture trace is empty",
                       positive_usb_transfer_intervals_ns);
    }
    const auto usb_minmax = std::minmax_element(
        usb.begin(), usb.end(), [](const auto& a, const auto& b) {
            return a.relative_time_ns < b.relative_time_ns;
        });
    const auto raw_minmax = std::minmax_element(
        selected_raw_input.begin(), selected_raw_input.end(),
        [](const auto& a, const auto& b) {
            return a.relative_time_ns < b.relative_time_ns;
        });
    const auto origin = std::min(usb_minmax.first->relative_time_ns,
                                 raw_minmax.first->relative_time_ns);
    const auto end = std::max(usb_minmax.second->relative_time_ns,
                              raw_minmax.second->relative_time_ns);
    if (origin < 0 || end < origin || end - origin > 60'000'000'000LL) {
        return Failure(ActivityCorrelationStatus::TemporalCorrelationUnavailable,
                       "gesture timestamps are invalid",
                       positive_usb_transfer_intervals_ns);
    }
    const auto bin_count = static_cast<std::size_t>((end - origin) /
        policy.bin_width_ns + 1LL);
    if (bin_count < 3U || bin_count > 10'000U) {
        return Failure(ActivityCorrelationStatus::TemporalCorrelationUnavailable,
                       "gesture duration is too short or too long",
                       positive_usb_transfer_intervals_ns);
    }
    const auto usb_bins = BinSamples(usb, origin, policy.bin_width_ns, bin_count);
    const auto raw_bins = BinSamples(selected_raw_input, origin,
                                     policy.bin_width_ns, bin_count);
    const int maximum_lag = static_cast<int>(policy.maximum_lag_ns /
                                             policy.bin_width_ns);
    double best = -1.0;
    int best_lag = 0;
    for (int lag = -maximum_lag; lag <= maximum_lag; ++lag) {
        const auto score = DirectionalCorrelation(usb_bins, raw_bins, lag);
        if (score > best) {
            best = score;
            best_lag = lag;
        }
    }

    ActivityCorrelationDecision result;
    result.correlation_score = best;
    result.best_lag_ns = static_cast<std::int64_t>(best_lag) * policy.bin_width_ns;
    AddPollingEvidence(result, positive_usb_transfer_intervals_ns);
    if (!std::isfinite(best) || best < policy.minimum_directional_correlation) {
        result.status = ActivityCorrelationStatus::WeakTemporalCorrelation;
        result.explanation =
            "mouse activity was present, but its time-window direction pattern was not distinctive";
        return result;
    }
    result.status = ActivityCorrelationStatus::Ready;
    result.identity_proven = true;
    result.explanation =
        "topology, decoded motion, click evidence, and tolerant temporal correlation identify this endpoint";
    return result;
}

ActivityCorrelationDecision EvaluateActivityCorrelation(
    const ActivityTotals& usb,
    const ActivityTotals& selected_raw_input,
    const ActivityTotals& other_raw_input,
    const std::span<const std::int64_t> positive_usb_transfer_intervals_ns,
    const std::uint64_t minimum_movement_counts) {
    (void)other_raw_input;  // unrelated mouse activity is not a capture failure.
    if (usb.packet_count == 0U || selected_raw_input.packet_count == 0U ||
        usb.absolute_motion_counts < minimum_movement_counts ||
        selected_raw_input.absolute_motion_counts < minimum_movement_counts) {
        return Failure(ActivityCorrelationStatus::InsufficientMovement,
                       "move the selected mouse farther during certification",
                       positive_usb_transfer_intervals_ns);
    }
    if (usb.left_down_edges == 0U || usb.left_up_edges == 0U ||
        selected_raw_input.left_down_edges == 0U ||
        selected_raw_input.left_up_edges == 0U) {
        return Failure(ActivityCorrelationStatus::ClickNotObserved,
                       "one complete left click was not visible in both channels",
                       positive_usb_transfer_intervals_ns);
    }
    ActivityCorrelationDecision result;
    result.status = ActivityCorrelationStatus::Ready;
    result.identity_proven = true;
    result.correlation_score = 0.5;  // topology-unique fallback, not a temporal score.
    result.explanation =
        "the topology-unique endpoint carried mouse motion and a complete click";
    AddPollingEvidence(result, positive_usb_transfer_intervals_ns);
    return result;
}

const char* ToString(const UniqueActivityWinnerStatus status) noexcept {
    switch (status) {
    case UniqueActivityWinnerStatus::Accepted: return "accepted";
    case UniqueActivityWinnerStatus::NoWinner: return "no_winner";
    case UniqueActivityWinnerStatus::Ambiguous: return "ambiguous";
    }
    return "unknown";
}

UniqueActivityWinnerDecision SelectUniqueActivityWinner(
    const std::span<const ActivityProofCandidateResult> candidates,
    const double minimum_margin) {
    UniqueActivityWinnerDecision result;
    for (std::size_t index = 0; index < candidates.size(); ++index) {
        const auto& candidate = candidates[index];
        if (candidate.correlation.identity_proven && candidate.source_capture_intact) {
            result.passing_indices.push_back(index);
        }
    }
    if (result.passing_indices.empty()) {
        result.status = UniqueActivityWinnerStatus::NoWinner;
        result.explanation =
            "no candidate endpoint carried a sufficiently correlated move-and-click gesture";
        return result;
    }
    std::sort(result.passing_indices.begin(), result.passing_indices.end(),
              [&](const auto left, const auto right) {
                  return candidates[left].correlation.correlation_score >
                         candidates[right].correlation.correlation_score;
              });

    // Keep only the strongest decoder/collection witness for each physical
    // USB source. A composite mouse often exposes the same endpoint through
    // several top-level collections; counting those as separate endpoints
    // creates a false ambiguity with identical scores.
    std::vector<std::size_t> source_winners;
    source_winners.reserve(result.passing_indices.size());
    for (const auto index : result.passing_indices) {
        const auto& candidate = candidates[index];
        const auto& source = candidate.source_stream_token.empty()
            ? candidate.pair_token
            : candidate.source_stream_token;
        const auto existing = std::find_if(
            source_winners.begin(), source_winners.end(),
            [&](const auto winner_index) {
                const auto& winner = candidates[winner_index];
                const auto& winner_source = winner.source_stream_token.empty()
                    ? winner.pair_token
                    : winner.source_stream_token;
                return winner_source == source;
            });
        if (existing == source_winners.end()) source_winners.push_back(index);
    }

    const auto winner = source_winners.front();
    if (source_winners.size() > 1U) {
        const auto margin = candidates[winner].correlation.correlation_score -
            candidates[source_winners[1]].correlation.correlation_score;
        if (!std::isfinite(margin) || margin < minimum_margin) {
            result.status = UniqueActivityWinnerStatus::Ambiguous;
            result.explanation =
                "multiple distinct USB source streams followed the gesture too closely to choose safely";
            return result;
        }
    }
    result.status = UniqueActivityWinnerStatus::Accepted;
    result.winning_index = winner;
    result.explanation =
        "one endpoint had a clear topology/activity correlation advantage";
    return result;
}

}  // namespace abdc::device
