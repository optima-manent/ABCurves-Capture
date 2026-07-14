#include "protocol/protocol_v1.hpp"

#include "base/Json.h"
#include "base/Sha256.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <set>
#include <span>
#include <utility>

namespace abdc::protocol {
namespace {

using JsonArray = json::Value::Array;
using JsonObject = json::Value::Object;

constexpr std::uint64_t kSplitMixIncrement = 0x9e3779b97f4a7c15ULL;

[[nodiscard]] double Distance(const double x, const double y) noexcept {
    return std::hypot(x, y);
}

[[nodiscard]] double ClampAbs(const double value, const double limit) noexcept {
    return std::clamp(value, -limit, limit);
}

[[nodiscard]] bool NearlyEqual(const double left, const double right) noexcept {
    return std::abs(left - right) <=
           1.0e-12 * std::max({1.0, std::abs(left), std::abs(right)});
}

[[nodiscard]] bool CalibrationMatches(const GenerationContext& context) {
    try {
        const auto expected =
            CountSpaceCalibrationForSensitivity(context.trainer_sensitivity);
        return NearlyEqual(context.target_count_scale, expected.target_count_scale) &&
               NearlyEqual(context.target_generation_radians_per_count,
                           expected.effective_radians_per_count) &&
               context.spawn_margin_counts == expected.spawn_margin_counts;
    } catch (...) {
        return false;
    }
}

[[nodiscard]] GenerationContext CalibrationContext(const RealizedTarget& target) {
    GenerationContext context;
    context.trainer_sensitivity = target.trainer_sensitivity;
    context.target_count_scale = target.target_count_scale;
    context.target_generation_radians_per_count =
        target.target_generation_radians_per_count;
    context.spawn_margin_counts = target.spawn_margin_counts;
    return context;
}

[[nodiscard]] double MaxVisibleCenterCounts(const double radius_counts,
                                            const double radians_per_count) noexcept {
    if (!(radians_per_count > 0.0)) {
        return 0.0;
    }
    const double usable_radians =
        (V1Constants::pi * 0.5 * V1Constants::visibility_margin) -
        (std::max(0.0, radius_counts) * radians_per_count);
    return std::max(0.0, usable_radians / radians_per_count);
}

[[nodiscard]] bool IsVisible(const double relative_x_counts,
                             const double relative_y_counts,
                             const double radius_counts,
                             const double radians_per_count) noexcept {
    if (!(radius_counts > 0.0) || !(radians_per_count > 0.0)) {
        return false;
    }
    const double edge_x = (std::abs(relative_x_counts) + radius_counts) * radians_per_count;
    const double edge_y = (std::abs(relative_y_counts) + radius_counts) * radians_per_count;
    const double limit = V1Constants::pi * 0.5 * V1Constants::visibility_margin;
    return edge_x <= limit && edge_y <= limit;
}

[[nodiscard]] bool CandidateOk(const GenerationContext& context,
                               const double relative_x,
                               const double relative_y,
                               const double radius) noexcept {
    if (!std::isfinite(relative_x) || !std::isfinite(relative_y) || !std::isfinite(radius)) {
        return false;
    }
    const double rounded_radius = std::max(1.0, std::round(radius));
    const double required = rounded_radius + static_cast<double>(context.spawn_margin_counts);
    return Distance(relative_x, relative_y) + 1.0e-6 >= required &&
           IsVisible(relative_x,
                     relative_y,
                     rounded_radius,
                     context.target_generation_radians_per_count);
}

[[nodiscard]] json::Value TailJson(const TailConfig& tail) {
    return JsonObject{
        {"maximum_ms", tail.maximum_ms},
        {"minimum_ms", tail.minimum_ms},
        {"settle_required_ms", tail.settle_required_ms},
    };
}

[[nodiscard]] json::Value BehaviorJson(const TargetBehavior& behavior) {
    return JsonObject{
        {"fade_total_ms", behavior.fade_total_ms},
        {"hit_inter_target_delay_ms", behavior.hit_inter_target_delay_ms},
        {"hit_tail", TailJson(behavior.hit_tail)},
        {"miss_click_ends", behavior.miss_click_ends},
        {"miss_inter_target_delay_ms", behavior.miss_inter_target_delay_ms},
        {"nonhit_tail", TailJson(behavior.nonhit_tail)},
        {"timeout_inter_target_delay_ms", behavior.timeout_inter_target_delay_ms},
    };
}

[[nodiscard]] json::Value RangeJson(const double minimum, const double maximum) {
    return JsonObject{{"maximum", maximum}, {"minimum", minimum}};
}

[[nodiscard]] json::Value RangeJson(const int minimum, const int maximum) {
    return JsonObject{{"maximum", maximum}, {"minimum", minimum}};
}

[[nodiscard]] json::Value MechanicsJson(const Pattern pattern) {
    TargetBehavior behavior{};
    JsonObject mechanics;
    mechanics["candidate_rule"] =
        "hypot(relative_x,relative_y)+1e-6 >= round(radius)+spawn_margin_counts; full target edge visible on both axes";
    mechanics["radius_rounding"] = "round after tier scaling; clamp to at least 1 count";

    switch (pattern) {
    case Pattern::default_static:
        behavior.hit_inter_target_delay_ms = 300;
        mechanics["attempt_limit"] = 128;
        mechanics["behavior"] = BehaviorJson(behavior);
        mechanics["radius_base_range"] = RangeJson(18.0 / 1.5, 34.0 / 1.5);
        mechanics["radius_tier"] = "medium";
        mechanics["relative_x"] =
            "uniform symmetric max_visible_center times x_band; x_band=0.75 with probability 0.75, otherwise 1.0";
        mechanics["relative_y"] = "uniform symmetric max_visible_center times 0.55";
        mechanics["timeout_ms"] = V1Constants::no_target_timeout_ms;
        break;

    case Pattern::chain_links:
        behavior.hit_inter_target_delay_ms = 150;
        mechanics["attempt_limit"] = 160;
        mechanics["behavior"] = BehaviorJson(behavior);
        mechanics["first_target"] = "uniform visible square";
        mechanics["linked_distance_bands"] = JsonArray{
            JsonObject{{"mix_max_exclusive", 0.35}, {"mix_min_inclusive", 0.0}, {"pct", RangeJson(0.03, 0.08)}},
            JsonObject{{"mix_max_exclusive", 0.70}, {"mix_min_inclusive", 0.35}, {"pct", RangeJson(0.08, 0.18)}},
            JsonObject{{"mix_max_exclusive", 0.90}, {"mix_min_inclusive", 0.70}, {"pct", RangeJson(0.18, 0.36)}},
            JsonObject{{"mix_max_exclusive", 1.0}, {"mix_min_inclusive", 0.90}, {"placement", "uniform visible square"}},
        };
        mechanics["linked_origin"] = "previous resolved target absolute position";
        mechanics["linked_visible_radius_multiplier"] = std::sqrt(2.0);
        mechanics["radius_base_range"] = RangeJson(7.0, 18.0);
        mechanics["radius_tier"] = "small";
        mechanics["timeout_ms"] = V1Constants::no_target_timeout_ms;
        break;

    case Pattern::tickle_fast: {
        behavior.hit_inter_target_delay_ms = 120;
        behavior.miss_inter_target_delay_ms = 500;
        behavior.timeout_inter_target_delay_ms = 500;
        TargetBehavior reset_behavior = behavior;
        reset_behavior.fade_total_ms =
            270 + V1Constants::fading_target_grace_ms;
        TargetBehavior small_behavior = behavior;
        small_behavior.miss_click_ends = true;
        mechanics["attempt_limit"] = 128;
        mechanics["reset"] = JsonObject{
            {"behavior", BehaviorJson(reset_behavior)},
            {"distance_range", JsonObject{{"maximum", "max(minimum,80*count_scale)"},
                                           {"minimum", "max(20*count_scale,radius+spawn_margin_counts)"}}},
            {"placement", "polar angle uniform [0,2*pi), rounded x and y"},
            {"radius_base_range_before_multiplier", RangeJson(24.0, 50.0)},
            {"radius_multiplier", 1.3},
            {"radius_tier", "big"},
            {"role", "tickle_reset"},
            {"timeout_ms", 270 + V1Constants::fading_target_grace_ms},
        };
        mechanics["small_after_reset_hit"] = JsonObject{
            {"behavior", BehaviorJson(small_behavior)},
            {"placement", "uniform visible square scaled by one shared pct draw"},
            {"position_pct_range", RangeJson(0.35, 0.50)},
            {"radius_base_range_before_divisor", RangeJson(5.0, 14.0)},
            {"radius_divisor", 1.3},
            {"radius_tier", "small"},
            {"role", "tickle_small"},
            {"timeout_ms", V1Constants::no_target_timeout_ms},
        };
        mechanics["state_transition"] =
            "reset hit or dwell_hit -> one small target; every other reset result and every small result -> reset";
        break;
    }

    case Pattern::accuracy:
        behavior.miss_click_ends = true;
        behavior.hit_inter_target_delay_ms = 300;
        behavior.miss_inter_target_delay_ms = 500;
        mechanics["attempt_limit"] = 128;
        mechanics["behavior"] = BehaviorJson(behavior);
        mechanics["radius_base_range"] = RangeJson(8.0 / 1.2, 24.0 / 1.2);
        mechanics["radius_tier"] = "medium";
        mechanics["relative_x"] = "uniform symmetric max_visible_center";
        mechanics["relative_y"] = "uniform symmetric max_visible_center times 0.50";
        mechanics["timeout_ms"] = V1Constants::no_target_timeout_ms;
        break;

    case Pattern::precision_big:
    case Pattern::precision_small: {
        const bool small = pattern == Pattern::precision_small;
        const int timeout = (small ? 450 : 400) +
            V1Constants::fading_target_grace_ms;
        behavior.fade_total_ms = timeout;
        behavior.hit_inter_target_delay_ms = 300;
        behavior.timeout_inter_target_delay_ms = 300;
        mechanics["attempt_limit"] = 128;
        mechanics["behavior"] = BehaviorJson(behavior);
        mechanics["position_pct"] = small ? 0.50 : 0.35;
        mechanics["radius_base_range"] = small ? RangeJson(5.0, 14.0) : RangeJson(24.0, 44.0);
        mechanics["radius_tier"] = small ? "small" : "big";
        mechanics["relative_xy"] = "independent uniform symmetric max_visible_center times position_pct";
        mechanics["timeout_ms"] = timeout;
        break;
    }

    case Pattern::dwell_control:
        behavior.hit_inter_target_delay_ms = 250;
        mechanics["attempt_limit"] = 128;
        mechanics["behavior"] = BehaviorJson(behavior);
        mechanics["distance"] = JsonObject{{"maximum", "300*count_scale"},
                                            {"minimum", "max(20*count_scale,radius+spawn_margin_counts)"}};
        mechanics["dwell_required_ms"] = RangeJson(90, 130);
        mechanics["placement"] = "polar angle uniform [0,2*pi), rounded x and y";
        mechanics["radius_base_range"] = RangeJson(8.0 / 2.0, 35.0 / 2.0);
        mechanics["radius_tier"] = "medium";
        mechanics["timeout_ms"] = V1Constants::no_target_timeout_ms;
        break;

    case Pattern::overshoot_recovery:
        behavior.miss_click_ends = true;
        behavior.hit_inter_target_delay_ms = 300;
        behavior.miss_inter_target_delay_ms = 400;
        behavior.timeout_inter_target_delay_ms = 400;
        behavior.hit_tail = {180, 60, 400};
        mechanics["attempt_limit"] = 160;
        mechanics["behavior"] = BehaviorJson(behavior);
        mechanics["distance"] = JsonObject{
            {"maximum", "min(900*count_scale,max_visible_center*sqrt(2)*0.95)"},
            {"minimum", "min(max(250*count_scale,radius+spawn_margin_counts),maximum)"},
        };
        mechanics["placement"] = "polar angle uniform [0,2*pi), rounded x and y";
        mechanics["radius_base_range"] = RangeJson(6.0, 22.0);
        mechanics["radius_tier"] = "medium";
        mechanics["timeout_ms"] = RangeJson(1200, 1600);
        break;

    case Pattern::micro_adjustments:
        behavior.hit_inter_target_delay_ms = 200;
        mechanics["attempt_limit"] = 160;
        mechanics["behavior"] = BehaviorJson(behavior);
        mechanics["distance"] = JsonObject{{"maximum", "max(minimum,70*count_scale)"},
                                            {"minimum", "max(3*count_scale,radius+spawn_margin_counts)"}};
        mechanics["placement"] = "polar angle uniform [0,2*pi), rounded x and y";
        mechanics["radius_base_range"] = RangeJson(3.0, 14.0);
        mechanics["radius_tier"] = "small";
        mechanics["timeout_ms"] = V1Constants::no_target_timeout_ms;
        break;

    case Pattern::fast_flicker:
        behavior.fade_total_ms =
            450 + V1Constants::fading_target_grace_ms;
        behavior.hit_inter_target_delay_ms = 275;
        behavior.timeout_inter_target_delay_ms = 275;
        mechanics["attempt_limit"] = 160;
        mechanics["behavior"] = BehaviorJson(behavior);
        mechanics["edge_branch"] = JsonObject{
            {"probability", 0.50},
            {"relative_x", "random sign times uniform [min(max_visible_center,max(350*count_scale,max_visible_center*0.55)),max_visible_center]"},
            {"relative_y", "uniform symmetric max_visible_center times 0.50"},
        };
        mechanics["polar_branch"] = JsonObject{
            {"distance_maximum", "min(350*count_scale,max_visible_center*sqrt(2)*0.85)"},
            {"distance_minimum", "min(max(40*count_scale,radius+spawn_margin_counts),distance_maximum)"},
            {"placement", "polar; round x and y; clamp y to symmetric max_visible_center times 0.50"},
        };
        mechanics["radius_base_range"] = RangeJson(12.0, 28.0);
        mechanics["radius_tier"] = "medium";
        mechanics["timeout_ms"] =
            450 + V1Constants::fading_target_grace_ms;
        break;
    }
    return mechanics;
}

[[nodiscard]] std::string Sha256Text(const std::string& text) {
    const std::span<const char> characters(text.data(), text.size());
    return Sha256Hex(std::as_bytes(characters));
}

[[nodiscard]] bool IsLowerHexDigest(const std::string& digest) noexcept {
    if (digest.size() != 64) {
        return false;
    }
    return std::all_of(digest.begin(), digest.end(), [](const char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

[[nodiscard]] std::int64_t ToJsonInteger(const std::size_t value, const char* const label) {
    if (value > static_cast<std::size_t>((std::numeric_limits<std::int64_t>::max)())) {
        throw ProtocolError(std::string(label) + " is too large for canonical JSON");
    }
    return static_cast<std::int64_t>(value);
}

void ValidateTail(const TailConfig& tail, const char* const label) {
    if (tail.minimum_ms < 0 || tail.settle_required_ms < 0 || tail.maximum_ms < 0 ||
        tail.minimum_ms > tail.maximum_ms || tail.settle_required_ms > tail.maximum_ms) {
        throw ProtocolError(std::string("invalid ") + label + " tail");
    }
}

void ValidateBehavior(const TargetBehavior& behavior, const char* const label) {
    if (behavior.fade_total_ms < 0 || behavior.hit_inter_target_delay_ms < 0 ||
        behavior.miss_inter_target_delay_ms < 0 || behavior.timeout_inter_target_delay_ms < 0) {
        throw ProtocolError(std::string("negative timing in ") + label);
    }
    ValidateTail(behavior.hit_tail, label);
    ValidateTail(behavior.nonhit_tail, label);
}

void ValidateRealizedScenario(const RealizedTarget& target, const BlockDefinition& block) {
    TargetBehavior expected_behavior{};
    double minimum_radius = 1.0;
    double maximum_radius = 1.0;
    int attempt_limit = 128;
    int minimum_timeout = V1Constants::no_target_timeout_ms;
    int maximum_timeout = V1Constants::no_target_timeout_ms;
    int minimum_dwell = 0;
    int maximum_dwell = 0;
    TargetRole expected_role = TargetRole::general;

    switch (block.pattern) {
    case Pattern::default_static:
        minimum_radius = 50.0;
        maximum_radius = 94.0;
        expected_behavior.hit_inter_target_delay_ms = 300;
        break;
    case Pattern::chain_links:
        minimum_radius = 35.0;
        maximum_radius = 90.0;
        attempt_limit = 160;
        expected_behavior.hit_inter_target_delay_ms = 150;
        break;
    case Pattern::tickle_fast:
        expected_behavior.hit_inter_target_delay_ms = 120;
        expected_behavior.miss_inter_target_delay_ms = 500;
        expected_behavior.timeout_inter_target_delay_ms = 500;
        if (target.role == TargetRole::tickle_reset) {
            expected_role = TargetRole::tickle_reset;
            minimum_radius = 78.0;
            maximum_radius = 163.0;
            minimum_timeout = 270 + V1Constants::fading_target_grace_ms;
            maximum_timeout = 270 + V1Constants::fading_target_grace_ms;
            expected_behavior.fade_total_ms =
                270 + V1Constants::fading_target_grace_ms;
        } else if (target.role == TargetRole::tickle_small) {
            expected_role = TargetRole::tickle_small;
            minimum_radius = 19.0;
            maximum_radius = 54.0;
            expected_behavior.miss_click_ends = true;
        } else {
            throw ProtocolError("tickle target has an invalid role");
        }
        break;
    case Pattern::accuracy:
        minimum_radius = 28.0;
        maximum_radius = 83.0;
        expected_behavior.miss_click_ends = true;
        expected_behavior.hit_inter_target_delay_ms = 300;
        expected_behavior.miss_inter_target_delay_ms = 500;
        break;
    case Pattern::precision_big:
        minimum_radius = 60.0;
        maximum_radius = 110.0;
        minimum_timeout = 400 + V1Constants::fading_target_grace_ms;
        maximum_timeout = 400 + V1Constants::fading_target_grace_ms;
        expected_behavior.fade_total_ms =
            400 + V1Constants::fading_target_grace_ms;
        expected_behavior.hit_inter_target_delay_ms = 300;
        expected_behavior.timeout_inter_target_delay_ms = 300;
        break;
    case Pattern::precision_small:
        minimum_radius = 25.0;
        maximum_radius = 70.0;
        minimum_timeout = 450 + V1Constants::fading_target_grace_ms;
        maximum_timeout = 450 + V1Constants::fading_target_grace_ms;
        expected_behavior.fade_total_ms =
            450 + V1Constants::fading_target_grace_ms;
        expected_behavior.hit_inter_target_delay_ms = 300;
        expected_behavior.timeout_inter_target_delay_ms = 300;
        break;
    case Pattern::dwell_control:
        minimum_radius = 17.0;
        maximum_radius = 73.0;
        minimum_dwell = 90;
        maximum_dwell = 130;
        expected_behavior.hit_inter_target_delay_ms = 250;
        break;
    case Pattern::overshoot_recovery:
        minimum_radius = 25.0;
        maximum_radius = 92.0;
        attempt_limit = 160;
        minimum_timeout = 1200;
        maximum_timeout = 1600;
        expected_behavior.miss_click_ends = true;
        expected_behavior.hit_inter_target_delay_ms = 300;
        expected_behavior.miss_inter_target_delay_ms = 400;
        expected_behavior.timeout_inter_target_delay_ms = 400;
        expected_behavior.hit_tail = {180, 60, 400};
        break;
    case Pattern::micro_adjustments:
        minimum_radius = 15.0;
        maximum_radius = 70.0;
        attempt_limit = 160;
        expected_behavior.hit_inter_target_delay_ms = 200;
        break;
    case Pattern::fast_flicker:
        minimum_radius = 50.0;
        maximum_radius = 117.0;
        attempt_limit = 160;
        minimum_timeout = 450 + V1Constants::fading_target_grace_ms;
        maximum_timeout = 450 + V1Constants::fading_target_grace_ms;
        expected_behavior.fade_total_ms =
            450 + V1Constants::fading_target_grace_ms;
        expected_behavior.hit_inter_target_delay_ms = 275;
        expected_behavior.timeout_inter_target_delay_ms = 275;
        break;
    }

    minimum_radius = std::max(1.0, std::floor(minimum_radius *
                                              target.target_count_scale - 0.5));
    maximum_radius = std::max(1.0, std::ceil(maximum_radius *
                                             target.target_count_scale + 0.5));
    if (target.role != expected_role || target.generation_attempt > static_cast<std::size_t>(attempt_limit) ||
        target.radius_counts < minimum_radius || target.radius_counts > maximum_radius ||
        target.timeout_ms < minimum_timeout || target.timeout_ms > maximum_timeout ||
        target.dwell_required_ms < minimum_dwell || target.dwell_required_ms > maximum_dwell ||
        target.behavior != expected_behavior) {
        throw ProtocolError("realized target does not match its protocol-v1 scenario");
    }

    const auto calibrated_context = CalibrationContext(target);
    if (!CandidateOk(calibrated_context,
                     target.relative_x_counts,
                     target.relative_y_counts,
                     target.radius_counts)) {
        throw ProtocolError("realized target violates protocol-v1 distance or visibility constraints");
    }
}

}  // namespace

const std::vector<ChallengeDefinition>& ChallengeDefinitionsV1() {
    static const std::vector<ChallengeDefinition> definitions{
        {"default_static", "Default", "default_static_flick", Pattern::default_static, 3, 60'000, V1Constants::protocol_version},
        {"chain_links", "Chain Links", "chain_micro_reacquire", Pattern::chain_links, 2, 60'000, V1Constants::protocol_version},
        {"tickle_fast", "Tickle Me Fast", "reacceleration_precision_switch", Pattern::tickle_fast, 3, 60'000, V1Constants::protocol_version},
        {"accuracy", "Accuracy", "accuracy_precision_miss_sensitive", Pattern::accuracy, 3, 60'000, V1Constants::protocol_version},
        {"precision_big", "Precision Big", "precision_big_timed", Pattern::precision_big, 1, 60'000, V1Constants::protocol_version},
        {"precision_small", "Precision Small", "precision_small_timed", Pattern::precision_small, 2, 60'000, V1Constants::protocol_version},
        {"dwell_control", "Dwell Control", "dwell_stabilize_static", Pattern::dwell_control, 2, 60'000, V1Constants::protocol_version},
        {"overshoot_recovery", "Overshoot Recovery", "overshoot_recovery_static", Pattern::overshoot_recovery, 2, 60'000, V1Constants::protocol_version},
        {"micro_adjustments", "Micro-adjustments", "microadjust_close_static", Pattern::micro_adjustments, 1, 60'000, V1Constants::protocol_version},
        {"fast_flicker", "Fast Flicker", "fast_flick_timed", Pattern::fast_flicker, 2, 60'000, V1Constants::protocol_version},
    };
    return definitions;
}

const std::vector<BlockDefinition>& OrderedBlocksV1() {
    static const std::vector<BlockDefinition> blocks = [] {
        std::vector<BlockDefinition> result;
        result.reserve(21);
        for (const ChallengeDefinition& definition : ChallengeDefinitionsV1()) {
            for (int repeat_index = 0; repeat_index < definition.repeat_count; ++repeat_index) {
                const std::size_t ordinal = result.size();
                result.push_back({
                    ordinal,
                    definition.challenge_id + "_r" + std::to_string(repeat_index + 1),
                    definition.challenge_id,
                    definition.display_name,
                    definition.task_type,
                    definition.pattern,
                    repeat_index,
                    definition.repeat_count,
                    definition.duration_ms,
                    definition.challenge_version,
                });
            }
        }
        return result;
    }();
    return blocks;
}

const std::vector<std::size_t>& QuickTestBlockOrdinalsV1() {
    static const std::vector<std::size_t> ordinals = [] {
        std::vector<std::size_t> result;
        result.reserve(ChallengeDefinitionsV1().size());
        for (const auto& block : OrderedBlocksV1()) {
            if (block.repeat_index == 0) result.push_back(block.ordinal);
        }
        return result;
    }();
    return ordinals;
}

bool CanSpawnTargetV1(const std::int64_t remaining_ms) noexcept {
    return remaining_ms >= V1Constants::minimum_useful_spawn_ms;
}

CountSpaceCalibration CountSpaceCalibrationForSensitivity(
    const double trainer_sensitivity) {
    if (!std::isfinite(trainer_sensitivity) ||
        trainer_sensitivity < V1Constants::minimum_trainer_sensitivity ||
        trainer_sensitivity > V1Constants::maximum_trainer_sensitivity) {
        throw ProtocolError("trainer sensitivity is outside 0.01..3.00");
    }
    CountSpaceCalibration calibration;
    calibration.trainer_sensitivity = trainer_sensitivity;
    calibration.target_count_scale = 1.0 / trainer_sensitivity;
    calibration.effective_radians_per_count =
        V1Constants::target_generation_radians_per_count * trainer_sensitivity;
    const auto margin = std::llround(
        static_cast<double>(V1Constants::spawn_margin_counts) *
        calibration.target_count_scale);
    if (margin < 1 || margin > std::numeric_limits<int>::max()) {
        throw ProtocolError("scaled spawn margin is outside its integer range");
    }
    calibration.spawn_margin_counts = static_cast<int>(margin);
    return calibration;
}

PortableRng::PortableRng(const std::uint64_t persisted_seed) noexcept
    : seed_(persisted_seed), state_(persisted_seed) {}

PortableRng::PortableRng(const RngCheckpoint checkpoint)
    : seed_(checkpoint.seed), state_(checkpoint.state), draws_(checkpoint.draws) {
    const std::uint64_t expected_state = checkpoint.seed + (kSplitMixIncrement * checkpoint.draws);
    if (checkpoint.state != expected_state) {
        throw ProtocolError("invalid SplitMix64 checkpoint: state does not match seed and draw count");
    }
}

std::uint64_t PortableRng::NextU64() noexcept {
    state_ += kSplitMixIncrement;
    ++draws_;
    std::uint64_t value = state_;
    value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31U);
}

double PortableRng::UniformDouble(double minimum, double maximum) {
    if (!std::isfinite(minimum) || !std::isfinite(maximum)) {
        throw ProtocolError("UniformDouble bounds must be finite");
    }
    if (maximum < minimum) {
        std::swap(minimum, maximum);
    }
    const double unit = static_cast<double>(NextU64() >> 11U) * 0x1.0p-53;
    if (minimum == maximum) {
        return minimum;
    }
    const double result = minimum + ((maximum - minimum) * unit);
    if (!std::isfinite(result)) {
        throw ProtocolError("UniformDouble range overflow");
    }
    return result < maximum ? result : std::nextafter(maximum, minimum);
}

int PortableRng::UniformInt(int minimum, int maximum) {
    if (maximum < minimum) {
        std::swap(minimum, maximum);
    }
    const std::uint64_t width = static_cast<std::uint64_t>(
                                    static_cast<std::int64_t>(maximum) -
                                    static_cast<std::int64_t>(minimum)) +
                                1ULL;
    const std::uint64_t threshold = (0ULL - width) % width;
    std::uint64_t sample = 0;
    do {
        sample = NextU64();
    } while (sample < threshold);
    const std::int64_t result = static_cast<std::int64_t>(minimum) +
                                static_cast<std::int64_t>(sample % width);
    return static_cast<int>(result);
}

bool PortableRng::Chance(const double probability) {
    if (!std::isfinite(probability) || probability < 0.0 || probability > 1.0) {
        throw ProtocolError("Chance probability must be finite and in [0,1]");
    }
    return UniformDouble(0.0, 1.0) < probability;
}

RngCheckpoint PortableRng::checkpoint() const noexcept {
    return {seed_, state_, draws_};
}

bool CountsAsV1ZeroSettleTick(const SettleTickObservation& tick) noexcept {
    return tick.summed_dx == 0 && tick.summed_dy == 0;
}

TargetGeneratorV1::TargetGeneratorV1(const std::uint64_t persisted_seed) : rng_(persisted_seed) {
    ValidateProtocolV1();
}

TargetGeneratorV1::TargetGeneratorV1(const RngCheckpoint checkpoint) : rng_(checkpoint) {
    ValidateProtocolV1();
}

void TargetGeneratorV1::BeginBlock(const std::size_t block_ordinal) {
    if (block_active_ || target_active_) {
        throw ProtocolError("cannot begin a block while another block or target is active");
    }
    if (block_ordinal != expected_block_ordinal_ || block_ordinal >= OrderedBlocksV1().size()) {
        throw ProtocolError("protocol blocks must begin once, in canonical ordinal order");
    }
    block_active_ = true;
    block_end_pending_ = false;
    current_block_ordinal_ = block_ordinal;
    target_ordinal_in_block_ = 0;
    has_previous_target_ = false;
    previous_target_x_ = 0.0;
    previous_target_y_ = 0.0;
    tickle_next_small_ = false;
    current_target_ = {};
}

void TargetGeneratorV1::ValidateContext(const GenerationContext& context) const {
    if (!block_active_) {
        throw ProtocolError("target generation requires an active protocol block");
    }
    if (target_active_) {
        throw ProtocolError("cannot generate a target while another target is active");
    }
    if (block_end_pending_) {
        throw ProtocolError("challenge-end timeout resolved; this block must end before another spawn");
    }
    if (context.event_id < 0 || context.event_start_tick < 0) {
        throw ProtocolError("event id and event start tick must be nonnegative");
    }
    if (context.challenge_remaining_ms < 0 ||
        context.challenge_remaining_ms > OrderedBlocksV1()[current_block_ordinal_].duration_ms) {
        throw ProtocolError("challenge remaining time is outside the active block");
    }
    if (!CanSpawnTargetV1(context.challenge_remaining_ms)) {
        throw ProtocolError("fewer than 250 ms remain; protocol v1 forbids a new target spawn");
    }
    if (!CalibrationMatches(context)) {
        throw ProtocolError("target-generation calibration does not match the locked sensitivity");
    }
}

RealizedTarget TargetGeneratorV1::Generate(const GenerationContext& context) {
    ValidateContext(context);
    RealizedTarget target = BuildTarget(context);
    current_target_ = target;
    target_active_ = true;
    ++target_ordinal_in_block_;
    return target;
}

RealizedTarget TargetGeneratorV1::BuildTarget(const GenerationContext& context) {
    const BlockDefinition& block = OrderedBlocksV1()[current_block_ordinal_];
    const std::uint64_t draw_begin = rng_.draws();

    const auto radius = [&](const double base_minimum,
                            const double base_maximum,
                            const double tier_scale) {
        const double sampled = rng_.UniformDouble(base_minimum * context.target_count_scale * tier_scale,
                                                  base_maximum * context.target_count_scale * tier_scale);
        return std::max(1.0, std::round(sampled));
    };

    const auto make_target = [&](const std::size_t attempt,
                                 const TargetBehavior& behavior,
                                 const TargetRole role,
                                 const double relative_x,
                                 const double relative_y,
                                 const double target_radius,
                                 const int timeout_ms,
                                 const int dwell_required_ms) {
        RealizedTarget result;
        result.protocol_hash = ProtocolSha256();
        result.persisted_seed = rng_.seed();
        result.rng_draw_begin = draw_begin;
        result.rng_draw_end = rng_.draws();
        result.generation_attempt = attempt;
        result.block_ordinal = current_block_ordinal_;
        result.target_ordinal_in_block = target_ordinal_in_block_;
        result.event_id = context.event_id;
        result.challenge_id = block.challenge_id;
        result.task_type = block.task_type;
        result.role = role;
        result.start_crosshair_x = context.camera_x;
        result.start_crosshair_y = context.camera_y;
        result.event_start_tick = context.event_start_tick;
        result.challenge_remaining_ms = context.challenge_remaining_ms;
        result.trainer_sensitivity = context.trainer_sensitivity;
        result.target_count_scale = context.target_count_scale;
        result.target_generation_radians_per_count =
            context.target_generation_radians_per_count;
        result.spawn_margin_counts = context.spawn_margin_counts;
        result.relative_x_counts = relative_x;
        result.relative_y_counts = relative_y;
        result.target_x_counts = static_cast<double>(context.camera_x) + relative_x;
        result.target_y_counts = static_cast<double>(context.camera_y) + relative_y;
        result.radius_counts = std::max(1.0, std::round(target_radius));
        result.initial_distance_counts = Distance(relative_x, relative_y);
        result.timeout_ms = timeout_ms;
        result.dwell_required_ms = dwell_required_ms;
        result.visible = true;
        result.visibility_adjusted = false;
        result.behavior = behavior;
        return result;
    };

    switch (block.pattern) {
    case Pattern::default_static: {
        TargetBehavior behavior{};
        behavior.hit_inter_target_delay_ms = 300;
        for (std::size_t attempt = 1; attempt <= 128; ++attempt) {
            const double target_radius = radius(18.0 / 1.5, 34.0 / 1.5, V1Constants::medium_radius_scale);
            const double max_center = MaxVisibleCenterCounts(
                target_radius, context.target_generation_radians_per_count);
            const double x_band = rng_.Chance(0.75) ? 0.75 : 1.0;
            const double relative_x = rng_.UniformDouble(-max_center * x_band, max_center * x_band);
            const double relative_y = rng_.UniformDouble(-max_center * 0.55, max_center * 0.55);
            if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                return make_target(attempt,
                                   behavior,
                                   TargetRole::general,
                                   relative_x,
                                   relative_y,
                                   target_radius,
                                   V1Constants::no_target_timeout_ms,
                                   0);
            }
        }
        break;
    }

    case Pattern::chain_links: {
        TargetBehavior behavior{};
        behavior.hit_inter_target_delay_ms = 150;
        for (std::size_t attempt = 1; attempt <= 160; ++attempt) {
            const double target_radius = radius(7.0, 18.0, V1Constants::small_radius_scale);
            const double max_center = MaxVisibleCenterCounts(
                target_radius, context.target_generation_radians_per_count);
            double relative_x = 0.0;
            double relative_y = 0.0;
            if (!has_previous_target_) {
                relative_x = rng_.UniformDouble(-max_center, max_center);
                relative_y = rng_.UniformDouble(-max_center, max_center);
            } else {
                const double mix = rng_.UniformDouble(0.0, 1.0);
                double pct_minimum = 0.03;
                double pct_maximum = 0.08;
                if (mix >= 0.35 && mix < 0.70) {
                    pct_minimum = 0.08;
                    pct_maximum = 0.18;
                } else if (mix >= 0.70 && mix < 0.90) {
                    pct_minimum = 0.18;
                    pct_maximum = 0.36;
                } else if (mix >= 0.90) {
                    relative_x = rng_.UniformDouble(-max_center, max_center);
                    relative_y = rng_.UniformDouble(-max_center, max_center);
                    if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                        return make_target(attempt,
                                           behavior,
                                           TargetRole::general,
                                           relative_x,
                                           relative_y,
                                           target_radius,
                                           V1Constants::no_target_timeout_ms,
                                           0);
                    }
                    continue;
                }
                const double visible_radius = max_center * std::sqrt(2.0);
                const double minimum_distance =
                    std::max(visible_radius * pct_minimum,
                             target_radius + static_cast<double>(context.spawn_margin_counts));
                const double maximum_distance =
                    std::max(minimum_distance, visible_radius * pct_maximum);
                const double target_distance =
                    rng_.UniformDouble(minimum_distance, maximum_distance);
                const double angle = rng_.UniformDouble(0.0, V1Constants::pi * 2.0);
                const double absolute_x = previous_target_x_ + (std::cos(angle) * target_distance);
                const double absolute_y = previous_target_y_ + (std::sin(angle) * target_distance);
                relative_x = absolute_x - static_cast<double>(context.camera_x);
                relative_y = absolute_y - static_cast<double>(context.camera_y);
            }
            if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                return make_target(attempt,
                                   behavior,
                                   TargetRole::general,
                                   relative_x,
                                   relative_y,
                                   target_radius,
                                   V1Constants::no_target_timeout_ms,
                                   0);
            }
        }
        break;
    }

    case Pattern::tickle_fast: {
        TargetBehavior behavior{};
        behavior.hit_inter_target_delay_ms = 120;
        behavior.timeout_inter_target_delay_ms = 500;
        behavior.miss_inter_target_delay_ms = 500;
        if (!tickle_next_small_) {
            behavior.fade_total_ms =
                270 + V1Constants::fading_target_grace_ms;
            for (std::size_t attempt = 1; attempt <= 128; ++attempt) {
                const double target_radius =
                    radius(24.0 * 1.3, 50.0 * 1.3, V1Constants::big_radius_scale);
                const double minimum_distance =
                    std::max(20.0 * context.target_count_scale,
                             target_radius + static_cast<double>(context.spawn_margin_counts));
                const double maximum_distance =
                    std::max(minimum_distance, 80.0 * context.target_count_scale);
                const double target_distance =
                    rng_.UniformDouble(minimum_distance, maximum_distance);
                const double angle = rng_.UniformDouble(0.0, V1Constants::pi * 2.0);
                const double relative_x = std::round(std::cos(angle) * target_distance);
                const double relative_y = std::round(std::sin(angle) * target_distance);
                if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                    return make_target(attempt,
                                       behavior,
                                       TargetRole::tickle_reset,
                                       relative_x,
                                       relative_y,
                                       target_radius,
                                       270 + V1Constants::fading_target_grace_ms,
                                       0);
                }
            }
        } else {
            behavior.miss_click_ends = true;
            for (std::size_t attempt = 1; attempt <= 128; ++attempt) {
                const double target_radius =
                    radius(5.0 / 1.3, 14.0 / 1.3, V1Constants::small_radius_scale);
                const double max_center = MaxVisibleCenterCounts(
                    target_radius, context.target_generation_radians_per_count);
                const double pct = rng_.UniformDouble(0.35, 0.50);
                const double relative_x =
                    rng_.UniformDouble(-max_center * pct, max_center * pct);
                const double relative_y =
                    rng_.UniformDouble(-max_center * pct, max_center * pct);
                if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                    return make_target(attempt,
                                       behavior,
                                       TargetRole::tickle_small,
                                       relative_x,
                                       relative_y,
                                       target_radius,
                                       V1Constants::no_target_timeout_ms,
                                       0);
                }
            }
        }
        break;
    }

    case Pattern::accuracy: {
        TargetBehavior behavior{};
        behavior.miss_click_ends = true;
        behavior.hit_inter_target_delay_ms = 300;
        behavior.miss_inter_target_delay_ms = 500;
        for (std::size_t attempt = 1; attempt <= 128; ++attempt) {
            const double target_radius = radius(8.0 / 1.2, 24.0 / 1.2, V1Constants::medium_radius_scale);
            const double max_center = MaxVisibleCenterCounts(
                target_radius, context.target_generation_radians_per_count);
            const double relative_x = rng_.UniformDouble(-max_center, max_center);
            const double relative_y = rng_.UniformDouble(-max_center * 0.50, max_center * 0.50);
            if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                return make_target(attempt,
                                   behavior,
                                   TargetRole::general,
                                   relative_x,
                                   relative_y,
                                   target_radius,
                                   V1Constants::no_target_timeout_ms,
                                   0);
            }
        }
        break;
    }

    case Pattern::precision_big:
    case Pattern::precision_small: {
        const bool small = block.pattern == Pattern::precision_small;
        const int timeout_ms = (small ? 450 : 400) +
            V1Constants::fading_target_grace_ms;
        TargetBehavior behavior{};
        behavior.fade_total_ms = timeout_ms;
        behavior.hit_inter_target_delay_ms = 300;
        behavior.timeout_inter_target_delay_ms = 300;
        for (std::size_t attempt = 1; attempt <= 128; ++attempt) {
            const double target_radius = small
                                             ? radius(5.0, 14.0, V1Constants::small_radius_scale)
                                             : radius(24.0, 44.0, V1Constants::big_radius_scale);
            const double max_center = MaxVisibleCenterCounts(
                target_radius, context.target_generation_radians_per_count);
            const double pct = small ? 0.50 : 0.35;
            const double relative_x = rng_.UniformDouble(-max_center * pct, max_center * pct);
            const double relative_y = rng_.UniformDouble(-max_center * pct, max_center * pct);
            if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                return make_target(attempt,
                                   behavior,
                                   TargetRole::general,
                                   relative_x,
                                   relative_y,
                                   target_radius,
                                   timeout_ms,
                                   0);
            }
        }
        break;
    }

    case Pattern::dwell_control: {
        TargetBehavior behavior{};
        behavior.hit_inter_target_delay_ms = 250;
        for (std::size_t attempt = 1; attempt <= 128; ++attempt) {
            const double target_radius = radius(8.0 / 2.0, 35.0 / 2.0, V1Constants::medium_radius_scale);
            const double target_distance =
                rng_.UniformDouble(
                    std::max(20.0 * context.target_count_scale,
                             target_radius + static_cast<double>(context.spawn_margin_counts)),
                    300.0 * context.target_count_scale);
            const double angle = rng_.UniformDouble(0.0, V1Constants::pi * 2.0);
            const double relative_x = std::round(std::cos(angle) * target_distance);
            const double relative_y = std::round(std::sin(angle) * target_distance);
            if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                const int dwell_required_ms = rng_.UniformInt(90, 130);
                return make_target(attempt,
                                   behavior,
                                   TargetRole::general,
                                   relative_x,
                                   relative_y,
                                   target_radius,
                                   V1Constants::no_target_timeout_ms,
                                   dwell_required_ms);
            }
        }
        break;
    }

    case Pattern::overshoot_recovery: {
        TargetBehavior behavior{};
        behavior.miss_click_ends = true;
        behavior.hit_inter_target_delay_ms = 300;
        behavior.miss_inter_target_delay_ms = 400;
        behavior.timeout_inter_target_delay_ms = 400;
        behavior.hit_tail = {180, 60, 400};
        for (std::size_t attempt = 1; attempt <= 160; ++attempt) {
            const double target_radius = radius(6.0, 22.0, V1Constants::medium_radius_scale);
            const double max_center = MaxVisibleCenterCounts(
                target_radius, context.target_generation_radians_per_count);
            const double maximum_distance =
                std::min(900.0 * context.target_count_scale,
                         max_center * std::sqrt(2.0) * 0.95);
            const double minimum_distance =
                std::min(std::max(250.0 * context.target_count_scale,
                                  target_radius + static_cast<double>(context.spawn_margin_counts)),
                         maximum_distance);
            const double target_distance =
                rng_.UniformDouble(minimum_distance, std::max(minimum_distance, maximum_distance));
            const double angle = rng_.UniformDouble(0.0, V1Constants::pi * 2.0);
            const double relative_x = std::round(std::cos(angle) * target_distance);
            const double relative_y = std::round(std::sin(angle) * target_distance);
            if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                const int timeout_ms = rng_.UniformInt(1200, 1600);
                return make_target(attempt,
                                   behavior,
                                   TargetRole::general,
                                   relative_x,
                                   relative_y,
                                   target_radius,
                                   timeout_ms,
                                   0);
            }
        }
        break;
    }

    case Pattern::micro_adjustments: {
        TargetBehavior behavior{};
        behavior.hit_inter_target_delay_ms = 200;
        for (std::size_t attempt = 1; attempt <= 160; ++attempt) {
            const double target_radius = radius(3.0, 14.0, V1Constants::small_radius_scale);
            const double minimum_distance =
                std::max(3.0 * context.target_count_scale,
                         target_radius + static_cast<double>(context.spawn_margin_counts));
            const double maximum_distance =
                std::max(minimum_distance, 70.0 * context.target_count_scale);
            const double target_distance =
                rng_.UniformDouble(minimum_distance, maximum_distance);
            const double angle = rng_.UniformDouble(0.0, V1Constants::pi * 2.0);
            const double relative_x = std::round(std::cos(angle) * target_distance);
            const double relative_y = std::round(std::sin(angle) * target_distance);
            if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                return make_target(attempt,
                                   behavior,
                                   TargetRole::general,
                                   relative_x,
                                   relative_y,
                                   target_radius,
                                   V1Constants::no_target_timeout_ms,
                                   0);
            }
        }
        break;
    }

    case Pattern::fast_flicker: {
        TargetBehavior behavior{};
        behavior.fade_total_ms =
            450 + V1Constants::fading_target_grace_ms;
        behavior.hit_inter_target_delay_ms = 275;
        behavior.timeout_inter_target_delay_ms = 275;
        for (std::size_t attempt = 1; attempt <= 160; ++attempt) {
            const double target_radius = radius(12.0, 28.0, V1Constants::medium_radius_scale);
            const double max_center = MaxVisibleCenterCounts(
                target_radius, context.target_generation_radians_per_count);
            double relative_x = 0.0;
            double relative_y = 0.0;
            if (rng_.Chance(0.50)) {
                const double edge_minimum =
                    std::min(max_center,
                             std::max(350.0 * context.target_count_scale, max_center * 0.55));
                relative_x = (rng_.Chance(0.50) ? -1.0 : 1.0) *
                             rng_.UniformDouble(edge_minimum, max_center);
                relative_y = rng_.UniformDouble(-max_center * 0.50, max_center * 0.50);
            } else {
                const double maximum_distance =
                    std::min(350.0 * context.target_count_scale,
                             max_center * std::sqrt(2.0) * 0.85);
                const double minimum_distance =
                    std::min(std::max(40.0 * context.target_count_scale,
                                      target_radius + static_cast<double>(context.spawn_margin_counts)),
                             maximum_distance);
                const double target_distance =
                    rng_.UniformDouble(minimum_distance, std::max(minimum_distance, maximum_distance));
                const double angle = rng_.UniformDouble(0.0, V1Constants::pi * 2.0);
                relative_x = std::round(std::cos(angle) * target_distance);
                relative_y = ClampAbs(std::round(std::sin(angle) * target_distance), max_center * 0.50);
            }
            if (CandidateOk(context, relative_x, relative_y, target_radius)) {
                return make_target(attempt,
                                   behavior,
                                   TargetRole::general,
                                   relative_x,
                                   relative_y,
                                   target_radius,
                                   450 + V1Constants::fading_target_grace_ms,
                                   0);
            }
        }
        break;
    }
    }

    throw ProtocolError("protocol v1 could not realize a valid target within the audited attempt limit");
}

ResolutionPlan TargetGeneratorV1::Resolve(const Resolution resolution) {
    if (!block_active_ || !target_active_) {
        throw ProtocolError("cannot resolve without an active target");
    }

    const bool hit = resolution == Resolution::hit || resolution == Resolution::dwell_hit;
    const bool miss_click = resolution == Resolution::miss_click;
    const bool challenge_end = resolution == Resolution::challenge_end_timeout;
    if (!hit && !miss_click && resolution != Resolution::timeout && !challenge_end) {
        throw ProtocolError("unknown target resolution");
    }
    if (miss_click && !current_target_.behavior.miss_click_ends) {
        throw ProtocolError("miss click does not resolve this protocol-v1 target");
    }
    if (resolution == Resolution::dwell_hit && current_target_.dwell_required_ms <= 0) {
        throw ProtocolError("dwell_hit is valid only for a dwell target");
    }
    if (resolution == Resolution::hit && current_target_.dwell_required_ms > 0) {
        throw ProtocolError("click hit cannot resolve a protocol-v1 dwell target");
    }

    ResolutionPlan plan;
    plan.scored = hit;
    plan.ends_challenge = challenge_end;
    plan.tail = hit ? current_target_.behavior.hit_tail : current_target_.behavior.nonhit_tail;
    if (hit) {
        plan.inter_target_delay_ms = current_target_.behavior.hit_inter_target_delay_ms;
    } else if (miss_click) {
        plan.inter_target_delay_ms = current_target_.behavior.miss_inter_target_delay_ms;
    } else {
        plan.inter_target_delay_ms = current_target_.behavior.timeout_inter_target_delay_ms;
    }

    if (OrderedBlocksV1()[current_block_ordinal_].pattern == Pattern::tickle_fast) {
        if (current_target_.role == TargetRole::tickle_reset) {
            tickle_next_small_ = hit;
        } else if (current_target_.role == TargetRole::tickle_small) {
            tickle_next_small_ = false;
        }
    }

    has_previous_target_ = true;
    previous_target_x_ = current_target_.target_x_counts;
    previous_target_y_ = current_target_.target_y_counts;
    block_end_pending_ = challenge_end;
    target_active_ = false;
    current_target_ = {};
    return plan;
}

void TargetGeneratorV1::AbortTechnical() {
    if (!block_active_ || !target_active_) {
        throw ProtocolError("cannot technically abort without an active target");
    }
    has_previous_target_ = false;
    if (OrderedBlocksV1()[current_block_ordinal_].pattern == Pattern::tickle_fast) {
        tickle_next_small_ = false;
    }
    target_active_ = false;
    current_target_ = {};
}

void TargetGeneratorV1::RestartCurrentBlockAttemptAfterTechnicalFailure() {
    if (!block_active_ || target_active_ || block_end_pending_) {
        throw ProtocolError("cannot restart a block attempt in the current target lifecycle state");
    }
    target_ordinal_in_block_ = 0;
    has_previous_target_ = false;
    previous_target_x_ = 0.0;
    previous_target_y_ = 0.0;
    tickle_next_small_ = false;
    current_target_ = {};
}

void TargetGeneratorV1::EndBlock() {
    if (!block_active_) {
        throw ProtocolError("cannot end a block that is not active");
    }
    if (target_active_) {
        throw ProtocolError("active target must resolve at the boundary before ending the block");
    }
    block_active_ = false;
    block_end_pending_ = false;
    has_previous_target_ = false;
    tickle_next_small_ = false;
    current_target_ = {};
    ++expected_block_ordinal_;
}

std::string PatternName(const Pattern pattern) {
    switch (pattern) {
    case Pattern::default_static:
        return "default_static";
    case Pattern::chain_links:
        return "chain_links";
    case Pattern::tickle_fast:
        return "tickle_fast";
    case Pattern::accuracy:
        return "accuracy";
    case Pattern::precision_big:
        return "precision_big";
    case Pattern::precision_small:
        return "precision_small";
    case Pattern::dwell_control:
        return "dwell_control";
    case Pattern::overshoot_recovery:
        return "overshoot_recovery";
    case Pattern::micro_adjustments:
        return "micro_adjustments";
    case Pattern::fast_flicker:
        return "fast_flicker";
    }
    throw ProtocolError("unknown protocol pattern");
}

std::string TargetRoleName(const TargetRole role) {
    switch (role) {
    case TargetRole::general:
        return "general";
    case TargetRole::tickle_reset:
        return "tickle_reset";
    case TargetRole::tickle_small:
        return "tickle_small";
    }
    throw ProtocolError("unknown target role");
}

std::string CanonicalScientificCorrectionsJson() {
    const json::Value document = JsonObject{
        {"corrections",
         JsonArray{
             JsonObject{
                 {"correction_id", "portable_persisted_rng"},
                 {"intentional", true},
                 {"legacy_oracle", "time-seeded std::mt19937 plus implementation-defined standard distributions"},
                 {"protocol_v1", "persisted uint64 seed; published SplitMix64 transition/mixer; specified high-53 double and unbiased inclusive integer mappings"},
             },
             JsonObject{
                 {"correction_id", "fail_closed_protocol_metadata"},
                 {"intentional", true},
                 {"legacy_oracle", "could expose an internal default challenge when definitions were absent"},
                 {"protocol_v1", "missing, invalid, reordered, or mismatched protocol metadata is an error; there is no fallback challenge"},
             },
             JsonObject{
                 {"correction_id", "raw_report_provenance_preserved"},
                 {"intentional", true},
                 {"legacy_oracle", "post-resolution settle tested only binned summed dx==0 and dy==0"},
                 {"protocol_v1", "settle decision retains summed-zero parity while authoritative data separately retains report_count and zero_delta_report_count, distinguishing no report, explicit zero reports, and cancelling multiple reports"},
             },
         }},
        {"schema", "abcurves.scientific_corrections.v1"},
    };
    return json::DumpCanonical(document, false);
}

std::string ScientificCorrectionsSha256() {
    static const std::string digest = Sha256Text(CanonicalScientificCorrectionsJson());
    return digest;
}

std::string CanonicalProtocolJson() {
    JsonArray challenges;
    challenges.reserve(ChallengeDefinitionsV1().size());
    for (const ChallengeDefinition& definition : ChallengeDefinitionsV1()) {
        challenges.emplace_back(JsonObject{
            {"challenge_id", definition.challenge_id},
            {"challenge_version", definition.challenge_version},
            {"display_name", definition.display_name},
            {"duration_ms", definition.duration_ms},
            {"mechanics", MechanicsJson(definition.pattern)},
            {"pattern", PatternName(definition.pattern)},
            {"repeat_count", definition.repeat_count},
            {"task_type", definition.task_type},
        });
    }

    JsonArray blocks;
    blocks.reserve(OrderedBlocksV1().size());
    for (const BlockDefinition& block : OrderedBlocksV1()) {
        blocks.emplace_back(JsonObject{
            {"block_id", block.block_id},
            {"challenge_id", block.challenge_id},
            {"challenge_version", block.challenge_version},
            {"display_name", block.display_name},
            {"duration_ms", block.duration_ms},
            {"ordinal", ToJsonInteger(block.ordinal, "block ordinal")},
            {"pattern", PatternName(block.pattern)},
            {"repeat_count", block.repeat_count},
            {"repeat_index", block.repeat_index},
            {"task_type", block.task_type},
        });
    }

    TargetBehavior common_behavior{};
    const json::Value document = JsonObject{
        {"blocks", std::move(blocks)},
        {"challenges", std::move(challenges)},
        {"global",
         JsonObject{
             {"countdown_ms", V1Constants::countdown_ms},
             {"default_behavior", BehaviorJson(common_behavior)},
             {"dwell_quiet_movement_sum_threshold_counts", V1Constants::dwell_quiet_movement_sum_threshold_counts},
             {"dwell_quiet_window_ms", V1Constants::dwell_quiet_window_ms},
             {"minimum_useful_spawn_ms", V1Constants::minimum_useful_spawn_ms},
             {"no_target_timeout_ms", V1Constants::no_target_timeout_ms},
             {"fading_target_grace_ms",
              V1Constants::fading_target_grace_ms},
             {"quick_test_block_duration_ms",
              V1Constants::quick_test_block_duration_ms},
             {"spawn_cutoff_rule", "spawn if and only if challenge_remaining_ms >= 250"},
             {"target_generation",
              JsonObject{
                  {"base_radians_per_count", V1Constants::target_generation_radians_per_count},
                   {"count_scale_formula", "1 / trainer_sensitivity"},
                   {"effective_radians_per_count_formula", "base_radians_per_count * trainer_sensitivity"},
                  {"radius_tier_scales",
                   JsonObject{{"big", V1Constants::big_radius_scale},
                              {"medium", V1Constants::medium_radius_scale},
                              {"small", V1Constants::small_radius_scale}}},
                   {"sensitivity_maximum", V1Constants::maximum_trainer_sensitivity},
                   {"sensitivity_minimum", V1Constants::minimum_trainer_sensitivity},
                   {"spawn_margin_counts_formula", "max(1, round(5 / trainer_sensitivity))"},
                  {"visibility_half_view_radians", V1Constants::pi * 0.5},
                  {"visibility_margin", V1Constants::visibility_margin},
              }},
         }},
        {"mechanics_oracle", "AIM TRAINER audited challenge schedule with locked sensitivity count-space calibration"},
        {"name", "abcurves_data_collection_protocol_v2"},
        {"protocol_version", V1Constants::protocol_version},
        {"resolution",
         JsonObject{
             {"active_target_at_block_boundary", "resolve challenge_end_timeout, retain nonhit tail, then end block"},
             {"challenge_end_timeout_ends_challenge", true},
             {"hit_resolutions", JsonArray{"hit", "dwell_hit"}},
             {"nonhit_resolutions", JsonArray{"miss_click", "timeout", "challenge_end_timeout"}},
             {"post_resolution_settle", "summed_dx==0 and summed_dy==0 parity; report provenance remains separate"},
             {"target_row_state", "pre-tick"},
         }},
        {"rng",
         JsonObject{
             {"algorithm", "SplitMix64"},
             {"checkpoint_invariant", "state == seed + draws*0x9e3779b97f4a7c15 modulo 2^64"},
             {"integer_mapping", "inclusive bounds with 64-bit rejection threshold (-width)%width"},
             {"seed", "required persisted uint64; never synthesized from time"},
             {"transition_increment_hex", "9e3779b97f4a7c15"},
             {"uniform_double_mapping", "high 53 output bits times 2^-53, interval [0,1)"},
         }},
        {"schema", "abcurves.protocol.v2"},
        {"scientific_corrections_schema", "abcurves.scientific_corrections.v1"},
        {"scientific_corrections_sha256", ScientificCorrectionsSha256()},
    };
    return json::DumpCanonical(document, false);
}

std::string ProtocolSha256() {
    static const std::string digest = Sha256Text(CanonicalProtocolJson());
    return digest;
}

std::string SerializeRealizedTargetJson(const RealizedTarget& target) {
    if (target.protocol_hash != ProtocolSha256() || !IsLowerHexDigest(target.protocol_hash)) {
        throw ProtocolError("realized target has missing or mismatched protocol hash");
    }
    if (target.block_ordinal >= OrderedBlocksV1().size()) {
        throw ProtocolError("realized target block ordinal is invalid");
    }
    const BlockDefinition& block = OrderedBlocksV1()[target.block_ordinal];
    if (target.challenge_id != block.challenge_id || target.task_type != block.task_type) {
        throw ProtocolError("realized target challenge metadata does not match its block");
    }
    const auto calibration_context = CalibrationContext(target);
    if (!CalibrationMatches(calibration_context)) {
        throw ProtocolError("realized target sensitivity/count-space calibration is inconsistent");
    }
    if (target.event_id < 0 || target.event_start_tick < 0 || target.generation_attempt == 0 ||
        target.rng_draw_end <= target.rng_draw_begin || target.timeout_ms <= 0 ||
        target.dwell_required_ms < 0 || !target.visible || target.visibility_adjusted ||
        target.challenge_remaining_ms < V1Constants::minimum_useful_spawn_ms ||
        target.challenge_remaining_ms > block.duration_ms ||
        !std::isfinite(target.relative_x_counts) || !std::isfinite(target.relative_y_counts) ||
        !std::isfinite(target.target_x_counts) || !std::isfinite(target.target_y_counts) ||
        !std::isfinite(target.radius_counts) || !std::isfinite(target.initial_distance_counts) ||
        target.radius_counts < 1.0 || target.radius_counts != std::round(target.radius_counts)) {
        throw ProtocolError("realized target contains invalid provenance, geometry, or timing");
    }
    if (target.target_x_counts != static_cast<double>(target.start_crosshair_x) + target.relative_x_counts ||
        target.target_y_counts != static_cast<double>(target.start_crosshair_y) + target.relative_y_counts ||
        std::abs(target.initial_distance_counts -
                 Distance(target.relative_x_counts, target.relative_y_counts)) > 1.0e-9) {
        throw ProtocolError("realized target geometry is internally inconsistent");
    }
    ValidateBehavior(target.behavior, "realized target");
    ValidateRealizedScenario(target, block);

    const json::Value document = JsonObject{
        {"behavior", BehaviorJson(target.behavior)},
        {"block_ordinal", ToJsonInteger(target.block_ordinal, "block ordinal")},
        {"challenge_id", target.challenge_id},
        {"challenge_remaining_ms", target.challenge_remaining_ms},
        {"dwell_required_ms", target.dwell_required_ms},
        {"event_id", target.event_id},
        {"event_start_tick", target.event_start_tick},
        {"effective_radians_per_count", target.target_generation_radians_per_count},
        {"generation_attempt", ToJsonInteger(target.generation_attempt, "generation attempt")},
        {"initial_distance_counts", target.initial_distance_counts},
        {"persisted_seed_u64", std::to_string(target.persisted_seed)},
        {"protocol_sha256", target.protocol_hash},
        {"radius_counts", target.radius_counts},
        {"relative_x_counts", target.relative_x_counts},
        {"relative_y_counts", target.relative_y_counts},
        {"rng_draw_begin_u64", std::to_string(target.rng_draw_begin)},
        {"rng_draw_end_u64", std::to_string(target.rng_draw_end)},
        {"role", TargetRoleName(target.role)},
        {"schema", "abcurves.realized_target.v3"},
        {"spawn_margin_counts", target.spawn_margin_counts},
        {"start_crosshair_x", target.start_crosshair_x},
        {"start_crosshair_y", target.start_crosshair_y},
        {"target_ordinal_in_block", ToJsonInteger(target.target_ordinal_in_block, "target ordinal")},
        {"target_count_scale", target.target_count_scale},
        {"target_x_counts", target.target_x_counts},
        {"target_y_counts", target.target_y_counts},
        {"task_type", target.task_type},
        {"timeout_ms", target.timeout_ms},
        {"trainer_sensitivity", target.trainer_sensitivity},
        {"visibility_adjusted", target.visibility_adjusted},
        {"visible", target.visible},
    };
    return json::DumpCanonical(document, false);
}

RealizedTarget ParseRealizedTargetJson(const std::string_view text) {
    const auto document = json::Parse(text);
    const auto parse_u64 = [](const json::Value& value, const char* const label) {
        try {
            const auto& encoded = value.AsString();
            std::size_t used = 0;
            const auto result = std::stoull(encoded, &used);
            if (used != encoded.size()) throw ProtocolError(std::string("invalid ") + label);
            return static_cast<std::uint64_t>(result);
        } catch (const ProtocolError&) {
            throw;
        } catch (...) {
            throw ProtocolError(std::string("invalid ") + label);
        }
    };
    const auto parse_size = [](const json::Value& value, const char* const label) {
        const auto encoded = value.AsInt();
        if (encoded < 0 || static_cast<std::uint64_t>(encoded) >
                               static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            throw ProtocolError(std::string("invalid ") + label);
        }
        return static_cast<std::size_t>(encoded);
    };
    const auto parse_tail = [](const json::Value& value) {
        TailConfig tail;
        tail.minimum_ms = static_cast<int>(value.At("minimum_ms").AsInt());
        tail.settle_required_ms = static_cast<int>(value.At("settle_required_ms").AsInt());
        tail.maximum_ms = static_cast<int>(value.At("maximum_ms").AsInt());
        return tail;
    };

    if (document.At("schema").AsString() != "abcurves.realized_target.v3") {
        throw ProtocolError("realized-target schema mismatch");
    }
    RealizedTarget target;
    target.protocol_hash = document.At("protocol_sha256").AsString();
    target.persisted_seed = parse_u64(document.At("persisted_seed_u64"), "persisted seed");
    target.rng_draw_begin = parse_u64(document.At("rng_draw_begin_u64"), "RNG draw begin");
    target.rng_draw_end = parse_u64(document.At("rng_draw_end_u64"), "RNG draw end");
    target.generation_attempt = parse_size(document.At("generation_attempt"), "generation attempt");
    target.block_ordinal = parse_size(document.At("block_ordinal"), "block ordinal");
    target.target_ordinal_in_block =
        parse_size(document.At("target_ordinal_in_block"), "target ordinal");
    target.event_id = document.At("event_id").AsInt();
    target.challenge_id = document.At("challenge_id").AsString();
    target.task_type = document.At("task_type").AsString();
    const auto& role = document.At("role").AsString();
    if (role == "general") target.role = TargetRole::general;
    else if (role == "tickle_reset") target.role = TargetRole::tickle_reset;
    else if (role == "tickle_small") target.role = TargetRole::tickle_small;
    else throw ProtocolError("realized target role is invalid");
    target.start_crosshair_x = document.At("start_crosshair_x").AsInt();
    target.start_crosshair_y = document.At("start_crosshair_y").AsInt();
    target.event_start_tick = document.At("event_start_tick").AsInt();
    target.challenge_remaining_ms = document.At("challenge_remaining_ms").AsInt();
    target.trainer_sensitivity = document.At("trainer_sensitivity").AsDouble();
    target.target_count_scale = document.At("target_count_scale").AsDouble();
    target.target_generation_radians_per_count =
        document.At("effective_radians_per_count").AsDouble();
    const auto encoded_spawn_margin = document.At("spawn_margin_counts").AsInt();
    if (encoded_spawn_margin < 1 ||
        encoded_spawn_margin > std::numeric_limits<int>::max()) {
        throw ProtocolError("realized target spawn margin is outside its integer range");
    }
    target.spawn_margin_counts = static_cast<int>(encoded_spawn_margin);
    target.relative_x_counts = document.At("relative_x_counts").AsDouble();
    target.relative_y_counts = document.At("relative_y_counts").AsDouble();
    target.target_x_counts = document.At("target_x_counts").AsDouble();
    target.target_y_counts = document.At("target_y_counts").AsDouble();
    target.radius_counts = document.At("radius_counts").AsDouble();
    target.initial_distance_counts = document.At("initial_distance_counts").AsDouble();
    target.timeout_ms = static_cast<int>(document.At("timeout_ms").AsInt());
    target.dwell_required_ms = static_cast<int>(document.At("dwell_required_ms").AsInt());
    target.visible = document.At("visible").AsBool();
    target.visibility_adjusted = document.At("visibility_adjusted").AsBool();

    const auto& behavior = document.At("behavior");
    target.behavior.miss_click_ends = behavior.At("miss_click_ends").AsBool();
    target.behavior.fade_total_ms = static_cast<int>(behavior.At("fade_total_ms").AsInt());
    target.behavior.hit_inter_target_delay_ms =
        static_cast<int>(behavior.At("hit_inter_target_delay_ms").AsInt());
    target.behavior.miss_inter_target_delay_ms =
        static_cast<int>(behavior.At("miss_inter_target_delay_ms").AsInt());
    target.behavior.timeout_inter_target_delay_ms =
        static_cast<int>(behavior.At("timeout_inter_target_delay_ms").AsInt());
    target.behavior.hit_tail = parse_tail(behavior.At("hit_tail"));
    target.behavior.nonhit_tail = parse_tail(behavior.At("nonhit_tail"));

    const auto regenerated = SerializeRealizedTargetJson(target);
    if (json::DumpCanonical(document, false) != regenerated) {
        throw ProtocolError("realized-target evidence has unknown, missing, or noncanonical fields");
    }
    return target;
}

void ValidateProtocolV1() {
    const auto& definitions = ChallengeDefinitionsV1();
    const auto& blocks = OrderedBlocksV1();
    if (definitions.size() != 10 || blocks.size() != 21) {
        throw ProtocolError("protocol v1 must contain exactly 10 definitions and 21 blocks");
    }

    const std::array<const char*, 10> expected_ids{
        "default_static",
        "chain_links",
        "tickle_fast",
        "accuracy",
        "precision_big",
        "precision_small",
        "dwell_control",
        "overshoot_recovery",
        "micro_adjustments",
        "fast_flicker",
    };
    const std::array<int, 10> expected_repeats{3, 2, 3, 3, 1, 2, 2, 2, 1, 2};
    std::set<std::string> ids;
    std::size_t expected_ordinal = 0;
    for (std::size_t index = 0; index < definitions.size(); ++index) {
        const ChallengeDefinition& definition = definitions[index];
        if (definition.challenge_id != expected_ids[index] ||
            definition.repeat_count != expected_repeats[index] ||
            definition.duration_ms != V1Constants::block_duration_ms ||
            definition.challenge_version != V1Constants::protocol_version ||
            definition.display_name.empty() || definition.task_type.empty() ||
            !ids.insert(definition.challenge_id).second) {
            throw ProtocolError("invalid or reordered protocol-v1 challenge definition");
        }
        for (int repeat = 0; repeat < definition.repeat_count; ++repeat) {
            if (expected_ordinal >= blocks.size()) {
                throw ProtocolError("protocol-v1 block expansion is truncated");
            }
            const BlockDefinition& block = blocks[expected_ordinal];
            const std::string expected_block_id =
                definition.challenge_id + "_r" + std::to_string(repeat + 1);
            if (block.ordinal != expected_ordinal || block.block_id != expected_block_id ||
                block.challenge_id != definition.challenge_id ||
                block.display_name != definition.display_name ||
                block.task_type != definition.task_type || block.pattern != definition.pattern ||
                block.repeat_index != repeat || block.repeat_count != definition.repeat_count ||
                block.duration_ms != definition.duration_ms ||
                block.challenge_version != definition.challenge_version) {
                throw ProtocolError("invalid protocol-v1 expanded block metadata");
            }
            ++expected_ordinal;
        }
    }
    if (expected_ordinal != blocks.size()) {
        throw ProtocolError("protocol-v1 block expansion contains unexpected trailing blocks");
    }

    TargetBehavior common_behavior{};
    ValidateBehavior(common_behavior, "common");
    if (common_behavior.hit_tail != TailConfig{160, 60, 350} ||
        common_behavior.nonhit_tail != TailConfig{120, 60, 220}) {
        throw ProtocolError("protocol-v1 common tails do not match the audited oracle");
    }
    if (!CanSpawnTargetV1(250) || CanSpawnTargetV1(249)) {
        throw ProtocolError("protocol-v1 spawn cutoff is invalid");
    }

    const std::string corrections = CanonicalScientificCorrectionsJson();
    const json::Value parsed_corrections = json::Parse(corrections);
    if (json::DumpCanonical(parsed_corrections, false) != corrections ||
        !IsLowerHexDigest(ScientificCorrectionsSha256())) {
        throw ProtocolError("scientific corrections document is not canonical or hashable");
    }
    const std::string protocol = CanonicalProtocolJson();
    const json::Value parsed_protocol = json::Parse(protocol);
    if (json::DumpCanonical(parsed_protocol, false) != protocol || !IsLowerHexDigest(ProtocolSha256())) {
        throw ProtocolError("protocol-v1 document is not canonical or hashable");
    }
}

}  // namespace abdc::protocol
