#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace abdc::protocol {

class ProtocolError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct V1Constants final {
    // Version 3 retains the audited challenge schedule, RNG, and replayable
    // count-space calibration while extending fading targets by 60 ms and
    // recording the 10-second Quick Test block duration.
    static constexpr int protocol_version = 3;
    static constexpr int block_duration_ms = 60'000;
    static constexpr int quick_test_block_duration_ms = 10'000;
    static constexpr int countdown_ms = 5'000;
    static constexpr int minimum_useful_spawn_ms = 250;
    static constexpr int no_target_timeout_ms = 10 * 60 * 1'000;
    static constexpr int fading_target_grace_ms = 60;

    static constexpr double target_generation_radians_per_count = 0.00125;
    static constexpr double target_count_scale = 1.0;
    static constexpr int spawn_margin_counts = 5;
    static constexpr double visibility_margin = 0.92;
    static constexpr double pi = 3.14159265358979323846;
    static constexpr double minimum_trainer_sensitivity = 0.01;
    static constexpr double maximum_trainer_sensitivity = 3.0;

    static constexpr double small_radius_scale = 5.0;
    static constexpr double medium_radius_scale = small_radius_scale / 1.2;
    static constexpr double big_radius_scale = small_radius_scale / 2.0;

    static constexpr int dwell_quiet_window_ms = 40;
    static constexpr int dwell_quiet_movement_sum_threshold_counts = 2;
};

struct CountSpaceCalibration {
    double trainer_sensitivity = 1.0;
    double target_count_scale = V1Constants::target_count_scale;
    double effective_radians_per_count =
        V1Constants::target_generation_radians_per_count;
    int spawn_margin_counts = V1Constants::spawn_margin_counts;
};

// Raw USB deltas are never scaled. This calibration converts the protocol's
// sensitivity-1 geometry into raw hardware-count geometry, so target/event
// fields and downstream Planner target inputs use the same units as movement.
[[nodiscard]] CountSpaceCalibration CountSpaceCalibrationForSensitivity(
    double trainer_sensitivity);

enum class Pattern {
    default_static,
    chain_links,
    tickle_fast,
    accuracy,
    precision_big,
    precision_small,
    dwell_control,
    overshoot_recovery,
    micro_adjustments,
    fast_flicker,
};

enum class TargetRole {
    general,
    tickle_reset,
    tickle_small,
};

enum class Resolution {
    hit,
    dwell_hit,
    miss_click,
    timeout,
    challenge_end_timeout,
};

struct TailConfig {
    int minimum_ms = 160;
    int settle_required_ms = 60;
    int maximum_ms = 350;
    bool operator==(const TailConfig&) const = default;
};

struct TargetBehavior {
    bool miss_click_ends = false;
    int fade_total_ms = 0;
    int hit_inter_target_delay_ms = 300;
    int miss_inter_target_delay_ms = 500;
    int timeout_inter_target_delay_ms = 300;
    TailConfig hit_tail{};
    TailConfig nonhit_tail{120, 60, 220};
    bool operator==(const TargetBehavior&) const = default;
};

struct ChallengeDefinition {
    std::string challenge_id;
    std::string display_name;
    std::string task_type;
    Pattern pattern = Pattern::default_static;
    int repeat_count = 1;
    int duration_ms = V1Constants::block_duration_ms;
    int challenge_version = V1Constants::protocol_version;
};

struct BlockDefinition {
    std::size_t ordinal = 0;
    std::string block_id;
    std::string challenge_id;
    std::string display_name;
    std::string task_type;
    Pattern pattern = Pattern::default_static;
    int repeat_index = 0;  // zero-based
    int repeat_count = 1;
    int duration_ms = V1Constants::block_duration_ms;
    int challenge_version = V1Constants::protocol_version;
};

[[nodiscard]] const std::vector<ChallengeDefinition>& ChallengeDefinitionsV1();
[[nodiscard]] const std::vector<BlockDefinition>& OrderedBlocksV1();
// Non-research quick-test plan: the first canonical block for each challenge.
// Ordinals remain canonical so persisted events retain their audited identities.
[[nodiscard]] const std::vector<std::size_t>& QuickTestBlockOrdinalsV1();
[[nodiscard]] bool CanSpawnTargetV1(std::int64_t remaining_ms) noexcept;
void ValidateProtocolV1();

// SplitMix64 with the published reference transition/mixer. UniformDouble uses
// the high 53 output bits in [0,1); UniformInt uses unbiased rejection and an
// inclusive upper bound. Results do not depend on a standard-library RNG.
struct RngCheckpoint {
    std::uint64_t seed = 0;
    std::uint64_t state = 0;
    std::uint64_t draws = 0;
};

class PortableRng final {
public:
    explicit PortableRng(std::uint64_t persisted_seed) noexcept;
    explicit PortableRng(RngCheckpoint checkpoint);

    [[nodiscard]] std::uint64_t NextU64() noexcept;
    [[nodiscard]] double UniformDouble(double minimum, double maximum);
    [[nodiscard]] int UniformInt(int minimum, int maximum);
    [[nodiscard]] bool Chance(double probability);
    [[nodiscard]] RngCheckpoint checkpoint() const noexcept;
    [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }
    [[nodiscard]] std::uint64_t draws() const noexcept { return draws_; }

private:
    std::uint64_t seed_ = 0;
    std::uint64_t state_ = 0;
    std::uint64_t draws_ = 0;
};

struct GenerationContext {
    std::int64_t event_id = 0;
    std::int64_t camera_x = 0;
    std::int64_t camera_y = 0;
    std::int64_t event_start_tick = 0;
    std::int64_t challenge_remaining_ms = V1Constants::block_duration_ms;
    double trainer_sensitivity = 1.0;
    double target_generation_radians_per_count = V1Constants::target_generation_radians_per_count;
    double target_count_scale = V1Constants::target_count_scale;
    int spawn_margin_counts = V1Constants::spawn_margin_counts;
};

struct RealizedTarget {
    std::string protocol_hash;
    std::uint64_t persisted_seed = 0;
    std::uint64_t rng_draw_begin = 0;
    std::uint64_t rng_draw_end = 0;
    std::size_t generation_attempt = 0;  // one-based successful attempt

    std::size_t block_ordinal = 0;
    std::size_t target_ordinal_in_block = 0;
    std::int64_t event_id = 0;
    std::string challenge_id;
    std::string task_type;
    TargetRole role = TargetRole::general;

    std::int64_t start_crosshair_x = 0;
    std::int64_t start_crosshair_y = 0;
    std::int64_t event_start_tick = 0;
    std::int64_t challenge_remaining_ms = V1Constants::block_duration_ms;
    double trainer_sensitivity = 1.0;
    double target_count_scale = V1Constants::target_count_scale;
    double target_generation_radians_per_count =
        V1Constants::target_generation_radians_per_count;
    int spawn_margin_counts = V1Constants::spawn_margin_counts;
    double relative_x_counts = 0.0;
    double relative_y_counts = 0.0;
    double target_x_counts = 0.0;
    double target_y_counts = 0.0;
    double radius_counts = 1.0;
    double initial_distance_counts = 0.0;
    int timeout_ms = 0;
    int dwell_required_ms = 0;
    bool visible = true;
    bool visibility_adjusted = false;
    TargetBehavior behavior{};
};

struct ResolutionPlan {
    TailConfig tail{};
    int inter_target_delay_ms = 300;
    bool scored = false;
    bool ends_challenge = false;
};

// The authoritative archive retains these diagnostics independently. Protocol
// v1 settle parity intentionally consults only summed_dx/summed_dy.
struct SettleTickObservation {
    std::int64_t summed_dx = 0;
    std::int64_t summed_dy = 0;
    std::uint32_t report_count = 0;
    std::uint32_t zero_delta_report_count = 0;
};

[[nodiscard]] bool CountsAsV1ZeroSettleTick(const SettleTickObservation& tick) noexcept;

class TargetGeneratorV1 final {
public:
    explicit TargetGeneratorV1(std::uint64_t persisted_seed);
    explicit TargetGeneratorV1(RngCheckpoint checkpoint);

    void BeginBlock(std::size_t block_ordinal);
    [[nodiscard]] RealizedTarget Generate(const GenerationContext& context);
    [[nodiscard]] ResolutionPlan Resolve(Resolution resolution);
    void AbortTechnical();
    void RestartCurrentBlockAttemptAfterTechnicalFailure();
    void EndBlock();

    [[nodiscard]] const PortableRng& rng() const noexcept { return rng_; }
    [[nodiscard]] bool target_active() const noexcept { return target_active_; }
    [[nodiscard]] bool block_active() const noexcept { return block_active_; }
    [[nodiscard]] std::size_t expected_block_ordinal() const noexcept { return expected_block_ordinal_; }

private:
    [[nodiscard]] RealizedTarget BuildTarget(const GenerationContext& context);
    void ValidateContext(const GenerationContext& context) const;

    PortableRng rng_;
    bool block_active_ = false;
    bool target_active_ = false;
    bool block_end_pending_ = false;
    std::size_t expected_block_ordinal_ = 0;
    std::size_t current_block_ordinal_ = 0;
    std::size_t target_ordinal_in_block_ = 0;
    bool has_previous_target_ = false;
    double previous_target_x_ = 0.0;
    double previous_target_y_ = 0.0;
    bool tickle_next_small_ = false;
    RealizedTarget current_target_{};
};

[[nodiscard]] std::string PatternName(Pattern pattern);
[[nodiscard]] std::string TargetRoleName(TargetRole role);
[[nodiscard]] std::string CanonicalScientificCorrectionsJson();
[[nodiscard]] std::string ScientificCorrectionsSha256();
[[nodiscard]] std::string CanonicalProtocolJson();
[[nodiscard]] std::string ProtocolSha256();
[[nodiscard]] std::string SerializeRealizedTargetJson(const RealizedTarget& target);
[[nodiscard]] RealizedTarget ParseRealizedTargetJson(std::string_view text);

}  // namespace abdc::protocol
