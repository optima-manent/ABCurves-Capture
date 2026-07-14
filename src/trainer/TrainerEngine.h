#pragma once

#include "protocol/protocol_v1.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <vector>

namespace abdc::trainer {

// The trainer domain deliberately speaks only in QPC values and raw mouse
// counts. Platform code owns Raw Input registration, rendering, and capture.
struct CountPosition final {
    std::int64_t x = 0;
    std::int64_t y = 0;
    bool operator==(const CountPosition&) const = default;
};

struct RawInputPacket final {
    std::int64_t qpc = 0;
    std::int64_t dx_counts = 0;
    std::int64_t dy_counts = 0;
    bool left_button_down = false;
    bool left_button_up = false;
};

enum class EngineState {
    idle,
    countdown,
    awaiting_presentation,
    event_active,
    event_tail,
    inter_target_delay,
    paused,
    complete,
};

enum class CountdownKind {
    none,
    block_start,
    resume,
};

enum class NaturalOutcome {
    none,
    hit_click,
    hit_dwell,
    miss_click,
    timeout,
    challenge_end_timeout,
};

enum class TechnicalOutcome {
    none,
    manual_pause,
    focus_lost,
    display_changed,
    graphics_device_lost,
    system_suspend,
    gameplay_input_unavailable,
};

struct ClickHypothesis final {
    std::int64_t qpc = 0;
    CountPosition pre_delta_position{};
    CountPosition post_delta_position{};
    bool pre_delta_inside = false;
    bool post_delta_inside = false;
    bool order_ambiguous = false;
    bool resolved_event = false;
};

struct TrainerEvent final {
    std::int64_t event_id = -1;
    std::size_t block_ordinal = 0;
    std::size_t target_ordinal_in_block = 0;
    protocol::RealizedTarget realized_target{};

    // Presentation is a real boundary, not a stillness test. The generator
    // camera and presentation camera can legitimately differ when the mouse
    // moved while the renderer was preparing the first frame.
    CountPosition generation_camera{};
    CountPosition presentation_camera{};
    CountPosition final_camera{};
    std::int64_t target_generated_qpc = 0;
    std::optional<std::int64_t> first_presented_qpc;
    std::optional<std::int64_t> event_start_qpc;
    std::optional<std::int64_t> natural_resolution_qpc;
    std::optional<std::int64_t> technical_interruption_qpc;
    std::optional<std::int64_t> tail_end_qpc;

    double target_x_counts = 0.0;
    double target_y_counts = 0.0;
    double target_radius_counts = 0.0;
    double initial_distance_counts = 0.0;
    double closest_point_distance_counts = 0.0;
    double closest_swept_distance_counts = 0.0;
    double inside_total_ms = 0.0;
    double maximum_consecutive_inside_ms = 0.0;

    NaturalOutcome natural_outcome = NaturalOutcome::none;
    TechnicalOutcome technical_outcome = TechnicalOutcome::none;
    bool presentation_interrupted = false;
    bool tail_interrupted = false;
    int tail_minimum_ms = 0;
    int tail_settle_required_ms = 0;
    int tail_maximum_ms = 0;
    double observed_tail_ms = 0.0;
    bool scored = false;
    int score_after_event = 0;
    std::vector<ClickHypothesis> click_hypotheses;
};

struct BlockResult final {
    std::size_t ordinal = 0;
    std::string block_id;
    std::string challenge_id;
    std::int64_t countdown_started_qpc = 0;
    std::optional<std::int64_t> gameplay_started_qpc;
    std::optional<std::int64_t> completed_qpc;
    int configured_duration_ms = protocol::V1Constants::block_duration_ms;
    double consumed_gameplay_ms = 0.0;
    int score = 0;
    std::size_t event_count = 0;
    std::size_t technical_event_count = 0;
};

struct TargetView final {
    std::int64_t event_id = -1;
    double absolute_x_counts = 0.0;
    double absolute_y_counts = 0.0;
    double relative_x_counts = 0.0;
    double relative_y_counts = 0.0;
    double radius_counts = 0.0;
    int dwell_required_ms = 0;
    int timeout_ms = 0;
    // Presentation-only strength. Fading targets move continuously from 1 to
    // 0 over their grace-extended playable lifetime; non-fading and pending
    // targets remain fully visible.
    float visual_strength = 1.0F;
    bool presentation_required = false;
};

struct TrainerConfig final {
    std::int64_t qpc_frequency = 10'000'000;
    std::uint64_t scenario_seed = 0;
    double trainer_sensitivity = 1.0;
    int block_duration_ms = protocol::V1Constants::block_duration_ms;
    CountPosition initial_camera{};

    // Empty selects all 21 canonical blocks. A custom, strictly increasing
    // subset is useful for quick-test builds and deterministic unit tests.
    std::vector<std::size_t> block_ordinals;
};

class TrainerEngine final {
public:
    static constexpr int kCountdownMs = 5'000;

    explicit TrainerEngine(TrainerConfig config);

    void Start(std::int64_t qpc);
    void AdvanceTo(std::int64_t qpc);
    void SubmitRawInput(const RawInputPacket& packet);

    // Returns false if there is no generated target awaiting its first
    // successful presentation. No camera-stillness condition is consulted.
    [[nodiscard]] bool AcknowledgeTargetPresented(std::int64_t first_presented_qpc);

    void Pause(std::int64_t qpc);
    // Records the precise recoverable interruption on an in-flight event.
    // The caller remains responsible for resuming after its subsystem is
    // healthy again.
    void PauseForTechnicalInterruption(TechnicalOutcome outcome,
                                       std::int64_t qpc);
    void Resume(std::int64_t qpc);
    // Focus restoration automatically starts the normal resume countdown when
    // focus loss was what paused the engine.
    void SetFocused(bool focused, std::int64_t qpc);

    [[nodiscard]] EngineState state() const noexcept { return state_; }
    [[nodiscard]] CountdownKind countdown_kind() const noexcept { return countdown_kind_; }
    [[nodiscard]] bool focused() const noexcept { return focused_; }
    [[nodiscard]] std::int64_t now_qpc() const noexcept { return now_qpc_; }
    [[nodiscard]] CountPosition camera() const noexcept { return camera_; }
    [[nodiscard]] int current_score() const noexcept;
    [[nodiscard]] std::size_t current_plan_index() const noexcept { return plan_index_; }
    [[nodiscard]] const std::vector<std::size_t>& planned_block_ordinals() const noexcept {
        return block_ordinals_;
    }
    [[nodiscard]] const protocol::BlockDefinition* current_block() const noexcept;
    [[nodiscard]] std::int64_t countdown_remaining_ms() const noexcept;
    [[nodiscard]] std::int64_t block_remaining_ms() const noexcept;
    [[nodiscard]] const protocol::RealizedTarget* pending_target() const noexcept;
    [[nodiscard]] std::optional<TargetView> target_view() const noexcept;
    [[nodiscard]] const TrainerEvent* current_event() const noexcept;
    [[nodiscard]] const std::vector<TrainerEvent>& events() const noexcept { return events_; }
    [[nodiscard]] const std::vector<BlockResult>& block_results() const noexcept {
        return block_results_;
    }

private:
    struct PendingTarget final {
        protocol::RealizedTarget target;
        CountPosition generation_camera{};
        std::int64_t generated_qpc = 0;
    };

    struct MovementSample final {
        std::int64_t qpc = 0;
        std::int64_t magnitude = 0;
    };

    struct ActiveEvent final {
        TrainerEvent record;
        protocol::ResolutionPlan resolution_plan{};
        std::optional<std::int64_t> inside_since_qpc;
        std::int64_t inside_accumulated_ticks = 0;
        std::int64_t maximum_inside_streak_ticks = 0;
        std::deque<MovementSample> dwell_movements;
        std::int64_t tail_last_nonquiet_qpc = 0;
    };

    TrainerConfig config_;
    protocol::TargetGeneratorV1 generator_;
    protocol::CountSpaceCalibration calibration_{};
    std::vector<std::size_t> block_ordinals_;
    std::vector<TrainerEvent> events_;
    std::vector<BlockResult> block_results_;
    std::optional<PendingTarget> pending_;
    std::optional<ActiveEvent> active_;

    EngineState state_ = EngineState::idle;
    CountdownKind countdown_kind_ = CountdownKind::none;
    TechnicalOutcome pause_reason_ = TechnicalOutcome::none;
    bool focused_ = true;
    std::int64_t now_qpc_ = 0;
    std::int64_t countdown_deadline_qpc_ = 0;
    std::int64_t block_duration_ticks_ = 0;
    std::int64_t block_remaining_ticks_ = 0;
    std::int64_t inter_target_deadline_qpc_ = 0;
    CountPosition camera_{};
    std::size_t plan_index_ = 0;
    std::int64_t next_event_id_ = 0;

    [[nodiscard]] std::int64_t TicksFromMilliseconds(std::int64_t milliseconds) const;
    [[nodiscard]] double MillisecondsFromTicks(std::int64_t ticks) const noexcept;
    [[nodiscard]] std::int64_t CeilMillisecondsFromTicks(std::int64_t ticks) const noexcept;
    [[nodiscard]] bool StateConsumesBlockTime() const noexcept;
    [[nodiscard]] std::optional<std::int64_t> NextDeadline() const;
    [[nodiscard]] std::optional<std::int64_t> NextDwellCompletionQpc() const;
    void MoveClockTo(std::int64_t qpc);
    void ProcessDeadline();

    void StartBlockCountdown(std::int64_t qpc);
    void StartResumeCountdown(std::int64_t qpc);
    void FinishCountdown();
    void PrepareTarget();
    void CompleteBlock(std::int64_t qpc);
    void ResolveNatural(NaturalOutcome outcome,
                        protocol::Resolution resolution,
                        std::int64_t qpc);
    void FinalizeNaturalTail(std::int64_t qpc);
    void FinalizeActiveForTechnicalInterruption(TechnicalOutcome outcome,
                                                std::int64_t qpc);
    void FinalizePendingForTechnicalInterruption(TechnicalOutcome outcome,
                                                 std::int64_t qpc);
    void StoreFinalizedEvent(TrainerEvent event);
    void PauseInternal(TechnicalOutcome outcome, std::int64_t qpc);

    [[nodiscard]] bool InsideTarget(CountPosition position) const noexcept;
    void UpdateActiveGeometry(CountPosition pre,
                              CountPosition post,
                              std::int64_t qpc,
                              std::int64_t movement_magnitude);
    void CloseInsideInterval(ActiveEvent& event, std::int64_t qpc);
    void PopulateFinalMetrics(ActiveEvent& event, std::int64_t qpc);
};

[[nodiscard]] std::string NaturalOutcomeName(NaturalOutcome outcome);
[[nodiscard]] std::string TechnicalOutcomeName(TechnicalOutcome outcome);

}  // namespace abdc::trainer
