#include "trainer/TrainerEngine.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <utility>

namespace abdc::trainer {
namespace {

[[nodiscard]] std::int64_t CheckedAdd(const std::int64_t left,
                                      const std::int64_t right,
                                      const char* const label) {
    if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
        throw std::overflow_error(label);
    }
    return left + right;
}

[[nodiscard]] std::int64_t SaturatingMagnitude(const std::int64_t x,
                                               const std::int64_t y) noexcept {
    const auto magnitude = [](const std::int64_t value) -> std::uint64_t {
        if (value >= 0) return static_cast<std::uint64_t>(value);
        return static_cast<std::uint64_t>(-(value + 1)) + 1U;
    };
    const auto x_magnitude = magnitude(x);
    const auto y_magnitude = magnitude(y);
    const auto maximum = static_cast<std::uint64_t>(
        std::numeric_limits<std::int64_t>::max());
    if (x_magnitude > maximum || y_magnitude > maximum - x_magnitude) {
        return std::numeric_limits<std::int64_t>::max();
    }
    return static_cast<std::int64_t>(x_magnitude + y_magnitude);
}

[[nodiscard]] double CenterDistance(const CountPosition position,
                                    const double target_x,
                                    const double target_y) noexcept {
    const long double dx = static_cast<long double>(position.x) - target_x;
    const long double dy = static_cast<long double>(position.y) - target_y;
    return static_cast<double>(std::hypotl(dx, dy));
}

[[nodiscard]] bool IsInside(const CountPosition position,
                            const double target_x,
                            const double target_y,
                            const double radius) noexcept {
    return CenterDistance(position, target_x, target_y) <= radius;
}

[[nodiscard]] double SweptCenterDistance(const CountPosition start,
                                         const CountPosition end,
                                         const double target_x,
                                         const double target_y) noexcept {
    const long double start_x = static_cast<long double>(start.x);
    const long double start_y = static_cast<long double>(start.y);
    const long double vx = static_cast<long double>(end.x) - start_x;
    const long double vy = static_cast<long double>(end.y) - start_y;
    const long double length_squared = vx * vx + vy * vy;
    if (length_squared == 0.0L) {
        return CenterDistance(start, target_x, target_y);
    }
    const long double target_delta_x = static_cast<long double>(target_x) - start_x;
    const long double target_delta_y = static_cast<long double>(target_y) - start_y;
    const long double projection = std::clamp(
        (target_delta_x * vx + target_delta_y * vy) / length_squared,
        0.0L, 1.0L);
    const long double closest_x = start_x + projection * vx;
    const long double closest_y = start_y + projection * vy;
    return static_cast<double>(std::hypotl(
        closest_x - static_cast<long double>(target_x),
        closest_y - static_cast<long double>(target_y)));
}

}  // namespace

TrainerEngine::TrainerEngine(TrainerConfig config)
    : config_(std::move(config)),
      generator_(config_.scenario_seed),
      calibration_(protocol::CountSpaceCalibrationForSensitivity(
          config_.trainer_sensitivity)),
      camera_(config_.initial_camera) {
    if (config_.qpc_frequency <= 0 ||
        config_.block_duration_ms < protocol::V1Constants::minimum_useful_spawn_ms ||
        config_.block_duration_ms > protocol::V1Constants::block_duration_ms) {
        throw std::invalid_argument("trainer configuration is outside the protocol limits");
    }
    block_duration_ticks_ = TicksFromMilliseconds(config_.block_duration_ms);
    if (block_duration_ticks_ <= 0) {
        throw std::invalid_argument("trainer block duration is not representable in QPC ticks");
    }

    block_ordinals_ = config_.block_ordinals;
    if (block_ordinals_.empty()) {
        block_ordinals_.reserve(protocol::OrderedBlocksV1().size());
        for (std::size_t ordinal = 0; ordinal < protocol::OrderedBlocksV1().size(); ++ordinal) {
            block_ordinals_.push_back(ordinal);
        }
    }
    for (std::size_t index = 0; index < block_ordinals_.size(); ++index) {
        if (block_ordinals_[index] >= protocol::OrderedBlocksV1().size() ||
            (index != 0 && block_ordinals_[index - 1] >= block_ordinals_[index])) {
            throw std::invalid_argument(
                "trainer block plan must be a strictly increasing canonical subset");
        }
    }
}

std::int64_t TrainerEngine::TicksFromMilliseconds(
    const std::int64_t milliseconds) const {
    if (milliseconds < 0) {
        throw std::invalid_argument("negative duration cannot be converted to QPC ticks");
    }
    const auto seconds = milliseconds / 1'000;
    const auto remainder_ms = milliseconds % 1'000;
    if (seconds != 0 &&
        config_.qpc_frequency > std::numeric_limits<std::int64_t>::max() / seconds) {
        throw std::overflow_error("QPC duration overflow");
    }
    const auto whole_ticks = seconds * config_.qpc_frequency;
    const auto frequency_quotient = config_.qpc_frequency / 1'000;
    const auto frequency_remainder = config_.qpc_frequency % 1'000;
    const auto remainder_ticks = remainder_ms * frequency_quotient +
        ((remainder_ms * frequency_remainder + 999) / 1'000);
    return CheckedAdd(whole_ticks, remainder_ticks, "QPC duration overflow");
}

double TrainerEngine::MillisecondsFromTicks(const std::int64_t ticks) const noexcept {
    if (ticks <= 0) return 0.0;
    return static_cast<double>(
        static_cast<long double>(ticks) * 1'000.0L /
        static_cast<long double>(config_.qpc_frequency));
}

std::int64_t TrainerEngine::CeilMillisecondsFromTicks(
    const std::int64_t ticks) const noexcept {
    if (ticks <= 0) return 0;
    const long double value =
        static_cast<long double>(ticks) * 1'000.0L /
        static_cast<long double>(config_.qpc_frequency);
    const long double rounded = std::ceil(value);
    if (rounded >= static_cast<long double>(std::numeric_limits<std::int64_t>::max())) {
        return std::numeric_limits<std::int64_t>::max();
    }
    return static_cast<std::int64_t>(rounded);
}

void TrainerEngine::Start(const std::int64_t qpc) {
    if (state_ != EngineState::idle || qpc < 0) {
        throw std::logic_error("trainer can start exactly once at a nonnegative QPC");
    }
    now_qpc_ = qpc;
    StartBlockCountdown(qpc);
}

void TrainerEngine::StartBlockCountdown(const std::int64_t qpc) {
    if (plan_index_ >= block_ordinals_.size()) {
        state_ = EngineState::complete;
        countdown_kind_ = CountdownKind::none;
        return;
    }

    const auto ordinal = block_ordinals_[plan_index_];
    while (generator_.expected_block_ordinal() < ordinal) {
        generator_.BeginBlock(generator_.expected_block_ordinal());
        generator_.EndBlock();
    }
    generator_.BeginBlock(ordinal);

    const auto& block = protocol::OrderedBlocksV1()[ordinal];
    BlockResult result;
    result.ordinal = ordinal;
    result.block_id = block.block_id;
    result.challenge_id = block.challenge_id;
    result.countdown_started_qpc = qpc;
    result.configured_duration_ms = config_.block_duration_ms;
    block_results_.push_back(std::move(result));

    block_remaining_ticks_ = block_duration_ticks_;
    inter_target_deadline_qpc_ = 0;
    countdown_kind_ = CountdownKind::block_start;
    countdown_deadline_qpc_ = CheckedAdd(
        qpc, TicksFromMilliseconds(kCountdownMs), "countdown QPC overflow");
    state_ = EngineState::countdown;
}

void TrainerEngine::StartResumeCountdown(const std::int64_t qpc) {
    if (state_ != EngineState::paused || !focused_) {
        throw std::logic_error("trainer cannot resume before focus is restored");
    }
    pause_reason_ = TechnicalOutcome::none;
    countdown_kind_ = CountdownKind::resume;
    countdown_deadline_qpc_ = CheckedAdd(
        qpc, TicksFromMilliseconds(kCountdownMs), "resume countdown QPC overflow");
    state_ = EngineState::countdown;
}

bool TrainerEngine::StateConsumesBlockTime() const noexcept {
    return state_ == EngineState::event_active ||
           state_ == EngineState::event_tail ||
           state_ == EngineState::inter_target_delay;
}

void TrainerEngine::MoveClockTo(const std::int64_t qpc) {
    if (qpc < now_qpc_) throw std::logic_error("QPC regressed");
    if (StateConsumesBlockTime()) {
        const auto elapsed = qpc - now_qpc_;
        block_remaining_ticks_ = std::max<std::int64_t>(
            0, block_remaining_ticks_ - std::min(elapsed, block_remaining_ticks_));
    }
    now_qpc_ = qpc;
}

std::optional<std::int64_t> TrainerEngine::NextDwellCompletionQpc() const {
    if (state_ != EngineState::event_active || !active_ ||
        active_->record.realized_target.dwell_required_ms <= 0 ||
        !active_->inside_since_qpc) {
        return std::nullopt;
    }

    const auto dwell_satisfied_qpc = CheckedAdd(
        *active_->inside_since_qpc,
        TicksFromMilliseconds(active_->record.realized_target.dwell_required_ms),
        "dwell QPC overflow");
    const auto quiet_ticks = TicksFromMilliseconds(
        protocol::V1Constants::dwell_quiet_window_ms);
    auto candidate = CheckedAdd(
        dwell_satisfied_qpc, quiet_ticks, "dwell quiet-window QPC overflow");

    // Only movement after dwell satisfaction belongs to the quiet window. If
    // the threshold is exceeded, advance to the first expiry that can make the
    // rolling sum eligible and then re-evaluate the shifted window.
    for (std::size_t iteration = 0;
         iteration <= active_->dwell_movements.size(); ++iteration) {
        const auto window_start = candidate - quiet_ticks;
        std::int64_t sum = 0;
        std::vector<const MovementSample*> contributing;
        for (const auto& sample : active_->dwell_movements) {
            if (sample.qpc <= dwell_satisfied_qpc || sample.qpc <= window_start ||
                sample.qpc > candidate) {
                continue;
            }
            contributing.push_back(&sample);
            if (sum > std::numeric_limits<std::int64_t>::max() - sample.magnitude) {
                sum = std::numeric_limits<std::int64_t>::max();
            } else {
                sum += sample.magnitude;
            }
        }
        if (sum <= protocol::V1Constants::dwell_quiet_movement_sum_threshold_counts) {
            return candidate;
        }

        bool advanced = false;
        for (const auto* sample : contributing) {
            sum = std::max<std::int64_t>(0, sum - sample->magnitude);
            if (sum <= protocol::V1Constants::dwell_quiet_movement_sum_threshold_counts) {
                const auto expiry = CheckedAdd(
                    sample->qpc, quiet_ticks, "dwell movement expiry QPC overflow");
                if (expiry > candidate) {
                    candidate = expiry;
                    advanced = true;
                }
                break;
            }
        }
        if (!advanced) return candidate;
    }
    return candidate;
}

std::optional<std::int64_t> TrainerEngine::NextDeadline() const {
    switch (state_) {
    case EngineState::countdown:
        return countdown_deadline_qpc_;

    case EngineState::event_active: {
        if (!active_ || !active_->record.event_start_qpc) {
            throw std::logic_error("active trainer event is incomplete");
        }
        auto deadline = CheckedAdd(
            now_qpc_, block_remaining_ticks_, "block boundary QPC overflow");
        const auto timeout = CheckedAdd(
            *active_->record.event_start_qpc,
            TicksFromMilliseconds(active_->record.realized_target.timeout_ms),
            "target timeout QPC overflow");
        deadline = std::min(deadline, timeout);
        if (const auto dwell = NextDwellCompletionQpc()) {
            deadline = std::min(deadline, *dwell);
        }
        return std::max(now_qpc_, deadline);
    }

    case EngineState::event_tail: {
        if (!active_ || !active_->record.natural_resolution_qpc) {
            throw std::logic_error("trainer tail lacks a natural resolution");
        }
        const auto resolution_qpc = *active_->record.natural_resolution_qpc;
        const auto minimum_complete = std::max(
            CheckedAdd(resolution_qpc,
                       TicksFromMilliseconds(active_->resolution_plan.tail.minimum_ms),
                       "tail minimum QPC overflow"),
            CheckedAdd(active_->tail_last_nonquiet_qpc,
                       TicksFromMilliseconds(
                           active_->resolution_plan.tail.settle_required_ms),
                       "tail settle QPC overflow"));
        const auto maximum_complete = CheckedAdd(
            resolution_qpc,
            TicksFromMilliseconds(active_->resolution_plan.tail.maximum_ms),
            "tail maximum QPC overflow");
        return std::max(now_qpc_, std::min(minimum_complete, maximum_complete));
    }

    case EngineState::inter_target_delay:
        return std::max(
            now_qpc_,
            std::min(inter_target_deadline_qpc_,
                     CheckedAdd(now_qpc_, block_remaining_ticks_,
                                "block boundary QPC overflow")));

    case EngineState::idle:
    case EngineState::awaiting_presentation:
    case EngineState::paused:
    case EngineState::complete:
        return std::nullopt;
    }
    throw std::logic_error("unknown trainer state");
}

void TrainerEngine::AdvanceTo(const std::int64_t qpc) {
    if (state_ == EngineState::idle) {
        throw std::logic_error("trainer must be started before advancing time");
    }
    if (qpc < now_qpc_) throw std::logic_error("QPC regressed");

    std::size_t transitions = 0;
    for (;;) {
        const auto deadline = NextDeadline();
        if (!deadline || *deadline > qpc) {
            MoveClockTo(qpc);
            return;
        }
        if (*deadline < now_qpc_) {
            throw std::logic_error("trainer produced a regressed deadline");
        }
        MoveClockTo(*deadline);
        const auto old_state = state_;
        const auto old_deadline = *deadline;
        ProcessDeadline();
        if (++transitions > 128U) {
            throw std::logic_error("trainer exceeded its immediate-transition limit");
        }
        const auto next = NextDeadline();
        if (state_ == old_state && next && *next == old_deadline) {
            throw std::logic_error("trainer deadline did not advance state");
        }
    }
}

void TrainerEngine::ProcessDeadline() {
    if (state_ == EngineState::countdown) {
        if (now_qpc_ < countdown_deadline_qpc_) return;
        FinishCountdown();
        return;
    }

    if (state_ == EngineState::event_active) {
        const auto dwell = NextDwellCompletionQpc();
        if (dwell && *dwell <= now_qpc_) {
            ResolveNatural(NaturalOutcome::hit_dwell,
                           protocol::Resolution::dwell_hit,
                           now_qpc_);
            return;
        }
        if (block_remaining_ticks_ == 0) {
            ResolveNatural(NaturalOutcome::challenge_end_timeout,
                           protocol::Resolution::challenge_end_timeout,
                           now_qpc_);
            return;
        }
        if (!active_ || !active_->record.event_start_qpc) {
            throw std::logic_error("target timeout lacks an active event");
        }
        const auto timeout_qpc = CheckedAdd(
            *active_->record.event_start_qpc,
            TicksFromMilliseconds(active_->record.realized_target.timeout_ms),
            "target timeout QPC overflow");
        if (now_qpc_ >= timeout_qpc) {
            ResolveNatural(NaturalOutcome::timeout,
                           protocol::Resolution::timeout,
                           now_qpc_);
        }
        return;
    }

    if (state_ == EngineState::event_tail) {
        const auto deadline = NextDeadline();
        if (deadline && *deadline <= now_qpc_) FinalizeNaturalTail(now_qpc_);
        return;
    }

    if (state_ == EngineState::inter_target_delay) {
        if (block_remaining_ticks_ == 0) {
            CompleteBlock(now_qpc_);
            return;
        }
        if (now_qpc_ >= inter_target_deadline_qpc_) {
            if (CeilMillisecondsFromTicks(block_remaining_ticks_) >=
                protocol::V1Constants::minimum_useful_spawn_ms) {
                PrepareTarget();
            } else {
                inter_target_deadline_qpc_ = CheckedAdd(
                    now_qpc_, block_remaining_ticks_,
                    "final block wait QPC overflow");
            }
        }
    }
}

void TrainerEngine::FinishCountdown() {
    if (state_ != EngineState::countdown) {
        throw std::logic_error("cannot finish a non-countdown state");
    }
    countdown_kind_ = CountdownKind::none;
    countdown_deadline_qpc_ = 0;
    if (!block_results_.empty() && !block_results_.back().gameplay_started_qpc) {
        block_results_.back().gameplay_started_qpc = now_qpc_;
    }
    if (CeilMillisecondsFromTicks(block_remaining_ticks_) >=
        protocol::V1Constants::minimum_useful_spawn_ms) {
        PrepareTarget();
    } else if (block_remaining_ticks_ == 0) {
        CompleteBlock(now_qpc_);
    } else {
        state_ = EngineState::inter_target_delay;
        inter_target_deadline_qpc_ = CheckedAdd(
            now_qpc_, block_remaining_ticks_, "final block wait QPC overflow");
    }
}

void TrainerEngine::PrepareTarget() {
    if (pending_ || active_ || plan_index_ >= block_ordinals_.size()) {
        throw std::logic_error("target cannot be prepared in the current lifecycle");
    }
    const auto remaining_ms = std::min<std::int64_t>(
        config_.block_duration_ms,
        CeilMillisecondsFromTicks(block_remaining_ticks_));
    if (!protocol::CanSpawnTargetV1(remaining_ms)) {
        throw std::logic_error("protocol forbids target spawn with the remaining block time");
    }

    protocol::GenerationContext context;
    context.event_id = next_event_id_;
    context.camera_x = camera_.x;
    context.camera_y = camera_.y;
    context.event_start_tick = std::max<std::int64_t>(
        0, static_cast<std::int64_t>(config_.block_duration_ms) - remaining_ms);
    context.challenge_remaining_ms = remaining_ms;
    context.trainer_sensitivity = calibration_.trainer_sensitivity;
    context.target_count_scale = calibration_.target_count_scale;
    context.target_generation_radians_per_count =
        calibration_.effective_radians_per_count;
    context.spawn_margin_counts = calibration_.spawn_margin_counts;

    PendingTarget pending;
    pending.generation_camera = camera_;
    pending.generated_qpc = now_qpc_;
    pending.target = generator_.Generate(context);
    pending_ = std::move(pending);
    inter_target_deadline_qpc_ = 0;
    state_ = EngineState::awaiting_presentation;
}

bool TrainerEngine::AcknowledgeTargetPresented(
    const std::int64_t first_presented_qpc) {
    AdvanceTo(first_presented_qpc);
    if (state_ != EngineState::awaiting_presentation || !pending_) return false;

    ActiveEvent active;
    active.record.event_id = pending_->target.event_id;
    active.record.block_ordinal = pending_->target.block_ordinal;
    active.record.target_ordinal_in_block = pending_->target.target_ordinal_in_block;
    active.record.realized_target = pending_->target;
    active.record.generation_camera = pending_->generation_camera;
    active.record.presentation_camera = camera_;
    active.record.final_camera = camera_;
    active.record.target_generated_qpc = pending_->generated_qpc;
    active.record.first_presented_qpc = first_presented_qpc;
    active.record.event_start_qpc = first_presented_qpc;
    active.record.target_x_counts = pending_->target.target_x_counts;
    active.record.target_y_counts = pending_->target.target_y_counts;
    active.record.target_radius_counts = pending_->target.radius_counts;
    active.record.initial_distance_counts = CenterDistance(
        camera_, pending_->target.target_x_counts, pending_->target.target_y_counts);
    active.record.closest_point_distance_counts = active.record.initial_distance_counts;
    active.record.closest_swept_distance_counts = active.record.initial_distance_counts;
    if (IsInside(camera_, active.record.target_x_counts,
                 active.record.target_y_counts,
                 active.record.target_radius_counts)) {
        active.inside_since_qpc = first_presented_qpc;
    }
    active_ = std::move(active);
    pending_.reset();
    state_ = EngineState::event_active;
    return true;
}

bool TrainerEngine::InsideTarget(const CountPosition position) const noexcept {
    if (!active_) return false;
    return IsInside(position,
                    active_->record.target_x_counts,
                    active_->record.target_y_counts,
                    active_->record.target_radius_counts);
}

void TrainerEngine::CloseInsideInterval(ActiveEvent& event,
                                        const std::int64_t qpc) {
    if (!event.inside_since_qpc) return;
    const auto duration = std::max<std::int64_t>(0, qpc - *event.inside_since_qpc);
    event.inside_accumulated_ticks = CheckedAdd(
        event.inside_accumulated_ticks, duration,
        "inside-target duration overflow");
    event.maximum_inside_streak_ticks = std::max(
        event.maximum_inside_streak_ticks, duration);
    event.inside_since_qpc.reset();
}

void TrainerEngine::UpdateActiveGeometry(const CountPosition pre,
                                         const CountPosition post,
                                         const std::int64_t qpc,
                                         const std::int64_t movement_magnitude) {
    if (state_ != EngineState::event_active || !active_) return;
    auto& active = *active_;
    const auto pre_distance = CenterDistance(
        pre, active.record.target_x_counts, active.record.target_y_counts);
    const auto post_distance = CenterDistance(
        post, active.record.target_x_counts, active.record.target_y_counts);
    active.record.closest_point_distance_counts = std::min(
        {active.record.closest_point_distance_counts, pre_distance, post_distance});
    active.record.closest_swept_distance_counts = std::min(
        active.record.closest_swept_distance_counts,
        SweptCenterDistance(pre, post,
                            active.record.target_x_counts,
                            active.record.target_y_counts));

    const bool was_inside = active.inside_since_qpc.has_value();
    const bool is_inside = InsideTarget(post);
    if (was_inside && !is_inside) {
        CloseInsideInterval(active, qpc);
        active.dwell_movements.clear();
    } else if (!was_inside && is_inside) {
        active.inside_since_qpc = qpc;
        active.dwell_movements.clear();
    } else if (was_inside && is_inside) {
        if (movement_magnitude != 0) {
            active.dwell_movements.push_back({qpc, movement_magnitude});
        }
    }
}

void TrainerEngine::SubmitRawInput(const RawInputPacket& packet) {
    AdvanceTo(packet.qpc);
    const CountPosition pre = camera_;
    const CountPosition post{
        CheckedAdd(pre.x, packet.dx_counts, "virtual camera X overflow"),
        CheckedAdd(pre.y, packet.dy_counts, "virtual camera Y overflow"),
    };

    const bool was_active = state_ == EngineState::event_active && active_.has_value();
    if (was_active) {
        UpdateActiveGeometry(pre, post, packet.qpc,
                             SaturatingMagnitude(packet.dx_counts,
                                                 packet.dy_counts));
    }
    if (state_ == EngineState::event_tail && active_ &&
        (packet.dx_counts != 0 || packet.dy_counts != 0)) {
        active_->tail_last_nonquiet_qpc = packet.qpc;
    }
    camera_ = post;

    if (!packet.left_button_down || state_ != EngineState::event_active || !active_) {
        return;
    }

    ClickHypothesis click;
    click.qpc = packet.qpc;
    click.pre_delta_position = pre;
    click.post_delta_position = post;
    click.pre_delta_inside = IsInside(
        pre, active_->record.target_x_counts, active_->record.target_y_counts,
        active_->record.target_radius_counts);
    click.post_delta_inside = IsInside(
        post, active_->record.target_x_counts, active_->record.target_y_counts,
        active_->record.target_radius_counts);
    click.order_ambiguous = click.pre_delta_inside != click.post_delta_inside;
    active_->record.click_hypotheses.push_back(click);

    if (active_->record.realized_target.dwell_required_ms > 0) return;
    if (click.pre_delta_inside || click.post_delta_inside) {
        active_->record.click_hypotheses.back().resolved_event = true;
        ResolveNatural(NaturalOutcome::hit_click, protocol::Resolution::hit, packet.qpc);
    } else if (active_->record.realized_target.behavior.miss_click_ends) {
        active_->record.click_hypotheses.back().resolved_event = true;
        ResolveNatural(NaturalOutcome::miss_click,
                       protocol::Resolution::miss_click,
                       packet.qpc);
    }
}

void TrainerEngine::ResolveNatural(const NaturalOutcome outcome,
                                   const protocol::Resolution resolution,
                                   const std::int64_t qpc) {
    if (state_ != EngineState::event_active || !active_ ||
        active_->record.natural_outcome != NaturalOutcome::none) {
        throw std::logic_error("trainer event cannot resolve naturally twice");
    }
    CloseInsideInterval(*active_, qpc);
    active_->resolution_plan = generator_.Resolve(resolution);
    active_->record.natural_outcome = outcome;
    active_->record.natural_resolution_qpc = qpc;
    active_->record.tail_minimum_ms = active_->resolution_plan.tail.minimum_ms;
    active_->record.tail_settle_required_ms =
        active_->resolution_plan.tail.settle_required_ms;
    active_->record.tail_maximum_ms = active_->resolution_plan.tail.maximum_ms;
    active_->record.scored = active_->resolution_plan.scored;
    if (active_->resolution_plan.scored) {
        ++block_results_.back().score;
    }
    active_->record.score_after_event = block_results_.back().score;
    active_->tail_last_nonquiet_qpc = qpc;
    state_ = EngineState::event_tail;
}

void TrainerEngine::PopulateFinalMetrics(ActiveEvent& event,
                                         const std::int64_t qpc) {
    CloseInsideInterval(event, qpc);
    event.record.final_camera = camera_;
    event.record.inside_total_ms =
        MillisecondsFromTicks(event.inside_accumulated_ticks);
    event.record.maximum_consecutive_inside_ms =
        MillisecondsFromTicks(event.maximum_inside_streak_ticks);
}

void TrainerEngine::StoreFinalizedEvent(TrainerEvent event) {
    if (event.event_id != next_event_id_ || block_results_.empty()) {
        throw std::logic_error("finalized trainer event is out of sequence");
    }
    ++block_results_.back().event_count;
    if (event.technical_outcome != TechnicalOutcome::none) {
        ++block_results_.back().technical_event_count;
    }
    events_.push_back(std::move(event));
    ++next_event_id_;
}

void TrainerEngine::FinalizeNaturalTail(const std::int64_t qpc) {
    if (state_ != EngineState::event_tail || !active_ ||
        !active_->record.natural_resolution_qpc) {
        throw std::logic_error("cannot finalize a missing natural tail");
    }
    PopulateFinalMetrics(*active_, qpc);
    active_->record.tail_end_qpc = qpc;
    active_->record.observed_tail_ms = MillisecondsFromTicks(
        qpc - *active_->record.natural_resolution_qpc);
    const bool ends_challenge = active_->resolution_plan.ends_challenge;
    const int inter_target_delay_ms = active_->resolution_plan.inter_target_delay_ms;
    auto record = std::move(active_->record);
    active_.reset();
    StoreFinalizedEvent(std::move(record));

    if (ends_challenge || block_remaining_ticks_ == 0) {
        CompleteBlock(qpc);
        return;
    }
    state_ = EngineState::inter_target_delay;
    inter_target_deadline_qpc_ = CheckedAdd(
        qpc, TicksFromMilliseconds(inter_target_delay_ms),
        "inter-target delay QPC overflow");
}

void TrainerEngine::FinalizePendingForTechnicalInterruption(
    const TechnicalOutcome outcome,
    const std::int64_t qpc) {
    if (state_ != EngineState::awaiting_presentation || !pending_) {
        throw std::logic_error("cannot interrupt a missing pending target");
    }
    generator_.AbortTechnical();
    TrainerEvent event;
    event.event_id = pending_->target.event_id;
    event.block_ordinal = pending_->target.block_ordinal;
    event.target_ordinal_in_block = pending_->target.target_ordinal_in_block;
    event.realized_target = pending_->target;
    event.generation_camera = pending_->generation_camera;
    event.presentation_camera = camera_;
    event.final_camera = camera_;
    event.target_generated_qpc = pending_->generated_qpc;
    event.technical_interruption_qpc = qpc;
    event.technical_outcome = outcome;
    event.presentation_interrupted = true;
    event.target_x_counts = pending_->target.target_x_counts;
    event.target_y_counts = pending_->target.target_y_counts;
    event.target_radius_counts = pending_->target.radius_counts;
    event.initial_distance_counts = CenterDistance(
        camera_, pending_->target.target_x_counts, pending_->target.target_y_counts);
    event.closest_point_distance_counts = event.initial_distance_counts;
    event.closest_swept_distance_counts = event.initial_distance_counts;
    event.score_after_event = block_results_.back().score;
    pending_.reset();
    StoreFinalizedEvent(std::move(event));
}

void TrainerEngine::FinalizeActiveForTechnicalInterruption(
    const TechnicalOutcome outcome,
    const std::int64_t qpc) {
    if ((state_ != EngineState::event_active && state_ != EngineState::event_tail) ||
        !active_) {
        throw std::logic_error("cannot interrupt a missing active event");
    }
    const bool interrupted_tail = state_ == EngineState::event_tail;
    if (!interrupted_tail) generator_.AbortTechnical();
    PopulateFinalMetrics(*active_, qpc);
    active_->record.technical_outcome = outcome;
    active_->record.technical_interruption_qpc = qpc;
    active_->record.tail_interrupted = interrupted_tail;
    active_->record.score_after_event = block_results_.back().score;
    if (interrupted_tail && active_->record.natural_resolution_qpc) {
        active_->record.tail_end_qpc = qpc;
        active_->record.observed_tail_ms = MillisecondsFromTicks(
            qpc - *active_->record.natural_resolution_qpc);
    }
    auto record = std::move(active_->record);
    active_.reset();
    StoreFinalizedEvent(std::move(record));
}

void TrainerEngine::PauseInternal(const TechnicalOutcome outcome,
                                  const std::int64_t qpc) {
    if (outcome == TechnicalOutcome::none) {
        throw std::logic_error("pause requires a technical reason");
    }
    if (state_ == EngineState::idle || state_ == EngineState::complete) return;
    if (state_ == EngineState::paused) return;

    if (state_ == EngineState::awaiting_presentation) {
        FinalizePendingForTechnicalInterruption(outcome, qpc);
    } else if (state_ == EngineState::event_active ||
               state_ == EngineState::event_tail) {
        FinalizeActiveForTechnicalInterruption(outcome, qpc);
    }
    state_ = EngineState::paused;
    countdown_kind_ = CountdownKind::none;
    countdown_deadline_qpc_ = 0;
    inter_target_deadline_qpc_ = 0;
    pause_reason_ = outcome;
}

void TrainerEngine::Pause(const std::int64_t qpc) {
    PauseForTechnicalInterruption(TechnicalOutcome::manual_pause, qpc);
}

void TrainerEngine::PauseForTechnicalInterruption(
    const TechnicalOutcome outcome, const std::int64_t qpc) {
    AdvanceTo(qpc);
    PauseInternal(outcome, qpc);
}

void TrainerEngine::Resume(const std::int64_t qpc) {
    AdvanceTo(qpc);
    StartResumeCountdown(qpc);
}

void TrainerEngine::SetFocused(const bool focused, const std::int64_t qpc) {
    AdvanceTo(qpc);
    if (focused_ == focused) return;
    focused_ = focused;
    if (!focused) {
        PauseInternal(TechnicalOutcome::focus_lost, qpc);
    } else if (state_ == EngineState::paused &&
               pause_reason_ == TechnicalOutcome::focus_lost) {
        StartResumeCountdown(qpc);
    }
}

void TrainerEngine::CompleteBlock(const std::int64_t qpc) {
    if (active_ || pending_ || block_results_.empty()) {
        throw std::logic_error("block cannot complete with a live target");
    }
    block_results_.back().consumed_gameplay_ms = MillisecondsFromTicks(
        block_duration_ticks_ - block_remaining_ticks_);
    block_results_.back().completed_qpc = qpc;
    block_remaining_ticks_ = 0;
    generator_.EndBlock();
    ++plan_index_;
    if (plan_index_ >= block_ordinals_.size()) {
        state_ = EngineState::complete;
        countdown_kind_ = CountdownKind::none;
        inter_target_deadline_qpc_ = 0;
        return;
    }
    StartBlockCountdown(qpc);
}

int TrainerEngine::current_score() const noexcept {
    if (state_ == EngineState::idle || state_ == EngineState::complete ||
        block_results_.empty()) {
        return 0;
    }
    return block_results_.back().score;
}

const protocol::BlockDefinition* TrainerEngine::current_block() const noexcept {
    if (plan_index_ >= block_ordinals_.size() || state_ == EngineState::idle ||
        state_ == EngineState::complete) {
        return nullptr;
    }
    return &protocol::OrderedBlocksV1()[block_ordinals_[plan_index_]];
}

std::int64_t TrainerEngine::countdown_remaining_ms() const noexcept {
    if (state_ != EngineState::countdown) return 0;
    return CeilMillisecondsFromTicks(
        std::max<std::int64_t>(0, countdown_deadline_qpc_ - now_qpc_));
}

std::int64_t TrainerEngine::block_remaining_ms() const noexcept {
    if (state_ == EngineState::idle || state_ == EngineState::complete) return 0;
    return CeilMillisecondsFromTicks(block_remaining_ticks_);
}

const protocol::RealizedTarget* TrainerEngine::pending_target() const noexcept {
    return pending_ ? &pending_->target : nullptr;
}

std::optional<TargetView> TrainerEngine::target_view() const noexcept {
    const protocol::RealizedTarget* target = nullptr;
    bool presentation_required = false;
    float visual_strength = 1.0F;
    if (state_ == EngineState::awaiting_presentation && pending_) {
        target = &pending_->target;
        presentation_required = true;
    } else if (state_ == EngineState::event_active && active_) {
        target = &active_->record.realized_target;
        if (target->behavior.fade_total_ms > 0 &&
            active_->record.event_start_qpc) {
            const double elapsed_ms = MillisecondsFromTicks(std::max<std::int64_t>(
                0, now_qpc_ - *active_->record.event_start_qpc));
            visual_strength = static_cast<float>(std::clamp(
                1.0 - elapsed_ms /
                    static_cast<double>(target->behavior.fade_total_ms),
                0.0, 1.0));
        }
    }
    if (target == nullptr) return std::nullopt;
    return TargetView{
        target->event_id,
        target->target_x_counts,
        target->target_y_counts,
        target->target_x_counts - static_cast<double>(camera_.x),
        target->target_y_counts - static_cast<double>(camera_.y),
        target->radius_counts,
        target->dwell_required_ms,
        target->timeout_ms,
        visual_strength,
        presentation_required,
    };
}

const TrainerEvent* TrainerEngine::current_event() const noexcept {
    return active_ ? &active_->record : nullptr;
}

std::string NaturalOutcomeName(const NaturalOutcome outcome) {
    switch (outcome) {
    case NaturalOutcome::none: return "none";
    case NaturalOutcome::hit_click: return "hit_click";
    case NaturalOutcome::hit_dwell: return "hit_dwell";
    case NaturalOutcome::miss_click: return "miss_click";
    case NaturalOutcome::timeout: return "timeout";
    case NaturalOutcome::challenge_end_timeout: return "challenge_end_timeout";
    }
    throw std::invalid_argument("unknown natural trainer outcome");
}

std::string TechnicalOutcomeName(const TechnicalOutcome outcome) {
    switch (outcome) {
    case TechnicalOutcome::none: return "none";
    case TechnicalOutcome::manual_pause: return "manual_pause";
    case TechnicalOutcome::focus_lost: return "focus_lost";
    case TechnicalOutcome::display_changed: return "display_changed";
    case TechnicalOutcome::graphics_device_lost: return "graphics_device_lost";
    case TechnicalOutcome::system_suspend: return "system_suspend";
    case TechnicalOutcome::gameplay_input_unavailable:
        return "gameplay_input_unavailable";
    }
    throw std::invalid_argument("unknown technical trainer outcome");
}

}  // namespace abdc::trainer
