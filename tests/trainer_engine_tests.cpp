#include "TestHarness.h"

#include "trainer/TrainerEngine.h"

#include <cmath>
#include <cstdint>
#include <set>
#include <vector>

namespace {

using abdc::trainer::CountdownKind;
using abdc::trainer::EngineState;
using abdc::trainer::NaturalOutcome;
using abdc::trainer::RawInputPacket;
using abdc::trainer::TechnicalOutcome;
using abdc::trainer::TrainerConfig;
using abdc::trainer::TrainerEngine;

TrainerConfig OneBlock(const std::size_t ordinal,
                       const int duration_ms = 1'000,
                       const std::uint64_t seed = 0x1234'5678ULL) {
    TrainerConfig config;
    config.qpc_frequency = 1'000;
    config.scenario_seed = seed;
    config.block_duration_ms = duration_ms;
    config.block_ordinals = {ordinal};
    return config;
}

void ReachFirstTarget(TrainerEngine& engine, const std::int64_t start_qpc = 0) {
    engine.Start(start_qpc);
    engine.AdvanceTo(start_qpc + TrainerEngine::kCountdownMs);
    EXPECT_EQ(engine.state(), EngineState::awaiting_presentation);
    EXPECT_TRUE(engine.pending_target() != nullptr);
}

RawInputPacket ClickAtTarget(const TrainerEngine& engine,
                             const std::int64_t qpc) {
    const auto view = engine.target_view();
    EXPECT_TRUE(view.has_value());
    return RawInputPacket{
        qpc,
        static_cast<std::int64_t>(std::llround(view->absolute_x_counts)) -
            engine.camera().x,
        static_cast<std::int64_t>(std::llround(view->absolute_y_counts)) -
            engine.camera().y,
        true,
        false,
    };
}

}  // namespace

TEST_CASE("trainer defaults preserve ten modes and twenty-one canonical blocks") {
    TrainerConfig config;
    config.qpc_frequency = 1'000;
    TrainerEngine engine(config);

    EXPECT_EQ(engine.planned_block_ordinals().size(), std::size_t{21});
    std::set<std::string> challenge_ids;
    for (const auto ordinal : engine.planned_block_ordinals()) {
        challenge_ids.insert(abdc::protocol::OrderedBlocksV1()[ordinal].challenge_id);
    }
    EXPECT_EQ(challenge_ids.size(), std::size_t{10});

    engine.Start(100);
    EXPECT_EQ(engine.state(), EngineState::countdown);
    EXPECT_EQ(engine.countdown_kind(), CountdownKind::block_start);
    EXPECT_EQ(engine.countdown_remaining_ms(), std::int64_t{5'000});
    EXPECT_EQ(engine.block_remaining_ms(), std::int64_t{60'000});
    engine.AdvanceTo(5'099);
    EXPECT_EQ(engine.state(), EngineState::countdown);
    engine.AdvanceTo(5'100);
    EXPECT_EQ(engine.state(), EngineState::awaiting_presentation);
}

TEST_CASE("presentation starts the event without a stillness guard") {
    TrainerEngine engine(OneBlock(0));
    ReachFirstTarget(engine);
    const auto generated_x = engine.pending_target()->target_x_counts;
    const auto generated_y = engine.pending_target()->target_y_counts;
    const auto generation_distance =
        engine.pending_target()->initial_distance_counts;

    engine.SubmitRawInput({6'000, 13, -7, false, false});
    EXPECT_EQ(engine.state(), EngineState::awaiting_presentation);
    EXPECT_EQ(engine.camera().x, std::int64_t{13});
    EXPECT_EQ(engine.camera().y, std::int64_t{-7});
    EXPECT_EQ(engine.block_remaining_ms(), std::int64_t{1'000});
    EXPECT_TRUE(engine.pending_target() != nullptr);
    EXPECT_TRUE(engine.pending_target()->target_x_counts == generated_x);
    EXPECT_TRUE(engine.pending_target()->target_y_counts == generated_y);

    EXPECT_TRUE(engine.AcknowledgeTargetPresented(7'000));
    EXPECT_EQ(engine.state(), EngineState::event_active);
    EXPECT_TRUE(engine.current_event() != nullptr);
    EXPECT_EQ(engine.current_event()->generation_camera.x, std::int64_t{0});
    EXPECT_EQ(engine.current_event()->presentation_camera.x, std::int64_t{13});
    const auto expected_presentation_distance = std::hypot(
        generated_x - 13.0, generated_y + 7.0);
    EXPECT_TRUE(std::abs(engine.current_event()->initial_distance_counts -
                         expected_presentation_distance) < 1.0e-9);
    EXPECT_EQ(engine.current_event()->realized_target.initial_distance_counts,
              generation_distance);
    EXPECT_EQ(*engine.current_event()->event_start_qpc, std::int64_t{7'000});
    EXPECT_EQ(engine.block_remaining_ms(), std::int64_t{1'000});
}

TEST_CASE("click hypotheses resolve hits and score the current block") {
    TrainerEngine engine(OneBlock(0, 2'000));
    ReachFirstTarget(engine);
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));

    engine.SubmitRawInput(ClickAtTarget(engine, 5'010));
    EXPECT_EQ(engine.state(), EngineState::event_tail);
    EXPECT_EQ(engine.current_score(), 1);
    EXPECT_TRUE(engine.current_event() != nullptr);
    EXPECT_EQ(engine.current_event()->natural_outcome, NaturalOutcome::hit_click);
    EXPECT_EQ(engine.current_event()->click_hypotheses.size(), std::size_t{1});
    EXPECT_TRUE(!engine.current_event()->click_hypotheses[0].pre_delta_inside);
    EXPECT_TRUE(engine.current_event()->click_hypotheses[0].post_delta_inside);
    EXPECT_TRUE(engine.current_event()->click_hypotheses[0].order_ambiguous);

    engine.AdvanceTo(5'170);
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_EQ(engine.events()[0].natural_outcome, NaturalOutcome::hit_click);
    EXPECT_TRUE(engine.events()[0].scored);
    EXPECT_EQ(engine.events()[0].score_after_event, 1);
    EXPECT_EQ(*engine.events()[0].natural_resolution_qpc, std::int64_t{5'010});
    EXPECT_EQ(*engine.events()[0].tail_end_qpc, std::int64_t{5'170});
    EXPECT_EQ(engine.state(), EngineState::inter_target_delay);
}

TEST_CASE("miss click timeout and challenge end remain distinct natural outcomes") {
    {
        TrainerEngine engine(OneBlock(8));  // accuracy: miss click ends the event
        ReachFirstTarget(engine);
        EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));
        engine.SubmitRawInput({5'001, 0, 0, true, false});
        EXPECT_EQ(engine.state(), EngineState::event_tail);
        EXPECT_EQ(engine.current_event()->natural_outcome, NaturalOutcome::miss_click);
        EXPECT_EQ(engine.current_score(), 0);
    }

    {
        TrainerEngine engine(OneBlock(11));  // precision_big: 400 ms fade + 60 ms grace
        ReachFirstTarget(engine);
        EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));
        EXPECT_EQ(engine.pending_target(), nullptr);
        engine.AdvanceTo(5'459);
        EXPECT_EQ(engine.state(), EngineState::event_active);
        engine.AdvanceTo(5'460);
        EXPECT_EQ(engine.state(), EngineState::event_tail);
        EXPECT_EQ(engine.current_event()->natural_outcome, NaturalOutcome::timeout);
    }

    {
        TrainerEngine engine(OneBlock(0, 300));
        ReachFirstTarget(engine);
        EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));
        engine.AdvanceTo(5'300);
        EXPECT_EQ(engine.state(), EngineState::event_tail);
        EXPECT_EQ(engine.current_event()->natural_outcome,
                  NaturalOutcome::challenge_end_timeout);
        engine.AdvanceTo(5'420);
        EXPECT_EQ(engine.state(), EngineState::complete);
        EXPECT_EQ(engine.events().size(), std::size_t{1});
        EXPECT_TRUE(engine.block_results()[0].completed_qpc.has_value());
        EXPECT_TRUE(std::abs(engine.block_results()[0].consumed_gameplay_ms - 300.0) < 0.001);
    }
}

TEST_CASE("every fading target receives the playable sixty millisecond grace") {
    struct FadeCase {
        std::size_t block_ordinal;
        int expected_lifetime_ms;
    };
    constexpr FadeCase cases[] = {
        {5U, 330},   // tickle reset: 270 + 60
        {11U, 460},  // precision big: 400 + 60
        {12U, 510},  // precision small: 450 + 60
        {19U, 510},  // fast flicker: 450 + 60
    };

    for (const auto& test : cases) {
        TrainerEngine engine(OneBlock(test.block_ordinal));
        ReachFirstTarget(engine);
        EXPECT_EQ(engine.pending_target()->timeout_ms,
                  test.expected_lifetime_ms);
        EXPECT_EQ(engine.pending_target()->behavior.fade_total_ms,
                  test.expected_lifetime_ms);
    }
}

TEST_CASE("fading target strength decreases continuously through its playable lifetime") {
    TrainerEngine engine(OneBlock(11));
    ReachFirstTarget(engine);
    EXPECT_EQ(engine.target_view()->visual_strength, 1.0F);
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));

    engine.AdvanceTo(5'230);
    const auto halfway = engine.target_view();
    EXPECT_TRUE(halfway.has_value());
    EXPECT_TRUE(std::abs(halfway->visual_strength - 0.5F) < 0.0001F);

    engine.AdvanceTo(5'459);
    const auto final_playable_millisecond = engine.target_view();
    EXPECT_TRUE(final_playable_millisecond.has_value());
    EXPECT_TRUE(final_playable_millisecond->visual_strength > 0.0F);

    engine.AdvanceTo(5'460);
    EXPECT_EQ(engine.state(), EngineState::event_tail);
    EXPECT_TRUE(!engine.target_view().has_value());
}

TEST_CASE("dwell requires continuous contact followed by the quiet window") {
    TrainerEngine engine(OneBlock(14, 1'000));  // first dwell_control block
    ReachFirstTarget(engine);
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));
    const auto dwell_required = engine.current_event()->realized_target.dwell_required_ms;
    EXPECT_TRUE(dwell_required >= 90 && dwell_required <= 130);

    auto enter = ClickAtTarget(engine, 5'001);
    enter.left_button_down = false;
    engine.SubmitRawInput(enter);
    engine.AdvanceTo(5'001 + dwell_required +
                     abdc::protocol::V1Constants::dwell_quiet_window_ms - 1);
    EXPECT_EQ(engine.state(), EngineState::event_active);
    engine.AdvanceTo(5'001 + dwell_required +
                     abdc::protocol::V1Constants::dwell_quiet_window_ms);
    EXPECT_EQ(engine.state(), EngineState::event_tail);
    EXPECT_EQ(engine.current_event()->natural_outcome, NaturalOutcome::hit_dwell);
    EXPECT_EQ(engine.current_score(), 1);
}

TEST_CASE("focus loss affects only the current event and freezes block time") {
    TrainerEngine engine(OneBlock(0));
    ReachFirstTarget(engine);
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));
    engine.SetFocused(false, 5'100);

    EXPECT_EQ(engine.state(), EngineState::paused);
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_EQ(engine.events()[0].natural_outcome, NaturalOutcome::none);
    EXPECT_EQ(engine.events()[0].technical_outcome, TechnicalOutcome::focus_lost);
    EXPECT_TRUE(!engine.events()[0].tail_interrupted);
    EXPECT_EQ(engine.block_remaining_ms(), std::int64_t{900});

    engine.AdvanceTo(20'000);
    EXPECT_EQ(engine.block_remaining_ms(), std::int64_t{900});
    engine.SetFocused(true, 20'000);
    EXPECT_EQ(engine.state(), EngineState::countdown);
    EXPECT_EQ(engine.countdown_kind(), CountdownKind::resume);
    engine.AdvanceTo(24'999);
    EXPECT_EQ(engine.state(), EngineState::countdown);
    EXPECT_EQ(engine.block_remaining_ms(), std::int64_t{900});
    engine.AdvanceTo(25'000);
    EXPECT_EQ(engine.state(), EngineState::awaiting_presentation);

    engine.SubmitRawInput({25'010, 4, 2, false, false});
    EXPECT_EQ(engine.state(), EngineState::awaiting_presentation);
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(25'020));
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_EQ(engine.events()[0].technical_outcome, TechnicalOutcome::focus_lost);
}

TEST_CASE("focus loss during a resolved tail preserves its natural result") {
    TrainerEngine engine(OneBlock(0));
    ReachFirstTarget(engine);
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));
    engine.SubmitRawInput(ClickAtTarget(engine, 5'010));
    EXPECT_EQ(engine.current_score(), 1);

    engine.SetFocused(false, 5'050);
    EXPECT_EQ(engine.state(), EngineState::paused);
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_EQ(engine.events()[0].natural_outcome, NaturalOutcome::hit_click);
    EXPECT_EQ(engine.events()[0].technical_outcome, TechnicalOutcome::focus_lost);
    EXPECT_TRUE(engine.events()[0].tail_interrupted);
    EXPECT_TRUE(std::abs(engine.events()[0].observed_tail_ms - 40.0) < 0.001);
    EXPECT_EQ(engine.events()[0].score_after_event, 1);
    EXPECT_EQ(engine.current_score(), 1);
}

TEST_CASE("manual pause can retire an unpresented target without spending block time") {
    TrainerEngine engine(OneBlock(0));
    ReachFirstTarget(engine);
    engine.SubmitRawInput({5'050, 8, -3, false, false});
    engine.Pause(5'100);

    EXPECT_EQ(engine.state(), EngineState::paused);
    EXPECT_EQ(engine.block_remaining_ms(), std::int64_t{1'000});
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_TRUE(engine.events()[0].presentation_interrupted);
    EXPECT_TRUE(!engine.events()[0].first_presented_qpc.has_value());
    EXPECT_TRUE(!engine.events()[0].event_start_qpc.has_value());
    EXPECT_EQ(engine.events()[0].technical_outcome, TechnicalOutcome::manual_pause);

    engine.Resume(6'000);
    EXPECT_EQ(engine.countdown_kind(), CountdownKind::resume);
    engine.AdvanceTo(11'000);
    EXPECT_EQ(engine.state(), EngineState::awaiting_presentation);
    EXPECT_TRUE(engine.pending_target() != nullptr);
    EXPECT_EQ(engine.pending_target()->event_id, std::int64_t{1});
    EXPECT_EQ(engine.block_remaining_ms(), std::int64_t{1'000});
}

TEST_CASE("pausing between targets never rewrites the completed event") {
    TrainerEngine engine(OneBlock(0, 2'000));
    ReachFirstTarget(engine);
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));
    engine.SubmitRawInput(ClickAtTarget(engine, 5'010));
    engine.AdvanceTo(5'170);
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_EQ(engine.events()[0].technical_outcome, TechnicalOutcome::none);

    engine.Pause(5'200);
    EXPECT_EQ(engine.state(), EngineState::paused);
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_EQ(engine.events()[0].natural_outcome, NaturalOutcome::hit_click);
    EXPECT_EQ(engine.events()[0].technical_outcome, TechnicalOutcome::none);
    EXPECT_TRUE(!engine.events()[0].tail_interrupted);
}
