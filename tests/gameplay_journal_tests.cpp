#include "TestHarness.h"

#include "protocol/protocol_v1.hpp"
#include "session/GameplayJournal.h"

#include <chrono>
#include <cmath>
#include <filesystem>
#include <string>

namespace {

std::filesystem::path TempGameplayDirectory() {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
        ("abcurves_gameplay_journal_" + std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

abdc::session::GameplayJournalIdentity Identity(const double sensitivity) {
    return {"s-gameplay-test", "u-gameplay-test", 1'000, sensitivity};
}

abdc::session::RenderEvidence Render() {
    return {1'920, 1'080, 2.0, 1.25, 0.5, 0.8, "linear-countspace-v1"};
}

abdc::trainer::TrainerConfig OneBlock(const double sensitivity = 1.0) {
    abdc::trainer::TrainerConfig config;
    config.qpc_frequency = 1'000;
    config.scenario_seed = 0x1234'5678ULL;
    config.trainer_sensitivity = sensitivity;
    config.block_duration_ms = 1'000;
    config.block_ordinals = {0};
    return config;
}

void ReachPresentedTarget(abdc::trainer::TrainerEngine& engine) {
    engine.Start(0);
    engine.AdvanceTo(abdc::trainer::TrainerEngine::kCountdownMs);
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'000));
}

abdc::trainer::RawInputPacket ClickAtTarget(
    const abdc::trainer::TrainerEngine& engine,
    const std::int64_t qpc) {
    const auto target = engine.target_view();
    EXPECT_TRUE(target.has_value());
    return {
        qpc,
        static_cast<std::int64_t>(std::llround(target->absolute_x_counts)) -
            engine.camera().x,
        static_cast<std::int64_t>(std::llround(target->absolute_y_counts)) -
            engine.camera().y,
        true,
        false,
    };
}

void ExpectEventsEquivalent(const abdc::trainer::TrainerEvent& actual,
                            const abdc::trainer::TrainerEvent& expected) {
    EXPECT_EQ(actual.event_id, expected.event_id);
    EXPECT_EQ(actual.block_ordinal, expected.block_ordinal);
    EXPECT_EQ(actual.target_ordinal_in_block, expected.target_ordinal_in_block);
    EXPECT_EQ(abdc::protocol::SerializeRealizedTargetJson(actual.realized_target),
              abdc::protocol::SerializeRealizedTargetJson(expected.realized_target));
    EXPECT_EQ(actual.generation_camera, expected.generation_camera);
    EXPECT_EQ(actual.presentation_camera, expected.presentation_camera);
    EXPECT_EQ(actual.final_camera, expected.final_camera);
    EXPECT_EQ(actual.target_generated_qpc, expected.target_generated_qpc);
    EXPECT_EQ(actual.first_presented_qpc, expected.first_presented_qpc);
    EXPECT_EQ(actual.event_start_qpc, expected.event_start_qpc);
    EXPECT_EQ(actual.natural_resolution_qpc, expected.natural_resolution_qpc);
    EXPECT_EQ(actual.technical_interruption_qpc, expected.technical_interruption_qpc);
    EXPECT_EQ(actual.tail_end_qpc, expected.tail_end_qpc);
    EXPECT_EQ(actual.target_x_counts, expected.target_x_counts);
    EXPECT_EQ(actual.target_y_counts, expected.target_y_counts);
    EXPECT_EQ(actual.target_radius_counts, expected.target_radius_counts);
    EXPECT_EQ(actual.initial_distance_counts, expected.initial_distance_counts);
    EXPECT_EQ(actual.closest_point_distance_counts,
              expected.closest_point_distance_counts);
    EXPECT_EQ(actual.closest_swept_distance_counts,
              expected.closest_swept_distance_counts);
    EXPECT_EQ(actual.inside_total_ms, expected.inside_total_ms);
    EXPECT_EQ(actual.maximum_consecutive_inside_ms,
              expected.maximum_consecutive_inside_ms);
    EXPECT_EQ(actual.natural_outcome, expected.natural_outcome);
    EXPECT_EQ(actual.technical_outcome, expected.technical_outcome);
    EXPECT_EQ(actual.presentation_interrupted, expected.presentation_interrupted);
    EXPECT_EQ(actual.tail_interrupted, expected.tail_interrupted);
    EXPECT_EQ(actual.tail_minimum_ms, expected.tail_minimum_ms);
    EXPECT_EQ(actual.tail_settle_required_ms, expected.tail_settle_required_ms);
    EXPECT_EQ(actual.tail_maximum_ms, expected.tail_maximum_ms);
    EXPECT_EQ(actual.observed_tail_ms, expected.observed_tail_ms);
    EXPECT_EQ(actual.scored, expected.scored);
    EXPECT_EQ(actual.score_after_event, expected.score_after_event);
    EXPECT_EQ(actual.click_hypotheses.size(), expected.click_hypotheses.size());
    for (std::size_t index = 0; index < actual.click_hypotheses.size(); ++index) {
        const auto& left = actual.click_hypotheses[index];
        const auto& right = expected.click_hypotheses[index];
        EXPECT_EQ(left.qpc, right.qpc);
        EXPECT_EQ(left.pre_delta_position, right.pre_delta_position);
        EXPECT_EQ(left.post_delta_position, right.post_delta_position);
        EXPECT_EQ(left.pre_delta_inside, right.pre_delta_inside);
        EXPECT_EQ(left.post_delta_inside, right.post_delta_inside);
        EXPECT_EQ(left.order_ambiguous, right.order_ambiguous);
        EXPECT_EQ(left.resolved_event, right.resolved_event);
    }
}

}  // namespace

TEST_CASE("gameplay journal round trips a focus-discarded event and independent annotations") {
    using namespace abdc::session;
    using abdc::trainer::NaturalOutcome;
    using abdc::trainer::TechnicalOutcome;

    const auto directory = TempGameplayDirectory();
    abdc::trainer::TrainerEngine engine(OneBlock(1.25));
    ReachPresentedTarget(engine);
    engine.SetFocused(false, 5'100);
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_EQ(engine.events()[0].natural_outcome, NaturalOutcome::none);
    EXPECT_EQ(engine.events()[0].technical_outcome, TechnicalOutcome::focus_lost);

    GameplayJournal journal(directory, Identity(1.25));
    EXPECT_EQ(journal.AppendPresentation(
                  {5'000, 0, true, Render(), "first_target_frame"}),
              std::uint64_t{0});
    EXPECT_EQ(journal.AppendEvent(engine.events()[0], Render()), std::uint64_t{0});
    EXPECT_EQ(journal.AppendBlockResult(engine.block_results()[0]), std::uint64_t{0});
    EXPECT_EQ(journal.AppendLifecycle(
                  {0, "session_started", std::size_t{0}, std::nullopt, "test"}),
              std::uint64_t{0});
    EXPECT_EQ(journal.AppendPause({5'100, true, "focus_lost", 0}),
              std::uint64_t{0});
    EXPECT_EQ(journal.AppendFocus({5'100, false, false, 0}), std::uint64_t{0});
    EXPECT_TRUE(journal.TryAppendRawInputWitness(
        {5'050, true, "ri-8a3f0c", 4, -2, 1U, 0}));
    EXPECT_TRUE(!journal.TryAppendRawInputWitness(
        {5'051, true, "privacy/unsafe/device/path", 1, 1, 0U, 0}));

    journal.Checkpoint();
    journal.Finalize();
    EXPECT_TRUE(journal.IsFinalized());
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        EXPECT_TRUE(entry.path().extension() != ".partial");
        EXPECT_TRUE(entry.path().filename().string().find(".partial") ==
                    std::string::npos);
    }

    const auto events = ReadGameplayEvents(directory / "events.jsonl");
    EXPECT_EQ(events.size(), std::size_t{1});
    EXPECT_EQ(events[0].identity, Identity(1.25));
    EXPECT_EQ(events[0].render, Render());
    ExpectEventsEquivalent(events[0].event, engine.events()[0]);

    const auto blocks = ReadGameplayBlockResults(directory / "blocks.jsonl");
    EXPECT_EQ(blocks.size(), std::size_t{1});
    EXPECT_EQ(blocks[0].block.ordinal, engine.block_results()[0].ordinal);
    EXPECT_EQ(blocks[0].block.event_count, std::size_t{1});
    EXPECT_EQ(blocks[0].block.technical_event_count, std::size_t{1});

    {
        AppendOnlyJsonlReader witness(
            directory / "raw_input_witness.jsonl",
            std::string(GameplayJournal::kRawInputWitnessSchema));
        const auto packet = witness.Next();
        EXPECT_TRUE(packet.has_value());
        EXPECT_TRUE(!packet->At("authoritative").AsBool());
        EXPECT_EQ(packet->At("authority").AsString(),
                  std::string("non_authoritative_windows_raw_input_witness"));
        EXPECT_EQ(packet->At("device_token").AsString(), std::string("ri-8a3f0c"));
        EXPECT_TRUE(!witness.Next().has_value());
    }
    {
        AppendOnlyJsonlReader focus(
            directory / "focus.jsonl", std::string(GameplayJournal::kFocusSchema));
        EXPECT_TRUE(!focus.Next()->At("focused").AsBool());
    }
    {
        AppendOnlyJsonlReader pauses(
            directory / "pauses.jsonl", std::string(GameplayJournal::kPauseSchema));
        EXPECT_EQ(pauses.Next()->At("reason").AsString(), std::string("focus_lost"));
    }
    {
        AppendOnlyJsonlReader presentation(
            directory / "presentation.jsonl",
            std::string(GameplayJournal::kPresentationSchema));
        EXPECT_TRUE(presentation.Next()->At("successful").AsBool());
    }

    std::filesystem::remove_all(directory);
}

TEST_CASE("gameplay journal preserves a natural result when its tail is interrupted") {
    using namespace abdc::session;
    using abdc::trainer::NaturalOutcome;
    using abdc::trainer::TechnicalOutcome;

    const auto directory = TempGameplayDirectory();
    abdc::trainer::TrainerEngine engine(OneBlock());
    ReachPresentedTarget(engine);
    engine.SubmitRawInput(ClickAtTarget(engine, 5'010));
    engine.SetFocused(false, 5'050);
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_EQ(engine.events()[0].natural_outcome, NaturalOutcome::hit_click);
    EXPECT_EQ(engine.events()[0].technical_outcome, TechnicalOutcome::focus_lost);
    EXPECT_TRUE(engine.events()[0].tail_interrupted);
    EXPECT_EQ(engine.events()[0].click_hypotheses.size(), std::size_t{1});

    GameplayJournal journal(directory, Identity(1.0));
    journal.AppendEvent(engine.events()[0], Render());
    journal.Finalize();

    const auto events = ReadGameplayEvents(directory / "events.jsonl");
    EXPECT_EQ(events.size(), std::size_t{1});
    ExpectEventsEquivalent(events[0].event, engine.events()[0]);
    EXPECT_EQ(events[0].event.natural_outcome, NaturalOutcome::hit_click);
    EXPECT_EQ(events[0].event.technical_outcome, TechnicalOutcome::focus_lost);
    EXPECT_TRUE(events[0].event.tail_interrupted);
    EXPECT_TRUE(events[0].event.tail_end_qpc.has_value());
    EXPECT_EQ(events[0].event.observed_tail_ms, 40.0);

    std::filesystem::remove_all(directory);
}

TEST_CASE("gameplay journal preserves generation and presentation distances after early motion") {
    using namespace abdc::session;

    const auto directory = TempGameplayDirectory();
    abdc::trainer::TrainerEngine engine(OneBlock());
    engine.Start(0);
    engine.AdvanceTo(abdc::trainer::TrainerEngine::kCountdownMs);
    EXPECT_TRUE(engine.pending_target() != nullptr);
    const auto generation_distance =
        engine.pending_target()->initial_distance_counts;
    const auto target_x = engine.pending_target()->target_x_counts;
    const auto target_y = engine.pending_target()->target_y_counts;

    // This is the exact production seam that failed: normal Raw Input arrived
    // after generation but before the first successful presentation frame.
    engine.SubmitRawInput({
        5'001,
        static_cast<std::int64_t>(std::llround(target_x)),
        static_cast<std::int64_t>(std::llround(target_y)),
        false,
        false,
    });
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(5'002));
    EXPECT_TRUE(std::abs(engine.current_event()->initial_distance_counts -
                         generation_distance) > 1.0e-6);
    engine.SubmitRawInput({5'003, 0, 0, true, false});
    engine.SetFocused(false, 5'050);
    EXPECT_EQ(engine.events().size(), std::size_t{1});

    GameplayJournal journal(directory, Identity(1.0));
    EXPECT_EQ(journal.AppendEvent(engine.events()[0], Render()),
              std::uint64_t{0});

    auto contradictory = engine.events()[0];
    contradictory.initial_distance_counts += 1.0;
    bool typed_validation_failure = false;
    try {
        (void)journal.AppendEvent(contradictory, Render());
    } catch (const GameplayRecordValidationError&) {
        typed_validation_failure = true;
    }
    EXPECT_TRUE(typed_validation_failure);
    journal.Finalize();

    const auto events = ReadGameplayEvents(directory / "events.jsonl");
    EXPECT_EQ(events.size(), std::size_t{1});
    EXPECT_EQ(events[0].event.realized_target.initial_distance_counts,
              generation_distance);
    EXPECT_EQ(events[0].event.initial_distance_counts,
              engine.events()[0].initial_distance_counts);
    EXPECT_EQ(events[0].event.presentation_camera,
              engine.events()[0].presentation_camera);
    std::filesystem::remove_all(directory);
}

TEST_CASE("gameplay journal validates scientific bounds without gating optional witness") {
    using namespace abdc::session;
    const auto directory = TempGameplayDirectory();
    GameplayJournal journal(directory, Identity(1.0));

    auto invalid_render = Render();
    invalid_render.counts_per_pixel_x = 0.25;
    PresentationAnnotation invalid_presentation{
        10, 0, true, invalid_render, "bad_inverse"};
    EXPECT_THROW(journal.AppendPresentation(invalid_presentation));
    EXPECT_TRUE(!journal.TryAppendRawInputWitness(
        {-1, true, "ri-valid-token", 0, 0, 0U, 0}));

    journal.Finalize();
    EXPECT_TRUE(std::filesystem::exists(directory / "events.jsonl"));
    EXPECT_TRUE(std::filesystem::exists(directory / "raw_input_witness.jsonl"));
    std::filesystem::remove_all(directory);
}
