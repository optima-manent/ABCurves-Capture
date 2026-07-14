#include "session/GameplayJournal.h"

#include "base/Json.h"
#include "protocol/protocol_v1.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace abdc::session {
namespace {

using JsonArray = json::Value::Array;
using JsonObject = json::Value::Object;

constexpr std::int64_t kMaximumPlausibleQpcFrequency = 1'000'000'000'000LL;
constexpr int kMaximumViewportDimension = 1'000'000;

[[nodiscard]] bool IsSafeIdentifier(const std::string_view value,
                                    const std::size_t maximum_length = 128U) {
    if (value.empty() || value.size() > maximum_length) return false;
    return std::all_of(value.begin(), value.end(), [](const char character) {
        const auto c = static_cast<unsigned char>(character);
        return (c >= static_cast<unsigned char>('a') &&
                c <= static_cast<unsigned char>('z')) ||
               (c >= static_cast<unsigned char>('A') &&
                c <= static_cast<unsigned char>('Z')) ||
               (c >= static_cast<unsigned char>('0') &&
                c <= static_cast<unsigned char>('9')) ||
               c == static_cast<unsigned char>('-') ||
               c == static_cast<unsigned char>('_') ||
               c == static_cast<unsigned char>('.');
    });
}

[[nodiscard]] bool IsSafeDetail(const std::string_view value) {
    return value.size() <= 2'048U && value.find('\0') == std::string_view::npos;
}

void ValidateIdentity(const GameplayJournalIdentity& identity) {
    if (!IsSafeIdentifier(identity.session_id) ||
        !IsSafeIdentifier(identity.user_id)) {
        throw std::invalid_argument("gameplay journal identity is invalid");
    }
    if (identity.qpc_frequency <= 0 ||
        identity.qpc_frequency > kMaximumPlausibleQpcFrequency) {
        throw std::invalid_argument("gameplay journal QPC frequency is invalid");
    }
    if (!std::isfinite(identity.trainer_sensitivity) ||
        identity.trainer_sensitivity < protocol::V1Constants::minimum_trainer_sensitivity ||
        identity.trainer_sensitivity > protocol::V1Constants::maximum_trainer_sensitivity) {
        throw std::invalid_argument("gameplay journal sensitivity is invalid");
    }
}

void ValidateRenderEvidence(const RenderEvidence& render) {
    if (render.viewport_width_px <= 0 ||
        render.viewport_width_px > kMaximumViewportDimension ||
        render.viewport_height_px <= 0 ||
        render.viewport_height_px > kMaximumViewportDimension ||
        !std::isfinite(render.pixels_per_count_x) ||
        !std::isfinite(render.pixels_per_count_y) ||
        !std::isfinite(render.counts_per_pixel_x) ||
        !std::isfinite(render.counts_per_pixel_y) ||
        render.pixels_per_count_x <= 0.0 ||
        render.pixels_per_count_y <= 0.0 ||
        render.counts_per_pixel_x <= 0.0 ||
        render.counts_per_pixel_y <= 0.0 ||
        !std::isfinite(render.effective_radians_per_count) ||
        render.effective_radians_per_count <= 0.0 ||
        !std::isfinite(render.crosshair_scale) ||
        render.crosshair_scale < 0.25 || render.crosshair_scale > 2.0 ||
        !IsSafeIdentifier(render.transform_revision)) {
        throw std::invalid_argument("render evidence is outside its valid bounds");
    }
    const auto reciprocal_matches = [](const double first, const double second) {
        const double product = first * second;
        return std::isfinite(product) &&
               std::abs(product - 1.0) <=
                   1.0e-9 * std::max(1.0, std::abs(product));
    };
    if (!reciprocal_matches(render.pixels_per_count_x, render.counts_per_pixel_x) ||
        !reciprocal_matches(render.pixels_per_count_y, render.counts_per_pixel_y)) {
        throw std::invalid_argument("render transform and inverse disagree");
    }
}

void ValidateQpc(const std::int64_t qpc, const char* const label) {
    if (qpc < 0) throw std::invalid_argument(std::string(label) + " QPC is negative");
}

void ValidateOptionalQpc(const std::optional<std::int64_t>& qpc,
                         const char* const label) {
    if (qpc) ValidateQpc(*qpc, label);
}

[[nodiscard]] std::int64_t EncodeSize(const std::size_t value,
                                      const char* const label) {
    if (value > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument(std::string(label) + " exceeds the JSON integer range");
    }
    return static_cast<std::int64_t>(value);
}

[[nodiscard]] std::size_t DecodeSize(const json::Value& value,
                                     const char* const label) {
    const auto encoded = value.AsInt();
    if (encoded < 0 || static_cast<std::uint64_t>(encoded) >
                           static_cast<std::uint64_t>(
                               std::numeric_limits<std::size_t>::max())) {
        throw std::runtime_error(std::string(label) + " is outside the size range");
    }
    return static_cast<std::size_t>(encoded);
}

[[nodiscard]] int DecodeInt(const json::Value& value, const char* const label) {
    const auto encoded = value.AsInt();
    if (encoded < std::numeric_limits<int>::min() ||
        encoded > std::numeric_limits<int>::max()) {
        throw std::runtime_error(std::string(label) + " is outside the int range");
    }
    return static_cast<int>(encoded);
}

[[nodiscard]] json::Value OptionalInteger(
    const std::optional<std::int64_t>& value) {
    return value ? json::Value(*value) : json::Value(nullptr);
}

[[nodiscard]] std::optional<std::int64_t> DecodeOptionalInteger(
    const json::Value& value) {
    return value.IsNull() ? std::nullopt
                          : std::optional<std::int64_t>(value.AsInt());
}

[[nodiscard]] json::Value CountPositionJson(
    const trainer::CountPosition position) {
    return JsonObject{{"x_counts", position.x}, {"y_counts", position.y}};
}

[[nodiscard]] trainer::CountPosition DecodeCountPosition(
    const json::Value& value) {
    return {value.At("x_counts").AsInt(), value.At("y_counts").AsInt()};
}

[[nodiscard]] json::Value RenderEvidenceJson(const RenderEvidence& render) {
    return JsonObject{
        {"counts_per_pixel_x", render.counts_per_pixel_x},
        {"counts_per_pixel_y", render.counts_per_pixel_y},
        {"crosshair_scale", render.crosshair_scale},
        {"effective_radians_per_count", render.effective_radians_per_count},
        {"fullscreen", render.fullscreen},
        {"pixels_per_count_x", render.pixels_per_count_x},
        {"pixels_per_count_y", render.pixels_per_count_y},
        {"target_highlight_enabled", render.target_highlight_enabled},
        {"transform_revision", render.transform_revision},
        {"viewport_height_px", render.viewport_height_px},
        {"viewport_width_px", render.viewport_width_px},
    };
}

[[nodiscard]] RenderEvidence DecodeRenderEvidence(const json::Value& value) {
    RenderEvidence render;
    render.viewport_width_px = DecodeInt(value.At("viewport_width_px"),
                                         "viewport width");
    render.viewport_height_px = DecodeInt(value.At("viewport_height_px"),
                                          "viewport height");
    render.pixels_per_count_x = value.At("pixels_per_count_x").AsDouble();
    render.pixels_per_count_y = value.At("pixels_per_count_y").AsDouble();
    render.counts_per_pixel_x = value.At("counts_per_pixel_x").AsDouble();
    render.counts_per_pixel_y = value.At("counts_per_pixel_y").AsDouble();
    render.transform_revision = value.At("transform_revision").AsString();
    render.effective_radians_per_count =
        value.At("effective_radians_per_count").AsDouble();
    render.crosshair_scale = value.At("crosshair_scale").AsDouble();
    render.target_highlight_enabled =
        value.At("target_highlight_enabled").AsBool();
    render.fullscreen = value.At("fullscreen").AsBool();
    ValidateRenderEvidence(render);
    return render;
}

void AddIdentity(JsonObject& record, const GameplayJournalIdentity& identity) {
    record.emplace("qpc_frequency", identity.qpc_frequency);
    record.emplace("session_id", identity.session_id);
    record.emplace("trainer_sensitivity", identity.trainer_sensitivity);
    record.emplace("user_id", identity.user_id);
}

[[nodiscard]] GameplayJournalIdentity DecodeIdentity(const json::Value& record) {
    GameplayJournalIdentity identity;
    identity.session_id = record.At("session_id").AsString();
    identity.user_id = record.At("user_id").AsString();
    identity.qpc_frequency = record.At("qpc_frequency").AsInt();
    identity.trainer_sensitivity = record.At("trainer_sensitivity").AsDouble();
    ValidateIdentity(identity);
    return identity;
}

[[nodiscard]] trainer::NaturalOutcome DecodeNaturalOutcome(
    const std::string_view value) {
    using trainer::NaturalOutcome;
    if (value == "none") return NaturalOutcome::none;
    if (value == "hit_click") return NaturalOutcome::hit_click;
    if (value == "hit_dwell") return NaturalOutcome::hit_dwell;
    if (value == "miss_click") return NaturalOutcome::miss_click;
    if (value == "timeout") return NaturalOutcome::timeout;
    if (value == "challenge_end_timeout") {
        return NaturalOutcome::challenge_end_timeout;
    }
    throw std::runtime_error("unknown natural trainer outcome in gameplay journal");
}

[[nodiscard]] trainer::TechnicalOutcome DecodeTechnicalOutcome(
    const std::string_view value) {
    using trainer::TechnicalOutcome;
    if (value == "none") return TechnicalOutcome::none;
    if (value == "manual_pause") return TechnicalOutcome::manual_pause;
    if (value == "focus_lost") return TechnicalOutcome::focus_lost;
    if (value == "display_changed") return TechnicalOutcome::display_changed;
    if (value == "graphics_device_lost") {
        return TechnicalOutcome::graphics_device_lost;
    }
    if (value == "system_suspend") return TechnicalOutcome::system_suspend;
    if (value == "gameplay_input_unavailable") {
        return TechnicalOutcome::gameplay_input_unavailable;
    }
    throw std::runtime_error("unknown technical trainer outcome in gameplay journal");
}

void ValidateEvent(const trainer::TrainerEvent& event,
                   const GameplayJournalIdentity& identity,
                   const RenderEvidence& render) {
    ValidateIdentity(identity);
    ValidateRenderEvidence(render);
    if (event.event_id < 0 ||
        event.block_ordinal >= protocol::OrderedBlocksV1().size() ||
        event.target_ordinal_in_block >
            static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("trainer event identity is outside its bounds");
    }
    ValidateQpc(event.target_generated_qpc, "target generation");
    ValidateOptionalQpc(event.first_presented_qpc, "first presentation");
    ValidateOptionalQpc(event.event_start_qpc, "event start");
    ValidateOptionalQpc(event.natural_resolution_qpc, "natural resolution");
    ValidateOptionalQpc(event.technical_interruption_qpc, "technical interruption");
    ValidateOptionalQpc(event.tail_end_qpc, "tail end");

    if (event.first_presented_qpc &&
        *event.first_presented_qpc < event.target_generated_qpc) {
        throw std::invalid_argument("event presentation predates target generation");
    }
    if (event.event_start_qpc && event.first_presented_qpc &&
        *event.event_start_qpc < *event.first_presented_qpc) {
        throw std::invalid_argument("event start predates first presentation");
    }
    if (event.natural_resolution_qpc && event.event_start_qpc &&
        *event.natural_resolution_qpc < *event.event_start_qpc) {
        throw std::invalid_argument("natural resolution predates event start");
    }
    if (event.technical_interruption_qpc &&
        *event.technical_interruption_qpc < event.target_generated_qpc) {
        throw std::invalid_argument("technical interruption predates target generation");
    }
    if (event.tail_end_qpc && event.natural_resolution_qpc &&
        *event.tail_end_qpc < *event.natural_resolution_qpc) {
        throw std::invalid_argument("tail end predates natural resolution");
    }

    const std::array<double, 9> metrics{
        event.target_x_counts,
        event.target_y_counts,
        event.target_radius_counts,
        event.initial_distance_counts,
        event.closest_point_distance_counts,
        event.closest_swept_distance_counts,
        event.inside_total_ms,
        event.maximum_consecutive_inside_ms,
        event.observed_tail_ms,
    };
    if (!std::all_of(metrics.begin(), metrics.end(), [](const double value) {
            return std::isfinite(value);
        }) ||
        event.target_radius_counts <= 0.0 ||
        event.initial_distance_counts < 0.0 ||
        event.closest_point_distance_counts < 0.0 ||
        event.closest_swept_distance_counts < 0.0 ||
        event.inside_total_ms < 0.0 ||
        event.maximum_consecutive_inside_ms < 0.0 ||
        event.observed_tail_ms < 0.0 ||
        event.tail_minimum_ms < 0 ||
        event.tail_settle_required_ms < 0 ||
        event.tail_maximum_ms < event.tail_minimum_ms ||
        event.score_after_event < 0) {
        throw std::invalid_argument("trainer event metrics are outside their bounds");
    }

    // Serialization is also the canonical, protocol-owned provenance and
    // geometry validator. Embedding its parsed output prevents drift between
    // this journal and the published target schema.
    const auto canonical_target =
        protocol::ParseRealizedTargetJson(
            protocol::SerializeRealizedTargetJson(event.realized_target));
    if (canonical_target.event_id != event.event_id ||
        canonical_target.block_ordinal != event.block_ordinal ||
        canonical_target.target_ordinal_in_block != event.target_ordinal_in_block ||
        canonical_target.trainer_sensitivity != identity.trainer_sensitivity ||
        canonical_target.target_x_counts != event.target_x_counts ||
        canonical_target.target_y_counts != event.target_y_counts ||
        canonical_target.radius_counts != event.target_radius_counts ||
        canonical_target.start_crosshair_x != event.generation_camera.x ||
        canonical_target.start_crosshair_y != event.generation_camera.y) {
        throw std::invalid_argument(
            "trainer event wrapper disagrees with realized target evidence");
    }

    // RealizedTarget.initial_distance_counts belongs to generation-time
    // provenance. The event wrapper begins at the first presented frame (or
    // at the interruption camera when presentation never succeeds), so its
    // initial distance is intentionally allowed to differ after legitimate
    // movement between generation and presentation.
    const double presentation_dx = event.target_x_counts -
        static_cast<double>(event.presentation_camera.x);
    const double presentation_dy = event.target_y_counts -
        static_cast<double>(event.presentation_camera.y);
    const double presentation_distance =
        std::hypot(presentation_dx, presentation_dy);
    if (std::abs(presentation_distance - event.initial_distance_counts) >
        1.0e-9 * std::max(1.0, std::abs(presentation_distance))) {
        throw std::invalid_argument(
            "trainer event initial distance disagrees with presentation camera");
    }
    if (event.natural_outcome != trainer::NaturalOutcome::none &&
        !event.natural_resolution_qpc) {
        throw std::invalid_argument("natural event outcome has no resolution QPC");
    }
    if (event.technical_outcome != trainer::TechnicalOutcome::none &&
        !event.technical_interruption_qpc) {
        throw std::invalid_argument("technical event outcome has no interruption QPC");
    }
    for (const auto& click : event.click_hypotheses) {
        ValidateQpc(click.qpc, "click hypothesis");
    }
}

[[nodiscard]] json::Value EventJson(const trainer::TrainerEvent& event,
                                    const GameplayJournalIdentity& identity,
                                    const RenderEvidence& render) {
    ValidateEvent(event, identity, render);
    JsonArray clicks;
    clicks.reserve(event.click_hypotheses.size());
    for (const auto& click : event.click_hypotheses) {
        clicks.emplace_back(JsonObject{
            {"order_ambiguous", click.order_ambiguous},
            {"post_delta_inside", click.post_delta_inside},
            {"post_delta_position", CountPositionJson(click.post_delta_position)},
            {"pre_delta_inside", click.pre_delta_inside},
            {"pre_delta_position", CountPositionJson(click.pre_delta_position)},
            {"qpc", click.qpc},
            {"resolved_event", click.resolved_event},
        });
    }

    JsonObject record{
        {"block_ordinal", EncodeSize(event.block_ordinal, "block ordinal")},
        {"click_hypotheses", std::move(clicks)},
        {"closest_point_distance_counts", event.closest_point_distance_counts},
        {"closest_swept_distance_counts", event.closest_swept_distance_counts},
        {"event_id", event.event_id},
        {"event_start_qpc", OptionalInteger(event.event_start_qpc)},
        {"final_camera", CountPositionJson(event.final_camera)},
        {"first_presented_qpc", OptionalInteger(event.first_presented_qpc)},
        {"generation_camera", CountPositionJson(event.generation_camera)},
        {"initial_distance_counts", event.initial_distance_counts},
        {"inside_total_ms", event.inside_total_ms},
        {"maximum_consecutive_inside_ms", event.maximum_consecutive_inside_ms},
        {"natural_outcome", trainer::NaturalOutcomeName(event.natural_outcome)},
        {"natural_resolution_qpc", OptionalInteger(event.natural_resolution_qpc)},
        {"observed_tail_ms", event.observed_tail_ms},
        {"presentation_camera", CountPositionJson(event.presentation_camera)},
        {"presentation_interrupted", event.presentation_interrupted},
        {"realized_target", json::Parse(
            protocol::SerializeRealizedTargetJson(event.realized_target))},
        {"record_type", "trainer_event"},
        {"render_evidence", RenderEvidenceJson(render)},
        {"score_after_event", event.score_after_event},
        {"scored", event.scored},
        {"tail_end_qpc", OptionalInteger(event.tail_end_qpc)},
        {"tail_interrupted", event.tail_interrupted},
        {"tail_maximum_ms", event.tail_maximum_ms},
        {"tail_minimum_ms", event.tail_minimum_ms},
        {"tail_settle_required_ms", event.tail_settle_required_ms},
        {"target_generated_qpc", event.target_generated_qpc},
        {"target_ordinal_in_block",
         EncodeSize(event.target_ordinal_in_block, "target ordinal")},
        {"target_radius_counts", event.target_radius_counts},
        {"target_x_counts", event.target_x_counts},
        {"target_y_counts", event.target_y_counts},
        {"technical_interruption_qpc",
         OptionalInteger(event.technical_interruption_qpc)},
        {"technical_outcome", trainer::TechnicalOutcomeName(event.technical_outcome)},
    };
    AddIdentity(record, identity);
    return record;
}

[[nodiscard]] trainer::TrainerEvent DecodeEvent(const json::Value& record) {
    if (record.At("record_type").AsString() != "trainer_event") {
        throw std::runtime_error("gameplay event record type mismatch");
    }
    trainer::TrainerEvent event;
    event.event_id = record.At("event_id").AsInt();
    event.block_ordinal = DecodeSize(record.At("block_ordinal"), "block ordinal");
    event.target_ordinal_in_block =
        DecodeSize(record.At("target_ordinal_in_block"), "target ordinal");
    event.realized_target = protocol::ParseRealizedTargetJson(
        json::DumpCanonical(record.At("realized_target"), false));
    event.generation_camera = DecodeCountPosition(record.At("generation_camera"));
    event.presentation_camera = DecodeCountPosition(record.At("presentation_camera"));
    event.final_camera = DecodeCountPosition(record.At("final_camera"));
    event.target_generated_qpc = record.At("target_generated_qpc").AsInt();
    event.first_presented_qpc =
        DecodeOptionalInteger(record.At("first_presented_qpc"));
    event.event_start_qpc = DecodeOptionalInteger(record.At("event_start_qpc"));
    event.natural_resolution_qpc =
        DecodeOptionalInteger(record.At("natural_resolution_qpc"));
    event.technical_interruption_qpc =
        DecodeOptionalInteger(record.At("technical_interruption_qpc"));
    event.tail_end_qpc = DecodeOptionalInteger(record.At("tail_end_qpc"));
    event.target_x_counts = record.At("target_x_counts").AsDouble();
    event.target_y_counts = record.At("target_y_counts").AsDouble();
    event.target_radius_counts = record.At("target_radius_counts").AsDouble();
    event.initial_distance_counts = record.At("initial_distance_counts").AsDouble();
    event.closest_point_distance_counts =
        record.At("closest_point_distance_counts").AsDouble();
    event.closest_swept_distance_counts =
        record.At("closest_swept_distance_counts").AsDouble();
    event.inside_total_ms = record.At("inside_total_ms").AsDouble();
    event.maximum_consecutive_inside_ms =
        record.At("maximum_consecutive_inside_ms").AsDouble();
    event.natural_outcome =
        DecodeNaturalOutcome(record.At("natural_outcome").AsString());
    event.technical_outcome =
        DecodeTechnicalOutcome(record.At("technical_outcome").AsString());
    event.presentation_interrupted = record.At("presentation_interrupted").AsBool();
    event.tail_interrupted = record.At("tail_interrupted").AsBool();
    event.tail_minimum_ms = DecodeInt(record.At("tail_minimum_ms"), "tail minimum");
    event.tail_settle_required_ms =
        DecodeInt(record.At("tail_settle_required_ms"), "tail settle requirement");
    event.tail_maximum_ms = DecodeInt(record.At("tail_maximum_ms"), "tail maximum");
    event.observed_tail_ms = record.At("observed_tail_ms").AsDouble();
    event.scored = record.At("scored").AsBool();
    event.score_after_event = DecodeInt(record.At("score_after_event"), "event score");
    for (const auto& encoded : record.At("click_hypotheses").AsArray()) {
        trainer::ClickHypothesis click;
        click.qpc = encoded.At("qpc").AsInt();
        click.pre_delta_position = DecodeCountPosition(encoded.At("pre_delta_position"));
        click.post_delta_position = DecodeCountPosition(encoded.At("post_delta_position"));
        click.pre_delta_inside = encoded.At("pre_delta_inside").AsBool();
        click.post_delta_inside = encoded.At("post_delta_inside").AsBool();
        click.order_ambiguous = encoded.At("order_ambiguous").AsBool();
        click.resolved_event = encoded.At("resolved_event").AsBool();
        event.click_hypotheses.push_back(click);
    }
    return event;
}

void ValidateBlock(const trainer::BlockResult& block) {
    if (block.ordinal >= protocol::OrderedBlocksV1().size()) {
        throw std::invalid_argument("block result ordinal is invalid");
    }
    const auto& definition = protocol::OrderedBlocksV1()[block.ordinal];
    if (block.block_id != definition.block_id ||
        block.challenge_id != definition.challenge_id) {
        throw std::invalid_argument("block result identity disagrees with protocol");
    }
    ValidateQpc(block.countdown_started_qpc, "block countdown");
    ValidateOptionalQpc(block.gameplay_started_qpc, "block gameplay start");
    ValidateOptionalQpc(block.completed_qpc, "block completion");
    if (block.gameplay_started_qpc &&
        *block.gameplay_started_qpc < block.countdown_started_qpc) {
        throw std::invalid_argument("block gameplay predates countdown");
    }
    if (block.completed_qpc && block.gameplay_started_qpc &&
        *block.completed_qpc < *block.gameplay_started_qpc) {
        throw std::invalid_argument("block completion predates gameplay");
    }
    if (block.configured_duration_ms < protocol::V1Constants::minimum_useful_spawn_ms ||
        block.configured_duration_ms > protocol::V1Constants::block_duration_ms ||
        !std::isfinite(block.consumed_gameplay_ms) ||
        block.consumed_gameplay_ms < 0.0 ||
        block.consumed_gameplay_ms >
            static_cast<double>(block.configured_duration_ms) + 1.0e-6 ||
        block.score < 0 || block.technical_event_count > block.event_count) {
        throw std::invalid_argument("block result metrics are outside their bounds");
    }
}

[[nodiscard]] json::Value BlockJson(const trainer::BlockResult& block,
                                    const GameplayJournalIdentity& identity) {
    ValidateIdentity(identity);
    ValidateBlock(block);
    JsonObject record{
        {"block_id", block.block_id},
        {"challenge_id", block.challenge_id},
        {"completed_qpc", OptionalInteger(block.completed_qpc)},
        {"configured_duration_ms", block.configured_duration_ms},
        {"consumed_gameplay_ms", block.consumed_gameplay_ms},
        {"countdown_started_qpc", block.countdown_started_qpc},
        {"event_count", EncodeSize(block.event_count, "block event count")},
        {"gameplay_started_qpc", OptionalInteger(block.gameplay_started_qpc)},
        {"ordinal", EncodeSize(block.ordinal, "block ordinal")},
        {"record_type", "block_result"},
        {"score", block.score},
        {"technical_event_count",
         EncodeSize(block.technical_event_count, "technical event count")},
    };
    AddIdentity(record, identity);
    return record;
}

[[nodiscard]] trainer::BlockResult DecodeBlock(const json::Value& record) {
    if (record.At("record_type").AsString() != "block_result") {
        throw std::runtime_error("gameplay block record type mismatch");
    }
    trainer::BlockResult block;
    block.ordinal = DecodeSize(record.At("ordinal"), "block ordinal");
    block.block_id = record.At("block_id").AsString();
    block.challenge_id = record.At("challenge_id").AsString();
    block.countdown_started_qpc = record.At("countdown_started_qpc").AsInt();
    block.gameplay_started_qpc =
        DecodeOptionalInteger(record.At("gameplay_started_qpc"));
    block.completed_qpc = DecodeOptionalInteger(record.At("completed_qpc"));
    block.configured_duration_ms =
        DecodeInt(record.At("configured_duration_ms"), "configured duration");
    block.consumed_gameplay_ms = record.At("consumed_gameplay_ms").AsDouble();
    block.score = DecodeInt(record.At("score"), "block score");
    block.event_count = DecodeSize(record.At("event_count"), "event count");
    block.technical_event_count =
        DecodeSize(record.At("technical_event_count"), "technical event count");
    ValidateBlock(block);
    return block;
}

[[nodiscard]] json::Value OptionalEventId(
    const std::optional<std::int64_t>& event_id) {
    return OptionalInteger(event_id);
}

void ValidateAnnotationEventId(const std::optional<std::int64_t>& event_id) {
    if (event_id && *event_id < 0) {
        throw std::invalid_argument("annotation event ID is negative");
    }
}

}  // namespace

struct GameplayJournal::JournalPaths final {
    std::filesystem::path events_partial;
    std::filesystem::path events_final;
    std::filesystem::path blocks_partial;
    std::filesystem::path blocks_final;
    std::filesystem::path raw_input_partial;
    std::filesystem::path raw_input_final;
    std::filesystem::path lifecycle_partial;
    std::filesystem::path lifecycle_final;
    std::filesystem::path pauses_partial;
    std::filesystem::path pauses_final;
    std::filesystem::path focus_partial;
    std::filesystem::path focus_final;
    std::filesystem::path presentation_partial;
    std::filesystem::path presentation_final;

    explicit JournalPaths(const std::filesystem::path& directory)
        : events_partial(directory / "events.jsonl.partial"),
          events_final(directory / "events.jsonl"),
          blocks_partial(directory / "blocks.jsonl.partial"),
          blocks_final(directory / "blocks.jsonl"),
          raw_input_partial(directory / "raw_input_witness.jsonl.partial"),
          raw_input_final(directory / "raw_input_witness.jsonl"),
          lifecycle_partial(directory / "lifecycle.jsonl.partial"),
          lifecycle_final(directory / "lifecycle.jsonl"),
          pauses_partial(directory / "pauses.jsonl.partial"),
          pauses_final(directory / "pauses.jsonl"),
          focus_partial(directory / "focus.jsonl.partial"),
          focus_final(directory / "focus.jsonl"),
          presentation_partial(directory / "presentation.jsonl.partial"),
          presentation_final(directory / "presentation.jsonl") {}

    [[nodiscard]] std::array<std::filesystem::path, 14> All() const {
        return {events_partial, events_final,
                blocks_partial, blocks_final,
                raw_input_partial, raw_input_final,
                lifecycle_partial, lifecycle_final,
                pauses_partial, pauses_final,
                focus_partial, focus_final,
                presentation_partial, presentation_final};
    }

    [[nodiscard]] std::array<std::filesystem::path, 7> Partials() const {
        return {events_partial, blocks_partial, raw_input_partial,
                lifecycle_partial, pauses_partial, focus_partial,
                presentation_partial};
    }
};

GameplayJournal::GameplayJournal(std::filesystem::path gameplay_directory,
                                 GameplayJournalIdentity identity)
    : directory_(std::move(gameplay_directory)),
      identity_(std::move(identity)) {
    ValidateIdentity(identity_);
    if (directory_.empty()) {
        throw std::invalid_argument("gameplay journal directory is empty");
    }
    std::filesystem::create_directories(directory_);
    paths_ = std::make_unique<JournalPaths>(directory_);
    for (const auto& path : paths_->All()) {
        if (std::filesystem::exists(path)) {
            throw std::runtime_error("refusing to overwrite an existing gameplay journal");
        }
    }

    try {
        events_ = std::make_unique<AppendOnlyJsonlWriter>(
            paths_->events_partial, std::string(kEventSchema));
        blocks_ = std::make_unique<AppendOnlyJsonlWriter>(
            paths_->blocks_partial, std::string(kBlockSchema));
        lifecycle_ = std::make_unique<AppendOnlyJsonlWriter>(
            paths_->lifecycle_partial, std::string(kLifecycleSchema));
        pauses_ = std::make_unique<AppendOnlyJsonlWriter>(
            paths_->pauses_partial, std::string(kPauseSchema));
        focus_ = std::make_unique<AppendOnlyJsonlWriter>(
            paths_->focus_partial, std::string(kFocusSchema));
        presentation_ = std::make_unique<AppendOnlyJsonlWriter>(
            paths_->presentation_partial, std::string(kPresentationSchema));
    } catch (...) {
        events_.reset();
        blocks_.reset();
        raw_input_witness_.reset();
        lifecycle_.reset();
        pauses_.reset();
        focus_.reset();
        presentation_.reset();
        for (const auto& path : paths_->Partials()) {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
        throw;
    }

    // Raw Input is useful corroborating context, but it is not part of the
    // authoritative capture contract. A private writer failure must not make
    // an otherwise recordable session impossible to start.
    try {
        raw_input_witness_ = std::make_unique<AppendOnlyJsonlWriter>(
            paths_->raw_input_partial, std::string(kRawInputWitnessSchema));
    } catch (...) {
        DisableRawInputWitness();
    }
}

GameplayJournal::~GameplayJournal() = default;

void GameplayJournal::DisableRawInputWitness() noexcept {
    raw_input_witness_.reset();
    if (paths_) {
        std::error_code ignored;
        std::filesystem::remove(paths_->raw_input_partial, ignored);
    }
}

std::uint64_t GameplayJournal::AppendEvent(const trainer::TrainerEvent& event,
                                           const RenderEvidence& render) {
    if (finalized_) throw std::logic_error("gameplay journal is finalized");
    const auto record = [&]() {
        try {
            return EventJson(event, identity_, render);
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::exception& error) {
            throw GameplayRecordValidationError(
                std::string("trainer event validation failed: ") + error.what());
        }
    }();
    return events_->Append(record);
}

std::uint64_t GameplayJournal::AppendBlockResult(
    const trainer::BlockResult& block) {
    if (finalized_) throw std::logic_error("gameplay journal is finalized");
    const auto record = [&]() {
        try {
            return BlockJson(block, identity_);
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::exception& error) {
            throw GameplayRecordValidationError(
                std::string("trainer block validation failed: ") + error.what());
        }
    }();
    return blocks_->Append(record);
}

bool GameplayJournal::TryAppendRawInputWitness(
    const RawInputWitnessPacket& packet) {
    if (finalized_) throw std::logic_error("gameplay journal is finalized");
    if (!raw_input_witness_ || packet.receipt_qpc < 0 ||
        !IsSafeIdentifier(packet.device_token) ||
        packet.dx_counts < std::numeric_limits<std::int32_t>::min() ||
        packet.dx_counts > std::numeric_limits<std::int32_t>::max() ||
        packet.dy_counts < std::numeric_limits<std::int32_t>::min() ||
        packet.dy_counts > std::numeric_limits<std::int32_t>::max()) {
        return false;
    }

    try {
        JsonObject record{
            {"authoritative", false},
            {"authority", "non_authoritative_windows_raw_input_witness"},
            {"button_data", static_cast<std::int64_t>(packet.button_data)},
            {"button_flags", static_cast<std::int64_t>(packet.button_flags)},
            {"device_token", packet.device_token},
            {"dx_counts", packet.dx_counts},
            {"dy_counts", packet.dy_counts},
            {"receipt_qpc", packet.receipt_qpc},
            {"record_type", "raw_input_witness_packet"},
            {"selected_device", packet.selected_device},
            {"source", "windows_raw_input"},
        };
        AddIdentity(record, identity_);
        raw_input_witness_->Append(std::move(record));
        return true;
    } catch (...) {
        DisableRawInputWitness();
        return false;
    }
}

std::uint64_t GameplayJournal::AppendLifecycle(
    const LifecycleAnnotation& annotation) {
    if (finalized_) throw std::logic_error("gameplay journal is finalized");
    ValidateQpc(annotation.qpc, "lifecycle annotation");
    ValidateAnnotationEventId(annotation.event_id);
    if (!IsSafeIdentifier(annotation.name, 64U) ||
        !IsSafeDetail(annotation.detail) ||
        (annotation.block_ordinal &&
         *annotation.block_ordinal >= protocol::OrderedBlocksV1().size())) {
        throw std::invalid_argument("lifecycle annotation is invalid");
    }
    JsonObject record{
        {"block_ordinal", annotation.block_ordinal
            ? json::Value(EncodeSize(*annotation.block_ordinal, "annotation block ordinal"))
            : json::Value(nullptr)},
        {"detail", annotation.detail},
        {"event_id", OptionalEventId(annotation.event_id)},
        {"name", annotation.name},
        {"qpc", annotation.qpc},
        {"record_type", "lifecycle_annotation"},
    };
    AddIdentity(record, identity_);
    return lifecycle_->Append(std::move(record));
}

std::uint64_t GameplayJournal::AppendPause(const PauseAnnotation& annotation) {
    if (finalized_) throw std::logic_error("gameplay journal is finalized");
    ValidateQpc(annotation.qpc, "pause annotation");
    ValidateAnnotationEventId(annotation.event_id);
    if (!IsSafeIdentifier(annotation.reason, 64U)) {
        throw std::invalid_argument("pause reason is invalid");
    }
    JsonObject record{
        {"event_id", OptionalEventId(annotation.event_id)},
        {"paused", annotation.paused},
        {"qpc", annotation.qpc},
        {"reason", annotation.reason},
        {"record_type", "pause_annotation"},
    };
    AddIdentity(record, identity_);
    return pauses_->Append(std::move(record));
}

std::uint64_t GameplayJournal::AppendFocus(const FocusAnnotation& annotation) {
    if (finalized_) throw std::logic_error("gameplay journal is finalized");
    ValidateQpc(annotation.qpc, "focus annotation");
    ValidateAnnotationEventId(annotation.event_id);
    JsonObject record{
        {"event_id", OptionalEventId(annotation.event_id)},
        {"focused", annotation.focused},
        {"minimized", annotation.minimized},
        {"qpc", annotation.qpc},
        {"record_type", "focus_annotation"},
    };
    AddIdentity(record, identity_);
    return focus_->Append(std::move(record));
}

std::uint64_t GameplayJournal::AppendPresentation(
    const PresentationAnnotation& annotation) {
    if (finalized_) throw std::logic_error("gameplay journal is finalized");
    ValidateQpc(annotation.qpc, "presentation annotation");
    if (annotation.event_id < 0 || !IsSafeDetail(annotation.detail)) {
        throw std::invalid_argument("presentation annotation is invalid");
    }
    ValidateRenderEvidence(annotation.render);
    JsonObject record{
        {"detail", annotation.detail},
        {"event_id", annotation.event_id},
        {"qpc", annotation.qpc},
        {"record_type", "presentation_annotation"},
        {"render_evidence", RenderEvidenceJson(annotation.render)},
        {"successful", annotation.successful},
    };
    AddIdentity(record, identity_);
    return presentation_->Append(std::move(record));
}

void GameplayJournal::Checkpoint() {
    if (finalized_) throw std::logic_error("gameplay journal is finalized");
    events_->Checkpoint();
    blocks_->Checkpoint();
    lifecycle_->Checkpoint();
    pauses_->Checkpoint();
    focus_->Checkpoint();
    presentation_->Checkpoint();
    if (raw_input_witness_) {
        try {
            raw_input_witness_->Checkpoint();
        } catch (...) {
            DisableRawInputWitness();
        }
    }
}

void GameplayJournal::Finalize() {
    if (finalized_) throw std::logic_error("gameplay journal is already finalized");
    for (const auto& path : std::array{
             paths_->events_final, paths_->blocks_final,
             paths_->lifecycle_final, paths_->pauses_final, paths_->focus_final,
             paths_->presentation_final}) {
        if (std::filesystem::exists(path)) {
            throw std::runtime_error("refusing to overwrite a finalized gameplay journal");
        }
    }

    Checkpoint();
    events_->Finalize(paths_->events_final);
    blocks_->Finalize(paths_->blocks_final);
    lifecycle_->Finalize(paths_->lifecycle_final);
    pauses_->Finalize(paths_->pauses_final);
    focus_->Finalize(paths_->focus_final);
    presentation_->Finalize(paths_->presentation_final);
    if (raw_input_witness_) {
        try {
            if (std::filesystem::exists(paths_->raw_input_final)) {
                throw std::runtime_error(
                    "refusing to overwrite a Raw Input witness journal");
            }
            raw_input_witness_->Finalize(paths_->raw_input_final);
        } catch (...) {
            DisableRawInputWitness();
        }
    }
    for (const auto& path : std::array{
             paths_->events_partial, paths_->blocks_partial,
             paths_->lifecycle_partial, paths_->pauses_partial,
             paths_->focus_partial, paths_->presentation_partial}) {
        if (std::filesystem::exists(path)) {
            throw std::runtime_error("gameplay journal finalization left a partial artifact");
        }
    }
    finalized_ = true;
}

std::vector<GameplayEventRecord> ReadGameplayEvents(
    const std::filesystem::path& path) {
    AppendOnlyJsonlReader reader(path, std::string(GameplayJournal::kEventSchema));
    std::vector<GameplayEventRecord> result;
    while (auto encoded = reader.Next()) {
        GameplayEventRecord record;
        record.identity = DecodeIdentity(*encoded);
        record.render = DecodeRenderEvidence(encoded->At("render_evidence"));
        record.event = DecodeEvent(*encoded);
        ValidateEvent(record.event, record.identity, record.render);
        result.push_back(std::move(record));
    }
    return result;
}

std::vector<GameplayBlockRecord> ReadGameplayBlockResults(
    const std::filesystem::path& path) {
    AppendOnlyJsonlReader reader(path, std::string(GameplayJournal::kBlockSchema));
    std::vector<GameplayBlockRecord> result;
    while (auto encoded = reader.Next()) {
        GameplayBlockRecord record;
        record.identity = DecodeIdentity(*encoded);
        record.block = DecodeBlock(*encoded);
        ValidateIdentity(record.identity);
        result.push_back(std::move(record));
    }
    return result;
}

}  // namespace abdc::session
