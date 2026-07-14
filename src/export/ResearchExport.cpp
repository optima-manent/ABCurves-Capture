#include "export/ResearchExport.h"

#include "base/AtomicFile.h"
#include "base/Json.h"
#include "base/Sha256.h"
#include "capture/ReportStream.h"
#include "derive/ClockAnchorFit.h"
#include "derive/MillisecondDeriver.h"
#include "protocol/protocol_v1.hpp"
#include "session/ClockJournal.h"
#include "session/GameplayJournal.h"
#include "session/SessionValidator.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <locale>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace abdc::research {
namespace {

using JsonArray = json::Value::Array;
using JsonObject = json::Value::Object;

constexpr std::array<std::string_view, 5> kRequiredSourceArtifacts{
    "manifest.json",
    "capture/mouse_usb.pcap",
    "clocks/anchors.jsonl",
    "gameplay/events.jsonl",
    "gameplay/blocks.jsonl",
};

[[nodiscard]] std::wstring FoldPathComponent(const std::filesystem::path& value) {
    auto text = value.native();
#ifdef _WIN32
    std::transform(text.begin(), text.end(), text.begin(), [](const wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
    });
#endif
    return text;
}

[[nodiscard]] bool IsWithin(const std::filesystem::path& candidate,
                            const std::filesystem::path& root) {
    const auto normalized_candidate = candidate.lexically_normal();
    const auto normalized_root = root.lexically_normal();
    auto candidate_it = normalized_candidate.begin();
    const auto candidate_end = normalized_candidate.end();
    auto root_it = normalized_root.begin();
    const auto root_end = normalized_root.end();
    for (; root_it != root_end; ++root_it, ++candidate_it) {
        if (candidate_it == candidate_end ||
            FoldPathComponent(*candidate_it) != FoldPathComponent(*root_it)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] const session::SessionArtifact& SourceArtifact(
    const session::ValidatedSession& session,
    const std::string_view relative_path) {
    const auto found = std::find_if(
        session.artifacts.begin(), session.artifacts.end(),
        [relative_path](const session::SessionArtifact& artifact) {
            return artifact.relative_path == relative_path;
        });
    if (found == session.artifacts.end()) {
        throw std::runtime_error(
            "sealed session lacks required research source artifact: " +
            std::string(relative_path));
    }
    return *found;
}

[[nodiscard]] std::string Number(const double value) {
    if (!std::isfinite(value)) {
        throw std::runtime_error("non-finite value cannot be exported");
    }
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << std::setprecision(std::numeric_limits<double>::max_digits10) << value;
    return output.str();
}

[[nodiscard]] std::string Number(const long double value) {
    if (!std::isfinite(value)) {
        throw std::runtime_error("non-finite clock value cannot be exported");
    }
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << std::setprecision(std::numeric_limits<long double>::max_digits10)
           << value;
    return output.str();
}

template <typename Integer>
[[nodiscard]] std::string IntegerText(const Integer value) {
    return std::to_string(value);
}

[[nodiscard]] std::string OptionalIntegerText(
    const std::optional<std::int64_t>& value) {
    return value ? std::to_string(*value) : std::string{};
}

[[nodiscard]] std::string CsvCell(const std::string_view value) {
    if (value.find_first_of(",\"\r\n") == std::string_view::npos) {
        return std::string(value);
    }
    std::string encoded;
    encoded.reserve(value.size() + 2U);
    encoded.push_back('"');
    for (const auto character : value) {
        if (character == '"') encoded.push_back('"');
        encoded.push_back(character);
    }
    encoded.push_back('"');
    return encoded;
}

void WriteCsvRow(std::ofstream& output,
                 const std::vector<std::string>& cells) {
    for (std::size_t index = 0; index < cells.size(); ++index) {
        if (index != 0U) output.put(',');
        output << CsvCell(cells[index]);
    }
    output.put('\n');
    if (!output) throw std::runtime_error("research CSV write failed");
}

[[nodiscard]] std::ofstream OpenOutput(const std::filesystem::path& path) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.imbue(std::locale::classic());
    if (!output) {
        throw std::runtime_error("cannot create research export artifact: " +
                                 path.filename().string());
    }
    return output;
}

void CloseOutput(std::ofstream& output, const char* label) {
    output.flush();
    if (!output) throw std::runtime_error(std::string(label) + " flush failed");
    output.close();
    if (!output) throw std::runtime_error(std::string(label) + " close failed");
}

[[nodiscard]] std::vector<capture::AuthoritativeReport> ReadReports(
    const std::filesystem::path& path,
    capture::ReportStreamIdentity& identity) {
    capture::ReportStreamReader reader(path);
    identity = reader.Identity();
    std::vector<capture::AuthoritativeReport> reports;
    while (auto report = reader.Next()) {
        if (report->bus != identity.bus || report->device != identity.device ||
            report->endpoint != identity.endpoint) {
            throw std::runtime_error(
                "decoded report route disagrees with report stream identity");
        }
        reports.push_back(std::move(*report));
    }
    return reports;
}

[[nodiscard]] std::vector<derive::ClockAnchor> ConvertClockAnchors(
    const std::vector<session::ClockJournalRecord>& records,
    const std::int64_t qpc_frequency) {
    std::vector<derive::ClockAnchor> anchors;
    anchors.reserve(records.size());
    for (const auto& record : records) {
        if (record.qpc_frequency != qpc_frequency) {
            throw std::runtime_error(
                "clock journal frequency disagrees with session manifest");
        }
        const auto converted = derive::MakeBracketedClockAnchor(
            record.anchor.qpc_before,
            record.anchor.utc_unix_ns,
            record.anchor.qpc_after,
            qpc_frequency);
        if (converted.qpc_ticks != record.anchor.qpc_midpoint) {
            throw std::runtime_error(
                "clock journal midpoint disagrees with its QPC bracket");
        }
        anchors.push_back(converted);
    }
    return anchors;
}

[[nodiscard]] std::optional<std::int64_t> MapQpc(
    const derive::QpcUtcClockFit& fit,
    const std::optional<std::int64_t>& qpc) {
    if (!qpc) return std::nullopt;
    return fit.QpcToUtcUnixNs(*qpc);
}

[[nodiscard]] std::optional<std::int64_t> MapQpc(
    const derive::QpcUtcClockFit& fit,
    const std::int64_t qpc) {
    return fit.QpcToUtcUnixNs(qpc);
}

[[nodiscard]] JsonArray ClockWarningNames(const std::uint32_t mask) {
    JsonArray result;
    const auto add = [&](const derive::ClockFitWarning warning,
                         const char* name) {
        if ((mask & derive::WarningMask(warning)) != 0U) {
            result.emplace_back(name);
        }
    };
    add(derive::ClockFitWarning::InsufficientAnchors, "insufficient_anchors");
    add(derive::ClockFitWarning::NonIncreasingQpc, "non_increasing_qpc");
    add(derive::ClockFitWarning::UtcClockStepDetected,
        "utc_clock_step_detected");
    add(derive::ClockFitWarning::HighResidual, "high_residual");
    add(derive::ClockFitWarning::HighAnchorUncertainty,
        "high_anchor_uncertainty");
    add(derive::ClockFitWarning::ExcessiveDrift, "excessive_drift");
    add(derive::ClockFitWarning::OutliersExcluded, "outliers_excluded");
    add(derive::ClockFitWarning::NonPositiveSlope, "non_positive_slope");
    return result;
}

[[nodiscard]] json::Value ButtonEdgesJson(
    const std::vector<derive::OrderedButtonEdge>& edges) {
    JsonArray encoded;
    encoded.reserve(edges.size());
    for (const auto& edge : edges) {
        encoded.emplace_back(JsonObject{
            {"buttons_after", static_cast<std::int64_t>(edge.buttons_after)},
            {"buttons_before", static_cast<std::int64_t>(edge.buttons_before)},
            {"capture_sequence", std::to_string(edge.capture_sequence)},
            {"capture_unix_ns", edge.capture_unix_ns},
            {"down_mask", static_cast<std::int64_t>(edge.down_mask)},
            {"report_ordinal_in_bin",
             static_cast<std::int64_t>(edge.report_ordinal_in_bin)},
            {"up_mask", static_cast<std::int64_t>(edge.up_mask)},
        });
    }
    return encoded;
}

[[nodiscard]] json::Value ClickHypothesesJson(
    const std::vector<trainer::ClickHypothesis>& clicks) {
    JsonArray encoded;
    encoded.reserve(clicks.size());
    for (const auto& click : clicks) {
        encoded.emplace_back(JsonObject{
            {"order_ambiguous", click.order_ambiguous},
            {"post_delta_inside", click.post_delta_inside},
            {"post_delta_x_counts", click.post_delta_position.x},
            {"post_delta_y_counts", click.post_delta_position.y},
            {"pre_delta_inside", click.pre_delta_inside},
            {"pre_delta_x_counts", click.pre_delta_position.x},
            {"pre_delta_y_counts", click.pre_delta_position.y},
            {"qpc", click.qpc},
            {"resolved_event", click.resolved_event},
        });
    }
    return encoded;
}

void WriteMouseCsv(const std::filesystem::path& path,
                   const derive::DenseBinningResult& result) {
    auto output = OpenOutput(path);
    WriteCsvRow(output, {
        "schema", "bin_index", "begin_unix_ns", "end_unix_ns",
        "device_dx", "device_dy", "canonical_dx", "canonical_dy",
        "wheel_sum", "horizontal_wheel_sum", "report_count",
        "zero_delta_report_count", "first_report_sequence",
        "last_report_sequence", "buttons_at_start", "buttons_at_end",
        "buttons_down_mask", "buttons_up_mask", "crosshair_pre_x_counts",
        "crosshair_pre_y_counts", "crosshair_post_x_counts",
        "crosshair_post_y_counts", "quality_mask", "button_edges_json",
    });
    for (const auto& bin : result.bins) {
        WriteCsvRow(output, {
            kDenseMouseCsvSchema,
            IntegerText(bin.bin_index),
            IntegerText(bin.begin_unix_ns),
            IntegerText(bin.end_unix_ns),
            IntegerText(bin.delta.device_dx),
            IntegerText(bin.delta.device_dy),
            IntegerText(bin.delta.derived_dx),
            IntegerText(bin.delta.derived_dy),
            IntegerText(bin.wheel_sum),
            IntegerText(bin.horizontal_wheel_sum),
            IntegerText(bin.report_count),
            IntegerText(bin.zero_delta_report_count),
            bin.first_report_sequence
                ? IntegerText(*bin.first_report_sequence) : std::string{},
            bin.last_report_sequence
                ? IntegerText(*bin.last_report_sequence) : std::string{},
            IntegerText(bin.buttons_at_start),
            IntegerText(bin.buttons_at_end),
            IntegerText(bin.buttons_down_mask),
            IntegerText(bin.buttons_up_mask),
            IntegerText(bin.crosshair_pre_delta.x),
            IntegerText(bin.crosshair_pre_delta.y),
            IntegerText(bin.crosshair_post_delta.x),
            IntegerText(bin.crosshair_post_delta.y),
            IntegerText(bin.quality_mask),
            json::DumpCanonical(ButtonEdgesJson(bin.ordered_button_edges), false),
        });
    }
    CloseOutput(output, "mouse CSV");
}

void WriteEventCsv(const std::filesystem::path& path,
                   const std::vector<session::GameplayEventRecord>& records,
                   const derive::QpcUtcClockFit& clock_fit) {
    auto output = OpenOutput(path);
    WriteCsvRow(output, {
        "schema", "session_id", "user_id", "event_id", "block_ordinal",
        "target_ordinal_in_block", "challenge_id", "task_type", "target_role",
        "trainer_sensitivity", "protocol_hash", "persisted_seed",
        "rng_draw_begin", "rng_draw_end", "generation_attempt",
        "target_generated_qpc", "target_generated_unix_ns",
        "first_presented_qpc", "first_presented_unix_ns", "event_start_qpc",
        "event_start_unix_ns", "natural_resolution_qpc",
        "natural_resolution_unix_ns", "technical_interruption_qpc",
        "technical_interruption_unix_ns", "tail_end_qpc", "tail_end_unix_ns",
        "target_x_counts", "target_y_counts", "target_radius_counts",
        "relative_target_x_counts", "relative_target_y_counts",
        "generation_distance_counts", "initial_distance_counts",
        "closest_point_distance_counts",
        "closest_swept_distance_counts", "start_crosshair_x_counts",
        "start_crosshair_y_counts", "generation_camera_x_counts",
        "generation_camera_y_counts", "presentation_camera_x_counts",
        "presentation_camera_y_counts", "final_camera_x_counts",
        "final_camera_y_counts", "natural_outcome", "technical_outcome",
        "scored", "score_after_event", "presentation_interrupted",
        "tail_interrupted", "inside_total_ms", "maximum_consecutive_inside_ms",
        "observed_tail_ms", "timeout_ms", "dwell_required_ms", "visible",
        "visibility_adjusted", "viewport_width_px", "viewport_height_px",
        "pixels_per_count_x", "pixels_per_count_y", "counts_per_pixel_x",
        "counts_per_pixel_y", "render_transform_revision", "click_count",
        "click_hypotheses_json", "clock_fit_warning_mask",
    });
    for (const auto& record : records) {
        const auto& event = record.event;
        const auto& target = event.realized_target;
        WriteCsvRow(output, {
            kTrainerEventCsvSchema,
            record.identity.session_id,
            record.identity.user_id,
            IntegerText(event.event_id),
            IntegerText(event.block_ordinal),
            IntegerText(event.target_ordinal_in_block),
            target.challenge_id,
            target.task_type,
            protocol::TargetRoleName(target.role),
            Number(record.identity.trainer_sensitivity),
            target.protocol_hash,
            IntegerText(target.persisted_seed),
            IntegerText(target.rng_draw_begin),
            IntegerText(target.rng_draw_end),
            IntegerText(target.generation_attempt),
            IntegerText(event.target_generated_qpc),
            OptionalIntegerText(MapQpc(clock_fit, event.target_generated_qpc)),
            OptionalIntegerText(event.first_presented_qpc),
            OptionalIntegerText(MapQpc(clock_fit, event.first_presented_qpc)),
            OptionalIntegerText(event.event_start_qpc),
            OptionalIntegerText(MapQpc(clock_fit, event.event_start_qpc)),
            OptionalIntegerText(event.natural_resolution_qpc),
            OptionalIntegerText(MapQpc(clock_fit, event.natural_resolution_qpc)),
            OptionalIntegerText(event.technical_interruption_qpc),
            OptionalIntegerText(MapQpc(clock_fit,
                                       event.technical_interruption_qpc)),
            OptionalIntegerText(event.tail_end_qpc),
            OptionalIntegerText(MapQpc(clock_fit, event.tail_end_qpc)),
            Number(event.target_x_counts),
            Number(event.target_y_counts),
            Number(event.target_radius_counts),
            Number(target.relative_x_counts),
            Number(target.relative_y_counts),
            Number(target.initial_distance_counts),
            Number(event.initial_distance_counts),
            Number(event.closest_point_distance_counts),
            Number(event.closest_swept_distance_counts),
            IntegerText(target.start_crosshair_x),
            IntegerText(target.start_crosshair_y),
            IntegerText(event.generation_camera.x),
            IntegerText(event.generation_camera.y),
            IntegerText(event.presentation_camera.x),
            IntegerText(event.presentation_camera.y),
            IntegerText(event.final_camera.x),
            IntegerText(event.final_camera.y),
            trainer::NaturalOutcomeName(event.natural_outcome),
            trainer::TechnicalOutcomeName(event.technical_outcome),
            event.scored ? "true" : "false",
            IntegerText(event.score_after_event),
            event.presentation_interrupted ? "true" : "false",
            event.tail_interrupted ? "true" : "false",
            Number(event.inside_total_ms),
            Number(event.maximum_consecutive_inside_ms),
            Number(event.observed_tail_ms),
            IntegerText(target.timeout_ms),
            IntegerText(target.dwell_required_ms),
            target.visible ? "true" : "false",
            target.visibility_adjusted ? "true" : "false",
            IntegerText(record.render.viewport_width_px),
            IntegerText(record.render.viewport_height_px),
            Number(record.render.pixels_per_count_x),
            Number(record.render.pixels_per_count_y),
            Number(record.render.counts_per_pixel_x),
            Number(record.render.counts_per_pixel_y),
            record.render.transform_revision,
            IntegerText(event.click_hypotheses.size()),
            json::DumpCanonical(ClickHypothesesJson(event.click_hypotheses), false),
            IntegerText(clock_fit.warning_mask),
        });
    }
    CloseOutput(output, "trainer event CSV");
}

void WriteBlockCsv(const std::filesystem::path& path,
                   const std::vector<session::GameplayBlockRecord>& records,
                   const derive::QpcUtcClockFit& clock_fit) {
    auto output = OpenOutput(path);
    WriteCsvRow(output, {
        "schema", "session_id", "user_id", "ordinal", "block_id",
        "challenge_id", "trainer_sensitivity", "countdown_started_qpc",
        "countdown_started_unix_ns", "gameplay_started_qpc",
        "gameplay_started_unix_ns", "completed_qpc", "completed_unix_ns",
        "configured_duration_ms", "consumed_gameplay_ms", "score",
        "event_count", "technical_event_count", "clock_fit_warning_mask",
    });
    for (const auto& record : records) {
        const auto& block = record.block;
        WriteCsvRow(output, {
            kBlockResultCsvSchema,
            record.identity.session_id,
            record.identity.user_id,
            IntegerText(block.ordinal),
            block.block_id,
            block.challenge_id,
            Number(record.identity.trainer_sensitivity),
            IntegerText(block.countdown_started_qpc),
            OptionalIntegerText(MapQpc(clock_fit, block.countdown_started_qpc)),
            OptionalIntegerText(block.gameplay_started_qpc),
            OptionalIntegerText(MapQpc(clock_fit, block.gameplay_started_qpc)),
            OptionalIntegerText(block.completed_qpc),
            OptionalIntegerText(MapQpc(clock_fit, block.completed_qpc)),
            IntegerText(block.configured_duration_ms),
            Number(block.consumed_gameplay_ms),
            IntegerText(block.score),
            IntegerText(block.event_count),
            IntegerText(block.technical_event_count),
            IntegerText(clock_fit.warning_mask),
        });
    }
    CloseOutput(output, "block result CSV");
}

[[nodiscard]] json::Value ClockFitJson(
    const std::vector<session::ClockJournalRecord>& source_records,
    const std::vector<derive::ClockAnchor>& anchors,
    const derive::QpcUtcClockFit& fit,
    const std::int64_t qpc_frequency) {
    JsonArray encoded_anchors;
    encoded_anchors.reserve(anchors.size());
    for (std::size_t index = 0; index < anchors.size(); ++index) {
        const auto& anchor = anchors[index];
        const auto& residual = fit.residuals[index];
        encoded_anchors.emplace_back(JsonObject{
            {"absolute_residual_beyond_uncertainty_ns",
             Number(residual.absolute_residual_beyond_uncertainty_ns)},
            {"exceeds_warning_limit", residual.exceeds_warning_limit},
            {"qpc_after", source_records[index].anchor.qpc_after},
            {"qpc_before", source_records[index].anchor.qpc_before},
            {"qpc_midpoint", anchor.qpc_ticks},
            {"residual_ns", Number(residual.residual_ns)},
            {"source", source_records[index].anchor.source},
            {"uncertainty_ns", anchor.uncertainty_ns},
            {"used_in_fit", residual.used_in_fit},
            {"utc_unix_ns", anchor.utc_unix_ns},
        });
    }
    return JsonObject{
        {"anchor_count", static_cast<std::int64_t>(fit.anchor_count)},
        {"anchors", std::move(encoded_anchors)},
        {"detected_clock_step_count",
         static_cast<std::int64_t>(fit.detected_clock_step_count)},
        {"drift_measured", fit.drift_measured},
        {"estimated_mapping_uncertainty_ns",
         Number(fit.estimated_mapping_uncertainty_ns)},
        {"fitted_anchor_count",
         static_cast<std::int64_t>(fit.fitted_anchor_count)},
        {"fitted_drift_ppm", Number(fit.fitted_drift_ppm)},
        {"fitted_ns_per_qpc_tick", Number(fit.fitted_ns_per_qpc_tick)},
        {"mapping_available", fit.mapping_available},
        {"max_abs_residual_ns", Number(fit.max_abs_residual_ns)},
        {"nominal_ns_per_qpc_tick", Number(fit.nominal_ns_per_qpc_tick)},
        {"qpc_frequency_hz", qpc_frequency},
        {"reference_qpc", fit.reference_qpc},
        {"reference_utc_unix_ns", fit.reference_utc_unix_ns},
        {"relative_intercept_ns", Number(fit.relative_intercept_ns)},
        {"rms_fitted_residual_ns", Number(fit.rms_fitted_residual_ns)},
        {"schema", kClockFitSchema},
        {"warning_mask", static_cast<std::int64_t>(fit.warning_mask)},
        {"warnings", ClockWarningNames(fit.warning_mask)},
    };
}

void ValidateScientificIdentity(
    const json::Value& manifest,
    const session::ValidatedSession& validated,
    const std::optional<capture::ReportStreamIdentity>& reports,
    const std::vector<session::GameplayEventRecord>& events,
    const std::vector<session::GameplayBlockRecord>& blocks,
    const std::vector<session::ClockJournalRecord>& clocks) {
    if (manifest.At("schema").AsString() != "abcurves.capture.session.v2" ||
        manifest.At("session_id").AsString() != validated.session_id ||
        manifest.At("status").AsString() != session::ToString(validated.status)) {
        throw std::runtime_error(
            "source manifest identity/status disagrees with sealed validation");
    }
    const auto user_id = manifest.At("user_id").AsString();
    const auto qpc_frequency = manifest.At("qpc_frequency").AsInt();
    const auto sensitivity = manifest.At("trainer_sensitivity").AsDouble();
    const auto protocol_hash = manifest.At("protocol_sha256").AsString();
    if (qpc_frequency <= 0 ||
        (reports && reports->qpc_frequency != qpc_frequency) ||
        !std::isfinite(sensitivity) || sensitivity < 0.01 || sensitivity > 3.0 ||
        protocol_hash.size() != 64U) {
        throw std::runtime_error("source manifest scientific identity is invalid");
    }
    const auto identity_matches = [&](const session::GameplayJournalIdentity& id) {
        return id.session_id == validated.session_id && id.user_id == user_id &&
               id.qpc_frequency == qpc_frequency &&
               id.trainer_sensitivity == sensitivity;
    };
    for (const auto& record : events) {
        if (!identity_matches(record.identity) ||
            record.event.realized_target.protocol_hash != protocol_hash ||
            record.event.realized_target.trainer_sensitivity != sensitivity) {
            throw std::runtime_error(
                "trainer event identity disagrees with source manifest");
        }
    }
    for (const auto& record : blocks) {
        if (!identity_matches(record.identity)) {
            throw std::runtime_error(
                "block result identity disagrees with source manifest");
        }
    }
    for (const auto& record : clocks) {
        if (record.qpc_frequency != qpc_frequency) {
            throw std::runtime_error(
                "clock anchor identity disagrees with source manifest");
        }
    }
}

[[nodiscard]] JsonArray OutputArtifactInventory(
    const std::filesystem::path& staging) {
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(staging)) {
        if (entry.is_regular_file() && entry.path().filename() != L"export_manifest.json") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
        return left.filename().generic_string() < right.filename().generic_string();
    });
    JsonArray result;
    result.reserve(files.size());
    for (const auto& path : files) {
        result.emplace_back(JsonObject{
            {"relative_path", path.filename().generic_string()},
            {"sha256", Sha256FileHex(path)},
            {"size_bytes", std::to_string(std::filesystem::file_size(path))},
        });
    }
    return result;
}

[[nodiscard]] JsonArray RequiredSourceInventory(
    const session::ValidatedSession& validated) {
    JsonArray result;
    result.reserve(kRequiredSourceArtifacts.size());
    for (const auto name : kRequiredSourceArtifacts) {
        const auto& artifact = SourceArtifact(validated, name);
        result.emplace_back(JsonObject{
            {"relative_path", artifact.relative_path},
            {"sha256", artifact.sha256},
            {"size_bytes", std::to_string(artifact.size_bytes)},
        });
    }
    return result;
}

[[nodiscard]] json::Value ExportManifest(
    const json::Value& source_manifest,
    const session::ValidatedSession& validated,
    const std::optional<capture::ReportStreamIdentity>& report_identity,
    const derive::DenseBinningResult& bins,
    const std::uint64_t report_count,
    const std::uint64_t event_count,
    const std::uint64_t block_count,
    const derive::QpcUtcClockFit& clock_fit,
    const derive::AxisConventionVersion axis_convention,
    const std::uint64_t maximum_dense_bins,
    JsonArray output_artifacts) {
    const auto axis = derive::DescribeAxisConvention(axis_convention);
    JsonObject range{
        {"bin_count", std::to_string(bins.bins.size())},
        {"first_bin_index", bins.range.first},
        {"grid_origin_unix_ns", bins.grid_origin_unix_ns},
        {"range_end_exclusive", bins.range.end_exclusive},
    };
    if (bins.bins.empty()) {
        range["first_begin_unix_ns"] = nullptr;
        range["last_end_unix_ns"] = nullptr;
    } else {
        range["first_begin_unix_ns"] = bins.bins.front().begin_unix_ns;
        range["last_end_unix_ns"] = bins.bins.back().end_unix_ns;
    }

    return JsonObject{
        {"adapter_claim",
         "transparent_native_count_interchange_not_a_direct_phalm_m16_tensor_format"},
        {"adapter_id", kDenseMouseCsvSchema},
        {"artifacts", std::move(output_artifacts)},
        {"clock_mapping", JsonObject{
            {"estimated_uncertainty_ns",
             Number(clock_fit.estimated_mapping_uncertainty_ns)},
            {"mapping_available", clock_fit.mapping_available},
            {"warning_mask", static_cast<std::int64_t>(clock_fit.warning_mask)},
            {"warnings", ClockWarningNames(clock_fit.warning_mask)},
        }},
        {"continuation", JsonObject{
            {"b_seam_defined", false},
            {"policy",
             "no_prefix_future_cut_is_selected_by_this_interchange_export"},
        }},
        {"coordinate_spaces", JsonObject{
            {"axis_adapter", JsonObject{
                {"derived_x_positive", std::string(axis.derived_x_positive)},
                {"derived_y_positive", std::string(axis.derived_y_positive)},
                {"stable_name", std::string(axis.stable_name)},
                {"version", static_cast<std::int64_t>(axis.version)},
            }},
            {"crosshair_integration",
             "row_pre_plus_row_canonical_delta_equals_row_post_and_next_row_pre"},
            {"dense_crosshair_origin",
             "zero_zero_immediately_before_first_exported_bin"},
            {"device_delta", "hid_dx_and_hid_dy_preserved_verbatim"},
            {"trainer_geometry",
             "separate_canonical_gameplay_camera_count_space_preserved_in_event_records"},
        }},
        {"counts", JsonObject{
            {"block_results", std::to_string(block_count)},
            {"decoded_reports", std::to_string(report_count)},
            {"dense_millisecond_bins", std::to_string(bins.bins.size())},
            {"trainer_events", std::to_string(event_count)},
        }},
        {"dense_grid", JsonObject{
            {"assignment", "begin_unix_ns<=capture_unix_ns<end_unix_ns"},
            {"empty_bins", "explicit_zero_rows"},
            {"initial_buttons_assumption", "zero_before_first_exported_report"},
            {"maximum_dense_bins", std::to_string(maximum_dense_bins)},
            {"period_ns", derive::kNanosecondsPerMillisecond},
            {"range", std::move(range)},
            {"timestamp_source", "authoritative_report.capture_unix_ns"},
        }},
        {"derived_quality", JsonObject{
            {"capture_sequence_regression_count",
             std::to_string(bins.capture_sequence_regression_count)},
            {"quality_mask", std::to_string(bins.quality_mask)},
            {"timestamp_regression_count",
             std::to_string(bins.timestamp_regression_count)},
        }},
        {"report_stream_identity", report_identity
            ? json::Value(JsonObject{
                {"bus", static_cast<std::int64_t>(report_identity->bus)},
                {"decoder_spec", report_identity->decoder_spec},
                {"descriptor_sha256", report_identity->descriptor_sha256},
                {"device", static_cast<std::int64_t>(report_identity->device)},
                {"endpoint", static_cast<std::int64_t>(report_identity->endpoint)},
                {"qpc_frequency", report_identity->qpc_frequency},
              })
            : json::Value(nullptr)},
        {"schema", kResearchExportSchema},
        {"source_artifacts", RequiredSourceInventory(validated)},
        {"source_session", JsonObject{
            {"protocol_id", source_manifest.At("protocol_id").AsString()},
            {"protocol_sha256",
             source_manifest.At("protocol_sha256").AsString()},
            {"qpc_frequency", source_manifest.At("qpc_frequency").AsInt()},
            {"sensitivity_definition",
             source_manifest.At("sensitivity_definition").AsString()},
            {"session_id", validated.session_id},
            {"status", session::ToString(validated.status)},
            {"trainer_sensitivity",
             source_manifest.At("trainer_sensitivity").AsDouble()},
        }},
    };
}

void CopySourceArtifact(const std::filesystem::path& source,
                        const std::filesystem::path& destination) {
    if (!std::filesystem::copy_file(source, destination)) {
        throw std::runtime_error("failed to copy validated source artifact");
    }
}

}  // namespace

ResearchExportResult ExportResearchSession(
    const ResearchExportOptions& options) {
    static_cast<void>(derive::DescribeAxisConvention(options.axis_convention));
    if (!options.sealed_session_directory.is_absolute() ||
        !options.output_directory.is_absolute() ||
        options.output_directory.filename().empty() ||
        options.maximum_dense_bins == 0U) {
        throw std::invalid_argument("research export options are incomplete");
    }

    // Validation is deliberately first: a failed source never causes even a
    // staging directory to appear.
    const auto source_input =
        options.sealed_session_directory.lexically_normal();
    const auto validated = session::ValidateSealedSession(source_input);
    const auto source = std::filesystem::weakly_canonical(source_input);
    for (const auto artifact : kRequiredSourceArtifacts) {
        static_cast<void>(SourceArtifact(validated, artifact));
    }

    const auto output_parent = std::filesystem::weakly_canonical(
        options.output_directory.parent_path());
    const auto output =
        (output_parent / options.output_directory.filename()).lexically_normal();
    if (IsWithin(output, source)) {
        throw std::invalid_argument(
            "research output may not be inside the sealed source session");
    }
    if (std::filesystem::exists(output)) {
        throw std::runtime_error("research output directory already exists");
    }

    const auto source_manifest_text = ReadUtf8File(source / "manifest.json");
    const auto source_manifest = json::Parse(source_manifest_text);
    std::optional<capture::ReportStreamIdentity> report_identity;
    std::vector<capture::AuthoritativeReport> reports;
    const auto report_path = source / "capture" / "mouse_reports.abcr2";
    const bool report_is_validated = std::any_of(
        validated.artifacts.begin(), validated.artifacts.end(),
        [](const auto& artifact) {
            return artifact.relative_path == "capture/mouse_reports.abcr2";
        });
    if (report_is_validated && std::filesystem::is_regular_file(report_path)) {
        try {
            capture::ReportStreamIdentity identity;
            reports = ReadReports(report_path, identity);
            report_identity = std::move(identity);
        } catch (const std::exception&) {
            // Decoded reports are a convenience derivative. The sealed raw
            // device PCAP remains the research source when this file cannot be
            // read; preprocessing can reconstruct or replace the decoder.
            reports.clear();
            report_identity.reset();
        }
    }
    auto clock_records = session::ReadClockJournal(
        source / "clocks" / "anchors.jsonl");
    auto events = session::ReadGameplayEvents(
        source / "gameplay" / "events.jsonl");
    auto blocks = session::ReadGameplayBlockResults(
        source / "gameplay" / "blocks.jsonl");
    ValidateScientificIdentity(source_manifest, validated, report_identity,
                               events, blocks, clock_records);

    const auto qpc_frequency = source_manifest.At("qpc_frequency").AsInt();
    const auto anchors = ConvertClockAnchors(clock_records, qpc_frequency);
    if (anchors.size() > 4'096U) {
        throw std::length_error(
            "clock anchor count exceeds the offline export safety limit");
    }
    derive::ClockFitConfig fit_config;
    fit_config.qpc_frequency_hz = qpc_frequency;
    fit_config.max_anchors = 4'096U;
    const auto clock_fit = derive::FitQpcUtcClockAnchors(anchors, fit_config);

    derive::DenseBinningResult dense;
    dense.axis_convention = options.axis_convention;
    if (!reports.empty()) {
        const auto minimum_timestamp = std::min_element(
            reports.begin(), reports.end(), [](const auto& left, const auto& right) {
                return left.capture_unix_ns < right.capture_unix_ns;
            })->capture_unix_ns;
        const auto grid = derive::MillisecondGrid::FloorAligned(minimum_timestamp);
        const auto range = derive::CoveringBinRange(reports, grid);
        if (!range) throw std::logic_error("non-empty reports lack a bin range");
        if (range->Size() > options.maximum_dense_bins) {
            throw std::length_error(
                "dense export range exceeds the configured safety limit");
        }
        derive::MillisecondBinningOptions bin_options;
        bin_options.axis_convention = options.axis_convention;
        bin_options.initial_crosshair = {0, 0};
        bin_options.initial_buttons = 0U;
        dense = derive::DeriveMillisecondBins(reports, grid, *range, bin_options);
    }

    std::filesystem::create_directories(output_parent);
    const auto staging = output_parent /
        (output.filename().wstring() + L".partial");
    if (std::filesystem::exists(staging) ||
        !std::filesystem::create_directory(staging)) {
        throw std::runtime_error("research export staging directory already exists");
    }
    try {
        WriteMouseCsv(staging / "mouse_1ms.csv", dense);
        WriteEventCsv(staging / "trainer_events.csv", events, clock_fit);
        WriteBlockCsv(staging / "block_results.csv", blocks, clock_fit);
        AtomicWriteFile(
            staging / "clock_fit.json",
            json::DumpCanonical(
                ClockFitJson(clock_records, anchors, clock_fit, qpc_frequency),
                true) + "\n");

        // These byte-identical, already validated records preserve every field
        // (including nested target policy and click hypotheses) beyond the
        // convenience CSV indexes.
        CopySourceArtifact(source / "manifest.json",
                           staging / "source_manifest.json");
        CopySourceArtifact(source / "gameplay" / "events.jsonl",
                           staging / "source_events.jsonl");
        CopySourceArtifact(source / "gameplay" / "blocks.jsonl",
                           staging / "source_blocks.jsonl");
        CopySourceArtifact(source / "clocks" / "anchors.jsonl",
                           staging / "source_anchors.jsonl");

        auto export_manifest = ExportManifest(
            source_manifest,
            validated,
            report_identity,
            dense,
            reports.size(),
            events.size(),
            blocks.size(),
            clock_fit,
            options.axis_convention,
            options.maximum_dense_bins,
            OutputArtifactInventory(staging));
        AtomicWriteFile(staging / "export_manifest.json",
                        json::DumpCanonical(export_manifest, true) + "\n");

        std::filesystem::rename(staging, output);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(staging, ignored);
        throw;
    }

    return {
        output,
        validated.session_id,
        static_cast<std::uint64_t>(reports.size()),
        static_cast<std::uint64_t>(dense.bins.size()),
        static_cast<std::uint64_t>(events.size()),
        static_cast<std::uint64_t>(blocks.size()),
        clock_fit.warning_mask,
    };
}

}  // namespace abdc::research
