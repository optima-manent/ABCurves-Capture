#include "TestHarness.h"

#include "base/AtomicFile.h"
#include "base/Json.h"
#include "base/Sha256.h"
#include "capture/DevicePcapWriter.h"
#include "capture/PcapReader.h"
#include "capture/ReportStream.h"
#include "export/ResearchExport.h"
#include "protocol/protocol_v1.hpp"
#include "session/ClockJournal.h"
#include "session/GameplayJournal.h"
#include "session/SessionValidator.h"
#include "session/SessionWorkspace.h"
#include "trainer/TrainerEngine.h"

#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr std::int64_t kBaseUtc = 1'750'000'000'000'000'000LL;
constexpr std::int64_t kQpcFrequency = 1'000'000;

std::filesystem::path TempRoot() {
    const auto suffix =
        std::chrono::steady_clock::now().time_since_epoch().count();
    auto root = std::filesystem::temp_directory_path() /
        ("abcurves_research_export_" + std::to_string(suffix));
    std::filesystem::create_directories(root);
    return std::filesystem::absolute(root);
}

abdc::capture::AuthoritativeReport Report(
    const std::uint64_t sequence,
    const std::int64_t capture_offset_ns,
    const std::int32_t dx,
    const std::int32_t dy,
    const std::uint32_t buttons,
    const std::int32_t wheel = 0) {
    abdc::capture::AuthoritativeReport report;
    report.capture_sequence = sequence;
    report.pcap_sequence = sequence + 100U;
    report.capture_unix_ns = kBaseUtc + capture_offset_ns;
    report.observed_qpc = 1'000'000 + static_cast<std::int64_t>(sequence);
    report.irp_id = sequence + 200U;
    report.function = 9U;
    report.bus = 1U;
    report.device = 2U;
    report.endpoint = 0x81U;
    report.transfer = 1U;
    report.info = 1U;
    report.hid_dx = dx;
    report.hid_dy = dy;
    report.hid_wheel = wheel;
    report.buttons = buttons;
    report.payload = {std::byte{0x00}, std::byte{0x01}};
    return report;
}

abdc::platform::ClockAnchor Anchor(const std::int64_t midpoint) {
    return {
        midpoint - 1,
        kBaseUtc + (midpoint - 1'000'000) * 1'000,
        midpoint + 1,
        midpoint,
        2,
        "research_export_test",
    };
}

abdc::session::SessionCreateOptions SessionOptions(
    const std::filesystem::path& root) {
    abdc::session::SessionCreateOptions options;
    options.output_root = root;
    options.session_id = "s-research-export-test";
    options.user_id = "u-research-export-test";
    options.application_version = "test";
    options.source_revision = "test";
    options.protocol_id = "aim-protocol-v2";
    options.protocol_sha256 = abdc::protocol::ProtocolSha256();
    options.scenario_seed = 0x1234U;
    options.trainer_sensitivity = 1.25;
    options.qpc_frequency = kQpcFrequency;
    options.started_utc_ns = kBaseUtc;
    options.device = abdc::json::Value::Object{{"product", "Test Mouse"}};
    return options;
}

abdc::session::RenderEvidence RenderEvidence() {
    return {1'920, 1'080, 2.0, 1.25, 0.5, 0.8,
            "linear-countspace-v1"};
}

std::filesystem::path BuildSealedFixture(const std::filesystem::path& root) {
    using namespace abdc;
    auto workspace = session::SessionWorkspace::Create(SessionOptions(root));

    {
        capture::PcapHeader header;
        header.little_endian = true;
        header.resolution = capture::TimestampResolution::Microseconds;
        header.major = 2U;
        header.minor = 4U;
        header.snap_length = 65'535U;
        header.link_type = capture::PcapReader::kUsbPcapLinkType;
        capture::DevicePcapWriter writer(
            workspace.CaptureDirectory() / "mouse_usb.pcap.partial",
            header, 1U, 2U);
        writer.Finalize(workspace.CaptureDirectory() / "mouse_usb.pcap");
    }

    capture::ReportStreamIdentity report_identity;
    report_identity.bus = 1U;
    report_identity.device = 2U;
    report_identity.endpoint = 0x81U;
    report_identity.descriptor_sha256 = std::string(64U, 'b');
    report_identity.descriptor_evidence = {std::byte{0x01}};
    report_identity.decoder_spec = "test-decoder-v1";
    report_identity.qpc_frequency = kQpcFrequency;
    {
        capture::ReportStreamWriter writer(
            workspace.CaptureDirectory() / "mouse_reports.abcr2.partial",
            report_identity,
            2U);
        writer.Append(Report(1U, 100'000, 1, 2, 0U));
        writer.Append(Report(2U, 900'000, 3, -1, 1U, 1));
        writer.Append(Report(3U, 1'000'000, 2, 3, 1U));
        writer.Append(Report(4U, 3'100'000, 0, 0, 0U, -1));
        writer.Finalize(workspace.CaptureDirectory() / "mouse_reports.abcr2");
    }

    {
        session::ClockJournal clocks(workspace.ClocksDirectory(), kQpcFrequency);
        clocks.Append(Anchor(1'000'000));
        clocks.Append(Anchor(4'000'000));
        clocks.Append(Anchor(8'000'000));
        clocks.Finalize();
    }

    trainer::TrainerConfig trainer_config;
    trainer_config.qpc_frequency = kQpcFrequency;
    trainer_config.scenario_seed = 0x1234U;
    trainer_config.trainer_sensitivity = 1.25;
    trainer_config.block_duration_ms = 1'000;
    trainer_config.block_ordinals = {0U};
    trainer::TrainerEngine engine(trainer_config);
    engine.Start(1'000'000);
    engine.AdvanceTo(6'000'000);
    EXPECT_TRUE(engine.AcknowledgeTargetPresented(6'000'000));
    const auto view = engine.target_view();
    EXPECT_TRUE(view.has_value());
    engine.SubmitRawInput({
        6'010'000,
        static_cast<std::int64_t>(std::llround(view->absolute_x_counts)) -
            engine.camera().x,
        static_cast<std::int64_t>(std::llround(view->absolute_y_counts)) -
            engine.camera().y,
        true,
        false,
    });
    engine.SetFocused(false, 6'050'000);
    EXPECT_EQ(engine.events().size(), std::size_t{1});
    EXPECT_EQ(engine.block_results().size(), std::size_t{1});

    {
        session::GameplayJournal gameplay(
            workspace.GameplayDirectory(),
            {"s-research-export-test", "u-research-export-test",
             kQpcFrequency, 1.25});
        gameplay.AppendEvent(engine.events().front(), RenderEvidence());
        gameplay.AppendBlockResult(engine.block_results().front());
        gameplay.Finalize();
    }

    session::SessionSealOptions seal;
    seal.status = session::SessionStatus::Complete;
    seal.ended_utc_ns = kBaseUtc + 10'000'000'000LL;
    seal.raw_pcap_records = 4U;
    seal.decoded_reports = 4U;
    seal.gameplay_events = 1U;
    seal.stop_reason = "test_complete";
    const auto sealed = workspace.Seal(seal);
    return sealed.directory;
}

std::vector<std::vector<std::string>> ReadCsv(
    const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read test CSV");
    std::vector<std::vector<std::string>> rows;
    std::vector<std::string> row;
    std::string cell;
    bool quoted = false;
    char character = 0;
    while (input.get(character)) {
        if (quoted) {
            if (character == '"') {
                if (input.peek() == '"') {
                    input.get(character);
                    cell.push_back('"');
                } else {
                    quoted = false;
                }
            } else {
                cell.push_back(character);
            }
        } else if (character == '"') {
            quoted = true;
        } else if (character == ',') {
            row.push_back(std::move(cell));
            cell.clear();
        } else if (character == '\n') {
            row.push_back(std::move(cell));
            cell.clear();
            rows.push_back(std::move(row));
            row.clear();
        } else if (character != '\r') {
            cell.push_back(character);
        }
    }
    if (quoted || !cell.empty() || !row.empty()) {
        throw std::runtime_error("malformed test CSV");
    }
    return rows;
}

std::map<std::string, std::size_t> HeaderIndex(
    const std::vector<std::string>& header) {
    std::map<std::string, std::size_t> result;
    for (std::size_t index = 0; index < header.size(); ++index) {
        result.emplace(header[index], index);
    }
    return result;
}

abdc::json::Value ReadJson(const std::filesystem::path& path) {
    return abdc::json::Parse(abdc::ReadUtf8File(path));
}

}  // namespace

TEST_CASE("research export preserves dense sums pre-delta rows and no B seam") {
    const auto root = TempRoot();
    const auto source = BuildSealedFixture(root);
    const auto source_manifest_hash =
        abdc::Sha256FileHex(source / "manifest.json");

    abdc::research::ResearchExportOptions options;
    options.sealed_session_directory = source;
    options.output_directory = root / "research-one";
    const auto exported = abdc::research::ExportResearchSession(options);
    EXPECT_EQ(exported.report_count, 4ULL);
    EXPECT_EQ(exported.bin_count, 4ULL);
    EXPECT_EQ(exported.event_count, 1ULL);
    EXPECT_EQ(exported.block_count, 1ULL);

    const auto rows = ReadCsv(exported.output_directory / "mouse_1ms.csv");
    EXPECT_EQ(rows.size(), std::size_t{5});
    const auto columns = HeaderIndex(rows.front());
    std::int64_t device_dx_sum = 0;
    std::int64_t device_dy_sum = 0;
    std::int64_t canonical_dx_sum = 0;
    std::int64_t canonical_dy_sum = 0;
    std::uint64_t report_sum = 0;
    for (std::size_t row = 1; row < rows.size(); ++row) {
        device_dx_sum += std::stoll(rows[row][columns.at("device_dx")]);
        device_dy_sum += std::stoll(rows[row][columns.at("device_dy")]);
        canonical_dx_sum += std::stoll(rows[row][columns.at("canonical_dx")]);
        canonical_dy_sum += std::stoll(rows[row][columns.at("canonical_dy")]);
        report_sum += std::stoull(rows[row][columns.at("report_count")]);
        if (row > 1U) {
            EXPECT_EQ(rows[row][columns.at("crosshair_pre_x_counts")],
                      rows[row - 1U][columns.at("crosshair_post_x_counts")]);
            EXPECT_EQ(rows[row][columns.at("crosshair_pre_y_counts")],
                      rows[row - 1U][columns.at("crosshair_post_y_counts")]);
        }
    }
    EXPECT_EQ(device_dx_sum, 6LL);
    EXPECT_EQ(device_dy_sum, 4LL);
    EXPECT_EQ(canonical_dx_sum, 6LL);
    EXPECT_EQ(canonical_dy_sum, -4LL);
    EXPECT_EQ(report_sum, 4ULL);
    EXPECT_EQ(rows[3][columns.at("report_count")], std::string("0"));
    // The report on the exact +1 ms edge belongs to the following row.
    EXPECT_EQ(rows[2][columns.at("device_dx")], std::string("2"));

    const auto manifest = ReadJson(exported.output_directory /
                                   "export_manifest.json");
    EXPECT_EQ(manifest.At("schema").AsString(),
              std::string(abdc::research::kResearchExportSchema));
    EXPECT_TRUE(!manifest.At("continuation").At("b_seam_defined").AsBool());
    EXPECT_EQ(
        manifest.At("coordinate_spaces").At("axis_adapter").At("stable_name")
            .AsString(),
        std::string("phalm_m16_count_space_x_right_y_up_v2"));
    EXPECT_EQ(
        manifest.At("adapter_claim").AsString(),
        std::string(
            "transparent_native_count_interchange_not_a_direct_phalm_m16_tensor_format"));
    EXPECT_TRUE(std::filesystem::exists(exported.output_directory /
                                        "source_events.jsonl"));
    EXPECT_TRUE(std::filesystem::exists(exported.output_directory /
                                        "source_anchors.jsonl"));
    EXPECT_TRUE(std::filesystem::exists(exported.output_directory /
                                        "clock_fit.json"));

    // The sealed source remains byte-for-byte valid after export.
    EXPECT_EQ(abdc::Sha256FileHex(source / "manifest.json"),
              source_manifest_hash);
    EXPECT_EQ(abdc::session::ValidateSealedSession(source).session_id,
              std::string("s-research-export-test"));
    std::filesystem::remove_all(root);
}

TEST_CASE("research export is deterministic and rejects unsafe dense gaps before output") {
    const auto root = TempRoot();
    const auto source = BuildSealedFixture(root);

    abdc::research::ResearchExportOptions first;
    first.sealed_session_directory = source;
    first.output_directory = root / "research-a";
    const auto first_result = abdc::research::ExportResearchSession(first);

    auto second = first;
    second.output_directory = root / "research-b";
    const auto second_result = abdc::research::ExportResearchSession(second);
    for (const auto& entry :
         std::filesystem::directory_iterator(first_result.output_directory)) {
        if (!entry.is_regular_file()) continue;
        const auto peer = second_result.output_directory / entry.path().filename();
        EXPECT_TRUE(std::filesystem::exists(peer));
        EXPECT_EQ(abdc::Sha256FileHex(entry.path()), abdc::Sha256FileHex(peer));
    }

    abdc::research::ResearchExportOptions bounded;
    bounded.sealed_session_directory = source;
    bounded.output_directory = root / "should-not-exist";
    bounded.maximum_dense_bins = 2U;
    EXPECT_THROW(abdc::research::ExportResearchSession(bounded));
    EXPECT_TRUE(!std::filesystem::exists(bounded.output_directory));
    std::filesystem::remove_all(root);
}
