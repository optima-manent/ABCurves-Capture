#include "TestHarness.h"

#include "base/AtomicFile.h"
#include "base/Binary.h"
#include "base/Json.h"
#include "base/Sha256.h"
#include "capture/DevicePcapWriter.h"
#include "capture/PcapReader.h"
#include "capture/ReportStream.h"
#include "capture/UsbPcapPacket.h"
#include "session/AppendOnlyJsonl.h"
#include "session/RecordingSession.h"

#include <chrono>
#include <cmath>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace {

std::filesystem::path RecordingTempRoot(const char* label) {
    const auto suffix =
        std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
        (std::string("abcurves_recording_") + label + "_" +
         std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

void WriteBytes(const std::filesystem::path& path,
                const std::vector<std::byte>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("test artifact write failed");
}

void WriteRecoverablePcapPartial(const std::filesystem::path& path) {
    std::vector<std::byte> bytes{
        std::byte{0xd4}, std::byte{0xc3}, std::byte{0xb2}, std::byte{0xa1}};
    abdc::binary::AppendU16(bytes, 2U);
    abdc::binary::AppendU16(bytes, 4U);
    abdc::binary::AppendU32(bytes, 0U);
    abdc::binary::AppendU32(bytes, 0U);
    abdc::binary::AppendU32(bytes, 65'535U);
    abdc::binary::AppendU32(bytes, 249U);  // LINKTYPE_USBPCAP
    abdc::binary::AppendU32(bytes, 1'700'000'000U);
    abdc::binary::AppendU32(bytes, 100U);
    std::vector<std::byte> packet;
    abdc::binary::AppendU16(packet, 27U);
    abdc::binary::AppendU64(packet, 55U);
    abdc::binary::AppendU32(packet, 0U);
    abdc::binary::AppendU16(packet, 9U);
    packet.push_back(std::byte{1});
    abdc::binary::AppendU16(packet, 3U);
    abdc::binary::AppendU16(packet, 7U);
    packet.push_back(std::byte{0x81});
    packet.push_back(std::byte{1});
    abdc::binary::AppendU32(packet, 3U);
    packet.push_back(std::byte{1});
    packet.push_back(std::byte{2});
    packet.push_back(std::byte{3});
    abdc::binary::AppendU32(bytes, static_cast<std::uint32_t>(packet.size()));
    abdc::binary::AppendU32(bytes, static_cast<std::uint32_t>(packet.size()));
    bytes.insert(bytes.end(), packet.begin(), packet.end());
    // Simulate an interrupted next record. Recovery must retain the first one.
    bytes.push_back(std::byte{0xaa});
    bytes.push_back(std::byte{0xbb});
    WriteBytes(path, bytes);
}

class FakeRecordingCapture final
    : public abdc::session::IRecordingCaptureControl {
public:
    explicit FakeRecordingCapture(const bool initially_ready = true)
        : initially_ready_(initially_ready) {}

    void BeginCapture(
        const abdc::session::CaptureStartRequest& request) override {
        if (!request.capture_directory.is_absolute() ||
            !std::filesystem::is_directory(request.capture_directory) ||
            !request.session_lease.is_absolute() ||
            !std::filesystem::is_regular_file(request.session_lease) ||
            request.qpc_frequency <= 0) {
            throw std::invalid_argument("fake received an invalid capture request");
        }
        capture_directory_ = request.capture_directory;
        locked_mouse_ = request.locked_mouse;
        qpc_frequency_ = request.qpc_frequency;
        snapshot_.ready = initially_ready_;
        snapshot_.running = true;
        ++begin_count_;
    }

    void RequestStop() override {
        ++stop_count_;
        snapshot_.stop_requested = true;
        if (snapshot_.fatal_issue) return;

        WriteFinalCaptureProducts();
        snapshot_.running = false;
        snapshot_.stop_complete = true;
        snapshot_.clean_stop = true;
    }

    abdc::session::RecordingCaptureSnapshot Snapshot() const override {
        return snapshot_;
    }

    void MakeReady() { snapshot_.ready = true; }
    void CorruptPublishedPcap() { corrupt_published_pcap_ = true; }
    void CorruptOptionalDerivatives() {
        corrupt_optional_derivatives_ = true;
    }
    void PublishHeaderOnlyCapture() { publish_header_only_capture_ = true; }

    void FailWithRecoverablePrefix(const abdc::session::RuntimeIssue issue) {
        WriteRecoverablePcapPartial(
            capture_directory_ / "mouse_usb.pcap.partial");
        snapshot_.counters.raw_pcap_records = 1U;
        snapshot_.fatal_issue = issue;
        snapshot_.detail = "simulated helper loss after a durable PCAP record";
        snapshot_.running = false;
        snapshot_.stop_complete = false;
        snapshot_.clean_stop = false;
    }

    void FailWithoutCaptureSource(const abdc::session::RuntimeIssue issue) {
        snapshot_.fatal_issue = issue;
        snapshot_.detail = "simulated helper loss before a PCAP record was durable";
        snapshot_.running = false;
        snapshot_.stop_complete = false;
        snapshot_.clean_stop = false;
    }

    [[nodiscard]] int BeginCount() const noexcept { return begin_count_; }
    [[nodiscard]] int StopCount() const noexcept { return stop_count_; }

private:
    void WriteFinalCaptureProducts() {
        abdc::capture::PcapHeader header;
        header.little_endian = true;
        header.resolution = abdc::capture::TimestampResolution::Microseconds;
        header.major = 2U;
        header.minor = 4U;
        header.snap_length = 65'535U;
        header.link_type = abdc::capture::PcapReader::kUsbPcapLinkType;
        {
            abdc::capture::DevicePcapWriter writer(
                capture_directory_ / "mouse_usb.pcap.partial", header,
                locked_mouse_.usb_bus, locked_mouse_.usb_device);
            const std::uint64_t endpoint_record_count =
                publish_header_only_capture_ ? 0U : 7U;
            for (std::uint64_t index = 0U;
                 index < endpoint_record_count; ++index) {
                std::vector<std::byte> packet;
                abdc::binary::AppendU16(packet, 27U);
                abdc::binary::AppendU64(packet, 100U + index);
                abdc::binary::AppendU32(packet, 0U);
                abdc::binary::AppendU16(packet, 9U);
                packet.push_back(std::byte{1});
                abdc::binary::AppendU16(packet, locked_mouse_.usb_bus);
                abdc::binary::AppendU16(packet, locked_mouse_.usb_device);
                packet.push_back(static_cast<std::byte>(
                    locked_mouse_.interrupt_in_endpoint));
                packet.push_back(std::byte{1});
                abdc::binary::AppendU32(packet, 3U);
                packet.push_back(std::byte{0});
                packet.push_back(std::byte{1});
                packet.push_back(std::byte{2});
                abdc::capture::PcapRecord record;
                record.timestamp_seconds = 1'700'000'000U;
                record.timestamp_fraction = static_cast<std::uint32_t>(index);
                record.resolution = header.resolution;
                record.original_length =
                    static_cast<std::uint32_t>(packet.size());
                record.data = packet;
                writer.Append(record,
                              abdc::capture::UsbPcapPacket::Parse(packet));
            }
            writer.Finalize(capture_directory_ / "mouse_usb.pcap");
        }

        const std::vector<std::byte> descriptor{std::byte{1}};
        abdc::capture::ReportStreamIdentity identity;
        identity.bus = locked_mouse_.usb_bus;
        identity.device = locked_mouse_.usb_device;
        identity.endpoint = locked_mouse_.interrupt_in_endpoint;
        identity.descriptor_sha256 = abdc::Sha256Hex(descriptor);
        identity.descriptor_evidence = descriptor;
        identity.decoder_spec = "recording-test-decoder-v1";
        identity.qpc_frequency = qpc_frequency_;
        {
            abdc::capture::ReportStreamWriter writer(
                capture_directory_ / "mouse_reports.abcr2.partial",
                identity, 2U);
            const std::uint64_t decoded_report_count =
                publish_header_only_capture_ ? 0U : 5U;
            for (std::uint64_t index = 0U;
                 index < decoded_report_count; ++index) {
                abdc::capture::AuthoritativeReport report;
                report.capture_sequence = index + 1U;
                report.pcap_sequence = index;
                report.capture_unix_ns =
                    1'700'000'000'000'000'000LL +
                    static_cast<std::int64_t>(index);
                report.observed_qpc =
                    1'000 + static_cast<std::int64_t>(index);
                report.irp_id = 100U + index;
                report.function = 9U;
                report.bus = locked_mouse_.usb_bus;
                report.device = locked_mouse_.usb_device;
                report.endpoint = locked_mouse_.interrupt_in_endpoint;
                report.transfer = 1U;
                report.info = 1U;
                report.payload = {std::byte{0}, std::byte{1}, std::byte{2}};
                writer.Append(report);
            }
            writer.Finalize(capture_directory_ / "mouse_reports.abcr2");
        }
        {
            abdc::session::AppendOnlyJsonlWriter writer(
                capture_directory_ / "capture_anomalies.jsonl.partial",
                "abcurves.capture.anomaly.v1");
            writer.Finalize(
                capture_directory_ / "capture_anomalies.jsonl");
        }
        if (corrupt_published_pcap_) {
            std::ofstream output(capture_directory_ / "mouse_usb.pcap",
                                 std::ios::binary | std::ios::app);
            output << "torn";
        }
        if (corrupt_optional_derivatives_) {
            for (const auto& path : {
                     capture_directory_ / "mouse_reports.abcr2",
                     capture_directory_ / "capture_anomalies.jsonl"}) {
                std::ofstream output(path, std::ios::binary | std::ios::trunc);
                output << "not a valid derivative";
            }
        }
        snapshot_.counters.raw_pcap_records =
            publish_header_only_capture_ ? 0U : 7U;
        snapshot_.counters.decoded_reports =
            publish_header_only_capture_ ? 0U : 5U;
    }

    bool initially_ready_ = true;
    std::filesystem::path capture_directory_;
    abdc::session::LockedMouseIdentity locked_mouse_;
    std::int64_t qpc_frequency_ = 0;
    abdc::session::RecordingCaptureSnapshot snapshot_;
    int begin_count_ = 0;
    int stop_count_ = 0;
    bool corrupt_published_pcap_ = false;
    bool corrupt_optional_derivatives_ = false;
    bool publish_header_only_capture_ = false;
};

abdc::session::RenderEvidence RuntimeRender() {
    return {1'920, 1'080, 2.0, 1.25, 0.5, 0.8,
            "linear-countspace-v1"};
}

abdc::session::RecordingSessionOptions RuntimeOptions(
    const std::filesystem::path& root) {
    static std::uint64_t identity = 0U;
    ++identity;

    abdc::session::RecordingSessionOptions options;
    options.workspace.output_root = root;
    options.workspace.session_id =
        "s-runtime-" + std::to_string(identity);
    options.workspace.user_id = "u-runtime-user";
    options.workspace.application_version = "0.2.0-test";
    options.workspace.source_revision = "recording-session-test";
    options.workspace.protocol_id = "aim-protocol-v2";
    options.workspace.protocol_sha256 = std::string(64U, 'a');
    options.workspace.scenario_seed = 0x1234'5678ULL;
    options.workspace.trainer_sensitivity = 1.0;
    options.workspace.qpc_frequency = 1'000;
    options.workspace.started_utc_ns = 1'700'000'000'000'000'000LL;

    options.trainer.qpc_frequency = options.workspace.qpc_frequency;
    options.trainer.scenario_seed = options.workspace.scenario_seed;
    options.trainer.trainer_sensitivity =
        options.workspace.trainer_sensitivity;
    options.trainer.block_duration_ms = 300;
    options.trainer.block_ordinals = {0};

    options.locked_mouse.selection_token = "mouse-certified";
    options.locked_mouse.display_name = "Research Mouse";
    options.locked_mouse.vendor_id = 0x046dU;
    options.locked_mouse.product_id = 0xc539U;
    options.locked_mouse.usb_bus = 3U;
    options.locked_mouse.usb_device = 7U;
    options.locked_mouse.interrupt_in_endpoint = 0x81U;
    options.locked_mouse.hid_descriptor_sha256 =
        abdc::Sha256Hex(std::vector<std::byte>{std::byte{1}});
    options.unpresented_render_calibration = RuntimeRender();
    options.checkpoint_interval_ticks = 50;
    return options;
}

abdc::platform::ClockAnchor RuntimeAnchor(const std::int64_t qpc,
                                          const char* source) {
    return {
        qpc,
        1'700'000'000'000'000'000LL + qpc * 1'000'000LL,
        qpc + 4,
        qpc + 2,
        4,
        source,
    };
}

void ReachRuntimeTarget(abdc::session::RecordingSession& session) {
    session.AdvanceTo(5'000);
    EXPECT_TRUE(session.trainer().target_view().has_value());
    EXPECT_TRUE(session.AcknowledgeTargetPresented(5'000, RuntimeRender()));
}

void FinishRuntimeSession(abdc::session::RecordingSession& session) {
    session.AdvanceTo(6'000);
    EXPECT_EQ(session.state(),
              abdc::session::RecordingSessionState::StopRequested);
    EXPECT_TRUE(session.TryFinalize(
        6'000, 1'700'000'001'000'000'000LL));
    EXPECT_TRUE(session.Result().has_value());
    EXPECT_TRUE(session.Result()->success);
}

}  // namespace

TEST_CASE("recording session waits for capture ready and completes with selected Raw Input") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("clean");
    FakeRecordingCapture capture(false);
    auto session = RecordingSession::Create(RuntimeOptions(root), capture);

    EXPECT_EQ(capture.BeginCount(), 1);
    EXPECT_TRUE(!session->TryStart(0));
    EXPECT_EQ(session->trainer().state(), abdc::trainer::EngineState::idle);
    capture.MakeReady();
    EXPECT_TRUE(session->TryStart(0));
    session->AddClockAnchor(RuntimeAnchor(1, "session_start"));
    ReachRuntimeTarget(*session);

    const auto target = session->trainer().target_view();
    EXPECT_TRUE(target.has_value());
    const auto initial_camera = session->trainer().camera();
    session->SubmitRawInput(
        {5'001, 100, 100, false, false},
        {false, "some-other-mouse", 0U, 0});
    EXPECT_EQ(session->trainer().camera(), initial_camera);

    session->SubmitRawInput(
        {
            5'002,
            static_cast<std::int64_t>(std::llround(target->absolute_x_counts)) -
                initial_camera.x,
            static_cast<std::int64_t>(std::llround(target->absolute_y_counts)) -
                initial_camera.y,
            true,
            false,
        },
        {true, "mouse-certified", 1U, 0});
    EXPECT_TRUE(session->trainer().camera() != initial_camera);

    FinishRuntimeSession(*session);
    EXPECT_EQ(capture.StopCount(), 1);
    EXPECT_EQ(session->Result()->status, SessionStatus::Complete);
    EXPECT_EQ(session->Result()->raw_pcap_records, 7U);
    EXPECT_EQ(session->Result()->decoded_reports, 5U);
    EXPECT_TRUE(std::filesystem::exists(session->Result()->archive->path));
    EXPECT_TRUE(ValidateSessionArchive(session->Result()->archive->path).valid);

    {
        AppendOnlyJsonlReader witnesses(
            session->Result()->seal->directory / "gameplay" /
                "raw_input_witness.jsonl",
            std::string(GameplayJournal::kRawInputWitnessSchema));
        EXPECT_TRUE(witnesses.Next()->At("selected_device").AsBool());
        EXPECT_TRUE(!witnesses.Next().has_value());
    }
    std::filesystem::remove_all(root);
}

TEST_CASE("recording session survives selected mouse motion before target presentation") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("pre_presentation_motion");
    FakeRecordingCapture capture;
    auto session = RecordingSession::Create(RuntimeOptions(root), capture);
    EXPECT_TRUE(session->TryStart(0));
    session->AddClockAnchor(RuntimeAnchor(1, "session_start"));
    session->AdvanceTo(5'000);
    EXPECT_TRUE(session->trainer().pending_target() != nullptr);

    const auto target_x = session->trainer().pending_target()->target_x_counts;
    const auto target_y = session->trainer().pending_target()->target_y_counts;
    const auto generation_distance =
        session->trainer().pending_target()->initial_distance_counts;
    session->SubmitRawInput(
        {
            5'001,
            static_cast<std::int64_t>(std::llround(target_x)),
            static_cast<std::int64_t>(std::llround(target_y)),
            false,
            false,
        },
        {true, "mouse-certified", 0U, 0});
    EXPECT_TRUE(session->AcknowledgeTargetPresented(5'002, RuntimeRender()));
    EXPECT_TRUE(std::abs(session->trainer().current_event()->initial_distance_counts -
                         generation_distance) > 1.0e-6);

    session->SubmitRawInput(
        {5'003, 0, 0, true, false},
        {true, "mouse-certified", 1U, 0});
    session->AdvanceTo(6'002);
    EXPECT_EQ(session->state(), RecordingSessionState::StopRequested);
    EXPECT_TRUE(session->TryFinalize(
        6'002, 1'700'000'001'002'000'000LL));
    EXPECT_TRUE(session->Result().has_value());
    EXPECT_TRUE(session->Result()->success);
    EXPECT_TRUE(session->Result()->gameplay_events > 0U);
    EXPECT_TRUE(ValidateSessionArchive(session->Result()->archive->path).valid);

    const auto events = ReadGameplayEvents(
        session->Result()->seal->directory / "gameplay" / "events.jsonl");
    EXPECT_TRUE(!events.empty());
    EXPECT_EQ(events[0].event.realized_target.initial_distance_counts,
              generation_distance);
    EXPECT_EQ(events[0].event.initial_distance_counts,
              session->trainer().events()[0].initial_distance_counts);
    std::filesystem::remove_all(root);
}

TEST_CASE("published capture bytes are parsed before authoritative verification") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("corrupt_published_capture");
    FakeRecordingCapture capture;
    capture.CorruptPublishedPcap();
    auto options = RuntimeOptions(root);
    const auto partial = root /
        ("session_" + options.workspace.session_id + ".partial");
    auto session = RecordingSession::Create(std::move(options), capture);
    EXPECT_TRUE(session->TryStart(0));
    ReachRuntimeTarget(*session);
    session->AdvanceTo(6'000);
    EXPECT_EQ(session->state(), RecordingSessionState::StopRequested);
    EXPECT_TRUE(session->TryFinalize(
        6'000, 1'700'000'001'500'000'000LL));
    EXPECT_TRUE(session->Result().has_value());
    EXPECT_TRUE(!session->Result()->success);
    EXPECT_TRUE(!session->Result()->verified_authoritative_source);
    EXPECT_EQ(session->state(), RecordingSessionState::FinalizationFailed);
    EXPECT_TRUE(std::filesystem::exists(partial));
    session.reset();
    std::filesystem::remove_all(root);
}

TEST_CASE("header-only PCAP is archived without an authoritative-source claim") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("header_only_capture");
    FakeRecordingCapture capture;
    capture.PublishHeaderOnlyCapture();
    auto session = RecordingSession::Create(RuntimeOptions(root), capture);
    EXPECT_TRUE(session->TryStart(0));
    ReachRuntimeTarget(*session);
    FinishRuntimeSession(*session);

    EXPECT_EQ(session->Result()->status,
              SessionStatus::CompleteWithWarnings);
    EXPECT_EQ(session->Result()->raw_pcap_records, 0U);
    EXPECT_TRUE(!session->Result()->verified_authoritative_source);
    EXPECT_TRUE(session->Result()->archive.has_value());
    EXPECT_TRUE(ValidateSessionArchive(session->Result()->archive->path).valid);
    const auto manifest = abdc::json::Parse(abdc::ReadUtf8File(
        session->Result()->seal->directory / "manifest.json"));
    EXPECT_TRUE(!manifest.At("verified_authoritative_source").AsBool());
    EXPECT_EQ(manifest.At("raw_pcap_records").AsString(), std::string("0"));
    std::filesystem::remove_all(root);
}

TEST_CASE("focus cycles discard only the active event and journal it exactly once") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("focus");
    FakeRecordingCapture capture;
    auto session = RecordingSession::Create(RuntimeOptions(root), capture);
    EXPECT_TRUE(session->TryStart(0));
    ReachRuntimeTarget(*session);

    session->SetFocus(false, false, 5'010);
    EXPECT_EQ(session->state(), RecordingSessionState::Paused);
    EXPECT_EQ(session->JournaledEventCount(), 1U);
    session->AdvanceTo(5'010);
    session->AdvanceTo(5'010);
    EXPECT_EQ(session->JournaledEventCount(), 1U);

    session->SetFocus(true, false, 6'000);
    EXPECT_EQ(session->state(), RecordingSessionState::Recording);
    session->AdvanceTo(11'000);
    EXPECT_TRUE(session->AcknowledgeTargetPresented(11'000, RuntimeRender()));
    session->AdvanceTo(12'000);
    EXPECT_TRUE(session->TryFinalize(
        12'000, 1'700'000'002'000'000'000LL));
    EXPECT_TRUE(session->Result()->success);
    EXPECT_TRUE(session->Result()->verified_authoritative_source);

    const auto events = ReadGameplayEvents(
        session->Result()->seal->directory / "gameplay" / "events.jsonl");
    EXPECT_EQ(events.size(), session->trainer().events().size());
    EXPECT_EQ(events.size(), std::size_t{2});
    EXPECT_EQ(events.front().event.technical_outcome,
              abdc::trainer::TechnicalOutcome::focus_lost);
    EXPECT_TRUE(events.front().event.natural_outcome ==
                abdc::trainer::NaturalOutcome::none);
    std::filesystem::remove_all(root);
}

TEST_CASE("recoverable display interruption resumes through the normal countdown") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("display_resume");
    FakeRecordingCapture capture;
    auto session = RecordingSession::Create(RuntimeOptions(root), capture);
    EXPECT_TRUE(session->TryStart(0));
    ReachRuntimeTarget(*session);

    session->ReportIssue(RuntimeIssue::DisplayChanged, 5'010,
                         "display mode changed while a target was active");
    EXPECT_EQ(session->state(), RecordingSessionState::Paused);
    EXPECT_EQ(session->trainer().state(),
              abdc::trainer::EngineState::paused);
    EXPECT_EQ(session->JournaledEventCount(), 1U);

    EXPECT_TRUE(session->ResumeAfterRecoverableIssue(
        6'000, "display_reinitialized"));
    EXPECT_EQ(session->state(), RecordingSessionState::Recording);
    EXPECT_EQ(session->trainer().state(),
              abdc::trainer::EngineState::countdown);
    EXPECT_EQ(session->trainer().countdown_kind(),
              abdc::trainer::CountdownKind::resume);

    session->AdvanceTo(11'000);
    EXPECT_TRUE(session->AcknowledgeTargetPresented(11'000, RuntimeRender()));
    session->AdvanceTo(12'000);
    EXPECT_TRUE(session->TryFinalize(
        12'000, 1'700'000'002'500'000'000LL));
    EXPECT_TRUE(session->Result()->success);
    EXPECT_EQ(session->Result()->status,
              SessionStatus::CompleteWithWarnings);

    const auto events = ReadGameplayEvents(
        session->Result()->seal->directory / "gameplay" / "events.jsonl");
    EXPECT_EQ(events.size(), std::size_t{2});
    EXPECT_EQ(events.front().event.technical_outcome,
              abdc::trainer::TechnicalOutcome::display_changed);
    std::filesystem::remove_all(root);
}

TEST_CASE("optional capture witnesses become warnings without gating completion") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("warning");
    FakeRecordingCapture capture;
    auto session = RecordingSession::Create(RuntimeOptions(root), capture);
    EXPECT_TRUE(session->TryStart(0));
    session->ReportIssue(RuntimeIssue::RawInputUsbDifference, 100,
                         "optional witnesses arrived in different batches");
    EXPECT_EQ(session->state(), RecordingSessionState::Recording);
    ReachRuntimeTarget(*session);
    FinishRuntimeSession(*session);

    EXPECT_EQ(session->Result()->status, SessionStatus::CompleteWithWarnings);
    EXPECT_EQ(session->Result()->warning_count, 1U);
    bool saw_optional_issue = false;
    {
        AppendOnlyJsonlReader lifecycle(
            session->Result()->seal->directory / "gameplay" / "lifecycle.jsonl",
            std::string(GameplayJournal::kLifecycleSchema));
        while (auto record = lifecycle.Next()) {
            saw_optional_issue = saw_optional_issue ||
                record->At("name").AsString() ==
                    "issue_raw_input_usb_difference";
        }
    }
    EXPECT_TRUE(saw_optional_issue);
    std::filesystem::remove_all(root);
}

TEST_CASE("corrupt optional derivatives cannot invalidate a clean raw capture") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("corrupt_derivatives");
    FakeRecordingCapture capture;
    capture.CorruptOptionalDerivatives();
    auto session = RecordingSession::Create(RuntimeOptions(root), capture);
    EXPECT_TRUE(session->TryStart(0));
    ReachRuntimeTarget(*session);
    FinishRuntimeSession(*session);

    EXPECT_TRUE(session->Result()->success);
    EXPECT_EQ(session->Result()->status, SessionStatus::CompleteWithWarnings);
    EXPECT_EQ(session->Result()->raw_pcap_records, 7U);
    EXPECT_EQ(session->Result()->decoded_reports, 0U);
    EXPECT_TRUE(session->Result()->verified_authoritative_source);
    EXPECT_TRUE(ValidateSessionArchive(session->Result()->archive->path).valid);
    std::filesystem::remove_all(root);
}

TEST_CASE("capture loss pauses gameplay and archives the longest verified prefix") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("capture_loss");
    FakeRecordingCapture capture;
    auto session = RecordingSession::Create(RuntimeOptions(root), capture);
    EXPECT_TRUE(session->TryStart(0));
    ReachRuntimeTarget(*session);

    capture.FailWithRecoverablePrefix(RuntimeIssue::CaptureHelperLost);
    session->AdvanceTo(5'010);
    EXPECT_EQ(session->state(), RecordingSessionState::StopRequested);
    EXPECT_EQ(capture.StopCount(), 1);
    EXPECT_EQ(session->JournaledEventCount(), 1U);
    EXPECT_TRUE(session->TryFinalize(
        5'010, 1'700'000'003'000'000'000LL));
    EXPECT_TRUE(session->Result()->success);
    EXPECT_EQ(session->Result()->status, SessionStatus::CaptureLost);
    EXPECT_EQ(session->Result()->raw_pcap_records, 1U);
    EXPECT_TRUE(session->Result()->recovery_was_required);
    EXPECT_TRUE(session->Result()->verified_authoritative_source);
    EXPECT_TRUE(session->Result()->warning_count >= 3U);

    const auto capture_directory =
        session->Result()->seal->directory / "capture";
    EXPECT_TRUE(std::filesystem::exists(
        capture_directory / "mouse_usb.pcap"));
    EXPECT_TRUE(std::filesystem::exists(capture_directory / "recovery.json"));
    EXPECT_TRUE(!std::filesystem::exists(
        capture_directory / "mouse_usb.pcap.partial"));
    EXPECT_TRUE(ValidateSessionArchive(session->Result()->archive->path).valid);
    std::filesystem::remove_all(root);
}

TEST_CASE("capture loss never calls an archive a verified prefix when none exists") {
    using namespace abdc::session;
    const auto root = RecordingTempRoot("capture_loss_without_source");
    FakeRecordingCapture capture;
    auto session = RecordingSession::Create(RuntimeOptions(root), capture);
    EXPECT_TRUE(session->TryStart(0));
    ReachRuntimeTarget(*session);

    capture.FailWithoutCaptureSource(RuntimeIssue::CaptureHelperLost);
    session->AdvanceTo(5'010);
    EXPECT_EQ(session->state(), RecordingSessionState::StopRequested);
    EXPECT_TRUE(session->TryFinalize(
        5'010, 1'700'000'003'500'000'000LL));
    EXPECT_TRUE(session->Result()->success);
    EXPECT_TRUE(session->Result()->recovery_was_required);
    EXPECT_TRUE(!session->Result()->verified_authoritative_source);
    EXPECT_TRUE(session->Result()->archive.has_value());
    EXPECT_TRUE(ValidateSessionArchive(session->Result()->archive->path).valid);
    std::filesystem::remove_all(root);
}
