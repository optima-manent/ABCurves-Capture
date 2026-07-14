#include "TestHarness.h"

#include "base/AtomicFile.h"
#include "base/Binary.h"
#include "base/Json.h"
#include "capture/DevicePcapWriter.h"
#include "capture/ReportStream.h"
#include "capture/UsbPcapPacket.h"
#include "session/AbandonedSessionRecovery.h"
#include "session/ClockJournal.h"
#include "session/GameplayJournal.h"
#include "session/SessionArchive.h"
#include "session/SessionValidator.h"
#include "session/SessionWorkspace.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

std::filesystem::path RecoverySessionRoot(const char* label) {
    const auto suffix =
        std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
        (std::string("abcurves_abandoned_") + label + "_" +
         std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

abdc::session::SessionCreateOptions RecoveryOptions(
    const std::filesystem::path& root, const std::string& session_id) {
    abdc::session::SessionCreateOptions options;
    options.output_root = root;
    options.session_id = session_id;
    options.user_id = "recovery-user-test";
    options.application_version = "0.2.0-test";
    options.source_revision = "test";
    options.protocol_id = "aim-protocol-v2";
    options.protocol_sha256 = std::string(64U, 'a');
    options.scenario_seed = 42U;
    options.trainer_sensitivity = 1.0;
    options.qpc_frequency = 1'000;
    options.started_utc_ns = 1'700'000'000'000'000'000LL;
    options.device = abdc::json::Value::Object{
        {"product", "Test Mouse"},
        {"identity_scope", "certified_interrupt_endpoint"},
        {"usb_bus", 3},
        {"usb_device", 7},
        {"interrupt_in_endpoint", 129},
        {"hid_descriptor_sha256", std::string(64U, 'a')},
    };
    return options;
}

std::vector<std::byte> UsbPcapRecordData() {
    std::vector<std::byte> data;
    abdc::binary::AppendU16(data, 27U);
    abdc::binary::AppendU64(data, 55U);
    abdc::binary::AppendU32(data, 0U);
    abdc::binary::AppendU16(data, 9U);
    data.push_back(std::byte{1});
    abdc::binary::AppendU16(data, 3U);
    abdc::binary::AppendU16(data, 7U);
    data.push_back(std::byte{0x81});
    data.push_back(std::byte{1});
    abdc::binary::AppendU32(data, 3U);
    data.push_back(std::byte{1});
    data.push_back(std::byte{2});
    data.push_back(std::byte{3});
    return data;
}

void WriteEndpointPcapPartial(const std::filesystem::path& capture_directory) {
    abdc::capture::PcapHeader header;
    header.little_endian = true;
    header.resolution = abdc::capture::TimestampResolution::Microseconds;
    header.major = 2U;
    header.minor = 4U;
    header.snap_length = 65'535U;
    header.link_type = abdc::capture::PcapReader::kUsbPcapLinkType;

    abdc::capture::PcapRecord record;
    record.timestamp_seconds = 1'700'000'000U;
    record.timestamp_fraction = 123U;
    record.resolution = abdc::capture::TimestampResolution::Microseconds;
    record.data = UsbPcapRecordData();
    record.original_length = static_cast<std::uint32_t>(record.data.size());
    const auto packet = abdc::capture::UsbPcapPacket::Parse(record.data);
    abdc::capture::DevicePcapWriter writer(
        capture_directory / "mouse_usb.pcap.partial", header, 3U, 7U);
    writer.Append(record, packet);
    writer.Checkpoint();
}

void WriteHeaderOnlyEndpointPcapPartial(
    const std::filesystem::path& capture_directory) {
    abdc::capture::PcapHeader header;
    header.little_endian = true;
    header.resolution = abdc::capture::TimestampResolution::Microseconds;
    header.major = 2U;
    header.minor = 4U;
    header.snap_length = 65'535U;
    header.link_type = abdc::capture::PcapReader::kUsbPcapLinkType;
    abdc::capture::DevicePcapWriter writer(
        capture_directory / "mouse_usb.pcap.partial", header, 3U, 7U);
    writer.Checkpoint();
}

void WriteMismatchedReportPartial(
    const std::filesystem::path& capture_directory) {
    abdc::capture::ReportStreamIdentity identity;
    identity.bus = 3U;
    identity.device = 7U;
    identity.endpoint = 0x81U;
    identity.descriptor_sha256 = std::string(64U, 'b');
    identity.descriptor_evidence = {std::byte{1}};
    identity.decoder_spec = "mismatched-test-decoder";
    identity.qpc_frequency = 1'000;
    abdc::capture::ReportStreamWriter writer(
        capture_directory / "mouse_reports.abcr2.partial",
        std::move(identity));
    writer.Checkpoint();
}

abdc::session::RenderEvidence RecoveryRenderEvidence() {
    return {1'920, 1'080, 2.0, 1.25, 0.5, 0.8,
            "linear-countspace-v1"};
}

void WriteGameplayAndClockPartials(
    const abdc::session::SessionWorkspace& workspace,
    const std::string& session_id, const bool append_torn_tail) {
    {
        abdc::session::GameplayJournal journal(
            workspace.GameplayDirectory(),
            {session_id, "recovery-user-test", 1'000, 1.0});
        EXPECT_TRUE(journal.TryAppendRawInputWitness(
            {100, true, "ri-recovery-test", 2, -1, 1U, 0}));
        journal.AppendLifecycle(
            {110, "recording_started", std::nullopt, std::nullopt, "test"});
        journal.AppendPause({120, true, "manual_pause", std::nullopt});
        journal.AppendFocus({130, false, false, std::nullopt});
        journal.AppendPresentation(
            {140, 0, true, RecoveryRenderEvidence(), "presented"});
        journal.Checkpoint();
    }
    {
        abdc::session::ClockJournal clocks(workspace.ClocksDirectory(), 1'000);
        clocks.Append({100, 1'700'000'000'000'000'000LL, 102, 101, 2,
                       "startup"});
        clocks.Checkpoint();
    }
    if (append_torn_tail) {
        std::ofstream output(
            workspace.GameplayDirectory() / "presentation.jsonl.partial",
            std::ios::binary | std::ios::app);
        const std::array<char, 5> torn{'t', 'o', 'r', 'n', '!'};
        output.write(torn.data(), static_cast<std::streamsize>(torn.size()));
    }
}

}  // namespace

TEST_CASE("abandoned recovery skips a workspace while its writer lease is held") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("busy");
    {
        auto workspace = SessionWorkspace::Create(
            RecoveryOptions(root, "recovery-busy-test"));
        const auto partial = workspace.Path();
        const auto recovered = RecoverAbandonedSession(
            partial, 1'700'000'001'000'000'000LL);
        EXPECT_EQ(recovered.state,
                  AbandonedRecoveryState::SkippedActiveWriter);
        EXPECT_TRUE(std::filesystem::exists(partial));
        EXPECT_TRUE(!std::filesystem::exists(partial / "recovery.json"));
    }
    std::filesystem::remove_all(root);
}

TEST_CASE("abandoned recovery leaves a legacy workspace without a lease untouched") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("unleased");
    std::filesystem::path partial;
    std::filesystem::path lease;
    {
        auto workspace = SessionWorkspace::Create(
            RecoveryOptions(root, "recovery-unleased-test"));
        partial = workspace.Path();
        lease = workspace.LeasePath();
        abdc::AtomicWriteFile(partial / "organizer-note.txt", "keep-me");
    }
    EXPECT_TRUE(std::filesystem::remove(lease));

    const auto recovered = RecoverAbandonedSession(
        partial, 1'700'000'001'000'000'000LL);
    EXPECT_EQ(recovered.state, AbandonedRecoveryState::Failed);
    EXPECT_TRUE(std::filesystem::exists(partial));
    EXPECT_EQ(abdc::ReadUtf8File(partial / "organizer-note.txt"),
              std::string("keep-me"));
    EXPECT_TRUE(!std::filesystem::exists(partial / "recovery.json"));
    std::filesystem::remove_all(root);
}

TEST_CASE("abandoned recovery rejects an invalid certified identity before mutation") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("invalid_identity");
    std::filesystem::path partial;
    {
        auto options = RecoveryOptions(root, "recovery-identity-test");
        options.device["hid_descriptor_sha256"] = "not-a-sha256";
        auto workspace = SessionWorkspace::Create(options);
        partial = workspace.Path();
    }

    const auto recovered = RecoverAbandonedSession(
        partial, 1'700'000'001'000'000'000LL);
    EXPECT_EQ(recovered.state, AbandonedRecoveryState::Failed);
    EXPECT_TRUE(std::filesystem::exists(partial));
    EXPECT_TRUE(!std::filesystem::exists(partial / "recovery.json"));
    EXPECT_TRUE(!std::filesystem::exists(
        partial / "capture" / "recovery.json"));
    std::filesystem::remove_all(root);
}

TEST_CASE("abandoned recovery trims journals and publishes a validated archive") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("complete");
    constexpr const char* session_id = "recovery-complete-test";
    std::filesystem::path partial;
    {
        auto workspace = SessionWorkspace::Create(
            RecoveryOptions(root, session_id));
        partial = workspace.Path();
        WriteEndpointPcapPartial(workspace.CaptureDirectory());
        WriteGameplayAndClockPartials(workspace, session_id, true);
    }

    const auto recovered = RecoverAbandonedSession(
        partial, 1'700'000'001'000'000'000LL);
    EXPECT_EQ(recovered.state, AbandonedRecoveryState::Recovered);
    EXPECT_EQ(recovered.status, SessionStatus::CaptureLost);
    EXPECT_TRUE(recovered.verified_authoritative_source);
    EXPECT_EQ(recovered.raw_pcap_records, 1U);
    EXPECT_EQ(recovered.gameplay_events, 0U);
    EXPECT_TRUE(recovered.warning_count >= 4U);
    EXPECT_TRUE(!std::filesystem::exists(partial));
    EXPECT_TRUE(std::filesystem::exists(recovered.sealed_session));
    EXPECT_TRUE(std::filesystem::exists(recovered.archive));
    EXPECT_TRUE(std::filesystem::exists(
        recovered.sealed_session / "capture" / "mouse_usb.pcap"));
    for (const auto* journal :
         {"events.jsonl", "blocks.jsonl", "raw_input_witness.jsonl",
          "lifecycle.jsonl", "pauses.jsonl", "focus.jsonl",
          "presentation.jsonl"}) {
        EXPECT_TRUE(std::filesystem::exists(
            recovered.sealed_session / "gameplay" / journal));
    }
    EXPECT_TRUE(std::filesystem::exists(
        recovered.sealed_session / "clocks" / "anchors.jsonl"));
    EXPECT_TRUE(std::filesystem::exists(
        recovered.sealed_session / "recovery.json"));
    const auto validated = ValidateSealedSession(recovered.sealed_session);
    EXPECT_EQ(validated.status, SessionStatus::CaptureLost);
    const auto archive_validation = ValidateSessionArchive(recovered.archive);
    EXPECT_TRUE(archive_validation.valid);

    const auto manifest = abdc::json::Parse(
        abdc::ReadUtf8File(recovered.sealed_session / "manifest.json"));
    EXPECT_TRUE(manifest.At("recovery_was_required").AsBool());
    EXPECT_TRUE(manifest.At("verified_authoritative_source").AsBool());
    EXPECT_EQ(manifest.At("raw_pcap_records").AsString(), std::string("1"));
    EXPECT_EQ(manifest.At("stop_reason").AsString(),
              std::string("abandoned_session_recovered"));
    std::filesystem::remove_all(root);
}

TEST_CASE("abandoned recovery never calls corrupt final PCAP authoritative") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("corrupt_pcap");
    std::filesystem::path partial;
    {
        auto workspace = SessionWorkspace::Create(
            RecoveryOptions(root, "recovery-corrupt-test"));
        partial = workspace.Path();
        abdc::AtomicWriteFile(
            workspace.CaptureDirectory() / "mouse_usb.pcap",
            "not-a-pcap");
    }

    const auto recovered = RecoverAbandonedSession(
        partial, 1'700'000'001'000'000'000LL);
    EXPECT_EQ(recovered.state, AbandonedRecoveryState::Recovered);
    EXPECT_EQ(recovered.status, SessionStatus::Interrupted);
    EXPECT_TRUE(!recovered.verified_authoritative_source);
    EXPECT_EQ(recovered.raw_pcap_records, 0U);
    EXPECT_TRUE(!std::filesystem::exists(
        recovered.sealed_session / "capture" / "mouse_usb.pcap"));
    EXPECT_TRUE(std::filesystem::exists(
        recovered.sealed_session / "capture" /
        "mouse_usb.pcap.unverified"));
    const auto manifest = abdc::json::Parse(
        abdc::ReadUtf8File(recovered.sealed_session / "manifest.json"));
    EXPECT_TRUE(!manifest.At("verified_authoritative_source").AsBool());
    std::filesystem::remove_all(root);
}

TEST_CASE("abandoned recovery never calls a header-only PCAP authoritative") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("header_only_pcap");
    std::filesystem::path partial;
    {
        auto workspace = SessionWorkspace::Create(
            RecoveryOptions(root, "recovery-header-only-test"));
        partial = workspace.Path();
        WriteHeaderOnlyEndpointPcapPartial(workspace.CaptureDirectory());
    }

    const auto recovered = RecoverAbandonedSession(
        partial, 1'700'000'001'000'000'000LL);
    EXPECT_EQ(recovered.state, AbandonedRecoveryState::Recovered);
    EXPECT_EQ(recovered.status, SessionStatus::Interrupted);
    EXPECT_EQ(recovered.raw_pcap_records, 0U);
    EXPECT_TRUE(!recovered.verified_authoritative_source);
    EXPECT_TRUE(std::filesystem::exists(
        recovered.sealed_session / "capture" / "mouse_usb.pcap"));
    EXPECT_TRUE(ValidateSessionArchive(recovered.archive).valid);
    const auto manifest = abdc::json::Parse(
        abdc::ReadUtf8File(recovered.sealed_session / "manifest.json"));
    EXPECT_TRUE(!manifest.At("verified_authoritative_source").AsBool());
    EXPECT_EQ(manifest.At("raw_pcap_records").AsString(), std::string("0"));
    std::filesystem::remove_all(root);
}

TEST_CASE("abandoned recovery quarantines a corrupt final before using its valid partial") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("final_and_partial");
    std::filesystem::path partial;
    {
        auto workspace = SessionWorkspace::Create(
            RecoveryOptions(root, "recovery-final-partial-test"));
        partial = workspace.Path();
        WriteEndpointPcapPartial(workspace.CaptureDirectory());
        abdc::AtomicWriteFile(
            workspace.CaptureDirectory() / "mouse_usb.pcap",
            "corrupt-final");
    }

    const auto recovered = RecoverAbandonedSession(
        partial, 1'700'000'001'000'000'000LL);
    EXPECT_EQ(recovered.state, AbandonedRecoveryState::Recovered);
    EXPECT_EQ(recovered.status, SessionStatus::CaptureLost);
    EXPECT_TRUE(recovered.verified_authoritative_source);
    EXPECT_EQ(recovered.raw_pcap_records, 1U);
    EXPECT_TRUE(std::filesystem::exists(
        recovered.sealed_session / "capture" / "mouse_usb.pcap"));
    EXPECT_TRUE(std::filesystem::exists(
        recovered.sealed_session / "capture" /
        "mouse_usb.pcap.unverified"));
    std::filesystem::remove_all(root);
}

TEST_CASE("device-wide recovery accepts another endpoint on the certified mouse") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("swapped_endpoint");
    std::filesystem::path partial;
    {
        auto options = RecoveryOptions(root, "recovery-endpoint-test");
        options.device["interrupt_in_endpoint"] = 130;
        auto workspace = SessionWorkspace::Create(options);
        partial = workspace.Path();
        WriteEndpointPcapPartial(workspace.CaptureDirectory());
    }

    const auto recovered = RecoverAbandonedSession(
        partial, 1'700'000'001'000'000'000LL);
    EXPECT_EQ(recovered.state, AbandonedRecoveryState::Recovered);
    EXPECT_EQ(recovered.status, SessionStatus::CaptureLost);
    EXPECT_TRUE(recovered.verified_authoritative_source);
    EXPECT_EQ(recovered.raw_pcap_records, 1U);
    EXPECT_TRUE(std::filesystem::exists(
        recovered.sealed_session / "capture" / "mouse_usb.pcap"));
    std::filesystem::remove_all(root);
}

TEST_CASE("abandoned recovery rejects a decoded stream with swapped descriptor evidence") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("swapped_descriptor");
    std::filesystem::path partial;
    {
        auto workspace = SessionWorkspace::Create(
            RecoveryOptions(root, "recovery-descriptor-test"));
        partial = workspace.Path();
        WriteEndpointPcapPartial(workspace.CaptureDirectory());
        WriteMismatchedReportPartial(workspace.CaptureDirectory());
    }

    const auto recovered = RecoverAbandonedSession(
        partial, 1'700'000'001'000'000'000LL);
    EXPECT_EQ(recovered.state, AbandonedRecoveryState::Recovered);
    EXPECT_EQ(recovered.status, SessionStatus::CaptureLost);
    EXPECT_TRUE(recovered.verified_authoritative_source);
    EXPECT_EQ(recovered.raw_pcap_records, 1U);
    EXPECT_EQ(recovered.decoded_reports, 0U);
    EXPECT_TRUE(!std::filesystem::exists(
        recovered.sealed_session / "capture" / "mouse_reports.abcr2"));
    EXPECT_TRUE(std::filesystem::exists(
        recovered.sealed_session / "capture" /
        "mouse_reports.abcr2.unverified"));
    std::filesystem::remove_all(root);
}

TEST_CASE("startup recovery completes only the missing archive of a sealed session") {
    using namespace abdc::session;
    const auto root = RecoverySessionRoot("sealed_without_archive");
    constexpr const char* session_id = "recovery-sealed-test";
    std::filesystem::path sealed_path;
    std::string manifest_before;
    {
        auto workspace = SessionWorkspace::Create(
            RecoveryOptions(root, session_id));
        abdc::AtomicWriteFile(
            workspace.CaptureDirectory() / "preserved-source.bin",
            "immutable-scientific-evidence");
        SessionSealOptions seal;
        seal.status = SessionStatus::CaptureLost;
        seal.ended_utc_ns = 1'700'000'001'000'000'000LL;
        seal.raw_pcap_records = 3U;
        seal.decoded_reports = 2U;
        seal.gameplay_events = 1U;
        seal.warning_count = 4U;
        seal.recovery_was_required = false;
        seal.verified_authoritative_source = true;
        seal.stop_reason = "capture_device_lost";
        sealed_path = workspace.Seal(seal).directory;
        manifest_before =
            abdc::ReadUtf8File(sealed_path / "manifest.json");
    }
    const auto archive_path = SubmissionArchivePath(sealed_path);
    EXPECT_TRUE(!std::filesystem::exists(archive_path));

    const auto results = RecoverAbandonedSessions(
        root, 1'700'000'002'000'000'000LL);
    EXPECT_EQ(results.size(), std::size_t{1});
    EXPECT_EQ(results[0].state, AbandonedRecoveryState::Recovered);
    EXPECT_EQ(results[0].sealed_session, sealed_path);
    EXPECT_EQ(results[0].archive, archive_path);
    EXPECT_EQ(results[0].status, SessionStatus::CaptureLost);
    EXPECT_TRUE(results[0].verified_authoritative_source);
    EXPECT_EQ(results[0].raw_pcap_records, 3U);
    EXPECT_EQ(results[0].decoded_reports, 2U);
    EXPECT_EQ(results[0].gameplay_events, 1U);
    EXPECT_EQ(results[0].warning_count, 4U);
    EXPECT_EQ(abdc::ReadUtf8File(sealed_path / "manifest.json"),
              manifest_before);
    EXPECT_TRUE(ValidateSessionArchive(archive_path).valid);

    // A regular already-published archive is deliberately skipped on later
    // launches instead of paying the full ZIP validation cost every time.
    EXPECT_TRUE(RecoverAbandonedSessions(
                    root, 1'700'000'003'000'000'000LL)
                    .empty());
    std::filesystem::remove_all(root);
}
