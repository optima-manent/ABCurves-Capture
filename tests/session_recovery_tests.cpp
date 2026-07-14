#include "TestHarness.h"

#include "base/Binary.h"
#include "base/Json.h"
#include "base/Sha256.h"
#include "capture/DevicePcapWriter.h"
#include "capture/HidDescriptor.h"
#include "capture/PcapReader.h"
#include "capture/ReportStream.h"
#include "capture/UsbPcapPacket.h"
#include "session/AppendOnlyJsonl.h"
#include "session/CrashRecovery.h"

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>

namespace {

std::filesystem::path RecoveryTempDirectory(const char* label) {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
        (std::string("abcurves_recovery_") + label + "_" + std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

std::vector<std::byte> RecoveryBytes(std::initializer_list<unsigned> values) {
    std::vector<std::byte> result;
    for (const auto value : values) result.push_back(static_cast<std::byte>(value));
    return result;
}

std::vector<std::byte> RecoveryMouseDescriptor() {
    return RecoveryBytes({
        0x05,0x01,0x09,0x02,0xA1,0x01,0x09,0x01,0xA1,0x00,
        0x05,0x09,0x19,0x01,0x29,0x03,0x15,0x00,0x25,0x01,
        0x95,0x03,0x75,0x01,0x81,0x02,0x95,0x01,0x75,0x05,0x81,0x01,
        0x05,0x01,0x09,0x30,0x09,0x31,0x15,0x81,0x25,0x7F,
        0x75,0x08,0x95,0x02,0x81,0x06,0xC0,0xC0
    });
}

std::vector<std::byte> RecoveryUsbRecordData() {
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
    const auto payload = RecoveryBytes({1U, 2U, 3U});
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

void AppendTornBytes(const std::filesystem::path& path) {
    std::ofstream output(path, std::ios::binary | std::ios::app);
    const std::array<char, 5> torn{'t','o','r','n','!'};
    output.write(torn.data(), static_cast<std::streamsize>(torn.size()));
}

}  // namespace

TEST_CASE("crash recovery trims only an unterminated JSONL tail") {
    using namespace abdc::session;
    const auto directory = RecoveryTempDirectory("jsonl");
    const auto partial = directory / "events.jsonl.partial";
    {
        AppendOnlyJsonlWriter writer(partial, "abcurves.gameplay.event.v1");
        abdc::json::Value event = abdc::json::Value::Object{};
        event["kind"] = "target_presented";
        writer.Append(std::move(event));
        writer.Checkpoint();
    }
    const auto good_size = std::filesystem::file_size(partial);
    AppendTornBytes(partial);
    const auto result = RecoverJsonlPartial(partial, "abcurves.gameplay.event.v1");
    EXPECT_TRUE(result.trimmed_incomplete_tail);
    EXPECT_EQ(result.retained_bytes, good_size);
    EXPECT_EQ(result.record_count, 1U);
    {
        AppendOnlyJsonlReader reader(partial, "abcurves.gameplay.event.v1");
        EXPECT_TRUE(reader.Next().has_value());
        EXPECT_TRUE(!reader.Next().has_value());
    }
    std::filesystem::remove_all(directory);
}

TEST_CASE("crash recovery preserves complete PCAP records before a torn record") {
    using namespace abdc::capture;
    const auto directory = RecoveryTempDirectory("pcap");
    const auto partial = directory / "mouse.pcap.partial";
    PcapHeader header;
    header.little_endian = true;
    header.resolution = TimestampResolution::Microseconds;
    header.major = 2U;
    header.minor = 4U;
    header.snap_length = 65'535U;
    header.link_type = PcapReader::kUsbPcapLinkType;
    PcapRecord record;
    record.timestamp_seconds = 1'700'000'000U;
    record.timestamp_fraction = 123U;
    record.resolution = TimestampResolution::Microseconds;
    record.data = RecoveryUsbRecordData();
    record.original_length = static_cast<std::uint32_t>(record.data.size());
    const auto packet = UsbPcapPacket::Parse(record.data);
    {
        DevicePcapWriter writer(partial, header, 3U, 7U);
        writer.Append(record, packet);
        writer.Checkpoint();
    }
    const auto good_size = std::filesystem::file_size(partial);
    AppendTornBytes(partial);
    const auto result = abdc::session::RecoverPcapPartial(partial);
    EXPECT_TRUE(result.trimmed_incomplete_tail);
    EXPECT_EQ(result.retained_bytes, good_size);
    EXPECT_EQ(result.record_count, 1U);
    {
        std::ifstream input(partial, std::ios::binary);
        PcapReader reader(input);
        EXPECT_TRUE(reader.Next().has_value());
        EXPECT_TRUE(!reader.Next().has_value());
    }
    std::filesystem::remove_all(directory);
}

TEST_CASE("crash recovery keeps CRC-complete report blocks") {
    using namespace abdc::capture;
    const auto directory = RecoveryTempDirectory("reports");
    const auto partial = directory / "reports.abcr.partial";
    const auto descriptor = RecoveryMouseDescriptor();
    const auto parsed = HidDescriptor::Parse(descriptor);
    ReportStreamIdentity identity;
    identity.bus = 3U;
    identity.device = 7U;
    identity.endpoint = 0x81U;
    identity.descriptor_evidence = descriptor;
    identity.descriptor_sha256 = abdc::Sha256Hex(descriptor);
    identity.decoder_spec = parsed.CanonicalDecoderSpec();
    identity.qpc_frequency = 10'000'000;
    {
        ReportStreamWriter writer(partial, identity, 1U);
        AuthoritativeReport report;
        report.capture_sequence = 1U;
        report.pcap_sequence = 3U;
        report.capture_unix_ns = 1000;
        report.observed_qpc = 2000;
        report.irp_id = 5U;
        report.function = 9U;
        report.bus = 3U;
        report.device = 7U;
        report.endpoint = 0x81U;
        report.transfer = 1U;
        report.info = 1U;
        report.hid_dx = 2;
        report.hid_dy = -1;
        report.payload = RecoveryBytes({1U, 2U, 3U});
        writer.Append(report);
        writer.Checkpoint();
    }
    const auto good_size = std::filesystem::file_size(partial);
    AppendTornBytes(partial);
    const auto result = abdc::session::RecoverReportStreamPartial(partial);
    EXPECT_TRUE(result.trimmed_incomplete_tail);
    EXPECT_EQ(result.retained_bytes, good_size);
    EXPECT_EQ(result.record_count, 1U);
    {
        ReportStreamReader reader(partial);
        EXPECT_TRUE(reader.Next().has_value());
        EXPECT_TRUE(!reader.Next().has_value());
        reader.Close();
    }
    std::filesystem::remove_all(directory);
}
