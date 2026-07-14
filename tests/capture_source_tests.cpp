#include "TestHarness.h"

#include "base/Binary.h"
#include "base/Sha256.h"
#include "capture/DevicePcapWriter.h"
#include "capture/HidDescriptor.h"
#include "capture/MouseReportExtractor.h"
#include "capture/PcapReader.h"
#include "capture/ReportStream.h"
#include "capture/UsbPcapPacket.h"
#include "windows_capture/NativeUsbPcap.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace {

std::vector<std::byte> Bytes(std::initializer_list<unsigned> values) {
    std::vector<std::byte> result;
    for (const auto value : values) result.push_back(static_cast<std::byte>(value));
    return result;
}

std::vector<std::byte> MouseDescriptorWithWheel() {
    return Bytes({
        0x05,0x01,0x09,0x02,0xA1,0x01,0x09,0x01,0xA1,0x00,
        0x05,0x09,0x19,0x01,0x29,0x03,0x15,0x00,0x25,0x01,
        0x95,0x03,0x75,0x01,0x81,0x02,0x95,0x01,0x75,0x05,0x81,0x01,
        0x05,0x01,0x09,0x30,0x09,0x31,0x09,0x38,0x15,0x81,0x25,0x7F,
        0x75,0x08,0x95,0x03,0x81,0x06,0xC0,0xC0
    });
}

std::vector<std::byte> UsbRecordData(std::uint32_t status,
                                     std::vector<std::byte> payload,
                                     bool completion = true) {
    std::vector<std::byte> data;
    abdc::binary::AppendU16(data, 27U);
    abdc::binary::AppendU64(data, 0x1122334455667788ULL);
    abdc::binary::AppendU32(data, status);
    abdc::binary::AppendU16(data, 9U);
    data.push_back(completion ? std::byte{1} : std::byte{0});
    abdc::binary::AppendU16(data, 3U);
    abdc::binary::AppendU16(data, 7U);
    data.push_back(std::byte{0x81});
    data.push_back(std::byte{1});
    abdc::binary::AppendU32(data, static_cast<std::uint32_t>(payload.size()));
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

abdc::capture::PcapRecord Record(std::uint64_t sequence,
                                 std::uint32_t micros,
                                 std::vector<std::byte> payload,
                                 std::int64_t observed_qpc) {
    abdc::capture::PcapRecord record;
    record.sequence = sequence;
    record.timestamp_seconds = 1'700'000'000U;
    record.timestamp_fraction = micros;
    record.resolution = abdc::capture::TimestampResolution::Microseconds;
    record.original_length = static_cast<std::uint32_t>(payload.size());
    record.observed_qpc = observed_qpc;
    record.data = std::move(payload);
    return record;
}

std::filesystem::path TempDirectory(const char* label) {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
        (std::string("abcurves_capture_") + label + "_" + std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

}  // namespace

TEST_CASE("device PCAP keeps original exact-address records") {
    using namespace abdc::capture;
    const auto directory = TempDirectory("pcap");
    const auto partial = directory / "selected.pcap.partial";
    const auto final = directory / "selected.pcap";
    PcapHeader header;
    header.little_endian = true;
    header.resolution = TimestampResolution::Microseconds;
    header.major = 2U;
    header.minor = 4U;
    header.snap_length = 65'535U;
    header.link_type = PcapReader::kUsbPcapLinkType;
    const auto source = Record(12U, 123U,
                               UsbRecordData(0U, Bytes({1U, 5U, 251U, 2U})),
                               1000);
    const auto packet = UsbPcapPacket::Parse(source.data);
    {
        DevicePcapWriter writer(partial, header, 3U, 7U);
        writer.Append(source, packet);
        writer.Finalize(final);
        EXPECT_EQ(writer.RecordCount(), 1U);
    }
    {
        std::ifstream input(final, std::ios::binary);
        PcapReader reader(input);
        const auto restored = reader.Next();
        EXPECT_TRUE(restored.has_value());
        EXPECT_EQ(restored->timestamp_fraction, source.timestamp_fraction);
        EXPECT_EQ(restored->original_length, source.original_length);
        EXPECT_EQ(restored->data, source.data);
        EXPECT_TRUE(!reader.Next().has_value());
    }
    std::filesystem::remove_all(directory);
}

TEST_CASE("USBPcap parser accepts only PCAP-proven snapshot truncation") {
    using namespace abdc::capture;
    const auto complete = UsbRecordData(
        0U, Bytes({1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U}));
    auto included = complete;
    included.resize(30U);  // 27-byte USBPcap header plus 3 captured bytes.

    EXPECT_THROW(UsbPcapPacket::Parse(included));
    EXPECT_THROW(UsbPcapPacket::Parse(
        included, static_cast<std::uint32_t>(complete.size() - 1U)));

    const auto packet = UsbPcapPacket::Parse(
        included, static_cast<std::uint32_t>(complete.size()));
    EXPECT_TRUE(packet.payload_truncated);
    EXPECT_EQ(packet.declared_data_length, 8U);
    EXPECT_EQ(packet.payload.size(), 3U);
}

TEST_CASE("whole-root USBPcap is available only through an explicit bounded mode") {
    abdc::windows_capture::NativeUsbPcapOptions options;
    options.root_index = 1U;
    options.device_address = 0U;
    EXPECT_TRUE(!abdc::windows_capture::ValidateNativeUsbPcapOptions(options).empty());
    options.capture_all_devices = true;
    EXPECT_TRUE(abdc::windows_capture::ValidateNativeUsbPcapOptions(options).empty());
}

TEST_CASE("lenient extractor records anomalies and keeps later reports") {
    using namespace abdc::capture;
    const auto descriptor = MouseDescriptorWithWheel();
    const auto parsed = HidDescriptor::Parse(descriptor);
    MouseReportExtractor extractor(3U, 7U, 0x81U,
                                   HidMouseDecoder(parsed.RelativeMouseLayouts()));

    auto failed = Record(0U, 500U, UsbRecordData(5U, Bytes({1U, 2U, 3U, 4U})), 1000);
    auto failed_result = extractor.Process(failed, UsbPcapPacket::Parse(failed.data));
    EXPECT_TRUE(failed_result.reports.empty());
    EXPECT_EQ(failed_result.anomalies.size(), 1U);
    EXPECT_EQ(failed_result.anomalies.front().code, CaptureAnomalyCode::FailedTransfer);

    auto good = Record(1U, 400U, UsbRecordData(0U, Bytes({1U, 5U, 251U, 2U})), 1100);
    auto good_result = extractor.Process(good, UsbPcapPacket::Parse(good.data));
    EXPECT_EQ(good_result.reports.size(), 1U);
    EXPECT_EQ(good_result.reports.front().hid_dx, 5);
    EXPECT_EQ(good_result.reports.front().hid_dy, -5);
    EXPECT_EQ(good_result.reports.front().hid_wheel, 2);
    EXPECT_TRUE((good_result.reports.front().quality_flags &
                 ReportQualityPcapTimestampRegressed) != 0U);
    EXPECT_EQ(good_result.anomalies.front().code,
              CaptureAnomalyCode::TimestampRegressed);
    EXPECT_EQ(extractor.Counters().decoded_reports, 1U);
}

TEST_CASE("report stream v2 retains native-time regression wheel and QPC") {
    using namespace abdc::capture;
    const auto directory = TempDirectory("reports");
    const auto partial = directory / "reports.abcr.partial";
    const auto final = directory / "reports.abcr";
    const auto descriptor = MouseDescriptorWithWheel();
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
        ReportStreamWriter writer(partial, identity, 2U);
        for (int index = 0; index < 2; ++index) {
            AuthoritativeReport report;
            report.capture_sequence = static_cast<std::uint64_t>(index);
            report.pcap_sequence = static_cast<std::uint64_t>(index + 4);
            report.capture_unix_ns = index == 0 ? 2'000 : 1'000;
            report.observed_qpc = 100 + index;
            report.irp_id = 9U + static_cast<std::uint64_t>(index);
            report.function = 9U;
            report.bus = 3U;
            report.device = 7U;
            report.endpoint = 0x81U;
            report.transfer = 1U;
            report.info = 1U;
            report.hid_dx = index + 1;
            report.hid_dy = -(index + 1);
            report.hid_wheel = index;
            report.buttons = 1U;
            report.quality_flags = index == 1
                ? ReportQualityPcapTimestampRegressed : ReportQualityNone;
            report.payload = Bytes({1U, 2U, 3U, 4U});
            writer.Append(report);
        }
        writer.Finalize(final);
    }
    {
        ReportStreamReader reader(final);
        const auto first = reader.Next();
        const auto second = reader.Next();
        EXPECT_TRUE(first.has_value() && second.has_value());
        EXPECT_EQ(second->capture_unix_ns, 1'000);
        EXPECT_EQ(second->observed_qpc, 101);
        EXPECT_EQ(second->hid_wheel, 1);
        EXPECT_EQ(second->quality_flags,
                  static_cast<std::uint32_t>(ReportQualityPcapTimestampRegressed));
        EXPECT_TRUE(!reader.Next().has_value());
    }
    std::filesystem::remove_all(directory);
}
