#include "TestHarness.h"

#include "acquisition/CaptureWorker.h"
#include "base/Binary.h"
#include "base/Sha256.h"
#include "capture/HidDescriptor.h"
#include "capture/PcapReader.h"
#include "capture/ReportStream.h"
#include "capture/UsbPcapPacket.h"
#include "session/AppendOnlyJsonl.h"
#include "session/CapturePrefixRecovery.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

std::vector<std::byte> Bytes(std::initializer_list<unsigned> values) {
    std::vector<std::byte> result;
    result.reserve(values.size());
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

std::vector<std::byte> UsbRecordData(const std::uint16_t bus,
                                     const std::uint16_t device,
                                     const std::uint8_t endpoint,
                                     const bool completion,
                                     const std::uint32_t status,
                                     const std::uint64_t irp,
                                     std::vector<std::byte> payload) {
    std::vector<std::byte> data;
    abdc::binary::AppendU16(data, 27U);
    abdc::binary::AppendU64(data, irp);
    abdc::binary::AppendU32(data, status);
    abdc::binary::AppendU16(data, 9U);
    data.push_back(completion ? std::byte{1} : std::byte{0});
    abdc::binary::AppendU16(data, bus);
    abdc::binary::AppendU16(data, device);
    data.push_back(static_cast<std::byte>(endpoint));
    data.push_back(std::byte{1});  // interrupt
    abdc::binary::AppendU32(data, static_cast<std::uint32_t>(payload.size()));
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

void AppendPcapRecord(std::vector<std::byte>& pcap,
                      const std::uint32_t timestamp_fraction,
                      const std::vector<std::byte>& data,
                      const std::uint32_t original_length = 0U) {
    abdc::binary::AppendU32(pcap, 1'700'000'000U);
    abdc::binary::AppendU32(pcap, timestamp_fraction);
    abdc::binary::AppendU32(pcap, static_cast<std::uint32_t>(data.size()));
    abdc::binary::AppendU32(
        pcap, original_length == 0U
            ? static_cast<std::uint32_t>(data.size())
            : original_length);
    pcap.insert(pcap.end(), data.begin(), data.end());
}

std::vector<std::byte> PcapHeader() {
    std::vector<std::byte> result = Bytes({0xd4,0xc3,0xb2,0xa1});
    abdc::binary::AppendU16(result, 2U);
    abdc::binary::AppendU16(result, 4U);
    abdc::binary::AppendU32(result, 0U);
    abdc::binary::AppendU32(result, 0U);
    abdc::binary::AppendU32(result, 65'535U);
    abdc::binary::AppendU32(result, abdc::capture::PcapReader::kUsbPcapLinkType);
    return result;
}

std::vector<std::byte> RepresentativePcap() {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(3U, 7U, 0x82U, true, 0U, 1U,
                      Bytes({1U, 1U, 1U, 0U})));
    AppendPcapRecord(pcap, 200U,
        UsbRecordData(3U, 7U, 0x81U, false, 0U, 2U, {}));
    AppendPcapRecord(pcap, 300U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 2U,
                      Bytes({1U, 5U, 251U, 2U})));
    AppendPcapRecord(pcap, 400U,
        UsbRecordData(3U, 7U, 0x81U, true, 5U, 3U,
                      Bytes({1U, 2U, 3U, 4U})));
    AppendPcapRecord(pcap, 500U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 4U,
                      Bytes({1U, 2U})));
    return pcap;
}

std::filesystem::path TempDirectory(const char* label) {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
        (std::string("abcurves_acquisition_") + label + "_" +
         std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

abdc::capture::ReportStreamIdentity Identity(
    const std::vector<std::byte>& descriptor) {
    const auto parsed = abdc::capture::HidDescriptor::Parse(descriptor);
    abdc::capture::ReportStreamIdentity result;
    result.bus = 3U;
    result.device = 7U;
    result.endpoint = 0x81U;
    result.descriptor_evidence = descriptor;
    result.descriptor_sha256 = abdc::Sha256Hex(descriptor);
    result.decoder_spec = parsed.CanonicalDecoderSpec();
    result.qpc_frequency = 10'000'000;
    return result;
}

std::unique_ptr<abdc::acquisition::CapturePipeline> MakePipeline(
    const std::filesystem::path& directory) {
    const auto descriptor = MouseDescriptorWithWheel();
    const auto parsed = abdc::capture::HidDescriptor::Parse(descriptor);
    return std::make_unique<abdc::acquisition::CapturePipeline>(
        abdc::acquisition::OutputPathsIn(directory),
        abdc::acquisition::CertifiedUsbDevice{3U, 7U},
        abdc::acquisition::DecodedMouseEndpoint{
            0x81U,
            abdc::capture::HidMouseDecoder(parsed.RelativeMouseLayouts()),
            Identity(descriptor),
        });
}

class FakeChunkSource final : public abdc::acquisition::IUsbPcapChunkSource {
public:
    FakeChunkSource(std::vector<std::vector<std::byte>> chunks,
                    const bool lose_bytes = false)
        : chunks_(chunks.begin(), chunks.end()), lose_bytes_(lose_bytes) {}

    bool Start(const abdc::windows_capture::NativeUsbPcapOptions&) override {
        status_.state = abdc::windows_capture::NativeUsbPcapState::Capturing;
        status_.filter_started = true;
        return true;
    }

    void RequestStop() override {
        stop_requested_ = true;
        if (!status_.reader_finished) {
            status_.state = abdc::windows_capture::NativeUsbPcapState::StopRequested;
        }
    }

    bool WaitTakeChunk(std::vector<std::byte>& chunk,
                       std::chrono::milliseconds) override {
        if (!chunks_.empty()) {
            chunk = std::move(chunks_.front());
            chunks_.pop_front();
            ++status_.counters.read_completions;
            ++status_.counters.chunks_delivered;
            status_.counters.bytes_read += chunk.size();
            status_.counters.bytes_delivered += chunk.size();
            return true;
        }
        if (stop_requested_) FinishReader();
        return false;
    }

    abdc::windows_capture::NativeUsbPcapStatus Status() const override {
        return status_;
    }

    abdc::windows_capture::NativeUsbPcapStopReport StopAndDrain(
        std::chrono::milliseconds,
        abdc::windows_capture::NativeUsbPcapSemanticGuard guard) override {
        FinishReader();
        const auto evidence = guard();
        abdc::windows_capture::NativeUsbPcapStopReport result;
        result.filter_stop_attempted = true;
        result.filter_stop_succeeded = true;
        result.kernel_quiet_observed = true;
        result.quiet_completion_observed = true;
        result.consumer_queue_empty = true;
        result.semantic_guard_invoked = true;
        result.semantic_guard_passed = evidence.parser_at_record_boundary &&
            evidence.authoritative_writer_clean &&
            evidence.accounted_bytes == status_.counters.bytes_read &&
            status_.counters.bytes_delivered == status_.counters.bytes_read;
        result.handle_closed = true;
        result.bytes_read = status_.counters.bytes_read;
        result.bytes_delivered = status_.counters.bytes_delivered;
        result.bytes_accounted = evidence.accounted_bytes;
        result.clean = !lose_bytes_ && result.semantic_guard_passed;
        result.diagnostic = result.clean ? "fake source drained cleanly"
                                         : "fake source observed byte loss";
        status_.handle_closed = true;
        status_.state = result.clean
            ? abdc::windows_capture::NativeUsbPcapState::Stopped
            : abdc::windows_capture::NativeUsbPcapState::QueueOverflow;
        return result;
    }

    void Abort() noexcept override {
        while (!chunks_.empty()) {
            status_.counters.bytes_discarded += chunks_.front().size();
            chunks_.pop_front();
        }
        status_.reader_finished = true;
        status_.state = abdc::windows_capture::NativeUsbPcapState::DrainFailed;
    }

private:
    void FinishReader() {
        if (status_.reader_finished) return;
        status_.reader_finished = true;
        status_.filter_stop_attempted = true;
        status_.filter_stop_succeeded = true;
        status_.kernel_quiet_observed = true;
        status_.quiet_completion_observed = true;
        if (lose_bytes_) {
            ++status_.counters.queue_overflow_events;
            status_.counters.bytes_discarded += 5U;
            status_.counters.bytes_read += 5U;
            status_.state = abdc::windows_capture::NativeUsbPcapState::QueueOverflow;
            status_.message = "simulated bounded-queue overflow";
        } else {
            status_.state = abdc::windows_capture::NativeUsbPcapState::Draining;
        }
    }

    std::deque<std::vector<std::byte>> chunks_;
    bool lose_bytes_ = false;
    bool stop_requested_ = false;
    abdc::windows_capture::NativeUsbPcapStatus status_{};
};

}  // namespace

TEST_CASE("acquisition pipeline writes the raw device before lenient decode") {
    const auto directory = TempDirectory("pipeline");
    auto pipeline = MakePipeline(directory);
    const auto pcap = RepresentativePcap();

    // Deliberately split the PCAP global header and records across native reads.
    const std::array<std::size_t, 4> cuts{7U, 31U, 83U, pcap.size()};
    std::size_t begin = 0;
    std::int64_t qpc = 1'000;
    for (const auto end : cuts) {
        pipeline->ProcessChunk(
            std::span<const std::byte>(pcap).subspan(begin, end - begin), qpc++);
        begin = end;
    }
    pipeline->Seal();
    pipeline->Publish();

    const auto snapshot = pipeline->Snapshot();
    EXPECT_EQ(snapshot.source_records, 5U);
    EXPECT_EQ(snapshot.raw_device_records, 5U);
    EXPECT_EQ(snapshot.decoded_endpoint_records, 4U);
    EXPECT_EQ(snapshot.decoded_reports, 1U);
    EXPECT_EQ(snapshot.anomalies, 2U);

    {
        std::ifstream input(directory / "mouse_usb.pcap", std::ios::binary);
        abdc::capture::PcapReader reader(input);
        std::uint64_t count = 0;
        while (const auto record = reader.Next()) {
            const auto packet = abdc::capture::UsbPcapPacket::Parse(record->data);
            EXPECT_EQ(packet.bus, 3U);
            EXPECT_EQ(packet.device, 7U);
            ++count;
        }
        EXPECT_EQ(count, 5U);
    }
    {
        abdc::capture::ReportStreamReader reader(directory / "mouse_reports.abcr2");
        const auto report = reader.Next();
        EXPECT_TRUE(report.has_value());
        EXPECT_EQ(report->hid_dx, 5);
        EXPECT_EQ(report->hid_dy, -5);
        EXPECT_TRUE(!reader.Next().has_value());
    }
    {
        abdc::session::AppendOnlyJsonlReader reader(
            directory / "capture_anomalies.jsonl",
            "abcurves.capture.anomaly.v1");
        const auto first = reader.Next();
        const auto second = reader.Next();
        EXPECT_TRUE(first.has_value() && second.has_value());
        EXPECT_EQ(first->At("code").AsString(), std::string("failed_transfer"));
        EXPECT_EQ(second->At("code").AsString(), std::string("decode_failed"));
        EXPECT_TRUE(!reader.Next().has_value());
    }
    std::filesystem::remove_all(directory);
}

TEST_CASE("acquisition pipeline preserves PCAP-proven snapshot truncation") {
    const auto directory = TempDirectory("pipeline_snaplen");
    auto pipeline = MakePipeline(directory);
    auto complete = UsbRecordData(
        3U, 7U, 0x81U, true, 0U, 99U,
        Bytes({1U, 5U, 251U, 2U, 9U, 8U, 7U, 6U}));
    const auto original_length = static_cast<std::uint32_t>(complete.size());
    complete.resize(30U);
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U, complete, original_length);

    pipeline->ProcessChunk(pcap, 1'000);
    pipeline->Seal();
    pipeline->Publish();

    const auto snapshot = pipeline->Snapshot();
    EXPECT_EQ(snapshot.source_records, 1U);
    EXPECT_EQ(snapshot.raw_device_records, 1U);
    EXPECT_EQ(snapshot.decoded_reports, 0U);
    EXPECT_EQ(snapshot.anomalies, 1U);
    {
        abdc::session::AppendOnlyJsonlReader reader(
            directory / "capture_anomalies.jsonl",
            "abcurves.capture.anomaly.v1");
        const auto anomaly = reader.Next();
        EXPECT_TRUE(anomaly.has_value());
        EXPECT_EQ(anomaly->At("code").AsString(),
                  std::string("snaplen_truncated"));
    }
    std::filesystem::remove_all(directory);
}

TEST_CASE("capture worker accepts an injected source and publishes a clean drain") {
    const auto directory = TempDirectory("worker_clean");
    auto pipeline = MakePipeline(directory);
    const auto pcap = RepresentativePcap();
    FakeChunkSource source({
        std::vector<std::byte>(pcap.begin(), pcap.begin() + 19),
        std::vector<std::byte>(pcap.begin() + 19, pcap.end()),
    });
    abdc::acquisition::CaptureWorkerOptions options;
    options.native.root_index = 1U;
    options.native.device_address = 7U;
    options.durable_flush_interval = std::chrono::milliseconds(1);
    std::int64_t qpc = 10'000;
    abdc::acquisition::CaptureWorker worker(
        source, *pipeline, options, [&qpc] { return qpc++; });

    // A pre-run request is held by the worker and only forwarded after Start;
    // this never mutates NativeUsbPcapCapture's active zero-byte semantics.
    worker.RequestStop();
    const auto result = worker.Run();
    EXPECT_TRUE(result.clean);
    EXPECT_EQ(result.fatal_reason, abdc::acquisition::CaptureFatalReason::None);
    EXPECT_TRUE(result.native_stop.clean);
    EXPECT_TRUE(std::filesystem::exists(directory / "mouse_usb.pcap"));
    EXPECT_TRUE(std::filesystem::exists(directory / "mouse_reports.abcr2"));
    EXPECT_TRUE(std::filesystem::exists(directory / "capture_anomalies.jsonl"));
    std::filesystem::remove_all(directory);
}

TEST_CASE("capture worker makes native queue or byte loss fatal without publishing") {
    const auto directory = TempDirectory("worker_loss");
    auto pipeline = MakePipeline(directory);
    const auto pcap = RepresentativePcap();
    FakeChunkSource source({pcap}, true);
    abdc::acquisition::CaptureWorkerOptions options;
    options.native.root_index = 1U;
    options.native.device_address = 7U;
    abdc::acquisition::CaptureWorker worker(
        source, *pipeline, options, [] { return 20'000; });

    worker.RequestStop();
    const auto result = worker.Run();
    EXPECT_TRUE(!result.clean);
    EXPECT_EQ(result.fatal_reason,
              abdc::acquisition::CaptureFatalReason::QueueOrByteLoss);
    EXPECT_TRUE(!std::filesystem::exists(directory / "mouse_usb.pcap"));
    EXPECT_TRUE(std::filesystem::exists(directory / "mouse_usb.pcap.partial"));
    pipeline.reset();
    const auto recovery = abdc::session::RecoverCapturePrefix(directory);
    EXPECT_TRUE(recovery.any_verified_source);
    EXPECT_TRUE(!recovery.any_unverified_bytes);
    EXPECT_TRUE(std::filesystem::exists(directory / "mouse_usb.pcap"));
    EXPECT_TRUE(std::filesystem::exists(directory / "mouse_reports.abcr2"));
    EXPECT_TRUE(std::filesystem::exists(directory / "capture_anomalies.jsonl"));
    EXPECT_TRUE(std::filesystem::exists(directory / "recovery.json"));
    EXPECT_TRUE(!std::filesystem::exists(directory / "mouse_usb.pcap.partial"));
    std::filesystem::remove_all(directory);
}

TEST_CASE("raw-only pipeline preserves the complete device without a decoder") {
    const auto directory = TempDirectory("raw_only");
    abdc::acquisition::CapturePipeline pipeline(
        abdc::acquisition::OutputPathsIn(directory),
        abdc::acquisition::CertifiedUsbDevice{3U, 7U}, std::nullopt);
    const auto pcap = RepresentativePcap();
    pipeline.ProcessChunk(pcap, 42'000);
    pipeline.Seal();
    pipeline.Publish();

    const auto snapshot = pipeline.Snapshot();
    EXPECT_EQ(snapshot.raw_device_records, 5U);
    EXPECT_TRUE(!snapshot.decoder_available);
    EXPECT_TRUE(!snapshot.report_stream_available);
    EXPECT_TRUE(std::filesystem::exists(directory / "mouse_usb.pcap"));
    EXPECT_TRUE(!std::filesystem::exists(directory / "mouse_reports.abcr2"));
    EXPECT_TRUE(std::filesystem::exists(
        directory / "capture_anomalies.jsonl"));
    std::filesystem::remove_all(directory);
}
