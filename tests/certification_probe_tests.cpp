#include "TestHarness.h"

#include "acquisition/CertificationProbe.h"
#include "base/Binary.h"
#include "capture/HidDescriptor.h"
#include "capture/PcapReader.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

std::vector<std::byte> Bytes(std::initializer_list<unsigned> values) {
    std::vector<std::byte> result;
    result.reserve(values.size());
    for (const auto value : values) {
        result.push_back(static_cast<std::byte>(value));
    }
    return result;
}

std::vector<std::byte> MouseDescriptor() {
    return Bytes({
        0x05,0x01,0x09,0x02,0xA1,0x01,0x09,0x01,0xA1,0x00,
        0x05,0x09,0x19,0x01,0x29,0x03,0x15,0x00,0x25,0x01,
        0x95,0x03,0x75,0x01,0x81,0x02,0x95,0x01,0x75,0x05,0x81,0x01,
        0x05,0x01,0x09,0x30,0x09,0x31,0x09,0x38,0x15,0x81,0x25,0x7F,
        0x75,0x08,0x95,0x03,0x81,0x06,0xC0,0xC0
    });
}

abdc::acquisition::CertificationProbeRouteConfig Route(
    std::string token, const std::uint8_t endpoint) {
    const auto descriptor =
        abdc::capture::HidDescriptor::Parse(MouseDescriptor());
    return {std::move(token), endpoint,
            abdc::capture::HidMouseDecoder(descriptor.RelativeMouseLayouts())};
}

std::vector<std::byte> UsbRecordData(
    const std::uint16_t bus,
    const std::uint16_t device,
    const std::uint8_t endpoint,
    const bool completion,
    const std::uint32_t status,
    const std::uint64_t irp,
    std::vector<std::byte> payload,
    const std::uint8_t transfer = 1U) {
    std::vector<std::byte> data;
    abdc::binary::AppendU16(data, 27U);
    abdc::binary::AppendU64(data, irp);
    abdc::binary::AppendU32(data, status);
    abdc::binary::AppendU16(data, 9U);
    data.push_back(completion ? std::byte{1} : std::byte{0});
    abdc::binary::AppendU16(data, bus);
    abdc::binary::AppendU16(data, device);
    data.push_back(static_cast<std::byte>(endpoint));
    data.push_back(static_cast<std::byte>(transfer));
    abdc::binary::AppendU32(data, static_cast<std::uint32_t>(payload.size()));
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

std::vector<std::byte> PcapHeader() {
    auto result = Bytes({0xd4,0xc3,0xb2,0xa1});
    abdc::binary::AppendU16(result, 2U);
    abdc::binary::AppendU16(result, 4U);
    abdc::binary::AppendU32(result, 0U);
    abdc::binary::AppendU32(result, 0U);
    abdc::binary::AppendU32(result, 65'535U);
    abdc::binary::AppendU32(
        result, abdc::capture::PcapReader::kUsbPcapLinkType);
    return result;
}

void AppendPcapRecord(std::vector<std::byte>& pcap,
                      const std::uint32_t timestamp_fraction,
                      const std::vector<std::byte>& data) {
    abdc::binary::AppendU32(pcap, 1'700'000'000U);
    abdc::binary::AppendU32(pcap, timestamp_fraction);
    abdc::binary::AppendU32(pcap, static_cast<std::uint32_t>(data.size()));
    abdc::binary::AppendU32(pcap, static_cast<std::uint32_t>(data.size()));
    pcap.insert(pcap.end(), data.begin(), data.end());
}

class FakeProbeSource final : public abdc::acquisition::IUsbPcapChunkSource {
public:
    explicit FakeProbeSource(std::vector<std::vector<std::byte>> chunks,
                             const bool lose_bytes = false)
        : chunks_(chunks.begin(), chunks.end()), lose_bytes_(lose_bytes) {}

    bool Start(const abdc::windows_capture::NativeUsbPcapOptions& options) override {
        started_options_ = options;
        status_.state = abdc::windows_capture::NativeUsbPcapState::Capturing;
        status_.filter_started = true;
        return true;
    }

    void RequestStop() override {
        stop_requested_ = true;
        status_.state = abdc::windows_capture::NativeUsbPcapState::StopRequested;
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
        if (stop_requested_) Finish();
        return false;
    }

    [[nodiscard]] abdc::windows_capture::NativeUsbPcapStatus Status()
        const override {
        return status_;
    }

    abdc::windows_capture::NativeUsbPcapStopReport StopAndDrain(
        std::chrono::milliseconds,
        abdc::windows_capture::NativeUsbPcapSemanticGuard guard) override {
        Finish();
        const auto semantic = guard();
        abdc::windows_capture::NativeUsbPcapStopReport report;
        report.filter_stop_attempted = true;
        report.filter_stop_succeeded = true;
        report.kernel_quiet_observed = true;
        report.quiet_completion_observed = true;
        report.consumer_queue_empty = true;
        report.semantic_guard_invoked = true;
        report.semantic_guard_passed = semantic.parser_at_record_boundary &&
            semantic.authoritative_writer_clean &&
            semantic.accounted_bytes == status_.counters.bytes_read;
        report.handle_closed = true;
        report.bytes_read = status_.counters.bytes_read;
        report.bytes_delivered = status_.counters.bytes_delivered;
        report.bytes_accounted = semantic.accounted_bytes;
        report.clean = !lose_bytes_ && report.semantic_guard_passed;
        report.diagnostic = report.clean ? "fake certification drain is clean"
                                         : "fake certification byte loss";
        status_.handle_closed = true;
        status_.state = report.clean
            ? abdc::windows_capture::NativeUsbPcapState::Stopped
            : abdc::windows_capture::NativeUsbPcapState::QueueOverflow;
        return report;
    }

    void Abort() noexcept override {
        while (!chunks_.empty()) chunks_.pop_front();
        status_.reader_finished = true;
        status_.state = abdc::windows_capture::NativeUsbPcapState::DrainFailed;
    }

    [[nodiscard]] const abdc::windows_capture::NativeUsbPcapOptions&
    StartedOptions() const noexcept {
        return started_options_;
    }

private:
    void Finish() {
        if (status_.reader_finished) return;
        status_.reader_finished = true;
        status_.filter_stop_attempted = true;
        status_.filter_stop_succeeded = true;
        status_.kernel_quiet_observed = true;
        status_.quiet_completion_observed = true;
        status_.state = abdc::windows_capture::NativeUsbPcapState::Draining;
        if (lose_bytes_) {
            ++status_.counters.queue_overflow_events;
            ++status_.counters.bytes_discarded;
            status_.message = "simulated certification queue overflow";
        }
    }

    std::deque<std::vector<std::byte>> chunks_;
    bool lose_bytes_ = false;
    bool stop_requested_ = false;
    abdc::windows_capture::NativeUsbPcapOptions started_options_{};
    abdc::windows_capture::NativeUsbPcapStatus status_{};
};

abdc::acquisition::CertificationProbeOptions ProbeOptions() {
    abdc::acquisition::CertificationProbeOptions options;
    options.native.root_index = 1U;
    options.native.device_address = 7U;
    options.selected_bus = 3U;
    options.selected_device = 7U;
    options.qpc_frequency = 1'000'000'000LL;
    options.maximum_duration_ns = 5LL;
    options.consumer_poll_interval = std::chrono::milliseconds(1);
    options.consumer_drain_timeout = std::chrono::milliseconds(100);
    return options;
}

abdc::acquisition::CertificationProbeResult RunProbe(
    std::vector<std::byte> pcap,
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes,
    abdc::acquisition::CertificationProbeOptions options = ProbeOptions(),
    const bool lose_bytes = false) {
    // Exercise split global-header and record framing on every successful path.
    std::vector<std::vector<std::byte>> chunks;
    const auto first = std::min<std::size_t>(7U, pcap.size());
    chunks.emplace_back(pcap.begin(), pcap.begin() +
        static_cast<std::ptrdiff_t>(first));
    chunks.emplace_back(pcap.begin() + static_cast<std::ptrdiff_t>(first),
                        pcap.end());
    FakeProbeSource source(std::move(chunks), lose_bytes);
    std::int64_t qpc = 0;
    abdc::acquisition::CertificationProbeWorker worker(
        source, std::move(routes), options, [&qpc] { return qpc++; });
    auto result = worker.Run();
    EXPECT_EQ(source.StartedOptions().root_index, options.native.root_index);
    EXPECT_EQ(source.StartedOptions().device_address,
              options.native.device_address);
    return result;
}

}  // namespace

TEST_CASE("certification probe keeps only candidate endpoint evidence in memory") {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(3U, 7U, 0x83U, true, 0U, 1U,
                      Bytes({0xffU, 0xeeU})));
    AppendPcapRecord(pcap, 200U,
        UsbRecordData(3U, 7U, 0x82U, true, 0U, 2U,
                      Bytes({0U, 1U, 0U, 0U})));
    AppendPcapRecord(pcap, 300U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 3U,
                      Bytes({0U, 70U, 0U, 0U})));
    AppendPcapRecord(pcap, 400U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 4U,
                      Bytes({0U, 0U, 196U, 0U})));

    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-movement", 0x81U));
    routes.push_back(Route("route-quiet", 0x82U));
    const auto result = RunProbe(std::move(pcap), std::move(routes));

    EXPECT_TRUE(result.clean);
    EXPECT_EQ(result.evidence.size(), 2U);
    EXPECT_EQ(result.ignored_records, 1U);
    EXPECT_EQ(result.candidate_records, 3U);
    EXPECT_EQ(result.evidence[0].usb_samples.size(), 2U);
    EXPECT_EQ(result.evidence[1].usb_samples.size(), 1U);
    EXPECT_TRUE(result.evidence[0].usb_totals.absolute_motion_counts >
                result.evidence[1].usb_totals.absolute_motion_counts);
    EXPECT_EQ(result.evidence[0].positive_usb_transfer_intervals_ns.size(), 1U);
    EXPECT_TRUE(result.evidence[0].source_capture_intact);
    EXPECT_TRUE(result.validated_identity.has_value());
    EXPECT_EQ(result.validated_identity->usbpcap_root_index, 1U);
    EXPECT_EQ(result.validated_identity->filtered_device_address, 7U);
    EXPECT_EQ(result.validated_identity->packet_bus, 3U);
    EXPECT_EQ(result.validated_identity->packet_device, 7U);
    EXPECT_TRUE(result.validated_identity->usbpcap_root_index !=
                result.validated_identity->packet_bus);
}

TEST_CASE("certification probe discovers packet bus without assuming root index") {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 8U,
                      Bytes({0U, 8U, 0U, 0U})));
    auto options = ProbeOptions();
    options.selected_bus = 0U;
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-discover-bus", 0x81U));
    const auto result = RunProbe(std::move(pcap), std::move(routes), options);

    EXPECT_TRUE(result.clean);
    EXPECT_TRUE(result.validated_identity.has_value());
    EXPECT_EQ(result.validated_identity->usbpcap_root_index, 1U);
    EXPECT_EQ(result.validated_identity->packet_bus, 3U);
    EXPECT_TRUE(result.validated_identity->usbpcap_root_index !=
                result.validated_identity->packet_bus);
}

TEST_CASE("whole-root certification corrects a sparse mapped address and stale endpoint") {
    auto pcap = PcapHeader();
    // Windows/topology pointed at address 7 endpoint 0x84. It emits a little
    // unrelated/sparse traffic, matching the real diagnostic failure shape.
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(3U, 7U, 0x84U, true, 0U, 70U,
                      Bytes({0U, 0U, 0U, 0U})));
    AppendPcapRecord(pcap, 200U,
        UsbRecordData(3U, 7U, 0x84U, true, 0U, 71U,
                      Bytes({1U, 0U, 0U, 0U})));

    // The actual moving USBPcap stream is address 8 on another endpoint.
    for (std::uint32_t index = 0U; index < 18U; ++index) {
        AppendPcapRecord(pcap, 300U + index * 100U,
            UsbRecordData(3U, 8U, 0x81U, true, 0U, 80U + index,
                          Bytes({index, 12U, 0U, 0U})));
    }

    auto options = ProbeOptions();
    options.native.capture_all_devices = true;
    options.native.device_address = 0U;
    options.selected_bus = 0U;
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-stale-endpoint", 0x84U));
    const auto result = RunProbe(std::move(pcap), std::move(routes), options);

    EXPECT_TRUE(result.clean);
    EXPECT_TRUE(result.validated_identity.has_value());
    EXPECT_TRUE(result.validated_identity->whole_root_capture);
    EXPECT_EQ(result.validated_identity->topology_device_address, 7U);
    EXPECT_EQ(result.validated_identity->filtered_device_address, 0U);
    EXPECT_EQ(result.validated_identity->packet_bus, 3U);
    EXPECT_EQ(result.validated_identity->packet_device, 8U);
    EXPECT_EQ(result.evidence.size(), 1U);
    EXPECT_EQ(result.evidence[0].observed_device_address, 8U);
    EXPECT_TRUE(result.evidence[0].device_address_discovered_from_root);
    EXPECT_TRUE(result.evidence[0].device_wide_activity);
    EXPECT_EQ(result.evidence[0].usb_successful_nonempty_completions, 18U);
    EXPECT_EQ(result.evidence[0].usb_payload_change_events, 17U);
}

TEST_CASE("certification probe rejects a packet bus change after discovery") {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 9U,
                      Bytes({0U, 8U, 0U, 0U})));
    AppendPcapRecord(pcap, 200U,
        UsbRecordData(4U, 7U, 0x81U, true, 0U, 10U,
                      Bytes({0U, 9U, 0U, 0U})));
    auto options = ProbeOptions();
    options.selected_bus = 0U;
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-changing-bus", 0x81U));
    const auto result = RunProbe(std::move(pcap), std::move(routes), options);

    EXPECT_TRUE(!result.clean);
    EXPECT_EQ(result.fatal_reason,
              abdc::acquisition::CertificationProbeFatalReason::DeviceIdentityMismatch);
}

TEST_CASE("certification probe preserves batched report order and button edges") {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 10U,
                      Bytes({1U, 10U, 0U, 0U,
                             0U, 20U, 0U, 0U})));
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-batch", 0x81U));
    const auto result = RunProbe(std::move(pcap), std::move(routes));

    EXPECT_TRUE(result.clean);
    EXPECT_EQ(result.evidence[0].usb_samples.size(), 2U);
    EXPECT_EQ(result.evidence[0].usb_samples[0].relative_time_ns, 0LL);
    EXPECT_EQ(result.evidence[0].usb_samples[1].relative_time_ns, 0LL);
    EXPECT_TRUE(result.evidence[0].usb_samples[0].left_down);
    EXPECT_TRUE(result.evidence[0].usb_samples[1].left_up);
    EXPECT_EQ(result.evidence[0].usb_totals.left_down_edges, 1U);
    EXPECT_EQ(result.evidence[0].usb_totals.left_up_edges, 1U);
    EXPECT_EQ(result.evidence[0].usb_totals.packet_count, 2U);
}

TEST_CASE("failed and undecodable transfers annotate but do not hide a later sample") {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(3U, 7U, 0x81U, true, 5U, 20U,
                      Bytes({0U, 1U, 2U, 0U})));
    AppendPcapRecord(pcap, 200U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 21U,
                      Bytes({0U, 1U})));
    AppendPcapRecord(pcap, 250U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 22U, {}));
    AppendPcapRecord(pcap, 300U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 23U,
                      Bytes({0U, 9U, 247U, 0U})));
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-warning", 0x81U));
    const auto result = RunProbe(std::move(pcap), std::move(routes));

    EXPECT_TRUE(result.clean);
    EXPECT_EQ(result.evidence[0].failed_transfers, 1U);
    EXPECT_EQ(result.route_counters[0].decode_failures, 1U);
    EXPECT_EQ(result.route_counters[0].empty_completions, 1U);
    EXPECT_TRUE(result.evidence[0].decode_warnings >= 1U);
    EXPECT_EQ(result.evidence[0].usb_samples.size(), 1U);
    EXPECT_EQ(result.evidence[0].usb_samples[0].canonical_dx, 9);
    EXPECT_EQ(result.evidence[0].positive_usb_transfer_intervals_ns.size(), 1U);
}

TEST_CASE("native timestamp regression is retained in relative gesture time") {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 300U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 30U,
                      Bytes({0U, 2U, 0U, 0U})));
    AppendPcapRecord(pcap, 200U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 31U,
                      Bytes({0U, 3U, 0U, 0U})));
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-regression", 0x81U));
    const auto result = RunProbe(std::move(pcap), std::move(routes));

    EXPECT_TRUE(result.clean);
    EXPECT_EQ(result.evidence[0].usb_samples.size(), 2U);
    EXPECT_EQ(result.evidence[0].usb_samples[1].relative_time_ns, -100'000LL);
    EXPECT_EQ(result.route_counters[0].timestamp_regressions, 1U);
    EXPECT_EQ(result.route_counters[0].nonpositive_transfer_intervals, 1U);
    EXPECT_TRUE(result.evidence[0].positive_usb_transfer_intervals_ns.empty());
}

TEST_CASE("duplicate-like USB reports are annotated and both remain in evidence") {
    auto pcap = PcapHeader();
    const auto payload = Bytes({0U, 4U, 252U, 0U});
    AppendPcapRecord(pcap, 500U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 35U, payload));
    AppendPcapRecord(pcap, 500U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 35U, payload));
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-duplicate", 0x81U));
    const auto result = RunProbe(std::move(pcap), std::move(routes));

    EXPECT_TRUE(result.clean);
    EXPECT_EQ(result.evidence[0].usb_samples.size(), 2U);
    EXPECT_EQ(result.route_counters[0].duplicate_like_records, 1U);
    EXPECT_EQ(result.evidence[0].decode_warnings, 1U);
    EXPECT_EQ(result.route_counters[0].nonpositive_transfer_intervals, 1U);
}

TEST_CASE("invalid source PCAP framing is fatal to certification") {
    auto pcap = PcapHeader();
    pcap[0] = std::byte{0};
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-framing", 0x81U));
    const auto result = RunProbe(std::move(pcap), std::move(routes));
    EXPECT_TRUE(!result.clean);
    EXPECT_EQ(result.fatal_reason,
              abdc::acquisition::CertificationProbeFatalReason::PcapFraming);
    EXPECT_TRUE(!result.evidence[0].source_capture_intact);
}

TEST_CASE("selected bus or device identity mismatch is fatal to certification") {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(4U, 7U, 0x81U, true, 0U, 40U,
                      Bytes({0U, 5U, 0U, 0U})));
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-identity", 0x81U));
    const auto result = RunProbe(std::move(pcap), std::move(routes));
    EXPECT_TRUE(!result.clean);
    EXPECT_EQ(result.fatal_reason,
              abdc::acquisition::CertificationProbeFatalReason::DeviceIdentityMismatch);
}

TEST_CASE("native queue or byte loss is fatal even with decoded evidence") {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 50U,
                      Bytes({0U, 12U, 0U, 0U})));
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-loss", 0x81U));
    const auto result = RunProbe(
        std::move(pcap), std::move(routes), ProbeOptions(), true);
    EXPECT_TRUE(!result.clean);
    EXPECT_EQ(result.fatal_reason,
              abdc::acquisition::CertificationProbeFatalReason::QueueOrByteLoss);
    EXPECT_EQ(result.evidence[0].usb_samples.size(), 1U);
    EXPECT_TRUE(!result.evidence[0].source_capture_intact);
}

TEST_CASE("certification sample cap stops safely without growing evidence") {
    auto pcap = PcapHeader();
    AppendPcapRecord(pcap, 100U,
        UsbRecordData(3U, 7U, 0x81U, true, 0U, 60U,
                      Bytes({0U, 1U, 0U, 0U,
                             0U, 2U, 0U, 0U,
                             0U, 3U, 0U, 0U})));
    auto options = ProbeOptions();
    options.maximum_samples_per_route = 2U;
    std::vector<abdc::acquisition::CertificationProbeRouteConfig> routes;
    routes.push_back(Route("route-bounded", 0x81U));
    const auto result = RunProbe(
        std::move(pcap), std::move(routes), options);

    EXPECT_TRUE(result.clean);
    EXPECT_TRUE(result.sample_limit_reached);
    EXPECT_EQ(result.evidence[0].usb_samples.size(), 2U);
    EXPECT_EQ(result.route_counters[0].samples_omitted_at_bound, 1U);
    EXPECT_TRUE(result.evidence[0].source_capture_intact);
}
