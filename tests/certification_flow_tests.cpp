#include "TestHarness.h"

#include "base/Json.h"
#include "device/CertificationFlow.h"

#include <array>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace abdc::device;

constexpr const char* kRawToken = "raw-secret-interface-token";
constexpr const char* kPhysicalToken = "physical-secret-token";
constexpr const char* kRootToken = "root-secret-token";

MouseInterfaceCandidate Mouse(const std::uintptr_t handle = 101U) {
    MouseInterfaceCandidate mouse;
    mouse.session_token = kRawToken;
    mouse.raw_input_handle = handle;
    mouse.sanitized_product_name = "Research\\Mouse\nEdition";
    mouse.vendor_id = 0x1234U;
    mouse.product_id = 0x5678U;
    mouse.version_number = 0x0102U;
    mouse.layout_fingerprint = std::string(64U, 'b');
    mouse.relative_mouse_report_ids = {0U};
    mouse.topology.physical_device_token = kPhysicalToken;
    mouse.topology.root_hub_token = kRootToken;
    mouse.topology.interface_number = static_cast<std::uint8_t>(0U);
    mouse.eligible_for_correlation_probe = true;
    return mouse;
}

DiscoverySnapshot Snapshot(const std::uintptr_t handle = 101U) {
    DiscoverySnapshot snapshot;
    snapshot.native_enumeration_complete = true;
    snapshot.mice.push_back(Mouse(handle));
    return snapshot;
}

ResolvedUsbMouseTransport Transport(const std::size_t route_count) {
    ResolvedUsbMouseTransport transport;
    transport.status = UsbTopologyResolutionStatus::Probeable;
    transport.usbpcap_root_index = 3U;
    transport.device_address = 17U;
    for (std::size_t index = 0; index < route_count; ++index) {
        UsbInterruptInCandidate candidate;
        candidate.interface_number = 0U;
        candidate.alternate_setting = 0U;
        candidate.endpoint_address = static_cast<std::uint8_t>(0x81U + index);
        candidate.endpoint_max_packet_bytes = 64U;
        candidate.endpoint_interval = 1U;
        transport.candidates.push_back(candidate);
    }
    transport.descriptor_evidence = {std::byte{0x05}, std::byte{0x01}};
    transport.descriptor_sha256 = std::string(64U, 'a');
    transport.decoder_spec = "relative mouse";
    transport.layout_fingerprint = std::string(64U, 'b');
    transport.report_ids = {0U};
    transport.descriptor_evidence_source = DescriptorEvidenceSource::QualifiedFixture;
    transport.descriptor_reconstructor = "qualified\\fixture";
    transport.descriptor_reconstructor_version = "1.0";
    transport.raw_to_pnp_join_proven = true;
    transport.root_mapping_proven = true;
    transport.physical_port_driver_key_proven = true;
    transport.device_address_proven = true;
    transport.active_configuration_proven = true;
    transport.descriptor_layout_supported = true;
    return transport;
}

CertificationFlow Flow(const std::size_t routes,
                       const CertificationPolicy& policy = {}) {
    const auto snapshot = Snapshot();
    const CertificationTopology topology{kRawToken, Transport(routes)};
    return CertificationFlow::Prepare(
        snapshot, kPhysicalToken, std::span<const CertificationTopology>(&topology, 1U),
        policy);
}

CertificationProbeEvidence UniqueEvidence(const std::string& token) {
    CertificationProbeEvidence evidence;
    evidence.probe_route_token = token;
    evidence.probe_duration_ns = 4'000'000'000LL;
    evidence.usb_totals = ActivityTotals{10, -20, 1U, 1U, 8U, 420U};
    evidence.selected_raw_input_totals =
        ActivityTotals{100, 80, 1U, 1U, 12U, 310U};
    evidence.usb_interrupt_records = 12U;
    evidence.usb_successful_nonempty_completions = 8U;
    evidence.usb_payload_change_events = 7U;
    evidence.positive_usb_transfer_intervals_ns = {
        1'000'000LL, 1'050'000LL, 950'000LL};
    return evidence;
}

struct GesturePair {
    std::vector<GestureSample> usb;
    std::vector<GestureSample> raw;
};

GesturePair DistinctiveGesture() {
    constexpr std::array<std::pair<std::int32_t, std::int32_t>, 12> directions{{
        {80, 0}, {0, 100}, {-120, 0}, {0, -90}, {70, 40}, {-50, 80},
        {100, -60}, {-90, -30}, {30, 110}, {-75, -85}, {115, 25}, {-20, -105},
    }};
    GesturePair result;
    for (std::size_t index = 0; index < directions.size(); ++index) {
        const auto [dx, dy] = directions[index];
        const auto time = static_cast<std::int64_t>(index) * 20'000'000LL;
        result.usb.push_back({time, dx, dy, index == 4U, index == 5U});
        result.raw.push_back({
            time + 30'000'000LL,
            static_cast<std::int32_t>(dx * 3 / 4),
            static_cast<std::int32_t>(dy * 3 / 4),
            index == 4U, index == 5U});
    }
    return result;
}

std::vector<GestureSample> WeakGesture() {
    std::vector<GestureSample> result;
    for (std::size_t index = 0; index < 12U; ++index) {
        const auto time = static_cast<std::int64_t>(index) * 20'000'000LL;
        const auto sign = index % 2U == 0U ? 1 : -1;
        result.push_back({time, 55 * sign, 55 * sign, index == 4U, index == 5U});
    }
    return result;
}

CertificationProbeEvidence TimedEvidence(
    const std::string& token, std::vector<GestureSample> usb,
    std::vector<GestureSample> raw) {
    CertificationProbeEvidence evidence;
    evidence.probe_route_token = token;
    evidence.probe_duration_ns = 5'000'000'000LL;
    evidence.usb_samples = std::move(usb);
    evidence.selected_raw_input_samples = std::move(raw);
    for (const auto& sample : evidence.selected_raw_input_samples) {
        evidence.selected_raw_input_totals.absolute_motion_counts +=
            static_cast<std::uint64_t>(std::abs(sample.canonical_dx)) +
            static_cast<std::uint64_t>(std::abs(sample.canonical_dy));
        if (sample.left_down) {
            ++evidence.selected_raw_input_totals.left_down_edges;
        }
        if (sample.left_up) {
            ++evidence.selected_raw_input_totals.left_up_edges;
        }
    }
    evidence.usb_interrupt_records = evidence.usb_samples.size();
    evidence.usb_successful_nonempty_completions = evidence.usb_samples.size();
    evidence.usb_payload_change_events =
        evidence.usb_samples.empty() ? 0U : evidence.usb_samples.size() - 1U;
    evidence.positive_usb_transfer_intervals_ns = {
        1'000'000LL, 1'100'000LL, 900'000LL, 1'020'000LL};
    return evidence;
}

}  // namespace

TEST_CASE("certification accepts a topology-unique route and emits a privacy-safe manifest") {
    auto flow = Flow(1U);
    EXPECT_EQ(flow.Decision().state, CertificationState::AwaitingProbe);
    EXPECT_EQ(flow.Routes().size(), 1U);

    auto evidence = UniqueEvidence(flow.Routes().front().probe_route_token);
    const auto& result = flow.SubmitProbe(
        std::span<const CertificationProbeEvidence>(&evidence, 1U));
    EXPECT_EQ(result.state, CertificationState::Certified);
    EXPECT_TRUE(result.success.has_value());
    EXPECT_EQ(result.success->proof_method, std::string("physical_usb_activity"));
    EXPECT_EQ(result.success->lock.product_name, std::string("Research Mouse Edition"));

    const auto manifest = abdc::json::Parse(result.success->sanitized_manifest_json);
    EXPECT_EQ(manifest.At("schema").AsString(),
              std::string("abcurves.mouse_certification.v1"));
    EXPECT_EQ(manifest.At("device").At("vendor_id").AsInt(), 0x1234);
    EXPECT_EQ(result.success->sanitized_manifest_json.find(kRawToken),
              std::string::npos);
    EXPECT_EQ(result.success->sanitized_manifest_json.find(kPhysicalToken),
              std::string::npos);
    EXPECT_EQ(result.success->sanitized_manifest_json.find(kRootToken),
              std::string::npos);
}

TEST_CASE("unrelated mouse activity does not gate a unique certification route") {
    auto flow = Flow(1U);
    auto evidence = UniqueEvidence(flow.Routes().front().probe_route_token);
    evidence.other_raw_input_totals =
        ActivityTotals{9'000, -8'000, 20U, 20U, 100U, 30'000U};
    const auto& result = flow.SubmitProbe(
        std::span<const CertificationProbeEvidence>(&evidence, 1U));
    EXPECT_EQ(result.state, CertificationState::Certified);
}

TEST_CASE("whole-root activity can correct the topology address without claiming an endpoint") {
    auto flow = Flow(1U);
    auto evidence = UniqueEvidence(flow.Routes().front().probe_route_token);
    evidence.observed_packet_bus = 3U;
    evidence.observed_device_address = 18U;
    evidence.device_address_discovered_from_root = true;
    evidence.device_wide_activity = true;

    const auto& result = flow.SubmitProbe(
        std::span<const CertificationProbeEvidence>(&evidence, 1U));
    EXPECT_EQ(result.state, CertificationState::Certified);
    EXPECT_TRUE(result.success.has_value());
    EXPECT_EQ(result.success->lock.device_address, 18U);
    EXPECT_EQ(result.success->live_identity.device_address, 18U);
    EXPECT_EQ(result.success->lock.endpoint_address, 0U);
    EXPECT_TRUE(result.success->lock.descriptor_sha256.empty());
    EXPECT_EQ(result.success->proof_method,
              std::string("whole_root_activity_remap"));
}

TEST_CASE("decoder warnings and measured polling are metadata rather than gates") {
    auto flow = Flow(1U);
    auto evidence = UniqueEvidence(flow.Routes().front().probe_route_token);
    evidence.decode_warnings = 7U;
    evidence.failed_transfers = 3U;
    evidence.positive_usb_transfer_intervals_ns = {
        8'000'000LL, 8'100'000LL, 7'900'000LL};
    const auto& result = flow.SubmitProbe(
        std::span<const CertificationProbeEvidence>(&evidence, 1U));
    EXPECT_EQ(result.state, CertificationState::Certified);
    EXPECT_EQ(result.success->decode_warnings, 7U);
    EXPECT_EQ(result.success->failed_transfers, 3U);
    EXPECT_TRUE(result.success->activity.measured_polling_hz < 200.0);
}

TEST_CASE("insufficient movement returns once and requires an explicit Retry") {
    auto flow = Flow(1U);
    auto evidence = UniqueEvidence(flow.Routes().front().probe_route_token);
    evidence.usb_totals.absolute_motion_counts = 2U;
    evidence.selected_raw_input_totals.absolute_motion_counts = 3U;
    const auto& failed = flow.SubmitProbe(
        std::span<const CertificationProbeEvidence>(&evidence, 1U));
    EXPECT_EQ(failed.state, CertificationState::RetryAvailable);
    EXPECT_EQ(failed.issue, CertificationIssue::InsufficientMovement);
    EXPECT_TRUE(failed.retry_available);
    EXPECT_EQ(flow.AttemptNumber(), 1U);

    const auto& unchanged = flow.SubmitProbe(
        std::span<const CertificationProbeEvidence>(&evidence, 1U));
    EXPECT_EQ(unchanged.state, CertificationState::RetryAvailable);
    EXPECT_EQ(flow.AttemptNumber(), 1U);

    const auto& retried = flow.Retry();
    EXPECT_EQ(retried.state, CertificationState::AwaitingProbe);
    EXPECT_EQ(flow.AttemptNumber(), 2U);
}

TEST_CASE("multiple active routes do not block an exact-device certification") {
    CertificationPolicy policy;
    policy.correlation.maximum_lag_ns = 40'000'000LL;
    auto flow = Flow(2U, policy);
    const auto gesture = DistinctiveGesture();
    std::array<CertificationProbeEvidence, 2> evidence{
        TimedEvidence(flow.Routes()[0].probe_route_token, gesture.usb, gesture.raw),
        TimedEvidence(flow.Routes()[1].probe_route_token, gesture.usb, gesture.raw),
    };
    const auto& result = flow.SubmitProbe(evidence);
    EXPECT_EQ(result.state, CertificationState::Certified);
    EXPECT_TRUE(result.success.has_value());
}

TEST_CASE("multiple routes select one clear tolerant temporal-correlation winner") {
    CertificationPolicy policy;
    policy.correlation.maximum_lag_ns = 40'000'000LL;
    auto flow = Flow(2U, policy);
    const auto gesture = DistinctiveGesture();
    std::array<CertificationProbeEvidence, 2> evidence{
        TimedEvidence(flow.Routes()[0].probe_route_token, gesture.usb, gesture.raw),
        TimedEvidence(flow.Routes()[1].probe_route_token, WeakGesture(), gesture.raw),
    };
    const auto& result = flow.SubmitProbe(evidence);
    EXPECT_EQ(result.state, CertificationState::Certified);
    EXPECT_EQ(result.success->live_identity.endpoint_address, 0x81U);
    EXPECT_EQ(result.success->proof_method,
              std::string("physical_usb_activity"));
}

TEST_CASE("composite mouse collections sharing an endpoint certify as one source") {
    constexpr const char* kSiblingToken = "raw-secret-sibling-token";
    auto snapshot = Snapshot();
    auto sibling = Mouse(202U);
    sibling.session_token = kSiblingToken;
    snapshot.mice.push_back(sibling);

    const std::array<CertificationTopology, 2> topologies{
        CertificationTopology{kRawToken, Transport(1U)},
        CertificationTopology{kSiblingToken, Transport(1U)},
    };
    auto flow = CertificationFlow::Prepare(snapshot, kPhysicalToken, topologies);
    EXPECT_EQ(flow.Decision().state, CertificationState::AwaitingProbe);
    EXPECT_EQ(flow.Routes().size(), 2U);
    EXPECT_EQ(flow.Routes()[0].source_stream_token,
              flow.Routes()[1].source_stream_token);

    // The application supplies the same physical-mouse aggregate to both
    // collection-specific decoder candidates. This covers devices whose
    // movement and click arrive through sibling Raw Input handles.
    std::array<CertificationProbeEvidence, 2> evidence{
        UniqueEvidence(flow.Routes()[0].probe_route_token),
        UniqueEvidence(flow.Routes()[1].probe_route_token),
    };
    const auto& result = flow.SubmitProbe(evidence);
    EXPECT_EQ(result.state, CertificationState::Certified);
    EXPECT_TRUE(result.success.has_value());
    EXPECT_EQ(result.success->proof_method,
              std::string("physical_usb_activity"));
    EXPECT_EQ(result.success->live_identity.endpoint_address, 0x81U);
}

TEST_CASE("gameplay routing includes every Raw Input collection of the certified mouse") {
    auto snapshot = Snapshot();
    auto sibling = Mouse(202U);
    sibling.session_token = "raw-secret-sibling-token";
    snapshot.mice.push_back(sibling);

    auto other = Mouse(303U);
    other.session_token = "other-raw-token";
    other.topology.physical_device_token = "other-physical-token";
    snapshot.mice.push_back(other);

    const auto routes = BuildRawDeviceRoutes(
        snapshot, kRawToken, kPhysicalToken);
    EXPECT_EQ(OriginForRawHandle(routes, 101U),
              RawDeviceOrigin::SelectedActive);
    EXPECT_EQ(OriginForRawHandle(routes, 202U),
              RawDeviceOrigin::SelectedPhysicalSibling);
    EXPECT_EQ(OriginForRawHandle(routes, 303U),
              RawDeviceOrigin::OtherPhysical);
    EXPECT_EQ(OriginForRawHandle(routes, 404U), RawDeviceOrigin::Unknown);
}

TEST_CASE("certification cancellation is explicit and terminal") {
    auto flow = Flow(1U);
    const auto& cancelled = flow.Cancel();
    EXPECT_EQ(cancelled.state, CertificationState::Cancelled);
    EXPECT_EQ(cancelled.issue, CertificationIssue::Cancelled);
    EXPECT_TRUE(!cancelled.retry_available);
    EXPECT_EQ(flow.Retry().state, CertificationState::Cancelled);
}

TEST_CASE("decoder and HID-cap uncertainty do not exclude a physical USB mouse") {
    EphemeralInterfaceRecord record;
    record.raw_input_mouse = true;
    record.raw_input_handle = 77U;
    record.raw_interface_path = L"\\\\?\\HID#VID_1234&PID_5678#mouse";
    record.pnp_instance_id = L"HID\\VID_1234&PID_5678\\mouse";
    record.physical_usb_instance_id = L"USB\\VID_1234&PID_5678\\physical";
    record.root_hub_instance_id = L"USB\\ROOT_HUB30\\root";
    record.product_name = L"Unusual Gaming Mouse";
    record.vendor_id = 0x1234U;
    record.product_id = 0x5678U;
    const std::array<std::byte, 16> salt{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8},
        std::byte{9}, std::byte{10}, std::byte{11}, std::byte{12},
        std::byte{13}, std::byte{14}, std::byte{15}, std::byte{16},
    };
    const auto inventory = AnalyzeInventory(
        std::span<const EphemeralInterfaceRecord>(&record, 1U), salt);
    EXPECT_EQ(inventory.mice.size(), 1U);
    EXPECT_TRUE(inventory.mice.front().eligible_for_correlation_probe);
    EXPECT_TRUE(std::find(inventory.mice.front().issues.begin(),
                          inventory.mice.front().issues.end(),
                          DiscoveryIssue::DecoderEvidenceUnavailable) !=
                inventory.mice.front().issues.end());
}

TEST_CASE("missing Raw Input VID PID does not reject an exact physical port") {
    const std::array<UsbPortIdentityEvidence, 1> ports{{
        {0x1234U, 0x5678U, 0x0100U, 7U},
    }};
    const auto selection = SelectUsbPortIdentity(
        ports, 0U, 0U, 0U, std::nullopt);
    EXPECT_EQ(selection.status, UsbPortIdentitySelectionStatus::Ready);
    EXPECT_EQ(selection.selected_index, 0U);
}

TEST_CASE("tentative address can break a driver-key tie without descriptor attributes") {
    const std::array<UsbPortIdentityEvidence, 2> ports{{
        {0x1111U, 0x2222U, 0x0100U, 4U},
        {0x3333U, 0x4444U, 0x0200U, 9U},
    }};
    const auto selection = SelectUsbPortIdentity(
        ports, 0U, 0U, 0U, static_cast<std::uint8_t>(9U));
    EXPECT_EQ(selection.status, UsbPortIdentitySelectionStatus::Ready);
    EXPECT_EQ(selection.selected_index, 1U);
}
