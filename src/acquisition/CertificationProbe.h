#pragma once

#include "acquisition/CaptureWorker.h"
#include "capture/HidDescriptor.h"
#include "device/CertificationFlow.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace abdc::acquisition {

// Runtime-only description of one route produced by CertificationFlow. The
// token joins the USB evidence back to its Raw Input witness in the unelevated
// parent; neither it nor any address-wide USB payload is persisted here.
struct CertificationProbeRouteConfig {
    std::string probe_route_token;
    // Zero observes every interrupt-IN endpoint on the selected stream. A
    // nonzero value narrows optional decoded evidence.
    std::uint8_t endpoint_address = 0;
    std::optional<capture::HidMouseDecoder> decoder;
};

struct CertificationProbeOptions {
    // Normal tests and exact probes use root_index/device_address as a kernel
    // filter. Public certification sets capture_all_devices and uses
    // selected_device only as the Windows-topology hint while deriving the
    // actual USBPcap packet address from bounded interrupt activity.
    // selected_bus is the packet-header bus when already known; zero discovers
    // it. A USBPcap root index must never be substituted for the packet bus.
    windows_capture::NativeUsbPcapOptions native;
    std::uint16_t selected_bus = 0;
    std::uint16_t selected_device = 0;
    std::int64_t qpc_frequency = 0;

    std::int64_t maximum_duration_ns = 10'000'000'000LL;
    std::size_t maximum_routes = 32U;
    std::size_t maximum_samples_per_route = 262'144U;
    std::size_t maximum_intervals_per_route = 262'144U;
    std::size_t maximum_reports_per_transfer = 4'096U;
    std::size_t maximum_candidate_payload_bytes = 64U * 1024U;
    std::size_t maximum_chunk_bytes = 1024U * 1024U;
    std::uint64_t maximum_source_bytes = 512ULL * 1024ULL * 1024ULL;
    std::uint64_t maximum_source_records = 2'000'000ULL;
    std::chrono::milliseconds consumer_poll_interval{20};
    std::chrono::milliseconds consumer_drain_timeout{5'000};
};

[[nodiscard]] std::string ValidateCertificationProbe(
    const CertificationProbeOptions& options,
    const std::vector<CertificationProbeRouteConfig>& routes);

enum class CertificationProbeFatalReason {
    None,
    InvalidConfiguration,
    SourceStartFailed,
    NativeCaptureLost,
    QueueOrByteLoss,
    PcapFraming,
    DeviceIdentityMismatch,
    SourceBoundExceeded,
    ClockFailure,
};

[[nodiscard]] const char* ToString(CertificationProbeFatalReason reason) noexcept;

// These counters are annotations. In particular, none of the decoder or
// timing observations below can invalidate an otherwise intact source probe.
struct CertificationProbeRouteCounters {
    std::uint64_t endpoint_records = 0;
    std::uint64_t requests = 0;
    std::uint64_t completions = 0;
    std::uint64_t successful_nonempty_completions = 0;
    std::uint64_t payload_change_events = 0;
    std::uint64_t decoded_transfers = 0;
    std::uint64_t decoded_reports = 0;
    std::uint64_t failed_transfers = 0;
    std::uint64_t empty_completions = 0;
    std::uint64_t decode_failures = 0;
    std::uint64_t timestamp_regressions = 0;
    std::uint64_t duplicate_like_records = 0;
    std::uint64_t nonpositive_transfer_intervals = 0;
    std::uint64_t samples_omitted_at_bound = 0;
    std::uint64_t intervals_omitted_at_bound = 0;
};

// USBPcap root indices identify capture filter devices; they are not packet
// bus numbers. This identity is returned only after at least one successful
// nonempty interrupt stream has been observed (whole-root mode), or a planned
// candidate record has passed the exact source identity check (exact mode).
struct ValidatedCertificationUsbIdentity {
    std::uint16_t usbpcap_root_index = 0;
    // Windows topology's pre-probe address. It is a hint, not packet truth.
    std::uint8_t topology_device_address = 0;
    // Zero means the bounded probe was whole-root. Session recording still
    // applies an exact filter using packet_device.
    std::uint8_t filtered_device_address = 0;
    std::uint16_t packet_bus = 0;
    std::uint16_t packet_device = 0;
    bool whole_root_capture = false;
};

struct CertificationProbeResult {
    bool clean = false;
    CertificationProbeFatalReason fatal_reason =
        CertificationProbeFatalReason::None;
    std::string detail;

    // Directly consumable by CertificationFlow after the unelevated parent
    // fills selected_raw_input_* and other_raw_input_totals.
    std::vector<device::CertificationProbeEvidence> evidence;
    std::vector<CertificationProbeRouteCounters> route_counters;
    std::optional<ValidatedCertificationUsbIdentity> validated_identity;

    std::uint64_t source_bytes = 0;
    std::uint64_t source_records = 0;
    std::uint64_t candidate_records = 0;
    std::uint64_t ignored_records = 0;
    std::uint64_t qpc_regressions = 0;
    bool duration_limit_reached = false;
    bool sample_limit_reached = false;
    bool interval_limit_reached = false;
    windows_capture::NativeUsbPcapStopReport native_stop;
};

// Elevated, ephemeral half of certification. The worker is finite by design:
// it stops at the QPC duration bound or an evidence-memory bound, drains the
// native source, and returns once. It never writes probe payloads to disk.
class CertificationProbeWorker final {
public:
    using QpcNow = std::function<std::int64_t()>;

    CertificationProbeWorker(
        IUsbPcapChunkSource& source,
        std::vector<CertificationProbeRouteConfig> routes,
        CertificationProbeOptions options,
        QpcNow qpc_now);

    CertificationProbeWorker(const CertificationProbeWorker&) = delete;
    CertificationProbeWorker& operator=(const CertificationProbeWorker&) = delete;

    [[nodiscard]] CertificationProbeResult Run();

private:
    IUsbPcapChunkSource& source_;
    std::vector<CertificationProbeRouteConfig> routes_;
    CertificationProbeOptions options_;
    QpcNow qpc_now_;
    bool run_entered_ = false;
};

}  // namespace abdc::acquisition
