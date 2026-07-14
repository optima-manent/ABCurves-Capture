#include "acquisition/CertificationProbe.h"

#include "capture/StreamingPcapParser.h"
#include "capture/UsbPcapPacket.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace abdc::acquisition {
namespace {

constexpr std::int64_t kNanosecondsPerSecond = 1'000'000'000LL;

class ProbeFailure final : public std::runtime_error {
public:
    ProbeFailure(const CertificationProbeFatalReason reason, std::string detail)
        : std::runtime_error(std::move(detail)), reason_(reason) {}

    [[nodiscard]] CertificationProbeFatalReason Reason() const noexcept {
        return reason_;
    }

private:
    CertificationProbeFatalReason reason_;
};

[[nodiscard]] bool IsInterruptInEndpoint(const std::uint8_t endpoint) noexcept {
    return (endpoint & 0x80U) != 0U && (endpoint & 0x0fU) != 0U &&
           (endpoint & 0x70U) == 0U;
}

[[nodiscard]] bool NativeQueueOrByteLoss(
    const windows_capture::NativeUsbPcapStatus& status) noexcept {
    return status.state == windows_capture::NativeUsbPcapState::QueueOverflow ||
           status.counters.queue_overflow_events != 0U ||
           status.counters.bytes_discarded != 0U;
}

[[nodiscard]] bool NativeStateIsFatal(
    const windows_capture::NativeUsbPcapState state) noexcept {
    using State = windows_capture::NativeUsbPcapState;
    switch (state) {
    case State::AccessDenied:
    case State::DeviceUnavailable:
    case State::ConfigurationFailed:
    case State::DeviceLost:
    case State::QueueOverflow:
    case State::StopFilteringFailed:
    case State::CancellationFailed:
    case State::DrainFailed:
    case State::InternalError:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] std::int64_t ElapsedNanoseconds(
    const std::int64_t start,
    const std::int64_t high_water,
    const std::int64_t frequency,
    const std::int64_t maximum) noexcept {
    if (high_water <= start || frequency <= 0 || maximum <= 0) return 1;
    const long double ticks = static_cast<long double>(high_water) -
                              static_cast<long double>(start);
    const long double value = ticks * static_cast<long double>(kNanosecondsPerSecond) /
                              static_cast<long double>(frequency);
    if (value >= static_cast<long double>(maximum)) return maximum;
    if (value <= 1.0L) return 1;
    return static_cast<std::int64_t>(value);
}

[[nodiscard]] bool DurationReached(const std::int64_t start,
                                   const std::int64_t high_water,
                                   const std::int64_t frequency,
                                   const std::int64_t maximum_ns) noexcept {
    if (high_water <= start) return false;
    const long double ticks = static_cast<long double>(high_water) -
                              static_cast<long double>(start);
    const long double elapsed_ns =
        ticks * static_cast<long double>(kNanosecondsPerSecond) /
        static_cast<long double>(frequency);
    return elapsed_ns >= static_cast<long double>(maximum_ns);
}

[[nodiscard]] bool CheckedAdd(const std::uint64_t left,
                              const std::uint64_t right,
                              std::uint64_t& result) noexcept {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) return false;
    result = left + right;
    return true;
}

[[nodiscard]] std::uint64_t Magnitude(const std::int32_t value) noexcept {
    const auto wide = static_cast<std::int64_t>(value);
    return static_cast<std::uint64_t>(wide < 0 ? -wide : wide);
}

[[nodiscard]] bool AddSigned(std::int64_t& destination,
                             const std::int32_t value) noexcept {
    const auto wide = static_cast<std::int64_t>(value);
    if (wide > 0 && destination > std::numeric_limits<std::int64_t>::max() - wide) {
        return false;
    }
    if (wide < 0 && destination < std::numeric_limits<std::int64_t>::min() - wide) {
        return false;
    }
    destination += wide;
    return true;
}

struct RouteAccumulator {
    explicit RouteAccumulator(CertificationProbeRouteConfig config)
        : token(std::move(config.probe_route_token)),
          endpoint(config.endpoint_address),
          decoder(std::move(config.decoder)) {
        minimum_report_bytes = std::numeric_limits<std::size_t>::max();
        if (decoder) {
            for (const auto& layout : decoder->Layouts()) {
                minimum_report_bytes = std::min(minimum_report_bytes,
                                                layout.byte_length);
            }
        }
        evidence.probe_route_token = token;
    }

    void Process(const capture::PcapRecord& record,
                 const capture::UsbPcapPacket& packet,
                 const CertificationProbeOptions& options,
                 const bool retain_derivatives,
                 bool& sample_limit_reached,
                 bool& interval_limit_reached) {
        ++counters.endpoint_records;
        if (!packet.IsCompletion()) {
            ++counters.requests;
            return;
        }

        ++counters.completions;
        const auto timestamp = record.UnixNanoseconds();
        if (maximum_timestamp && timestamp < *maximum_timestamp) {
            ++counters.timestamp_regressions;
        }
        maximum_timestamp = maximum_timestamp
            ? std::max(*maximum_timestamp, timestamp)
            : timestamp;

        const bool payload_is_bounded =
            packet.payload.size() <= options.maximum_candidate_payload_bytes;
        const bool duplicate_like = last_record_valid &&
            last_irp_id == packet.irp_id && last_timestamp == timestamp &&
            payload_is_bounded && last_payload.size() == packet.payload.size() &&
            std::equal(last_payload.begin(), last_payload.end(),
                       packet.payload.begin());
        if (duplicate_like) ++counters.duplicate_like_records;
        last_irp_id = packet.irp_id;
        last_timestamp = timestamp;
        last_record_valid = payload_is_bounded;
        if (payload_is_bounded) {
            last_payload.assign(packet.payload.begin(), packet.payload.end());
        } else {
            last_payload.clear();
        }

        if (packet.status != 0U) {
            ++counters.failed_transfers;
            return;
        }
        if (packet.payload.empty()) {
            ++counters.empty_completions;
            return;
        }

        ++counters.successful_nonempty_completions;
        auto& previous_payload = last_successful_payload_by_endpoint[packet.endpoint];
        if (!previous_payload.empty() &&
            (previous_payload.size() != packet.payload.size() ||
             !std::equal(previous_payload.begin(), previous_payload.end(),
                         packet.payload.begin()))) {
            ++counters.payload_change_events;
        }
        if (payload_is_bounded) {
            previous_payload.assign(packet.payload.begin(), packet.payload.end());
        } else {
            previous_payload.clear();
        }
        // A whole-root probe may observe many unrelated devices. Retain only
        // bounded counters/payload-change state for address selection; decoded
        // samples and interval vectors are built only for exact probes.
        if (!retain_derivatives) return;
        if (last_positive_transfer_timestamp) {
            if (timestamp > *last_positive_transfer_timestamp) {
                const auto interval = timestamp - *last_positive_transfer_timestamp;
                if (evidence.positive_usb_transfer_intervals_ns.size() <
                    options.maximum_intervals_per_route) {
                    evidence.positive_usb_transfer_intervals_ns.push_back(interval);
                    if (evidence.positive_usb_transfer_intervals_ns.size() ==
                        options.maximum_intervals_per_route) {
                        interval_limit_reached = true;
                    }
                } else {
                    ++counters.intervals_omitted_at_bound;
                    interval_limit_reached = true;
                }
                last_positive_transfer_timestamp = timestamp;
            } else {
                ++counters.nonpositive_transfer_intervals;
            }
        } else {
            last_positive_transfer_timestamp = timestamp;
        }

        if (!decoder || packet.payload_truncated || !payload_is_bounded ||
            minimum_report_bytes == 0U ||
            minimum_report_bytes == std::numeric_limits<std::size_t>::max() ||
            packet.payload.size() / minimum_report_bytes >
                options.maximum_reports_per_transfer) {
            ++counters.decode_failures;
            return;
        }

        std::vector<capture::DecodedMouseReport> decoded;
        try {
            decoded = decoder->DecodeBatch(packet.payload);
        } catch (const std::exception&) {
            ++counters.decode_failures;
            return;
        }
        if (decoded.size() > options.maximum_reports_per_transfer) {
            ++counters.decode_failures;
            return;
        }

        ++counters.decoded_transfers;
        counters.decoded_reports += static_cast<std::uint64_t>(decoded.size());
        for (const auto& report : decoded) {
            if (evidence.usb_samples.size() >= options.maximum_samples_per_route) {
                ++counters.samples_omitted_at_bound;
                sample_limit_reached = true;
                continue;
            }

            const bool left_pressed = (report.buttons & 1U) != 0U;
            device::GestureSample sample;
            if (!sample_time_origin) sample_time_origin = timestamp;
            // This subtraction intentionally preserves a native PCAP
            // regression as a regressing relative time. It is evidence, not a
            // clock repair.
            sample.relative_time_ns = timestamp - *sample_time_origin;
            sample.canonical_dx = report.dx;
            sample.canonical_dy = report.dy;
            sample.left_down = !left_button_pressed && left_pressed;
            sample.left_up = left_button_pressed && !left_pressed;

            std::uint64_t magnitude = 0;
            const auto x_magnitude = Magnitude(report.dx);
            const auto y_magnitude = Magnitude(report.dy);
            if (!CheckedAdd(x_magnitude, y_magnitude, magnitude) ||
                !AddSigned(evidence.usb_totals.canonical_dx, report.dx) ||
                !AddSigned(evidence.usb_totals.canonical_dy, report.dy) ||
                magnitude > std::numeric_limits<std::uint64_t>::max() -
                    evidence.usb_totals.absolute_motion_counts ||
                evidence.usb_totals.packet_count ==
                    std::numeric_limits<std::uint64_t>::max()) {
                throw ProbeFailure(
                    CertificationProbeFatalReason::SourceBoundExceeded,
                    "certification evidence numeric bound was exceeded");
            }

            evidence.usb_totals.absolute_motion_counts += magnitude;
            ++evidence.usb_totals.packet_count;
            if (sample.left_down) ++evidence.usb_totals.left_down_edges;
            if (sample.left_up) ++evidence.usb_totals.left_up_edges;
            left_button_pressed = left_pressed;
            evidence.usb_samples.push_back(sample);
            if (evidence.usb_samples.size() ==
                options.maximum_samples_per_route) {
                sample_limit_reached = true;
            }
        }
    }

    void Finish(const std::int64_t duration_ns, const bool source_intact) {
        evidence.probe_duration_ns = duration_ns;
        evidence.source_capture_intact = source_intact;
        evidence.failed_transfers = counters.failed_transfers;
        evidence.usb_interrupt_records = counters.endpoint_records;
        evidence.usb_successful_nonempty_completions =
            counters.successful_nonempty_completions;
        evidence.usb_payload_change_events = counters.payload_change_events;
        evidence.decode_warnings = counters.empty_completions +
            counters.decode_failures + counters.timestamp_regressions +
            counters.duplicate_like_records;
    }

    std::string token;
    std::uint8_t endpoint = 0;
    std::optional<capture::HidMouseDecoder> decoder;
    std::size_t minimum_report_bytes = 0;
    device::CertificationProbeEvidence evidence;
    CertificationProbeRouteCounters counters;
    std::optional<std::int64_t> maximum_timestamp;
    std::optional<std::int64_t> last_positive_transfer_timestamp;
    std::optional<std::int64_t> sample_time_origin;
    std::uint64_t last_irp_id = 0;
    std::int64_t last_timestamp = 0;
    std::vector<std::byte> last_payload;
    std::map<std::uint8_t, std::vector<std::byte>>
        last_successful_payload_by_endpoint;
    bool last_record_valid = false;
    bool left_button_pressed = false;
};

struct ProbeStreamKey {
    std::uint16_t bus = 0;
    std::uint16_t device = 0;

    [[nodiscard]] bool operator<(const ProbeStreamKey& other) const noexcept {
        return std::tie(bus, device) < std::tie(other.bus, other.device);
    }
};

struct AddressActivity {
    void Process(const capture::UsbPcapPacket& packet,
                 const std::size_t maximum_payload_bytes) {
        ++interrupt_in_records;
        if (!packet.IsCompletion() || packet.status != 0U ||
            packet.payload.empty()) {
            return;
        }
        ++successful_nonempty_completions;
        const bool bounded = packet.payload.size() <= maximum_payload_bytes;
        auto& previous = last_payload_by_endpoint[packet.endpoint];
        if (!previous.empty() && bounded &&
            (previous.size() != packet.payload.size() ||
             !std::equal(previous.begin(), previous.end(),
                         packet.payload.begin()))) {
            ++payload_change_events;
        }
        if (bounded) {
            previous.assign(packet.payload.begin(), packet.payload.end());
        } else {
            previous.clear();
        }
    }

    std::uint64_t interrupt_in_records = 0;
    std::uint64_t successful_nonempty_completions = 0;
    std::uint64_t payload_change_events = 0;
    std::map<std::uint8_t, std::vector<std::byte>> last_payload_by_endpoint;
};

class ProbeAccumulator final {
public:
    ProbeAccumulator(std::vector<CertificationProbeRouteConfig> configs,
                     const CertificationProbeOptions& options)
        : options_(options) {
        if (options_.selected_bus != 0U) {
            observed_source_bus_ = options_.selected_bus;
        }
        if (options_.native.capture_all_devices) {
            route_templates_ = std::move(configs);
        } else {
            routes_.reserve(configs.size());
            for (auto& config : configs) {
                routes_.emplace_back(std::move(config));
            }
        }
    }

    void ProcessChunk(const std::span<const std::byte> chunk) {
        if (chunk.size() > options_.maximum_chunk_bytes) {
            throw ProbeFailure(CertificationProbeFatalReason::SourceBoundExceeded,
                               "native probe chunk exceeded its strict bound");
        }
        std::uint64_t next_source_bytes = 0;
        if (!CheckedAdd(source_bytes_, static_cast<std::uint64_t>(chunk.size()),
                        next_source_bytes) ||
            next_source_bytes > options_.maximum_source_bytes) {
            throw ProbeFailure(CertificationProbeFatalReason::SourceBoundExceeded,
                               "bounded certification source byte limit reached");
        }
        source_bytes_ = next_source_bytes;

        std::vector<capture::PcapRecord> records;
        try {
            parser_.Append(chunk);
            records = parser_.TakeRecords();
        } catch (const std::exception& error) {
            throw ProbeFailure(
                CertificationProbeFatalReason::PcapFraming,
                std::string("invalid USBPcap source framing: ") + error.what());
        }

        for (const auto& record : records) {
            if (source_records_ == options_.maximum_source_records) {
                throw ProbeFailure(
                    CertificationProbeFatalReason::SourceBoundExceeded,
                    "bounded certification source record limit reached");
            }
            ++source_records_;

            capture::UsbPcapPacket packet;
            try {
                packet = capture::UsbPcapPacket::Parse(record.data,
                                                       record.original_length);
            } catch (const std::exception& error) {
                throw ProbeFailure(
                    CertificationProbeFatalReason::PcapFraming,
                    std::string("invalid LINKTYPE_USBPCAP record: ") + error.what());
            }
            if (options_.native.capture_all_devices) {
                ProcessWholeRootRecord(record, packet);
            } else {
                ProcessExactRecord(record, packet);
            }
        }
    }

    void Finalize() {
        try {
            parser_.Finalize();
        } catch (const std::exception& error) {
            throw ProbeFailure(
                CertificationProbeFatalReason::PcapFraming,
                std::string("certification source ended mid-frame: ") +
                    error.what());
        }
        finalized_ = true;
    }

    [[nodiscard]] bool BoundReached() const noexcept {
        return sample_limit_reached_ || interval_limit_reached_;
    }

    [[nodiscard]] windows_capture::NativeUsbPcapSemanticDrainEvidence
    DrainEvidence() const {
        windows_capture::NativeUsbPcapSemanticDrainEvidence evidence;
        evidence.parser_at_record_boundary = finalized_ && parser_.AtRecordBoundary();
        // There is deliberately no writer in this ephemeral probe. "clean"
        // means every delivered source byte was parsed and accounted for.
        evidence.authoritative_writer_clean = finalized_;
        evidence.accounted_bytes = source_bytes_;
        evidence.diagnostic = evidence.parser_at_record_boundary
            ? "ephemeral certification source is at a PCAP record boundary"
            : "ephemeral certification source is not at a PCAP record boundary";
        return evidence;
    }

    void FillResult(CertificationProbeResult& result,
                    const std::int64_t duration_ns,
                    const bool source_intact) {
        result.source_bytes = source_bytes_;
        result.source_records = source_records_;
        result.candidate_records = candidate_records_;
        result.ignored_records = ignored_records_;
        result.sample_limit_reached = sample_limit_reached_;
        result.interval_limit_reached = interval_limit_reached_;

        if (options_.native.capture_all_devices) {
            FillWholeRootResult(result, duration_ns, source_intact);
            return;
        }
        if (observed_candidate_bus_ && observed_candidate_device_) {
            result.validated_identity = ValidatedCertificationUsbIdentity{
                options_.native.root_index,
                static_cast<std::uint8_t>(options_.selected_device),
                options_.native.device_address,
                *observed_candidate_bus_,
                *observed_candidate_device_,
                false,
            };
        }
        MoveRoutesToResult(result, routes_, duration_ns, source_intact,
                           observed_candidate_bus_, observed_candidate_device_,
                           false);
    }

private:
    [[nodiscard]] std::vector<RouteAccumulator> FreshWholeRootRoutes() const {
        std::vector<RouteAccumulator> result;
        result.reserve(route_templates_.size());
        for (const auto& source : route_templates_) {
            // Address discovery is descriptor-independent. Avoid multiplying
            // decoded samples/interval vectors across every device on a root.
            CertificationProbeRouteConfig config;
            config.probe_route_token = source.probe_route_token;
            config.endpoint_address = source.endpoint_address;
            result.emplace_back(std::move(config));
        }
        return result;
    }

    void ProcessExactRecord(const capture::PcapRecord& record,
                            const capture::UsbPcapPacket& packet) {
        if (packet.bus == 0U || packet.device != options_.selected_device ||
            (observed_source_bus_ && packet.bus != *observed_source_bus_)) {
            std::ostringstream detail;
            detail << "exact-address certification source did not retain packet identity ";
            if (observed_source_bus_) detail << *observed_source_bus_;
            else detail << "<discover>";
            detail << ':' << options_.selected_device << " (observed "
                   << packet.bus << ':' << packet.device << ')';
            throw ProbeFailure(
                CertificationProbeFatalReason::DeviceIdentityMismatch,
                detail.str());
        }
        bool candidate_record = false;
        if (packet.transfer == capture::UsbTransfer::Interrupt) {
            for (auto& route : routes_) {
                if ((packet.endpoint & 0x80U) == 0U ||
                    (route.endpoint != 0U && route.endpoint != packet.endpoint)) {
                    continue;
                }
                candidate_record = true;
                route.Process(record, packet, options_, true,
                              sample_limit_reached_, interval_limit_reached_);
            }
        }
        if (candidate_record) {
            if (!observed_source_bus_) observed_source_bus_ = packet.bus;
            if (!observed_candidate_bus_) {
                observed_candidate_bus_ = packet.bus;
                observed_candidate_device_ = packet.device;
            }
            ++candidate_records_;
        } else {
            ++ignored_records_;
        }
    }

    void ProcessWholeRootRecord(const capture::PcapRecord& record,
                                const capture::UsbPcapPacket& packet) {
        if (packet.bus == 0U || packet.device == 0U || packet.device > 127U ||
            packet.transfer != capture::UsbTransfer::Interrupt ||
            (packet.endpoint & 0x80U) == 0U ||
            (options_.selected_bus != 0U &&
             packet.bus != options_.selected_bus)) {
            ++ignored_records_;
            return;
        }

        const ProbeStreamKey key{packet.bus, packet.device};
        address_activity_[key].Process(
            packet, options_.maximum_candidate_payload_bytes);
        auto found = broad_routes_.find(key);
        if (found == broad_routes_.end()) {
            found = broad_routes_.emplace(
                key, FreshWholeRootRoutes()).first;
        }
        for (auto& route : found->second) {
            if (route.endpoint != 0U && route.endpoint != packet.endpoint) {
                continue;
            }
            route.Process(record, packet, options_, false,
                          sample_limit_reached_, interval_limit_reached_);
        }
        ++candidate_records_;
    }

    [[nodiscard]] std::optional<ProbeStreamKey> BestWholeRootStream() const {
        std::optional<ProbeStreamKey> best;
        std::optional<ProbeStreamKey> topology_stream;
        for (const auto& [key, activity] : address_activity_) {
            if (activity.successful_nonempty_completions == 0U) continue;
            if (key.device == options_.selected_device) {
                if (!topology_stream ||
                    std::tie(activity.payload_change_events,
                             activity.successful_nonempty_completions,
                             activity.interrupt_in_records) >
                        std::tie(
                            address_activity_.at(*topology_stream)
                                .payload_change_events,
                            address_activity_.at(*topology_stream)
                                .successful_nonempty_completions,
                            address_activity_.at(*topology_stream)
                                .interrupt_in_records)) {
                    topology_stream = key;
                }
            }
            if (!best) {
                best = key;
                continue;
            }
            const auto& previous = address_activity_.at(*best);
            const auto score = std::make_tuple(
                activity.payload_change_events,
                activity.successful_nonempty_completions,
                key.device == options_.selected_device,
                activity.interrupt_in_records);
            const auto previous_score = std::make_tuple(
                previous.payload_change_events,
                previous.successful_nonempty_completions,
                best->device == options_.selected_device,
                previous.interrupt_in_records);
            if (score > previous_score) best = key;
        }
        if (best && topology_stream && best->device != options_.selected_device) {
            const auto& candidate = address_activity_.at(*best);
            const auto& topology = address_activity_.at(*topology_stream);
            const bool clearly_dominates =
                candidate.payload_change_events >= 16U &&
                (topology.payload_change_events == 0U ||
                 candidate.payload_change_events / 8U >
                     topology.payload_change_events);
            if (!clearly_dominates) return topology_stream;
        }
        return best;
    }

    static void MoveRoutesToResult(
        CertificationProbeResult& result,
        std::vector<RouteAccumulator>& routes,
        const std::int64_t duration_ns,
        const bool source_intact,
        const std::optional<std::uint16_t> observed_bus,
        const std::optional<std::uint16_t> observed_device,
        const bool discovered_from_root) {
        result.evidence.reserve(routes.size());
        result.route_counters.reserve(routes.size());
        for (auto& route : routes) {
            route.Finish(duration_ns, source_intact);
            if (observed_bus && observed_device) {
                route.evidence.observed_packet_bus = *observed_bus;
                route.evidence.observed_device_address =
                    static_cast<std::uint8_t>(*observed_device);
                route.evidence.device_address_discovered_from_root =
                    discovered_from_root;
            }
            result.evidence.push_back(std::move(route.evidence));
            result.route_counters.push_back(route.counters);
        }
    }

    void FillWholeRootResult(CertificationProbeResult& result,
                             const std::int64_t duration_ns,
                             const bool source_intact) {
        const auto best = BestWholeRootStream();
        std::vector<RouteAccumulator> empty_routes;
        std::vector<RouteAccumulator>* selected_routes = nullptr;
        if (best) {
            selected_routes = &broad_routes_.at(*best);
            result.validated_identity = ValidatedCertificationUsbIdentity{
                options_.native.root_index,
                static_cast<std::uint8_t>(options_.selected_device),
                0U,
                best->bus,
                best->device,
                true,
            };
            const auto& aggregate = address_activity_.at(*best);
            std::uint64_t strongest_route_changes = 0U;
            std::uint64_t strongest_route_completions = 0U;
            for (const auto& route : *selected_routes) {
                strongest_route_changes = std::max(
                    strongest_route_changes,
                    route.counters.payload_change_events);
                strongest_route_completions = std::max(
                    strongest_route_completions,
                    route.counters.successful_nonempty_completions);
            }
            const bool enumerated_routes_missed_activity =
                strongest_route_completions == 0U ||
                (aggregate.payload_change_events >= 16U &&
                 (strongest_route_changes == 0U ||
                  aggregate.payload_change_events / 8U >
                      strongest_route_changes));
            if (enumerated_routes_missed_activity &&
                !selected_routes->empty()) {
                // Promote one existing token to the hidden device-wide proof.
                // Cardinality remains identical to CertificationFlow's plan,
                // while the resulting lock truthfully drops endpoint/decoder
                // claims that the live traffic did not support.
                auto& fallback = selected_routes->front();
                fallback.counters.endpoint_records =
                    aggregate.interrupt_in_records;
                fallback.counters.completions =
                    aggregate.successful_nonempty_completions;
                fallback.counters.successful_nonempty_completions =
                    aggregate.successful_nonempty_completions;
                fallback.counters.payload_change_events =
                    aggregate.payload_change_events;
                fallback.evidence.device_wide_activity = true;
            }
        } else {
            empty_routes = FreshWholeRootRoutes();
            selected_routes = &empty_routes;
        }
        MoveRoutesToResult(
            result, *selected_routes, duration_ns, source_intact,
            best ? std::optional<std::uint16_t>(best->bus) : std::nullopt,
            best ? std::optional<std::uint16_t>(best->device) : std::nullopt,
            true);
    }

    CertificationProbeOptions options_;
    capture::StreamingPcapParser parser_;
    std::vector<CertificationProbeRouteConfig> route_templates_;
    std::vector<RouteAccumulator> routes_;
    std::map<ProbeStreamKey, AddressActivity> address_activity_;
    std::map<ProbeStreamKey, std::vector<RouteAccumulator>> broad_routes_;
    std::uint64_t source_bytes_ = 0;
    std::uint64_t source_records_ = 0;
    std::uint64_t candidate_records_ = 0;
    std::uint64_t ignored_records_ = 0;
    std::optional<std::uint16_t> observed_source_bus_;
    std::optional<std::uint16_t> observed_candidate_bus_;
    std::optional<std::uint16_t> observed_candidate_device_;
    bool sample_limit_reached_ = false;
    bool interval_limit_reached_ = false;
    bool finalized_ = false;
};

}  // namespace

std::string ValidateCertificationProbe(
    const CertificationProbeOptions& options,
    const std::vector<CertificationProbeRouteConfig>& routes) {
    const auto native_error =
        windows_capture::ValidateNativeUsbPcapOptions(options.native);
    if (!native_error.empty()) return native_error;
    if (options.selected_device == 0U || options.selected_device > 127U) {
        return "selected packet device hint must be in [1,127]";
    }
    if (options.native.capture_all_devices) {
        if (options.native.device_address != 0U) {
            return "whole-root certification must represent its kernel filter with device address zero";
        }
    } else if (options.selected_device != options.native.device_address) {
        return "selected packet device must match the exact-address filter; packet bus is discovered independently of the USBPcap root index";
    }
    if (options.qpc_frequency <= 0 || options.qpc_frequency > 1'000'000'000'000LL) {
        return "QPC frequency is outside the supported positive range";
    }
    if (options.maximum_duration_ns <= 0 ||
        options.maximum_duration_ns > 60'000'000'000LL) {
        return "certification duration must be in (0,60] seconds";
    }
    if (options.maximum_routes == 0U || options.maximum_routes > 256U ||
        routes.empty() || routes.size() > options.maximum_routes) {
        return "certification requires a bounded nonempty route set";
    }
    if (options.maximum_samples_per_route == 0U ||
        options.maximum_samples_per_route > 2'000'000U ||
        options.maximum_intervals_per_route == 0U ||
        options.maximum_intervals_per_route > 2'000'000U ||
        options.maximum_reports_per_transfer == 0U ||
        options.maximum_reports_per_transfer > 65'536U) {
        return "certification evidence bounds are outside supported limits";
    }
    // Per-route limits are not enough on a composite device with many
    // plausible routes. Bound their worst-case aggregate before capture so a
    // caller cannot accidentally configure hundreds of megabytes of evidence.
    constexpr std::size_t kMaximumAggregateEntries = 4U * 1024U * 1024U;
    if (routes.size() >
            kMaximumAggregateEntries / options.maximum_samples_per_route ||
        routes.size() >
            kMaximumAggregateEntries / options.maximum_intervals_per_route) {
        return "aggregate certification evidence memory bound is too large";
    }
    if (options.maximum_candidate_payload_bytes == 0U ||
        options.maximum_candidate_payload_bytes > 1024U * 1024U ||
        options.maximum_chunk_bytes == 0U ||
        options.maximum_chunk_bytes > 1024U * 1024U ||
        options.native.read_chunk_bytes > options.maximum_chunk_bytes) {
        return "certification payload or native chunk bound is invalid";
    }
    if (options.maximum_source_bytes == 0U ||
        options.maximum_source_bytes > 4ULL * 1024ULL * 1024ULL * 1024ULL ||
        options.maximum_source_records == 0U ||
        options.maximum_source_records > 10'000'000ULL) {
        return "certification source bounds are outside supported limits";
    }
    if (options.consumer_poll_interval <= std::chrono::milliseconds::zero() ||
        options.consumer_poll_interval > std::chrono::seconds(1) ||
        options.consumer_drain_timeout <= std::chrono::milliseconds::zero() ||
        options.consumer_drain_timeout > std::chrono::seconds(30)) {
        return "certification poll or drain timeout is invalid";
    }

    std::set<std::string> tokens;
    for (const auto& route : routes) {
        if (route.probe_route_token.empty() ||
            route.probe_route_token.size() > 256U ||
            !tokens.insert(route.probe_route_token).second) {
            return "certification route tokens must be bounded, nonempty, and unique";
        }
        if (route.endpoint_address != 0U &&
            !IsInterruptInEndpoint(route.endpoint_address)) {
            return "certification route endpoint is not interrupt-IN";
        }
        if (route.endpoint_address == 0U && route.decoder) {
            return "device-wide certification routes cannot attach one endpoint decoder";
        }
        if (route.decoder) {
            if (route.decoder->Layouts().empty()) {
                return "certification decoder has no report layouts";
            }
            for (const auto& layout : route.decoder->Layouts()) {
                if (layout.byte_length == 0U ||
                    layout.byte_length > options.maximum_candidate_payload_bytes) {
                    return "certification route report layout exceeds its payload bound";
                }
            }
        }
    }
    return {};
}

const char* ToString(const CertificationProbeFatalReason reason) noexcept {
    switch (reason) {
    case CertificationProbeFatalReason::None: return "none";
    case CertificationProbeFatalReason::InvalidConfiguration:
        return "invalid_configuration";
    case CertificationProbeFatalReason::SourceStartFailed:
        return "source_start_failed";
    case CertificationProbeFatalReason::NativeCaptureLost:
        return "native_capture_lost";
    case CertificationProbeFatalReason::QueueOrByteLoss:
        return "queue_or_byte_loss";
    case CertificationProbeFatalReason::PcapFraming: return "pcap_framing";
    case CertificationProbeFatalReason::DeviceIdentityMismatch:
        return "device_identity_mismatch";
    case CertificationProbeFatalReason::SourceBoundExceeded:
        return "source_bound_exceeded";
    case CertificationProbeFatalReason::ClockFailure: return "clock_failure";
    }
    return "unknown";
}

CertificationProbeWorker::CertificationProbeWorker(
    IUsbPcapChunkSource& source,
    std::vector<CertificationProbeRouteConfig> routes,
    CertificationProbeOptions options,
    QpcNow qpc_now)
    : source_(source),
      routes_(std::move(routes)),
      options_(std::move(options)),
      qpc_now_(std::move(qpc_now)) {}

CertificationProbeResult CertificationProbeWorker::Run() {
    if (run_entered_) throw std::logic_error("certification probe can only run once");
    run_entered_ = true;

    CertificationProbeResult result;
    const auto validation = ValidateCertificationProbe(options_, routes_);
    if (!validation.empty() || !qpc_now_) {
        result.fatal_reason = CertificationProbeFatalReason::InvalidConfiguration;
        result.detail = validation.empty() ? "certification QPC source is missing"
                                           : validation;
        return result;
    }

    ProbeAccumulator accumulator(std::move(routes_), options_);
    std::int64_t start_qpc = 0;
    std::int64_t high_water_qpc = 0;
    try {
        start_qpc = qpc_now_();
        high_water_qpc = start_qpc;
    } catch (const std::exception& error) {
        result.fatal_reason = CertificationProbeFatalReason::ClockFailure;
        result.detail = std::string("could not start bounded probe clock: ") +
                        error.what();
        accumulator.FillResult(result, 1, false);
        return result;
    } catch (...) {
        result.fatal_reason = CertificationProbeFatalReason::ClockFailure;
        result.detail = "could not start bounded probe clock";
        accumulator.FillResult(result, 1, false);
        return result;
    }

    if (!source_.Start(options_.native)) {
        const auto status = source_.Status();
        result.fatal_reason = NativeQueueOrByteLoss(status)
            ? CertificationProbeFatalReason::QueueOrByteLoss
            : CertificationProbeFatalReason::SourceStartFailed;
        result.detail = status.message.empty()
            ? "USBPcap certification source did not start"
            : status.message;
        source_.Abort();
        accumulator.FillResult(result, 1, false);
        return result;
    }

    CertificationProbeFatalReason pending_reason =
        CertificationProbeFatalReason::None;
    std::string pending_detail;
    bool stop_forwarded = false;
    std::optional<std::chrono::steady_clock::time_point> shutdown_deadline;
    const auto probe_wall_deadline = std::chrono::steady_clock::now() +
        std::chrono::nanoseconds(options_.maximum_duration_ns);

    const auto bounded_duration = [&] {
        return result.duration_limit_reached
            ? options_.maximum_duration_ns
            : ElapsedNanoseconds(start_qpc, high_water_qpc,
                                 options_.qpc_frequency,
                                 options_.maximum_duration_ns);
    };

    const auto forward_stop = [&] {
        if (stop_forwarded) return;
        source_.RequestStop();
        stop_forwarded = true;
        shutdown_deadline = std::chrono::steady_clock::now() +
                            options_.consumer_drain_timeout;
    };

    try {
        for (;;) {
            std::vector<std::byte> chunk;
            const bool received = source_.WaitTakeChunk(
                chunk, options_.consumer_poll_interval);
            if (received) accumulator.ProcessChunk(chunk);

            std::int64_t observed_qpc = 0;
            try {
                observed_qpc = qpc_now_();
            } catch (const std::exception& error) {
                throw ProbeFailure(
                    CertificationProbeFatalReason::ClockFailure,
                    std::string("bounded certification clock failed: ") +
                        error.what());
            } catch (...) {
                throw ProbeFailure(CertificationProbeFatalReason::ClockFailure,
                                   "bounded certification clock failed");
            }
            if (observed_qpc < high_water_qpc) {
                ++result.qpc_regressions;
            } else {
                high_water_qpc = observed_qpc;
            }

            if (!stop_forwarded &&
                (DurationReached(start_qpc, high_water_qpc,
                                 options_.qpc_frequency,
                                 options_.maximum_duration_ns) ||
                 std::chrono::steady_clock::now() >= probe_wall_deadline)) {
                result.duration_limit_reached = true;
                forward_stop();
            }
            if (!stop_forwarded && accumulator.BoundReached()) forward_stop();

            const auto status = source_.Status();
            if (NativeQueueOrByteLoss(status)) {
                pending_reason = CertificationProbeFatalReason::QueueOrByteLoss;
                pending_detail = status.message.empty()
                    ? "native certification source lost queued bytes"
                    : status.message;
                forward_stop();
            } else if (NativeStateIsFatal(status.state) &&
                       pending_reason == CertificationProbeFatalReason::None) {
                pending_reason = CertificationProbeFatalReason::NativeCaptureLost;
                pending_detail = status.message.empty()
                    ? "native certification source entered a fatal state"
                    : status.message;
                forward_stop();
            }

            if (!received && status.reader_finished) {
                if (!stop_forwarded &&
                    pending_reason == CertificationProbeFatalReason::None) {
                    pending_reason = CertificationProbeFatalReason::NativeCaptureLost;
                    pending_detail =
                        "native certification reader ended before its bounded stop";
                }
                break;
            }
            if (stop_forwarded && shutdown_deadline &&
                std::chrono::steady_clock::now() >= *shutdown_deadline) {
                pending_reason = CertificationProbeFatalReason::NativeCaptureLost;
                pending_detail =
                    "native certification reader did not stop within its drain bound";
                source_.Abort();
                result.fatal_reason = pending_reason;
                result.detail = pending_detail;
                accumulator.FillResult(result, bounded_duration(), false);
                return result;
            }
        }

        accumulator.Finalize();
    } catch (const ProbeFailure& error) {
        source_.Abort();
        result.fatal_reason = error.Reason();
        result.detail = error.what();
        accumulator.FillResult(result, bounded_duration(), false);
        return result;
    } catch (const std::exception& error) {
        source_.Abort();
        result.fatal_reason = CertificationProbeFatalReason::NativeCaptureLost;
        result.detail = std::string("certification probe failed: ") + error.what();
        accumulator.FillResult(result, bounded_duration(), false);
        return result;
    }

    try {
        result.native_stop = source_.StopAndDrain(
            options_.consumer_drain_timeout,
            [&accumulator] { return accumulator.DrainEvidence(); });
    } catch (const std::exception& error) {
        if (pending_reason == CertificationProbeFatalReason::None) {
            pending_reason = CertificationProbeFatalReason::NativeCaptureLost;
            pending_detail = std::string("certification source drain failed: ") +
                             error.what();
        }
    } catch (...) {
        if (pending_reason == CertificationProbeFatalReason::None) {
            pending_reason = CertificationProbeFatalReason::NativeCaptureLost;
            pending_detail = "certification source drain failed";
        }
    }

    const auto final_status = source_.Status();
    const bool byte_accounting_failed = NativeQueueOrByteLoss(final_status) ||
        result.native_stop.bytes_read != result.native_stop.bytes_delivered ||
        result.native_stop.bytes_read != result.native_stop.bytes_accounted ||
        !result.native_stop.consumer_queue_empty;
    if (byte_accounting_failed) {
        pending_reason = CertificationProbeFatalReason::QueueOrByteLoss;
        pending_detail = result.native_stop.diagnostic.empty()
            ? "native certification source byte accounting was incomplete"
            : result.native_stop.diagnostic;
    } else if ((!result.native_stop.clean ||
                !result.native_stop.semantic_guard_invoked ||
                !result.native_stop.semantic_guard_passed) &&
               pending_reason == CertificationProbeFatalReason::None) {
        pending_reason = CertificationProbeFatalReason::NativeCaptureLost;
        pending_detail = result.native_stop.diagnostic.empty()
            ? "native certification source did not drain cleanly"
            : result.native_stop.diagnostic;
    }

    result.clean = pending_reason == CertificationProbeFatalReason::None;
    result.fatal_reason = pending_reason;
    result.detail = result.clean
        ? "bounded USB certification probe drained cleanly"
        : pending_detail;
    accumulator.FillResult(result, bounded_duration(), result.clean);
    return result;
}

}  // namespace abdc::acquisition
