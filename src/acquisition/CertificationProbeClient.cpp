#include "acquisition/CertificationProbeClient.h"

#include "base/Json.h"
#include "base/Sha256.h"
#include "capture/HidDescriptor.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <utility>

namespace abdc::acquisition {
namespace {

constexpr std::wstring_view kProbeHelperFilename = L"abct_probe_helper.exe";
constexpr std::uint32_t kForcedProbeExitCode = 0xabdc0002U;
constexpr std::chrono::milliseconds kPollInterval{50};
constexpr std::chrono::milliseconds kForcedWait{2'000};

[[nodiscard]] std::int64_t JsonInteger(const std::uint64_t value) {
    if (value > static_cast<std::uint64_t>(
                    std::numeric_limits<std::int64_t>::max())) {
        throw std::runtime_error("probe protocol integer exceeds JSON range");
    }
    return static_cast<std::int64_t>(value);
}

[[nodiscard]] std::uint64_t Unsigned(const json::Value& value,
                                     const std::uint64_t maximum,
                                     const char* label) {
    const auto number = value.AsInt();
    if (number < 0 || static_cast<std::uint64_t>(number) > maximum) {
        throw std::runtime_error(std::string(label) + " is outside its bound");
    }
    return static_cast<std::uint64_t>(number);
}

[[nodiscard]] std::size_t Size(const json::Value& value,
                               const std::size_t maximum,
                               const char* label) {
    return static_cast<std::size_t>(Unsigned(value, maximum, label));
}

[[nodiscard]] bool ValidCapability(const std::string_view value) {
    return value.size() == 64U &&
           std::all_of(value.begin(), value.end(), [](const char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

[[nodiscard]] bool ValidRouteToken(const std::string_view value) {
    if (value.empty() || value.size() > 128U) return false;
    return std::all_of(value.begin(), value.end(), [](const unsigned char value) {
        return std::isalnum(value) != 0 || value == '-' || value == '_' ||
               value == '.' || value == ':';
    });
}

[[nodiscard]] bool ValidInterruptInEndpoint(const std::uint8_t endpoint) {
    return (endpoint & 0x80U) != 0U && (endpoint & 0x0fU) != 0U &&
           (endpoint & 0x70U) == 0U;
}

[[nodiscard]] std::string Hex(std::span<const std::byte> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2U, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const auto value = std::to_integer<unsigned char>(bytes[index]);
        result[index * 2U] = digits[value >> 4U];
        result[index * 2U + 1U] = digits[value & 0x0fU];
    }
    return result;
}

[[nodiscard]] unsigned char HexNibble(const char value) {
    if (value >= '0' && value <= '9') return static_cast<unsigned char>(value - '0');
    if (value >= 'a' && value <= 'f') {
        return static_cast<unsigned char>(10 + value - 'a');
    }
    throw std::runtime_error("probe descriptor contains invalid hexadecimal text");
}

[[nodiscard]] std::vector<std::byte> Unhex(const std::string_view text,
                                           const std::size_t maximum) {
    if ((text.size() & 1U) != 0U || text.size() / 2U > maximum) {
        throw std::runtime_error("probe descriptor evidence has an unsafe size");
    }
    std::vector<std::byte> result(text.size() / 2U);
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::byte>(
            (HexNibble(text[index * 2U]) << 4U) |
             HexNibble(text[index * 2U + 1U]));
    }
    return result;
}

[[nodiscard]] std::string BytesToText(const std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

[[nodiscard]] std::vector<std::byte> TextToBytes(const std::string_view text) {
    std::vector<std::byte> result(text.size());
    std::transform(text.begin(), text.end(), result.begin(), [](const char value) {
        return static_cast<std::byte>(static_cast<unsigned char>(value));
    });
    return result;
}

void ValidateLaunchRoute(const CertificationProbeLaunchRoute& route) {
    if (!ValidRouteToken(route.probe_route_token) ||
        (route.endpoint_address != 0U &&
         !ValidInterruptInEndpoint(route.endpoint_address))) {
        throw std::invalid_argument("probe route token or endpoint is invalid");
    }
    const bool has_descriptor = !route.descriptor_evidence.empty();
    const bool has_spec = !route.canonical_decoder_spec.empty();
    if (has_descriptor != has_spec ||
        route.descriptor_evidence.size() > (1U << 20U) ||
        route.canonical_decoder_spec.size() > (1U << 20U) ||
        (route.endpoint_address == 0U && has_descriptor)) {
        throw std::invalid_argument("probe descriptor evidence is outside its bound");
    }
    if (!has_descriptor) return;
    const auto descriptor =
        capture::HidDescriptor::Parse(route.descriptor_evidence);
    if (descriptor.RelativeMouseLayouts().empty() ||
        descriptor.CanonicalDecoderSpec() != route.canonical_decoder_spec) {
        throw std::invalid_argument(
            "probe descriptor does not reproduce the supplied decoder specification");
    }
}

void ValidateLaunchConfig(const CertificationProbeLaunchConfig& config) {
    if (config.usbpcap_root_index == 0U ||
        config.usbpcap_root_index > 255U ||
        config.filtered_device_address == 0U ||
        config.filtered_device_address > 127U) {
        throw std::invalid_argument("probe USBPcap root or device address is invalid");
    }
    if (config.routes.empty() || config.routes.size() > 32U) {
        throw std::invalid_argument("probe requires between one and 32 routes");
    }
    if (config.maximum_duration_ns <= 0 ||
        config.maximum_duration_ns > 60'000'000'000LL ||
        config.maximum_samples_per_route == 0U ||
        config.maximum_samples_per_route > 262'144U ||
        config.maximum_intervals_per_route == 0U ||
        config.maximum_intervals_per_route > 262'144U ||
        config.maximum_reports_per_transfer == 0U ||
        config.maximum_reports_per_transfer > 4'096U ||
        config.maximum_candidate_payload_bytes == 0U ||
        config.maximum_candidate_payload_bytes > (1U << 20U) ||
        config.maximum_source_bytes == 0U ||
        config.maximum_source_bytes > (2ULL << 30U) ||
        config.maximum_source_records == 0U ||
        config.maximum_source_records > 10'000'000ULL ||
        config.graceful_shutdown_timeout <= std::chrono::milliseconds::zero() ||
        config.graceful_shutdown_timeout > std::chrono::seconds(30)) {
        throw std::invalid_argument("probe resource or duration bound is invalid");
    }
    std::set<std::string, std::less<>> tokens;
    for (const auto& route : config.routes) {
        ValidateLaunchRoute(route);
        if (!tokens.insert(route.probe_route_token).second) {
            throw std::invalid_argument("probe route tokens must be unique");
        }
    }
}

[[nodiscard]] json::Value TotalsJson(const device::ActivityTotals& totals) {
    json::Value value(json::Value::Object{});
    value["dx"] = totals.canonical_dx;
    value["dy"] = totals.canonical_dy;
    value["left_down_edges"] = JsonInteger(totals.left_down_edges);
    value["left_up_edges"] = JsonInteger(totals.left_up_edges);
    value["packet_count"] = JsonInteger(totals.packet_count);
    value["absolute_motion_counts"] = JsonInteger(totals.absolute_motion_counts);
    return value;
}

[[nodiscard]] device::ActivityTotals ParseTotals(const json::Value& value) {
    device::ActivityTotals result;
    result.canonical_dx = value.At("dx").AsInt();
    result.canonical_dy = value.At("dy").AsInt();
    result.left_down_edges = Unsigned(value.At("left_down_edges"),
                                     10'000'000ULL, "left-down edges");
    result.left_up_edges = Unsigned(value.At("left_up_edges"),
                                   10'000'000ULL, "left-up edges");
    result.packet_count = Unsigned(value.At("packet_count"),
                                   10'000'000ULL, "packet count");
    result.absolute_motion_counts = Unsigned(
        value.At("absolute_motion_counts"),
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()),
        "motion count");
    return result;
}

[[nodiscard]] json::Value SampleJson(const device::GestureSample& sample) {
    json::Value value(json::Value::Object{});
    value["t_ns"] = sample.relative_time_ns;
    value["dx"] = static_cast<std::int64_t>(sample.canonical_dx);
    value["dy"] = static_cast<std::int64_t>(sample.canonical_dy);
    value["left_down"] = sample.left_down;
    value["left_up"] = sample.left_up;
    return value;
}

[[nodiscard]] device::GestureSample ParseSample(const json::Value& value) {
    device::GestureSample sample;
    sample.relative_time_ns = value.At("t_ns").AsInt();
    const auto dx = value.At("dx").AsInt();
    const auto dy = value.At("dy").AsInt();
    if (dx < std::numeric_limits<std::int32_t>::min() ||
        dx > std::numeric_limits<std::int32_t>::max() ||
        dy < std::numeric_limits<std::int32_t>::min() ||
        dy > std::numeric_limits<std::int32_t>::max()) {
        throw std::runtime_error("probe sample count is outside int32 range");
    }
    sample.canonical_dx = static_cast<std::int32_t>(dx);
    sample.canonical_dy = static_cast<std::int32_t>(dy);
    sample.left_down = value.At("left_down").AsBool();
    sample.left_up = value.At("left_up").AsBool();
    return sample;
}

[[nodiscard]] CertificationProbeFatalReason ParseFatalReason(
    const std::string_view text) {
    constexpr std::array reasons{
        CertificationProbeFatalReason::None,
        CertificationProbeFatalReason::InvalidConfiguration,
        CertificationProbeFatalReason::SourceStartFailed,
        CertificationProbeFatalReason::NativeCaptureLost,
        CertificationProbeFatalReason::QueueOrByteLoss,
        CertificationProbeFatalReason::PcapFraming,
        CertificationProbeFatalReason::DeviceIdentityMismatch,
        CertificationProbeFatalReason::SourceBoundExceeded,
        CertificationProbeFatalReason::ClockFailure,
    };
    for (const auto reason : reasons) {
        if (text == ToString(reason)) return reason;
    }
    throw std::runtime_error("unknown certification probe fatal reason");
}

[[nodiscard]] json::Value CounterJson(
    const CertificationProbeRouteCounters& counter) {
    json::Value value(json::Value::Object{});
#define ABDC_PROBE_COUNTER(name) value[#name] = JsonInteger(counter.name)
    ABDC_PROBE_COUNTER(endpoint_records);
    ABDC_PROBE_COUNTER(requests);
    ABDC_PROBE_COUNTER(completions);
    ABDC_PROBE_COUNTER(successful_nonempty_completions);
    ABDC_PROBE_COUNTER(payload_change_events);
    ABDC_PROBE_COUNTER(decoded_transfers);
    ABDC_PROBE_COUNTER(decoded_reports);
    ABDC_PROBE_COUNTER(failed_transfers);
    ABDC_PROBE_COUNTER(empty_completions);
    ABDC_PROBE_COUNTER(decode_failures);
    ABDC_PROBE_COUNTER(timestamp_regressions);
    ABDC_PROBE_COUNTER(duplicate_like_records);
    ABDC_PROBE_COUNTER(nonpositive_transfer_intervals);
    ABDC_PROBE_COUNTER(samples_omitted_at_bound);
    ABDC_PROBE_COUNTER(intervals_omitted_at_bound);
#undef ABDC_PROBE_COUNTER
    return value;
}

[[nodiscard]] CertificationProbeRouteCounters ParseCounter(
    const json::Value& value) {
    CertificationProbeRouteCounters result;
#define ABDC_PROBE_PARSE_COUNTER(name)                                      \
    result.name = Unsigned(value.At(#name), 10'000'000ULL, #name)
    ABDC_PROBE_PARSE_COUNTER(endpoint_records);
    ABDC_PROBE_PARSE_COUNTER(requests);
    ABDC_PROBE_PARSE_COUNTER(completions);
    ABDC_PROBE_PARSE_COUNTER(successful_nonempty_completions);
    ABDC_PROBE_PARSE_COUNTER(payload_change_events);
    ABDC_PROBE_PARSE_COUNTER(decoded_transfers);
    ABDC_PROBE_PARSE_COUNTER(decoded_reports);
    ABDC_PROBE_PARSE_COUNTER(failed_transfers);
    ABDC_PROBE_PARSE_COUNTER(empty_completions);
    ABDC_PROBE_PARSE_COUNTER(decode_failures);
    ABDC_PROBE_PARSE_COUNTER(timestamp_regressions);
    ABDC_PROBE_PARSE_COUNTER(duplicate_like_records);
    ABDC_PROBE_PARSE_COUNTER(nonpositive_transfer_intervals);
    ABDC_PROBE_PARSE_COUNTER(samples_omitted_at_bound);
    ABDC_PROBE_PARSE_COUNTER(intervals_omitted_at_bound);
#undef ABDC_PROBE_PARSE_COUNTER
    return result;
}

[[nodiscard]] std::uint32_t ProcessId(const json::Value& value) {
    return static_cast<std::uint32_t>(Unsigned(
        value, std::numeric_limits<std::uint32_t>::max(), "process id"));
}

[[nodiscard]] CertificationProbeReadySnapshot ParseReady(
    const std::string_view text,
    const std::uint32_t expected_helper,
    const std::uint32_t expected_parent) {
    const auto value = json::Parse(text);
    if (value.At("schema").AsString() != "abcurves.certification.ready.v1" ||
        value.At("state").AsString() != "ready") {
        throw std::runtime_error("invalid certification ready schema");
    }
    CertificationProbeReadySnapshot result;
    result.capability = value.At("capability").AsString();
    result.helper_pid = ProcessId(value.At("helper_pid"));
    result.parent_pid = ProcessId(value.At("parent_pid"));
    if (!ValidCapability(result.capability) ||
        result.helper_pid != expected_helper ||
        result.parent_pid != expected_parent) {
        throw std::runtime_error("certification ready identity did not match launch");
    }
    return result;
}

[[nodiscard]] std::string CancelJson(const std::string_view capability) {
    json::Value value(json::Value::Object{});
    value["schema"] = "abcurves.certification.cancel.v1";
    value["capability"] = std::string(capability);
    return json::DumpCanonical(value, false) + "\n";
}

}  // namespace

std::vector<std::byte> SerializeCertificationProbeHelperConfig(
    const CertificationProbeLaunchConfig& config) {
    ValidateLaunchConfig(config);
    json::Value value(json::Value::Object{});
    value["schema"] = "abcurves.certification.config.v2";
    value["usbpcap_root_index"] = static_cast<std::int64_t>(
        config.usbpcap_root_index);
    value["filtered_device_address"] = static_cast<std::int64_t>(
        config.filtered_device_address);
    value["discover_device_address"] = config.discover_device_address;
    value["expected_packet_bus"] = static_cast<std::int64_t>(
        config.expected_packet_bus);
    value["maximum_duration_ns"] = config.maximum_duration_ns;
    value["maximum_samples_per_route"] = JsonInteger(
        config.maximum_samples_per_route);
    value["maximum_intervals_per_route"] = JsonInteger(
        config.maximum_intervals_per_route);
    value["maximum_reports_per_transfer"] = JsonInteger(
        config.maximum_reports_per_transfer);
    value["maximum_candidate_payload_bytes"] = JsonInteger(
        config.maximum_candidate_payload_bytes);
    value["maximum_source_bytes"] = JsonInteger(config.maximum_source_bytes);
    value["maximum_source_records"] = JsonInteger(config.maximum_source_records);
    json::Value::Array routes;
    routes.reserve(config.routes.size());
    for (const auto& route : config.routes) {
        json::Value item(json::Value::Object{});
        item["probe_route_token"] = route.probe_route_token;
        item["endpoint_address"] = static_cast<std::int64_t>(
            route.endpoint_address);
        item["descriptor_hex"] = Hex(route.descriptor_evidence);
        item["canonical_decoder_spec"] = route.canonical_decoder_spec;
        routes.emplace_back(std::move(item));
    }
    value["routes"] = std::move(routes);
    const auto text = json::DumpCanonical(value, false) + "\n";
    if (text.size() > kMaximumCertificationProbeConfigBytes) {
        throw std::invalid_argument("probe helper config exceeds its byte bound");
    }
    return TextToBytes(text);
}

CertificationProbeHelperPlan ParseCertificationProbeHelperConfig(
    const std::span<const std::byte> bytes) {
    if (bytes.empty() || bytes.size() > kMaximumCertificationProbeConfigBytes) {
        throw std::invalid_argument("probe helper config has an unsafe size");
    }
    const auto value = json::Parse(BytesToText(bytes));
    if (value.At("schema").AsString() != "abcurves.certification.config.v2") {
        throw std::invalid_argument("unsupported probe helper config schema");
    }

    CertificationProbeHelperPlan plan;
    plan.options.native.root_index = static_cast<std::uint16_t>(Unsigned(
        value.At("usbpcap_root_index"), 255U, "USBPcap root index"));
    plan.options.native.device_address = static_cast<std::uint8_t>(Unsigned(
        value.At("filtered_device_address"), 127U, "device address"));
    plan.options.native.capture_all_devices =
        value.At("discover_device_address").AsBool();
    plan.options.selected_bus = static_cast<std::uint16_t>(Unsigned(
        value.At("expected_packet_bus"),
        std::numeric_limits<std::uint16_t>::max(), "packet bus"));
    plan.options.selected_device = plan.options.native.device_address;
    if (plan.options.native.capture_all_devices) {
        // The topology address remains the ranking hint. Address zero truthfully
        // represents the whole-root kernel filter used only by this probe.
        plan.options.native.device_address = 0U;
        // Mouse HID reports are far smaller than this. A bounded snapshot keeps
        // unrelated bulk traffic from dominating the transient probe while
        // preserving every plausible interrupt payload needed for selection.
        plan.options.native.snapshot_length = 4U * 1024U;
    }
    plan.options.maximum_duration_ns = value.At("maximum_duration_ns").AsInt();
    plan.options.maximum_samples_per_route = Size(
        value.At("maximum_samples_per_route"), 262'144U, "sample limit");
    plan.options.maximum_intervals_per_route = Size(
        value.At("maximum_intervals_per_route"), 262'144U, "interval limit");
    plan.options.maximum_reports_per_transfer = Size(
        value.At("maximum_reports_per_transfer"), 4'096U, "report batch limit");
    plan.options.maximum_candidate_payload_bytes = Size(
        value.At("maximum_candidate_payload_bytes"), 1U << 20U,
        "candidate payload limit");
    plan.options.maximum_source_bytes = Unsigned(
        value.At("maximum_source_bytes"), 2ULL << 30U, "source byte limit");
    plan.options.maximum_source_records = Unsigned(
        value.At("maximum_source_records"), 10'000'000ULL,
        "source record limit");

    const auto& route_values = value.At("routes").AsArray();
    if (route_values.empty() || route_values.size() > 32U) {
        throw std::invalid_argument("probe helper route count is invalid");
    }
    plan.options.maximum_routes = 32U;
    std::set<std::string, std::less<>> tokens;
    for (const auto& item : route_values) {
        const auto token = item.At("probe_route_token").AsString();
        const auto endpoint = static_cast<std::uint8_t>(Unsigned(
            item.At("endpoint_address"), 255U, "endpoint"));
        const auto descriptor_bytes = Unhex(
            item.At("descriptor_hex").AsString(), 1U << 20U);
        const auto spec = item.At("canonical_decoder_spec").AsString();
        const bool has_descriptor = !descriptor_bytes.empty();
        const bool has_spec = !spec.empty();
        if (!ValidRouteToken(token) ||
            (endpoint != 0U && !ValidInterruptInEndpoint(endpoint)) ||
            has_descriptor != has_spec || spec.size() > (1U << 20U) ||
            (endpoint == 0U && has_descriptor) ||
            !tokens.insert(token).second) {
            throw std::invalid_argument("probe helper route is invalid");
        }
        std::optional<capture::HidMouseDecoder> decoder;
        if (has_descriptor) {
            const auto descriptor = capture::HidDescriptor::Parse(descriptor_bytes);
            auto layouts = descriptor.RelativeMouseLayouts();
            if (layouts.empty() || descriptor.CanonicalDecoderSpec() != spec) {
                throw std::invalid_argument(
                    "probe helper descriptor/decoder verification failed");
            }
            decoder.emplace(std::move(layouts));
        }
        plan.routes.push_back({token, endpoint, std::move(decoder)});
    }
    plan.options.qpc_frequency = 1;
    const auto validation = ValidateCertificationProbe(plan.options, plan.routes);
    plan.options.qpc_frequency = 0;
    if (!validation.empty()) throw std::invalid_argument(validation);
    return plan;
}

CertificationProbeCommand BuildCertificationProbeCommand(
    const CertificationProbeControlPaths& controls,
    const std::filesystem::path& executable,
    const std::uint32_t parent_pid,
    const std::string_view config_sha256) {
    if (parent_pid == 0U || executable.empty() ||
        controls.config.empty() || controls.ready.empty() ||
        controls.result.empty() || controls.cancel.empty() ||
        controls.error.empty() || !ValidCapability(config_sha256)) {
        throw std::invalid_argument("probe helper command is incomplete");
    }
    CertificationProbeCommand result;
    result.executable = executable;
    result.arguments = {
        L"--certification-probe",
        L"--config", controls.config.wstring(),
        L"--config-sha256", std::wstring(config_sha256.begin(),
                                          config_sha256.end()),
        L"--parent-pid", std::to_wstring(parent_pid),
        L"--ready-file", controls.ready.wstring(),
        L"--result-file", controls.result.wstring(),
        L"--cancel-file", controls.cancel.wstring(),
        L"--error-file", controls.error.wstring(),
    };
    result.parameter_line = SerializeCaptureHelperArguments(result.arguments);
    return result;
}

std::string SerializeCertificationProbeResultEnvelope(
    const CertificationProbeTransportResult& result,
    const std::string_view capability,
    const std::uint32_t helper_pid,
    const std::uint32_t parent_pid) {
    if (!ValidCapability(capability) || helper_pid == 0U || parent_pid == 0U ||
        result.probe.evidence.size() > 32U ||
        result.probe.route_counters.size() > 32U ||
        result.probe.detail.size() > 4096U) {
        throw std::invalid_argument("probe result envelope is invalid");
    }
    json::Value root(json::Value::Object{});
    root["schema"] = "abcurves.certification.result.v2";
    root["state"] = result.cancelled ? "cancelled" : "complete";
    root["capability"] = std::string(capability);
    root["helper_pid"] = static_cast<std::int64_t>(helper_pid);
    root["parent_pid"] = static_cast<std::int64_t>(parent_pid);

    json::Value probe(json::Value::Object{});
    probe["clean"] = result.probe.clean;
    probe["fatal_reason"] = ToString(result.probe.fatal_reason);
    probe["detail"] = result.probe.detail;
    probe["source_bytes"] = JsonInteger(result.probe.source_bytes);
    probe["source_records"] = JsonInteger(result.probe.source_records);
    probe["candidate_records"] = JsonInteger(result.probe.candidate_records);
    probe["ignored_records"] = JsonInteger(result.probe.ignored_records);
    probe["qpc_regressions"] = JsonInteger(result.probe.qpc_regressions);
    probe["duration_limit_reached"] = result.probe.duration_limit_reached;
    probe["sample_limit_reached"] = result.probe.sample_limit_reached;
    probe["interval_limit_reached"] = result.probe.interval_limit_reached;

    json::Value::Array evidence;
    evidence.reserve(result.probe.evidence.size());
    for (const auto& item : result.probe.evidence) {
        if (!ValidRouteToken(item.probe_route_token) ||
            item.usb_samples.size() > 262'144U ||
            item.positive_usb_transfer_intervals_ns.size() > 262'144U) {
            throw std::invalid_argument("probe evidence exceeds protocol bounds");
        }
        json::Value encoded(json::Value::Object{});
        encoded["probe_route_token"] = item.probe_route_token;
        encoded["probe_duration_ns"] = item.probe_duration_ns;
        encoded["observed_packet_bus"] = static_cast<std::int64_t>(
            item.observed_packet_bus);
        encoded["observed_device_address"] = static_cast<std::int64_t>(
            item.observed_device_address);
        encoded["device_address_discovered_from_root"] =
            item.device_address_discovered_from_root;
        encoded["device_wide_activity"] = item.device_wide_activity;
        encoded["usb_totals"] = TotalsJson(item.usb_totals);
        encoded["usb_interrupt_records"] =
            JsonInteger(item.usb_interrupt_records);
        encoded["usb_successful_nonempty_completions"] =
            JsonInteger(item.usb_successful_nonempty_completions);
        encoded["usb_payload_change_events"] =
            JsonInteger(item.usb_payload_change_events);
        encoded["source_capture_intact"] = item.source_capture_intact;
        encoded["decode_warnings"] = JsonInteger(item.decode_warnings);
        encoded["failed_transfers"] = JsonInteger(item.failed_transfers);
        json::Value::Array samples;
        samples.reserve(item.usb_samples.size());
        for (const auto& sample : item.usb_samples) {
            samples.emplace_back(SampleJson(sample));
        }
        encoded["usb_samples"] = std::move(samples);
        json::Value::Array intervals;
        intervals.reserve(item.positive_usb_transfer_intervals_ns.size());
        for (const auto interval : item.positive_usb_transfer_intervals_ns) {
            intervals.emplace_back(interval);
        }
        encoded["positive_usb_transfer_intervals_ns"] = std::move(intervals);
        evidence.emplace_back(std::move(encoded));
    }
    probe["evidence"] = std::move(evidence);

    json::Value::Array counters;
    counters.reserve(result.probe.route_counters.size());
    for (const auto& counter : result.probe.route_counters) {
        counters.emplace_back(CounterJson(counter));
    }
    probe["route_counters"] = std::move(counters);

    if (result.probe.validated_identity) {
        json::Value identity(json::Value::Object{});
        identity["usbpcap_root_index"] = static_cast<std::int64_t>(
            result.probe.validated_identity->usbpcap_root_index);
        identity["topology_device_address"] = static_cast<std::int64_t>(
            result.probe.validated_identity->topology_device_address);
        identity["filtered_device_address"] = static_cast<std::int64_t>(
            result.probe.validated_identity->filtered_device_address);
        identity["packet_bus"] = static_cast<std::int64_t>(
            result.probe.validated_identity->packet_bus);
        identity["packet_device"] = static_cast<std::int64_t>(
            result.probe.validated_identity->packet_device);
        identity["whole_root_capture"] =
            result.probe.validated_identity->whole_root_capture;
        probe["validated_identity"] = std::move(identity);
    } else {
        probe["validated_identity"] = nullptr;
    }

    json::Value stop(json::Value::Object{});
#define ABDC_STOP_BOOL(name) stop[#name] = result.probe.native_stop.name
    ABDC_STOP_BOOL(clean);
    ABDC_STOP_BOOL(filter_stop_attempted);
    ABDC_STOP_BOOL(filter_stop_succeeded);
    ABDC_STOP_BOOL(kernel_quiet_observed);
    ABDC_STOP_BOOL(cancellation_observed);
    ABDC_STOP_BOOL(quiet_completion_observed);
    ABDC_STOP_BOOL(consumer_queue_empty);
    ABDC_STOP_BOOL(semantic_guard_invoked);
    ABDC_STOP_BOOL(semantic_guard_passed);
    ABDC_STOP_BOOL(handle_closed);
#undef ABDC_STOP_BOOL
    stop["bytes_read"] = JsonInteger(result.probe.native_stop.bytes_read);
    stop["bytes_delivered"] = JsonInteger(
        result.probe.native_stop.bytes_delivered);
    stop["bytes_accounted"] = JsonInteger(
        result.probe.native_stop.bytes_accounted);
    stop["bytes_left_in_queue"] = JsonInteger(
        result.probe.native_stop.bytes_left_in_queue);
    stop["win32_error"] = static_cast<std::int64_t>(
        result.probe.native_stop.win32_error);
    stop["diagnostic"] = result.probe.native_stop.diagnostic.substr(0, 4096U);
    probe["native_stop"] = std::move(stop);
    root["probe"] = std::move(probe);

    const auto text = json::DumpCanonical(root, false) + "\n";
    if (text.size() > kMaximumCertificationProbeResultBytes) {
        throw std::invalid_argument("probe derivative result exceeds its byte bound");
    }
    return text;
}

CertificationProbeTransportResult ParseCertificationProbeResultEnvelope(
    const std::string_view text,
    const std::string_view expected_capability,
    const std::uint32_t expected_helper_pid,
    const std::uint32_t expected_parent_pid) {
    if (text.empty() || text.size() > kMaximumCertificationProbeResultBytes ||
        !ValidCapability(expected_capability)) {
        throw std::invalid_argument("probe result envelope has an unsafe size");
    }
    const auto root = json::Parse(text);
    if (root.At("schema").AsString() != "abcurves.certification.result.v2" ||
        root.At("capability").AsString() != expected_capability ||
        ProcessId(root.At("helper_pid")) != expected_helper_pid ||
        ProcessId(root.At("parent_pid")) != expected_parent_pid) {
        throw std::runtime_error("probe result identity did not match launch");
    }
    CertificationProbeTransportResult result;
    const auto state = root.At("state").AsString();
    if (state == "cancelled") result.cancelled = true;
    else if (state != "complete") {
        throw std::runtime_error("probe result state is invalid");
    }
    const auto& probe = root.At("probe");
    result.probe.clean = probe.At("clean").AsBool();
    result.probe.fatal_reason = ParseFatalReason(
        probe.At("fatal_reason").AsString());
    result.probe.detail = probe.At("detail").AsString();
    if (result.probe.detail.size() > 4096U) {
        throw std::runtime_error("probe result detail exceeds its bound");
    }
    result.probe.source_bytes = Unsigned(
        probe.At("source_bytes"), 2ULL << 30U, "source bytes");
    result.probe.source_records = Unsigned(
        probe.At("source_records"), 10'000'000ULL, "source records");
    result.probe.candidate_records = Unsigned(
        probe.At("candidate_records"), 10'000'000ULL, "candidate records");
    result.probe.ignored_records = Unsigned(
        probe.At("ignored_records"), 10'000'000ULL, "ignored records");
    result.probe.qpc_regressions = Unsigned(
        probe.At("qpc_regressions"), 10'000'000ULL, "QPC regressions");
    result.probe.duration_limit_reached =
        probe.At("duration_limit_reached").AsBool();
    result.probe.sample_limit_reached =
        probe.At("sample_limit_reached").AsBool();
    result.probe.interval_limit_reached =
        probe.At("interval_limit_reached").AsBool();

    const auto& evidence = probe.At("evidence").AsArray();
    if (evidence.size() > 32U) throw std::runtime_error("too many probe routes");
    for (const auto& encoded : evidence) {
        device::CertificationProbeEvidence item;
        item.probe_route_token = encoded.At("probe_route_token").AsString();
        if (!ValidRouteToken(item.probe_route_token)) {
            throw std::runtime_error("invalid probe route token");
        }
        item.probe_duration_ns = encoded.At("probe_duration_ns").AsInt();
        item.observed_packet_bus = static_cast<std::uint16_t>(Unsigned(
            encoded.At("observed_packet_bus"),
            std::numeric_limits<std::uint16_t>::max(),
            "observed packet bus"));
        item.observed_device_address = static_cast<std::uint8_t>(Unsigned(
            encoded.At("observed_device_address"), 127U,
            "observed device address"));
        item.device_address_discovered_from_root =
            encoded.At("device_address_discovered_from_root").AsBool();
        item.device_wide_activity =
            encoded.At("device_wide_activity").AsBool();
        item.usb_totals = ParseTotals(encoded.At("usb_totals"));
        item.usb_interrupt_records = Unsigned(
            encoded.At("usb_interrupt_records"), 10'000'000ULL,
            "USB interrupt records");
        item.usb_successful_nonempty_completions = Unsigned(
            encoded.At("usb_successful_nonempty_completions"),
            10'000'000ULL, "USB nonempty completions");
        item.usb_payload_change_events = Unsigned(
            encoded.At("usb_payload_change_events"), 10'000'000ULL,
            "USB payload changes");
        item.source_capture_intact =
            encoded.At("source_capture_intact").AsBool();
        item.decode_warnings = Unsigned(encoded.At("decode_warnings"),
                                       10'000'000ULL, "decode warnings");
        item.failed_transfers = Unsigned(encoded.At("failed_transfers"),
                                        10'000'000ULL, "failed transfers");
        const auto& samples = encoded.At("usb_samples").AsArray();
        if (samples.size() > 262'144U) {
            throw std::runtime_error("probe sample array exceeds its bound");
        }
        item.usb_samples.reserve(samples.size());
        for (const auto& sample : samples) {
            item.usb_samples.push_back(ParseSample(sample));
        }
        const auto& intervals =
            encoded.At("positive_usb_transfer_intervals_ns").AsArray();
        if (intervals.size() > 262'144U) {
            throw std::runtime_error("probe interval array exceeds its bound");
        }
        item.positive_usb_transfer_intervals_ns.reserve(intervals.size());
        for (const auto& interval : intervals) {
            const auto number = interval.AsInt();
            if (number <= 0) throw std::runtime_error("probe interval is not positive");
            item.positive_usb_transfer_intervals_ns.push_back(number);
        }
        result.probe.evidence.emplace_back(std::move(item));
    }
    const auto& counters = probe.At("route_counters").AsArray();
    if (counters.size() > 32U) throw std::runtime_error("too many probe counters");
    for (const auto& counter : counters) {
        result.probe.route_counters.push_back(ParseCounter(counter));
    }
    if (result.probe.route_counters.size() != result.probe.evidence.size()) {
        throw std::runtime_error("probe evidence/counter cardinality mismatch");
    }

    const auto& identity = probe.At("validated_identity");
    if (!identity.IsNull()) {
        ValidatedCertificationUsbIdentity parsed;
        parsed.usbpcap_root_index = static_cast<std::uint16_t>(Unsigned(
            identity.At("usbpcap_root_index"), 255U, "USBPcap root"));
        parsed.topology_device_address = static_cast<std::uint8_t>(Unsigned(
            identity.At("topology_device_address"), 127U,
            "topology device"));
        parsed.filtered_device_address = static_cast<std::uint8_t>(Unsigned(
            identity.At("filtered_device_address"), 127U, "filtered device"));
        parsed.packet_bus = static_cast<std::uint16_t>(Unsigned(
            identity.At("packet_bus"),
            std::numeric_limits<std::uint16_t>::max(), "packet bus"));
        parsed.packet_device = static_cast<std::uint16_t>(Unsigned(
            identity.At("packet_device"),
            std::numeric_limits<std::uint16_t>::max(), "packet device"));
        parsed.whole_root_capture =
            identity.At("whole_root_capture").AsBool();
        if (parsed.usbpcap_root_index == 0U ||
            parsed.topology_device_address == 0U || parsed.packet_bus == 0U ||
            parsed.packet_device == 0U || parsed.packet_device > 127U ||
            (parsed.whole_root_capture
                 ? parsed.filtered_device_address != 0U
                 : (parsed.filtered_device_address == 0U ||
                    parsed.packet_device !=
                        parsed.filtered_device_address))) {
            throw std::runtime_error("validated probe identity is inconsistent");
        }
        result.probe.validated_identity = parsed;
    }

    const auto& stop = probe.At("native_stop");
#define ABDC_PARSE_STOP_BOOL(name)                                      \
    result.probe.native_stop.name = stop.At(#name).AsBool()
    ABDC_PARSE_STOP_BOOL(clean);
    ABDC_PARSE_STOP_BOOL(filter_stop_attempted);
    ABDC_PARSE_STOP_BOOL(filter_stop_succeeded);
    ABDC_PARSE_STOP_BOOL(kernel_quiet_observed);
    ABDC_PARSE_STOP_BOOL(cancellation_observed);
    ABDC_PARSE_STOP_BOOL(quiet_completion_observed);
    ABDC_PARSE_STOP_BOOL(consumer_queue_empty);
    ABDC_PARSE_STOP_BOOL(semantic_guard_invoked);
    ABDC_PARSE_STOP_BOOL(semantic_guard_passed);
    ABDC_PARSE_STOP_BOOL(handle_closed);
#undef ABDC_PARSE_STOP_BOOL
    result.probe.native_stop.bytes_read = Unsigned(
        stop.At("bytes_read"), 2ULL << 30U, "native bytes read");
    result.probe.native_stop.bytes_delivered = Unsigned(
        stop.At("bytes_delivered"), 2ULL << 30U, "native bytes delivered");
    result.probe.native_stop.bytes_accounted = Unsigned(
        stop.At("bytes_accounted"), 2ULL << 30U, "native bytes accounted");
    result.probe.native_stop.bytes_left_in_queue = Size(
        stop.At("bytes_left_in_queue"), 32U << 20U, "native queue bytes");
    result.probe.native_stop.win32_error = static_cast<std::uint32_t>(Unsigned(
        stop.At("win32_error"), std::numeric_limits<std::uint32_t>::max(),
        "native error"));
    result.probe.native_stop.diagnostic = stop.At("diagnostic").AsString();
    if (result.probe.native_stop.diagnostic.size() > 4096U) {
        throw std::runtime_error("native probe diagnostic exceeds its bound");
    }
    return result;
}

class CertificationProbeClient::Mutex final {
public:
    std::mutex value;
};

CertificationProbeClient::CertificationProbeClient()
    : CertificationProbeClient(std::make_shared<Win32CaptureHelperPlatform>()) {}

CertificationProbeClient::CertificationProbeClient(
    std::shared_ptr<ICaptureHelperPlatform> platform)
    : platform_(std::move(platform)), mutex_(std::make_unique<Mutex>()) {
    if (!platform_) throw std::invalid_argument("probe helper platform is required");
}

CertificationProbeClient::~CertificationProbeClient() {
    CancelAndWait();
}

CertificationProbeStartResult CertificationProbeClient::Start(
    const CertificationProbeLaunchConfig& config) {
    std::scoped_lock lock(mutex_->value);
    if (start_attempted_) {
        return {false, CertificationProbeStartFailure::InvalidConfiguration,
                "Mouse certification has already been attempted."};
    }
    start_attempted_ = true;
    state_ = CertificationProbeClientState::Starting;
    config_ = config;
    try {
        const auto executable = config.helper_executable.empty()
            ? platform_->SiblingExecutable(kProbeHelperFilename)
            : std::filesystem::absolute(config.helper_executable);
        config_.helper_executable = executable;
        const auto encoded = SerializeCertificationProbeHelperConfig(config_);
        if (!platform_->IsRegularFile(executable)) {
            state_ = CertificationProbeClientState::Failed;
            message_ = "The mouse certification helper is missing.";
            return {false, CertificationProbeStartFailure::HelperMissing, message_};
        }
        const auto root = config.control_root.empty()
            ? platform_->DefaultControlRoot()
            : std::filesystem::absolute(config.control_root);
        controls_.directory = platform_->CreatePrivateControlDirectory(root);
        controls_created_ = true;
        controls_.config = controls_.directory / L"probe_config.json";
        controls_.ready = controls_.directory / L"ready.json";
        controls_.result = controls_.directory / L"result.json";
        controls_.cancel = controls_.directory / L"cancel.json";
        controls_.error = controls_.directory / L"error.json";
        platform_->WriteNewPrivateFile(controls_.config, encoded);

        parent_pid_ = platform_->CurrentProcessId();
        if (parent_pid_ == 0U) throw std::runtime_error("parent process is unavailable");
        const auto command = BuildCertificationProbeCommand(
            controls_, executable, parent_pid_, Sha256Hex(encoded));
        const auto launch = platform_->LaunchElevated(
            command.executable, command.parameter_line);
        if (launch.disposition != ElevatedLaunchDisposition::Started ||
            launch.process == 0U || launch.process_id == 0U) {
            state_ = CertificationProbeClientState::Failed;
            if (launch.disposition == ElevatedLaunchDisposition::UacDenied) {
                message_ = "Mouse certification needs administrator approval.";
                CleanupControls();
                return {false, CertificationProbeStartFailure::UacDenied, message_};
            }
            message_ = launch.disposition == ElevatedLaunchDisposition::NotFound
                ? "The mouse certification helper is missing."
                : "Mouse certification could not start.";
            CleanupControls();
            return {false,
                    launch.disposition == ElevatedLaunchDisposition::NotFound
                        ? CertificationProbeStartFailure::HelperMissing
                        : CertificationProbeStartFailure::LaunchFailed,
                    message_};
        }
        process_ = launch.process;
        helper_pid_ = launch.process_id;
        message_.clear();
        return {true, CertificationProbeStartFailure::None, {}};
    } catch (const std::invalid_argument& error) {
        state_ = CertificationProbeClientState::Failed;
        message_ = error.what();
        CleanupControls();
        return {false, CertificationProbeStartFailure::InvalidConfiguration,
                message_};
    } catch (...) {
        state_ = CertificationProbeClientState::Failed;
        message_ = "Mouse certification could not start.";
        TerminateAndClose();
        CleanupControls();
        return {false, CertificationProbeStartFailure::LaunchFailed, message_};
    }
}

CertificationProbeClientSnapshot CertificationProbeClient::Snapshot() {
    std::scoped_lock lock(mutex_->value);
    return SnapshotWithoutLock();
}

CertificationProbeClientSnapshot CertificationProbeClient::SnapshotWithoutLock() {
    ObserveFiles();
    if (process_ != 0U) {
        const auto poll = platform_->WaitProcess(
            process_, std::chrono::milliseconds::zero());
        if (poll.state == CaptureHelperProcessState::Exited) {
            ObserveFiles();
            FinishExited(poll.exit_code);
        } else if (poll.state == CaptureHelperProcessState::Failed) {
            message_ = "Mouse certification process status is unavailable.";
        }
    }
    return {state_, exit_code_, ready_, result_, message_};
}

void CertificationProbeClient::ObserveFiles() noexcept {
    try {
        if (!controls_created_) return;
        if (!ready_ && platform_->FileExists(controls_.ready)) {
            ready_ = ParseReady(platform_->ReadSmallFile(controls_.ready, 4096U),
                                helper_pid_, parent_pid_);
            if (state_ == CertificationProbeClientState::Starting) {
                state_ = CertificationProbeClientState::Running;
            }
        }
        if (ready_ && cancel_pending_ && !cancel_written_) {
            platform_->AtomicWriteFile(controls_.cancel,
                                       CancelJson(ready_->capability));
            cancel_written_ = true;
        }
        if (ready_ && !result_ && platform_->FileExists(controls_.result)) {
            result_ = ParseCertificationProbeResultEnvelope(
                platform_->ReadSmallFile(controls_.result,
                    kMaximumCertificationProbeResultBytes),
                ready_->capability, helper_pid_, parent_pid_);
        }
        if (platform_->FileExists(controls_.error)) {
            const auto error = json::Parse(
                platform_->ReadSmallFile(controls_.error, 16U << 10U));
            if (error.At("schema").AsString() ==
                    "abcurves.certification.error.v1" &&
                ProcessId(error.At("helper_pid")) == helper_pid_ &&
                ProcessId(error.At("parent_pid")) == parent_pid_) {
                message_ = error.At("detail").AsString().substr(0, 4096U);
            }
        }
    } catch (...) {
        // One-shot files are write-through, but an observer may still race a
        // create/write boundary. Process exit plus a final parse decides.
    }
}

bool CertificationProbeClient::RequestCancel() {
    std::scoped_lock lock(mutex_->value);
    if (state_ == CertificationProbeClientState::Completed ||
        state_ == CertificationProbeClientState::Cancelled) return true;
    if (process_ == 0U) return false;
    cancel_pending_ = true;
    state_ = CertificationProbeClientState::CancelRequested;
    ObserveFiles();
    return true;
}

void CertificationProbeClient::CancelAndWait() noexcept {
    if (!mutex_) return;
    std::scoped_lock lock(mutex_->value);
    if (process_ == 0U) {
        CleanupControls();
        return;
    }
    cancel_pending_ = true;
    state_ = CertificationProbeClientState::CancelRequested;
    ObserveFiles();
    auto remaining = config_.graceful_shutdown_timeout;
    while (remaining > std::chrono::milliseconds::zero() && process_ != 0U) {
        const auto slice = std::min(remaining, kPollInterval);
        CaptureHelperProcessPoll poll;
        try {
            poll = platform_->WaitProcess(process_, slice);
        } catch (...) {
            poll.state = CaptureHelperProcessState::Failed;
        }
        remaining -= slice;
        ObserveFiles();
        if (poll.state == CaptureHelperProcessState::Exited) {
            FinishExited(poll.exit_code);
            return;
        }
        if (poll.state == CaptureHelperProcessState::Failed) break;
    }
    TerminateAndClose();
}

void CertificationProbeClient::FinishExited(
    const std::optional<std::uint32_t> exit_code) noexcept {
    exit_code_ = exit_code;
    if (process_ != 0U) {
        platform_->CloseProcess(process_);
        process_ = 0U;
    }
    if (result_ && exit_code && *exit_code == 0U) {
        state_ = result_->cancelled ? CertificationProbeClientState::Cancelled
                                    : CertificationProbeClientState::Completed;
        if (!result_->cancelled) message_.clear();
    } else {
        state_ = CertificationProbeClientState::Failed;
        if (message_.empty()) {
            message_ = "Mouse certification stopped before returning valid evidence.";
        }
    }
    CleanupControls();
}

void CertificationProbeClient::TerminateAndClose() noexcept {
    if (process_ == 0U) return;
    try {
        static_cast<void>(platform_->TerminateProcess(
            process_, kForcedProbeExitCode));
        const auto poll = platform_->WaitProcess(process_, kForcedWait);
        if (poll.state == CaptureHelperProcessState::Exited) {
            ObserveFiles();
            FinishExited(poll.exit_code);
            if (state_ != CertificationProbeClientState::Cancelled) {
                state_ = CertificationProbeClientState::Failed;
                message_ = "Mouse certification was force-stopped.";
            }
            return;
        }
        platform_->CloseProcess(process_);
        process_ = 0U;
    } catch (...) {
    }
    state_ = CertificationProbeClientState::Failed;
    if (message_.empty()) message_ = "Mouse certification is still stopping.";
}

void CertificationProbeClient::CleanupControls() noexcept {
    if (!controls_created_ || process_ != 0U) return;
    platform_->RemoveOwnedFile(controls_.cancel);
    platform_->RemoveOwnedFile(controls_.error);
    platform_->RemoveOwnedFile(controls_.result);
    platform_->RemoveOwnedFile(controls_.ready);
    platform_->RemoveOwnedFile(controls_.config);
    platform_->RemoveOwnedDirectoryIfEmpty(controls_.directory);
    controls_created_ = false;
}

}  // namespace abdc::acquisition
