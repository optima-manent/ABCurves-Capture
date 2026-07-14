#include "device/CertificationFlow.h"

#include "base/Json.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <set>
#include <tuple>
#include <utility>

namespace abdc::device {
namespace {

bool IsInterruptInEndpoint(const std::uint8_t endpoint) noexcept {
    return (endpoint & 0x80U) != 0U && (endpoint & 0x0fU) != 0U &&
           (endpoint & 0x70U) == 0U;
}

std::vector<std::uint8_t> NormalizedReportIds(std::vector<std::uint8_t> ids) {
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
}

std::string SanitizedText(const std::string& input, const std::size_t maximum_bytes,
                          const std::string& fallback) {
    std::string output;
    output.reserve(std::min(input.size(), maximum_bytes));
    bool previous_space = false;
    for (const unsigned char value : input) {
        if (output.size() >= maximum_bytes) break;
        const bool replace_with_space = value < 0x20U || value == 0x7fU ||
                                        value == '\\' || value == '/';
        const bool is_space = replace_with_space || value == ' ' || value == '\t';
        if (is_space) {
            if (!output.empty() && !previous_space) output.push_back(' ');
            previous_space = true;
            continue;
        }
        output.push_back(static_cast<char>(value));
        previous_space = false;
    }
    while (!output.empty() && output.back() == ' ') output.pop_back();
    return output.empty() ? fallback : output;
}

std::int64_t JsonCount(const std::uint64_t value) noexcept {
    constexpr auto maximum = static_cast<std::uint64_t>(
        std::numeric_limits<std::int64_t>::max());
    return static_cast<std::int64_t>(std::min(value, maximum));
}

CertificationDecision FailureDecision(const CertificationIssue issue,
                                      std::string explanation,
                                      std::string participant_action) {
    CertificationDecision result;
    result.state = CertificationState::PreparationFailed;
    result.issue = issue;
    result.explanation = std::move(explanation);
    result.participant_action = std::move(participant_action);
    return result;
}

bool TransportProofIsComplete(const ResolvedUsbMouseTransport& transport) noexcept {
    return transport.status == UsbTopologyResolutionStatus::Probeable &&
           transport.raw_to_pnp_join_proven && transport.root_mapping_proven &&
           transport.physical_port_driver_key_proven &&
           transport.device_address_proven &&
           transport.usbpcap_root_index > 0U &&
           transport.usbpcap_root_index <= 255U &&
           transport.device_address > 0U && transport.device_address <= 127U;
}

const MouseInterfaceCandidate* FindMouse(
    const std::vector<MouseInterfaceCandidate>& mice,
    const std::string& raw_interface_token) noexcept {
    const MouseInterfaceCandidate* found = nullptr;
    for (const auto& mouse : mice) {
        if (mouse.session_token != raw_interface_token) continue;
        if (found != nullptr) return nullptr;
        found = &mouse;
    }
    return found;
}

json::Value::Array ReportIdJson(const std::vector<std::uint8_t>& ids) {
    json::Value::Array output;
    output.reserve(ids.size());
    for (const auto id : ids) output.emplace_back(static_cast<std::int64_t>(id));
    return output;
}

std::string MakeManifest(const PrivacySafeMouseLock& lock,
                         const std::string& proof_method,
                         const ActivityCorrelationDecision& activity,
                         const CertificationProbeEvidence& evidence) {
    json::Value root(json::Value::Object{});
    root["schema"] = "abcurves.mouse_certification.v1";

    json::Value device(json::Value::Object{});
    device["product_name"] = lock.product_name;
    device["vendor_id"] = static_cast<std::int64_t>(lock.vendor_id);
    device["product_id"] = static_cast<std::int64_t>(lock.product_id);
    device["version_number"] = static_cast<std::int64_t>(lock.version_number);
    root["device"] = std::move(device);

    json::Value route(json::Value::Object{});
    route["usbpcap_root_index"] =
        static_cast<std::int64_t>(lock.usbpcap_root_index);
    route["device_address"] = static_cast<std::int64_t>(lock.device_address);
    route["interface_number"] = static_cast<std::int64_t>(lock.interface_number);
    route["endpoint_address"] = static_cast<std::int64_t>(lock.endpoint_address);
    route["endpoint_max_packet_bytes"] =
        static_cast<std::int64_t>(lock.endpoint_max_packet_bytes);
    route["endpoint_interval"] = static_cast<std::int64_t>(lock.endpoint_interval);
    root["route"] = std::move(route);

    json::Value descriptor(json::Value::Object{});
    descriptor["sha256"] = lock.descriptor_sha256;
    descriptor["evidence_source"] = ToString(lock.descriptor_evidence_source);
    descriptor["reconstructor"] = lock.descriptor_reconstructor;
    descriptor["reconstructor_version"] = lock.descriptor_reconstructor_version;
    descriptor["layout_fingerprint"] = lock.layout_fingerprint;
    descriptor["report_ids"] = ReportIdJson(lock.report_ids);
    root["descriptor"] = std::move(descriptor);

    json::Value probe(json::Value::Object{});
    probe["method"] = proof_method;
    probe["directional_correlation"] = activity.correlation_score;
    probe["best_lag_ns"] = activity.best_lag_ns;
    probe["polling_interval_count"] = JsonCount(activity.polling_interval_count);
    probe["median_polling_interval_ns"] = activity.median_polling_interval_ns;
    probe["p95_polling_interval_ns"] = activity.p95_polling_interval_ns;
    probe["measured_polling_hz"] = activity.measured_polling_hz;
    probe["decode_warnings"] = JsonCount(evidence.decode_warnings);
    probe["failed_transfers"] = JsonCount(evidence.failed_transfers);
    root["probe"] = std::move(probe);

    return json::DumpCanonical(root);
}

CertificationSuccess MakeSuccess(const CertificationProbeRoute& route,
                                 const MouseInterfaceCandidate& mouse,
                                 const ActivityCorrelationDecision& activity,
                                 const CertificationProbeEvidence& evidence,
                                 std::string proof_method) {
    const auto report_ids = NormalizedReportIds(route.transport.report_ids);

    LockedMouseIdentity live;
    live.raw_interface_token = mouse.session_token;
    live.raw_input_handle = mouse.raw_input_handle;
    live.physical_device_token = mouse.topology.physical_device_token;
    live.root_hub_token = mouse.topology.root_hub_token;
    live.usbpcap_root_index = route.transport.usbpcap_root_index;
    live.device_address = route.transport.device_address;
    live.interface_number = route.transport.interface_number;
    live.endpoint_address = route.transport.endpoint_address;
    live.descriptor_sha256 = route.transport.descriptor_sha256;
    live.descriptor_evidence_source = route.transport.descriptor_evidence_source;
    live.descriptor_reconstructor = route.transport.descriptor_reconstructor;
    live.descriptor_reconstructor_version =
        route.transport.descriptor_reconstructor_version;
    live.layout_fingerprint = route.transport.layout_fingerprint;
    live.report_ids = report_ids;

    PrivacySafeMouseLock safe;
    safe.product_name = SanitizedText(
        mouse.sanitized_product_name, 96U, "USB HID mouse");
    safe.vendor_id = mouse.vendor_id;
    safe.product_id = mouse.product_id;
    safe.version_number = mouse.version_number;
    safe.usbpcap_root_index = route.transport.usbpcap_root_index;
    safe.device_address = route.transport.device_address;
    safe.interface_number = route.transport.interface_number;
    safe.endpoint_address = route.transport.endpoint_address;
    safe.endpoint_max_packet_bytes = route.transport.endpoint_max_packet_bytes;
    safe.endpoint_interval = route.transport.endpoint_interval;
    safe.descriptor_sha256 = route.transport.descriptor_sha256;
    safe.descriptor_evidence_source = route.transport.descriptor_evidence_source;
    if (!route.transport.descriptor_reconstructor.empty()) {
        safe.descriptor_reconstructor = SanitizedText(
            route.transport.descriptor_reconstructor, 96U, "");
    }
    if (!route.transport.descriptor_reconstructor_version.empty()) {
        safe.descriptor_reconstructor_version = SanitizedText(
            route.transport.descriptor_reconstructor_version, 48U, "");
    }
    safe.layout_fingerprint = route.transport.layout_fingerprint;
    safe.report_ids = report_ids;

    CertificationSuccess success;
    success.lock = std::move(safe);
    success.live_identity = std::move(live);
    success.proof_method = std::move(proof_method);
    success.activity = activity;
    success.decode_warnings = evidence.decode_warnings;
    success.failed_transfers = evidence.failed_transfers;
    success.sanitized_manifest_json = MakeManifest(
        success.lock, success.proof_method, activity, evidence);
    return success;
}

void SetRetryDecision(CertificationDecision& decision,
                      const CertificationIssue issue,
                      std::string explanation,
                      std::string action) {
    decision = {};
    decision.state = CertificationState::RetryAvailable;
    decision.issue = issue;
    decision.explanation = std::move(explanation);
    decision.participant_action = std::move(action);
    decision.retry_available = true;
}

}  // namespace

const char* ToString(const CertificationState state) noexcept {
    switch (state) {
    case CertificationState::PreparationFailed: return "preparation_failed";
    case CertificationState::AwaitingProbe: return "awaiting_probe";
    case CertificationState::RetryAvailable: return "retry_available";
    case CertificationState::Certified: return "certified";
    case CertificationState::Cancelled: return "cancelled";
    }
    return "unknown";
}

const char* ToString(const CertificationIssue issue) noexcept {
    switch (issue) {
    case CertificationIssue::None: return "none";
    case CertificationIssue::InventoryIncomplete: return "inventory_incomplete";
    case CertificationIssue::PhysicalSelectionMissing: return "physical_selection_missing";
    case CertificationIssue::PhysicalSelectionAmbiguous:
        return "physical_selection_ambiguous";
    case CertificationIssue::NoProbeableRoute: return "no_probeable_route";
    case CertificationIssue::InvalidTopology: return "invalid_topology";
    case CertificationIssue::InvalidProbeEvidence: return "invalid_probe_evidence";
    case CertificationIssue::ProbeWindowInvalid: return "probe_window_invalid";
    case CertificationIssue::InsufficientMovement: return "insufficient_movement";
    case CertificationIssue::ClickNotObserved: return "click_not_observed";
    case CertificationIssue::UsbActivityNotObserved:
        return "usb_activity_not_observed";
    case CertificationIssue::WeakTemporalCorrelation:
        return "weak_temporal_correlation";
    case CertificationIssue::AmbiguousRoutes: return "ambiguous_routes";
    case CertificationIssue::SourceCaptureLost: return "source_capture_lost";
    case CertificationIssue::Cancelled: return "cancelled";
    }
    return "unknown";
}

CertificationFlow CertificationFlow::Prepare(
    const DiscoverySnapshot& snapshot,
    const std::string& selected_physical_device_token,
    const std::span<const CertificationTopology> topologies,
    const CertificationPolicy& policy) {
    CertificationFlow flow;
    flow.policy_ = policy;
    if (!snapshot.native_enumeration_complete) {
        flow.decision_ = FailureDecision(
            CertificationIssue::InventoryIncomplete,
            "Windows did not return a complete mouse inventory.",
            "Choose Rescan after Windows finishes enumerating your mouse.");
        return flow;
    }
    if (selected_physical_device_token.empty()) {
        flow.decision_ = FailureDecision(
            CertificationIssue::PhysicalSelectionMissing,
            "No physical mouse was selected.", "Select the mouse you will use.");
        return flow;
    }
    if (policy.maximum_probe_duration_ns <= 0 ||
        policy.correlation.minimum_movement_counts == 0U ||
        policy.correlation.bin_width_ns <= 0 ||
        policy.correlation.maximum_lag_ns < 0 ||
        !std::isfinite(policy.correlation.minimum_directional_correlation) ||
        !std::isfinite(policy.correlation.unique_winner_margin) ||
        policy.correlation.minimum_directional_correlation < -1.0 ||
        policy.correlation.minimum_directional_correlation > 1.0 ||
        policy.correlation.unique_winner_margin < 0.0) {
        flow.decision_ = FailureDecision(
            CertificationIssue::InvalidTopology,
            "The certification policy is invalid.",
            "Restart the application with its default certification settings.");
        return flow;
    }

    for (const auto& mouse : snapshot.mice) {
        if (mouse.topology.physical_device_token == selected_physical_device_token) {
            flow.selected_mice_.push_back(mouse);
        }
    }
    if (flow.selected_mice_.empty()) {
        flow.decision_ = FailureDecision(
            CertificationIssue::PhysicalSelectionMissing,
            "The selected physical mouse is no longer present.",
            "Choose Rescan, then select the mouse again.");
        return flow;
    }
    std::set<std::string> raw_tokens;
    for (const auto& mouse : flow.selected_mice_) {
        if (mouse.session_token.empty() || !raw_tokens.insert(mouse.session_token).second) {
            flow.decision_ = FailureDecision(
                CertificationIssue::PhysicalSelectionAmbiguous,
                "Windows reported ambiguous collections for the selected mouse.",
                "Choose Rescan; reconnect the mouse only if ambiguity remains.");
            return flow;
        }
    }

    std::set<std::tuple<std::string, std::uint16_t, std::uint8_t,
                        std::uint8_t, std::uint8_t>> unique_routes;
    std::vector<std::pair<
        std::tuple<std::uint16_t, std::uint8_t, std::uint8_t, std::uint8_t>,
        std::string>> source_streams;
    for (const auto& topology : topologies) {
        const auto* mouse = FindMouse(flow.selected_mice_, topology.raw_interface_token);
        if (mouse == nullptr || !mouse->eligible_for_correlation_probe ||
            mouse->raw_input_handle == 0U) {
            flow.decision_ = FailureDecision(
                CertificationIssue::InvalidTopology,
                "A topology result does not belong to a probeable collection of the selected mouse.",
                "Choose Rescan, then try certification again.");
            return flow;
        }
        if (!TransportProofIsComplete(topology.transport)) {
            flow.decision_ = FailureDecision(
                CertificationIssue::InvalidTopology,
                "The selected physical mouse could not be mapped to one USBPcap device address.",
                "Reconnect the mouse and choose Rescan.");
            return flow;
        }
        auto candidates = topology.transport.candidates;
        if (candidates.empty()) {
            // Zero is an explicit device-wide interrupt-IN observer. It is
            // used when optional standard configuration metadata is absent.
            candidates.push_back({});
        }
        for (const auto& candidate : candidates) {
            if (!IsInterruptInEndpoint(candidate.endpoint_address) ||
                candidate.endpoint_max_packet_bytes == 0U) {
                if (candidate.endpoint_address == 0U) {
                    // Device-wide fallback deliberately has no endpoint
                    // packet metadata or decoder.
                } else {
                    flow.decision_ = FailureDecision(
                        CertificationIssue::InvalidTopology,
                        "A retained route is not a compatible interrupt-IN endpoint.",
                        "Reconnect the mouse and choose Rescan.");
                    return flow;
                }
            }
            const auto key = std::make_tuple(
                topology.raw_interface_token, topology.transport.usbpcap_root_index,
                topology.transport.device_address, candidate.interface_number,
                candidate.endpoint_address);
            if (!unique_routes.insert(key).second) {
                flow.decision_ = FailureDecision(
                    CertificationIssue::InvalidTopology,
                    "The same probe route was returned more than once.",
                    "Choose Rescan, then try certification again.");
                return flow;
            }
            CertificationProbeRoute route;
            route.probe_route_token =
                "probe-route-" + std::to_string(flow.routes_.size() + 1U);
            const auto source_key = std::make_tuple(
                topology.transport.usbpcap_root_index,
                topology.transport.device_address, candidate.interface_number,
                candidate.endpoint_address);
            const auto source = std::find_if(
                source_streams.begin(), source_streams.end(),
                [&](const auto& item) { return item.first == source_key; });
            if (source == source_streams.end()) {
                route.source_stream_token =
                    "source-stream-" +
                    std::to_string(source_streams.size() + 1U);
                source_streams.emplace_back(source_key,
                                            route.source_stream_token);
            } else {
                route.source_stream_token = source->second;
            }
            route.raw_interface_token = topology.raw_interface_token;
            if (candidate.endpoint_address == 0U) {
                route.transport = topology.transport;
                route.transport.candidates.clear();
                route.transport.interface_number = 0U;
                route.transport.endpoint_address = 0U;
                route.transport.endpoint_max_packet_bytes = 0U;
                route.transport.endpoint_interval = 0U;
                // One decoder cannot be attached to an unknown endpoint.
                route.transport.descriptor_evidence.clear();
                route.transport.descriptor_sha256.clear();
                route.transport.decoder_spec.clear();
                route.transport.layout_fingerprint.clear();
                route.transport.report_ids.clear();
                route.transport.descriptor_evidence_source =
                    DescriptorEvidenceSource::None;
                route.transport.descriptor_reconstructor.clear();
                route.transport.descriptor_reconstructor_version.clear();
                route.transport.descriptor_layout_supported = false;
            } else {
                route.transport = SelectUsbTransportCandidate(
                    topology.transport, candidate);
            }
            flow.routes_.push_back(std::move(route));
        }
    }
    if (flow.routes_.empty()) {
        flow.decision_ = FailureDecision(
            CertificationIssue::NoProbeableRoute,
            "No plausible interrupt-IN route was found for the selected mouse.",
            "Reconnect the mouse and choose Rescan.");
        return flow;
    }

    flow.attempt_number_ = 1U;
    flow.decision_.state = CertificationState::AwaitingProbe;
    flow.decision_.issue = CertificationIssue::None;
    flow.decision_.explanation =
        "The selected physical mouse is ready for one bounded move-and-click probe.";
    flow.decision_.participant_action =
        "Move that mouse through a wide, changing path and complete one left click.";
    return flow;
}

const CertificationDecision& CertificationFlow::SubmitProbe(
    const std::span<const CertificationProbeEvidence> evidence) {
    if (decision_.state != CertificationState::AwaitingProbe) return decision_;
    if (evidence.size() != routes_.size()) {
        SetRetryDecision(
            decision_, CertificationIssue::InvalidProbeEvidence,
            "The probe did not return one result for every plausible route.",
            "Choose Retry to run one fresh move-and-click probe.");
        return decision_;
    }

    std::vector<const CertificationProbeEvidence*> ordered(routes_.size(), nullptr);
    std::optional<std::pair<std::uint16_t, std::uint8_t>> observed_identity;
    std::optional<bool> observed_from_root;
    for (const auto& item : evidence) {
        const auto route = std::find_if(
            routes_.begin(), routes_.end(), [&](const auto& candidate) {
                return candidate.probe_route_token == item.probe_route_token;
            });
        if (route == routes_.end()) {
            SetRetryDecision(
                decision_, CertificationIssue::InvalidProbeEvidence,
                "The probe returned an unknown route token.",
                "Choose Retry to run one fresh move-and-click probe.");
            return decision_;
        }
        const auto index = static_cast<std::size_t>(route - routes_.begin());
        if (ordered[index] != nullptr) {
            SetRetryDecision(
                decision_, CertificationIssue::InvalidProbeEvidence,
                "The probe returned the same route more than once.",
                "Choose Retry to run one fresh move-and-click probe.");
            return decision_;
        }
        if (item.probe_duration_ns <= 0 ||
            item.probe_duration_ns > policy_.maximum_probe_duration_ns) {
            SetRetryDecision(
                decision_, CertificationIssue::ProbeWindowInvalid,
                "The certification gesture did not fit inside the bounded probe window.",
                "Choose Retry, then move and click once before the probe ends.");
            return decision_;
        }
        if (!item.source_capture_intact) {
            decision_ = FailureDecision(
                CertificationIssue::SourceCaptureLost,
                "A USB source probe was lost, so the selected route cannot be certified safely.",
                "Restart mouse certification after the capture helper is healthy.");
            return decision_;
        }
        const bool has_observed_bus = item.observed_packet_bus != 0U;
        const bool has_observed_device = item.observed_device_address != 0U;
        if (has_observed_bus != has_observed_device ||
            item.observed_device_address > 127U ||
            (item.device_address_discovered_from_root &&
             !has_observed_device)) {
            SetRetryDecision(
                decision_, CertificationIssue::InvalidProbeEvidence,
                "The probe returned an incomplete USB packet identity.",
                "Choose Retry to run one fresh move-and-click probe.");
            return decision_;
        }
        if (has_observed_device) {
            const auto current_identity = std::make_pair(
                item.observed_packet_bus, item.observed_device_address);
            if ((observed_identity && *observed_identity != current_identity) ||
                (observed_from_root &&
                 *observed_from_root !=
                     item.device_address_discovered_from_root)) {
                SetRetryDecision(
                    decision_, CertificationIssue::InvalidProbeEvidence,
                    "The probe routes disagreed on the observed USB stream.",
                    "Choose Retry to run one fresh move-and-click probe.");
                return decision_;
            }
            observed_identity = current_identity;
            observed_from_root = item.device_address_discovered_from_root;
        }
        ordered[index] = &item;
    }

    const auto& selected_activity = ordered.front()->selected_raw_input_totals;
    if (selected_activity.absolute_motion_counts <
        policy_.correlation.minimum_movement_counts) {
        SetRetryDecision(
            decision_, CertificationIssue::InsufficientMovement,
            "The selected mouse did not move far enough during this probe.",
            "Choose Retry, move through a wider path, and click once.");
        return decision_;
    }
    if (selected_activity.left_down_edges == 0U ||
        selected_activity.left_up_edges == 0U) {
        SetRetryDecision(
            decision_, CertificationIssue::ClickNotObserved,
            "A complete left click was not visible from the selected mouse.",
            "Choose Retry, move the selected mouse, then press and release its left button once.");
        return decision_;
    }

    std::size_t index = 0U;
    bool usb_activity_observed = false;
    for (std::size_t candidate = 0; candidate < ordered.size(); ++candidate) {
        const auto& current = *ordered[candidate];
        if (current.usb_successful_nonempty_completions == 0U) continue;
        if (!usb_activity_observed ||
            std::tie(current.usb_payload_change_events,
                     current.usb_successful_nonempty_completions,
                     current.usb_totals.absolute_motion_counts) >
                std::tie(ordered[index]->usb_payload_change_events,
                         ordered[index]->usb_successful_nonempty_completions,
                         ordered[index]->usb_totals.absolute_motion_counts)) {
            index = candidate;
        }
        usb_activity_observed = true;
    }
    if (!usb_activity_observed) {
        SetRetryDecision(
            decision_, CertificationIssue::UsbActivityNotObserved,
            "The selected mouse moved, but USBPcap produced no usable interrupt data for it.",
            "Choose Retry once. If it repeats, reconnect the mouse or receiver and Rescan.");
        return decision_;
    }

    ActivityCorrelationDecision activity;
    activity.status = ActivityCorrelationStatus::Ready;
    activity.identity_proven = true;
    activity.explanation =
        "selected Raw Input movement/click and live USBPcap activity were both observed";
    if (ordered[index]->usb_totals.absolute_motion_counts != 0U) {
        const auto decoded = EvaluateActivityCorrelation(
            ordered[index]->usb_totals, selected_activity,
            ordered[index]->other_raw_input_totals,
            ordered[index]->positive_usb_transfer_intervals_ns,
            policy_.correlation.minimum_movement_counts);
        if (decoded.status == ActivityCorrelationStatus::Ready) activity = decoded;
    }
    const auto* mouse = FindMouse(selected_mice_, routes_[index].raw_interface_token);
    if (mouse == nullptr) {
        decision_ = FailureDecision(
            CertificationIssue::InvalidTopology,
            "The winning route lost its selected Raw Input collection.",
            "Choose Rescan, then select the mouse again.");
        return decision_;
    }
    decision_ = {};
    decision_.state = CertificationState::Certified;
    decision_.issue = CertificationIssue::None;
    const auto& winning_evidence = *ordered[index];
    auto winning_route = routes_[index];
    const auto topology_address = winning_route.transport.device_address;
    if (winning_evidence.observed_device_address != 0U) {
        winning_route.transport.device_address =
            winning_evidence.observed_device_address;
    }
    if (winning_evidence.device_wide_activity) {
        winning_route.transport.candidates.clear();
        winning_route.transport.interface_number = 0U;
        winning_route.transport.endpoint_address = 0U;
        winning_route.transport.endpoint_max_packet_bytes = 0U;
        winning_route.transport.endpoint_interval = 0U;
        winning_route.transport.descriptor_evidence.clear();
        winning_route.transport.descriptor_sha256.clear();
        winning_route.transport.decoder_spec.clear();
        winning_route.transport.layout_fingerprint.clear();
        winning_route.transport.report_ids.clear();
        winning_route.transport.descriptor_evidence_source =
            DescriptorEvidenceSource::None;
        winning_route.transport.descriptor_reconstructor.clear();
        winning_route.transport.descriptor_reconstructor_version.clear();
        winning_route.transport.descriptor_layout_supported = false;
    }
    const bool address_remapped =
        winning_route.transport.device_address != topology_address;
    decision_.explanation = address_remapped
        ? "The selected mouse moved and clicked while USBPcap identified its live interrupt stream under a corrected address."
        : "The selected mouse moved and clicked while USBPcap produced live interrupt data.";
    decision_.participant_action = "Continue to sensitivity and trainer setup.";
    decision_.success = MakeSuccess(
        winning_route, *mouse, activity, winning_evidence,
        address_remapped
            ? "whole_root_activity_remap"
            : (winning_evidence.device_address_discovered_from_root
                   ? "whole_root_activity_confirmed"
                   : "physical_usb_activity"));
    return decision_;
}

const CertificationDecision& CertificationFlow::Retry() {
    if (decision_.state != CertificationState::RetryAvailable) return decision_;
    decision_ = {};
    decision_.state = CertificationState::AwaitingProbe;
    decision_.issue = CertificationIssue::None;
    decision_.explanation = "A fresh bounded certification probe is ready.";
    decision_.participant_action =
        "Move the selected mouse through a wide, changing path and complete one left click.";
    ++attempt_number_;
    return decision_;
}

const CertificationDecision& CertificationFlow::Cancel() {
    if (decision_.state == CertificationState::Certified ||
        decision_.state == CertificationState::Cancelled) {
        return decision_;
    }
    decision_ = {};
    decision_.state = CertificationState::Cancelled;
    decision_.issue = CertificationIssue::Cancelled;
    decision_.explanation = "Mouse certification was cancelled by the participant.";
    decision_.participant_action = "Select a mouse whenever you are ready to continue.";
    return decision_;
}

}  // namespace abdc::device
