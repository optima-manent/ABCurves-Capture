#pragma once

#include "device/ActivityCorrelation.h"
#include "device/MouseDiscovery.h"
#include "device/PhysicalMouseSelection.h"
#include "device/UsbTopologyResolver.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace abdc::device {

// One topology resolution belongs to one Raw Input collection of the physical
// mouse selected by the participant. A composite mouse may contribute more
// than one collection. The participant never has to choose between them.
struct CertificationTopology {
    std::string raw_interface_token;
    ResolvedUsbMouseTransport transport;
};

// Ephemeral instructions for the bounded probe capture. Neither token is
// persistable; they only join the in-memory probe result back to this plan.
struct CertificationProbeRoute {
    std::string probe_route_token;

    // Ephemeral group identity for one physical interrupt-IN stream. Several
    // collection-specific decoders may legitimately share this token.
    std::string source_stream_token;
    std::string raw_interface_token;
    ResolvedUsbMouseTransport transport;
};

struct CertificationPolicy {
    ActivityCorrelationPolicy correlation;
    std::int64_t maximum_probe_duration_ns = 20'000'000'000LL;
};

struct CertificationProbeEvidence {
    std::string probe_route_token;
    std::int64_t probe_duration_ns = 0;

    // Packet identity observed by the elevated probe. A zero pair is accepted
    // only by synthetic/legacy callers and falls back to the topology address.
    // Public collection uses a transient whole-root probe so a stale Windows
    // address cannot hide the real moving USBPcap stream.
    std::uint16_t observed_packet_bus = 0;
    std::uint8_t observed_device_address = 0;
    bool device_address_discovered_from_root = false;
    // True when endpoint metadata did not describe the dominant stream and
    // the proof therefore used every interrupt-IN endpoint on the selected
    // address. Final collection is still exact-address and device-wide.
    bool device_wide_activity = false;

    // Used for a topology-unique route. The totals need not agree in scale or
    // packet count. Activity from unrelated mice is retained only as metadata.
    ActivityTotals usb_totals;
    ActivityTotals selected_raw_input_totals;
    ActivityTotals other_raw_input_totals;

    // Descriptor-independent proof that the selected USBPcap stream was active
    // during the selected mouse gesture. Payload changes are counted per
    // endpoint, so traffic from sibling endpoints is never compared as if it
    // were one report format.
    std::uint64_t usb_interrupt_records = 0;
    std::uint64_t usb_successful_nonempty_completions = 0;
    std::uint64_t usb_payload_change_events = 0;

    // Used when two or more plausible route/collection pairs must be ranked.
    std::vector<GestureSample> usb_samples;
    std::vector<GestureSample> selected_raw_input_samples;
    std::vector<std::int64_t> positive_usb_transfer_intervals_ns;

    // Decode and failed-transfer counts are quality metadata. Only loss of the
    // source probe capture makes the identity proof unusable.
    bool source_capture_intact = true;
    std::uint64_t decode_warnings = 0;
    std::uint64_t failed_transfers = 0;
};

// This is the only lock shape that may be serialized. It deliberately excludes
// Raw Input handles, native paths, location strings, container identifiers,
// root-hub tokens, and salted runtime join tokens.
struct PrivacySafeMouseLock {
    std::string product_name;
    std::uint16_t vendor_id = 0;
    std::uint16_t product_id = 0;
    std::uint16_t version_number = 0;
    std::uint16_t usbpcap_root_index = 0;
    std::uint8_t device_address = 0;
    std::uint8_t interface_number = 0;
    std::uint8_t endpoint_address = 0;
    std::uint16_t endpoint_max_packet_bytes = 0;
    std::uint8_t endpoint_interval = 0;
    std::string descriptor_sha256;
    DescriptorEvidenceSource descriptor_evidence_source =
        DescriptorEvidenceSource::None;
    std::string descriptor_reconstructor;
    std::string descriptor_reconstructor_version;
    std::string layout_fingerprint;
    std::vector<std::uint8_t> report_ids;
};

struct CertificationSuccess {
    PrivacySafeMouseLock lock;

    // Runtime-only state for WM_INPUT routing and destructive-change checks.
    // Callers must never write this object to a session or diagnostic log.
    LockedMouseIdentity live_identity;

    std::string sanitized_manifest_json;
    std::string proof_method;
    ActivityCorrelationDecision activity;
    std::uint64_t decode_warnings = 0;
    std::uint64_t failed_transfers = 0;
};

enum class CertificationState {
    PreparationFailed,
    AwaitingProbe,
    RetryAvailable,
    Certified,
    Cancelled,
};

enum class CertificationIssue {
    None,
    InventoryIncomplete,
    PhysicalSelectionMissing,
    PhysicalSelectionAmbiguous,
    NoProbeableRoute,
    InvalidTopology,
    InvalidProbeEvidence,
    ProbeWindowInvalid,
    InsufficientMovement,
    ClickNotObserved,
    UsbActivityNotObserved,
    WeakTemporalCorrelation,
    AmbiguousRoutes,
    SourceCaptureLost,
    Cancelled,
};

[[nodiscard]] const char* ToString(CertificationState state) noexcept;
[[nodiscard]] const char* ToString(CertificationIssue issue) noexcept;

struct CertificationDecision {
    CertificationState state = CertificationState::PreparationFailed;
    CertificationIssue issue = CertificationIssue::None;
    std::string explanation;
    std::string participant_action;
    bool retry_available = false;
    std::optional<CertificationSuccess> success;
};

// Finite coordinator: SubmitProbe consumes one bounded attempt. A failed probe
// cannot silently begin another; the UI must expose and invoke Retry explicitly.
class CertificationFlow final {
public:
    [[nodiscard]] static CertificationFlow Prepare(
        const DiscoverySnapshot& snapshot,
        const std::string& selected_physical_device_token,
        std::span<const CertificationTopology> topologies,
        const CertificationPolicy& policy = {});

    [[nodiscard]] const CertificationDecision& Decision() const noexcept {
        return decision_;
    }
    [[nodiscard]] std::span<const CertificationProbeRoute> Routes() const noexcept {
        return routes_;
    }
    [[nodiscard]] std::uint32_t AttemptNumber() const noexcept {
        return attempt_number_;
    }

    const CertificationDecision& SubmitProbe(
        std::span<const CertificationProbeEvidence> evidence);
    const CertificationDecision& Retry();
    const CertificationDecision& Cancel();

private:
    CertificationFlow() = default;

    CertificationPolicy policy_;
    std::vector<CertificationProbeRoute> routes_;
    std::vector<MouseInterfaceCandidate> selected_mice_;
    CertificationDecision decision_;
    std::uint32_t attempt_number_ = 0;
};

}  // namespace abdc::device
