#pragma once

#include "device/MouseDiscovery.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace abdc::device {

// Converts either a USB device-interface symbolic link or a PnP instance ID
// to a comparison-only canonical instance ID. The value is ephemeral.
[[nodiscard]] std::wstring CanonicalUsbInstanceId(std::wstring value);

struct UsbInterruptInCandidate {
    std::uint8_t interface_number = 0;
    std::uint8_t alternate_setting = 0;
    std::uint8_t endpoint_address = 0;
    std::uint16_t endpoint_max_packet_bytes = 0;
    std::uint8_t endpoint_interval = 0;
    std::optional<std::uint16_t> advertised_report_descriptor_bytes;
};

struct UsbEndpointCandidateDiagnostic {
    std::uint8_t interface_number = 0;
    std::uint8_t alternate_setting = 0;
    std::uint8_t endpoint_address = 0;
    bool retained = false;
    std::string reason;
};

struct ParsedUsbTransportCandidates {
    bool valid_configuration = false;
    std::string error;
    std::vector<UsbInterruptInCandidate> candidates;
    std::vector<UsbEndpointCandidateDiagnostic> diagnostics;
};

// Enumerates interrupt-IN endpoints from a live configuration descriptor.
// Endpoint enumeration improves optional decoding and diagnostics; exact
// device-address capture does not depend on finding one perfect endpoint.
[[nodiscard]] ParsedUsbTransportCandidates ParseUsbTransportCandidates(
    std::span<const std::byte> descriptor,
    std::optional<std::uint8_t> proven_interface_number = std::nullopt);

// The caller has already narrowed these candidates with the selected physical
// devnode's exact driver key. VID/PID/version and PnP address are therefore
// tie-breakers, not extra eligibility gates: some valid HID stacks do not
// expose complete descriptor attributes to the Raw Input collection.
struct UsbPortIdentityEvidence {
    std::uint16_t vendor_id = 0;
    std::uint16_t product_id = 0;
    std::uint16_t version_number = 0;
    std::uint8_t device_address = 0;
};

enum class UsbPortIdentitySelectionStatus {
    Ready,
    NoDescriptorMatch,
    Ambiguous,
};

struct UsbPortIdentitySelection {
    UsbPortIdentitySelectionStatus status =
        UsbPortIdentitySelectionStatus::NoDescriptorMatch;
    std::size_t selected_index = 0;
};

[[nodiscard]] UsbPortIdentitySelection SelectUsbPortIdentity(
    std::span<const UsbPortIdentityEvidence> candidates,
    std::uint16_t selected_vendor_id,
    std::uint16_t selected_product_id,
    std::uint16_t selected_version_number,
    std::optional<std::uint8_t> tentative_bus_address);

enum class UsbTopologyResolutionStatus {
    Probeable,
    InvalidSelection,
    DecoderEvidenceUnavailable,
    RawInputHandleUnavailable,
    HidInterfaceJoinFailed,
    UsbAncestorUnavailable,
    UsbPcapRootEnumerationFailed,
    UsbPcapRootAmbiguous,
    PhysicalPortNotFound,
    PhysicalPortAmbiguous,
    DeviceDescriptorMismatch,
    ConfigurationDescriptorUnavailable,
    InterfaceDescriptorUnsupported,
    NoCompatibleInterruptInEndpoint,
};

[[nodiscard]] const char* ToString(UsbTopologyResolutionStatus status);

struct ResolvedUsbMouseTransport {
    UsbTopologyResolutionStatus status =
        UsbTopologyResolutionStatus::InvalidSelection;
    std::string explanation;
    std::uint16_t usbpcap_root_index = 0;
    std::uint8_t device_address = 0;
    std::vector<UsbInterruptInCandidate> candidates;
    std::vector<UsbEndpointCandidateDiagnostic> endpoint_diagnostics;
    std::vector<std::string> diagnostics;

    // These singular fields describe an optional decoded route selected after
    // the device-wide activity probe. Zero means raw-only capture.
    std::uint8_t interface_number = 0;
    std::uint8_t endpoint_address = 0;
    std::uint16_t endpoint_max_packet_bytes = 0;
    std::uint8_t endpoint_interval = 0;

    std::vector<std::byte> descriptor_evidence;
    std::string descriptor_sha256;
    std::string decoder_spec;
    std::string layout_fingerprint;
    std::vector<std::uint8_t> report_ids;
    DescriptorEvidenceSource descriptor_evidence_source =
        DescriptorEvidenceSource::None;
    std::string descriptor_reconstructor;
    std::string descriptor_reconstructor_version;

    bool raw_to_pnp_join_proven = false;
    bool root_mapping_proven = false;
    bool physical_port_driver_key_proven = false;
    bool device_address_proven = false;
    bool active_configuration_proven = false;
    bool descriptor_layout_supported = false;
};

// Produces the legacy-shaped single-route transport consumed by the existing
// capture/finalization pipeline. It does not claim activity verification.
[[nodiscard]] ResolvedUsbMouseTransport SelectUsbTransportCandidate(
    const ResolvedUsbMouseTransport& transport,
    const UsbInterruptInCandidate& candidate);

// Read-only native preflight. Probeable means Windows' selected physical USB
// devnode was mapped to one USBPcap root/address. Descriptor decoding and
// endpoint enumeration remain optional capabilities. Exact active proof is
// still mandatory before a lock can be created.
[[nodiscard]] ResolvedUsbMouseTransport ResolveWindowsUsbMouseTransport(
    const MouseInterfaceCandidate& selected);

}  // namespace abdc::device
