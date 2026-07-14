#pragma once

#include "device/WindowsHidDecoderEvidence.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace abdc::device {

// This is deliberately an ephemeral input to AnalyzeInventory. The native PnP
// strings and container identifiers can contain stable identifiers and must
// never be written to a session, manifest, log, or submission bundle.
struct EphemeralInterfaceRecord {
    bool raw_input_mouse = false;
    std::uintptr_t raw_input_handle = 0;
    std::wstring raw_interface_path;
    std::wstring pnp_instance_id;
    std::wstring physical_usb_instance_id;
    std::wstring root_hub_instance_id;
    std::wstring location_path;
    std::wstring container_id;
    std::wstring product_name;
    std::uint16_t vendor_id = 0;
    std::uint16_t product_id = 0;
    std::uint16_t version_number = 0;
    std::optional<std::uint8_t> interface_number;
    std::optional<std::uint8_t> tentative_bus_address;
    HidCapsEvidence hid;
    WindowsHidDecoderEvidence decoder_evidence;
};

enum class DiscoveryIssue {
    RawInputInterfaceNotResolved,
    HidCapsUnavailable,
    NotUsbTransport,
    UsbAncestorUnavailable,
    RootHubUnavailable,
    UsbAddressUnavailable,
    UnsupportedTopLevelCollection,
    RelativeXyUnavailable,
    LeftButtonUnavailable,
    AmbiguousRelativeLayout,
    DecoderEvidenceUnavailable,
    DecoderParityFailed,
    CompositeOrReceiver,
    MultipleMouseCollections,
};

[[nodiscard]] const char* ToString(DiscoveryIssue issue);

struct UsbTopologyEvidence {
    bool usb_transport = false;
    std::string physical_device_token;
    std::string root_hub_token;
    std::string location_path_token;
    std::optional<std::uint8_t> interface_number;

    // DEVPKEY_Device_Address is bus-specific evidence. It remains tentative
    // until a controlled USBPcap probe confirms the same root/address.
    std::optional<std::uint8_t> tentative_bus_address;
    std::uint16_t hid_collections_on_physical_device = 0;
    std::uint16_t mouse_collections_on_physical_device = 0;
    bool composite_or_receiver = false;
};

struct MouseInterfaceCandidate {
    std::string session_token;
    std::uintptr_t raw_input_handle = 0;
    std::string sanitized_product_name;
    std::uint16_t vendor_id = 0;
    std::uint16_t product_id = 0;
    std::uint16_t version_number = 0;
    HidCapsEvidence hid;
    WindowsHidDecoderEvidence decoder_evidence;
    std::string layout_fingerprint;
    std::vector<std::uint8_t> relative_mouse_report_ids;
    UsbTopologyEvidence topology;
    std::vector<DiscoveryIssue> issues;

    // Runtime-only native join evidence. These strings can contain stable
    // identifiers and must never be serialized, logged, or copied into a
    // session. Keeping the already-resolved physical devnode avoids having to
    // rediscover it later through one exact SetupAPI path spelling.
    std::wstring runtime_raw_interface_path;
    std::wstring runtime_physical_usb_instance_id;
    std::wstring runtime_root_hub_instance_id;

    // True means the interface is a live Raw Input mouse with a physical USB
    // ancestor and can enter the explicit move-and-click activity probe.
    // Descriptor decoding is a capability, not an eligibility requirement.
    bool eligible_for_correlation_probe = false;
};

struct DiscoverySnapshot {
    bool native_enumeration_complete = false;
    std::vector<MouseInterfaceCandidate> mice;
    std::vector<std::string> diagnostics;
};

// Injectable/pure inventory analysis used by tests and by the native enumerator.
// A fresh cryptographically random session salt of at least 16 bytes is required.
[[nodiscard]] DiscoverySnapshot AnalyzeInventory(
    std::span<const EphemeralInterfaceRecord> records,
    std::span<const std::byte> session_salt);

// Enumerates present Raw Input mouse interfaces, joins them to SetupAPI HID
// interfaces, walks the ConfigMgr parent chain, and reads HIDP capabilities.
// It performs no capture and therefore cannot by itself create a locked device.
[[nodiscard]] DiscoverySnapshot DiscoverWindowsMouseInterfaces(
    std::span<const std::byte> session_salt);

struct LockedMouseIdentity {
    std::string raw_interface_token;
    std::uintptr_t raw_input_handle = 0;
    std::string physical_device_token;
    std::string root_hub_token;
    std::uint16_t usbpcap_root_index = 0;
    std::uint8_t device_address = 0;
    std::uint8_t interface_number = 0;
    std::uint8_t endpoint_address = 0;
    std::string descriptor_sha256;
    DescriptorEvidenceSource descriptor_evidence_source = DescriptorEvidenceSource::None;
    std::string descriptor_reconstructor;
    std::string descriptor_reconstructor_version;
    std::string layout_fingerprint;
    std::vector<std::uint8_t> report_ids;
};

}  // namespace abdc::device
