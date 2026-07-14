#pragma once

#include "device/MouseDiscovery.h"
#include "device/RawDeviceOrigin.h"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace abdc::device {

struct PhysicalMouseChoice {
    std::string physical_device_token;
    std::string product_name;
    std::uint16_t vendor_id = 0;
    std::uint16_t product_id = 0;
    std::vector<std::size_t> candidate_indices;
    bool ready = false;
    std::string reason_code;
    std::string concise_reason;
};

struct MouseCandidateReadiness {
    bool ready = false;
    std::string reason_code;
    std::string concise_reason;
};

// Raw Input can expose several HID mouse collections for one composite USB
// receiver. Contributors choose a physical device; activity proof chooses the
// one collection that actually carries its relative movement.
[[nodiscard]] std::vector<PhysicalMouseChoice> BuildPhysicalMouseChoices(
    const DiscoverySnapshot& snapshot,
    std::span<const bool> candidate_ready);

[[nodiscard]] std::vector<PhysicalMouseChoice> BuildPhysicalMouseChoices(
    const DiscoverySnapshot& snapshot,
    std::span<const MouseCandidateReadiness> candidate_readiness);

struct RawDeviceRoute {
    std::uintptr_t raw_input_handle = 0;
    std::string stable_interface_token;
    std::string physical_device_token;
    std::string layout_fingerprint;
    RawDeviceOrigin origin = RawDeviceOrigin::Unknown;
};

// Classifies every current Raw Input handle from one coherent discovery
// snapshot. A transient handle is routing state only; stable interface and
// physical-device tokens determine its origin.
[[nodiscard]] std::vector<RawDeviceRoute> BuildRawDeviceRoutes(
    const DiscoverySnapshot& snapshot,
    const std::string& selected_interface_token,
    const std::string& selected_physical_device_token);

[[nodiscard]] RawDeviceOrigin OriginForRawHandle(
    std::span<const RawDeviceRoute> routes,
    std::uintptr_t raw_input_handle) noexcept;

enum class SelectedInterfaceStatus {
    Present,
    HandleReplaced,
    Removed,
    Ambiguous,
    PhysicalIdentityChanged,
};

[[nodiscard]] SelectedInterfaceStatus ClassifySelectedInterface(
    const DiscoverySnapshot& snapshot,
    const std::string& selected_interface_token,
    const std::string& selected_physical_device_token,
    std::uintptr_t previous_raw_input_handle);

}  // namespace abdc::device
