#pragma once

#include "app/ParticipantUi.h"
#include "device/CertificationFlow.h"
#include "device/MouseDiscovery.h"
#include "device/PhysicalMouseSelection.h"
#include "device/UsbTopologyResolver.h"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace abdc::app {

// Ephemeral application inventory. Native paths and physical join tokens stay
// inside this object and are never serialized by the session layer.
struct ParticipantInventory final {
    device::DiscoverySnapshot discovery;
    std::vector<device::ResolvedUsbMouseTransport> transports;
    std::vector<device::PhysicalMouseChoice> choices;
    std::vector<ParticipantMouseOption> participant_options;
    std::vector<std::string> diagnostics;
};

[[nodiscard]] ParticipantInventory DiscoverParticipantInventory(
    std::span<const std::byte> session_salt);

[[nodiscard]] std::vector<device::CertificationTopology>
CertificationTopologiesForChoice(const ParticipantInventory& inventory,
                                 std::size_t choice_index);

}  // namespace abdc::app
