#include "app/ParticipantInventory.h"

#include <stdexcept>

namespace abdc::app {
namespace {

std::string ConciseUnavailableReason(
    const device::ResolvedUsbMouseTransport& transport) {
    using Status = device::UsbTopologyResolutionStatus;
    switch (transport.status) {
    case Status::DecoderEvidenceUnavailable:
    case Status::InterfaceDescriptorUnsupported:
    case Status::NoCompatibleInterruptInEndpoint:
        return "This mouse does not expose a compatible report stream.";
    case Status::UsbPcapRootEnumerationFailed:
    case Status::UsbPcapRootAmbiguous:
        return "USBPcap could not map this mouse yet.";
    case Status::RawInputHandleUnavailable:
    case Status::HidInterfaceJoinFailed:
    case Status::UsbAncestorUnavailable:
    case Status::PhysicalPortNotFound:
    case Status::PhysicalPortAmbiguous:
    case Status::DeviceDescriptorMismatch:
    case Status::ConfigurationDescriptorUnavailable:
        return "Windows could not prepare this mouse for collection.";
    case Status::InvalidSelection:
        return "This mouse is not available for collection.";
    case Status::Probeable:
        return {};
    }
    return "This mouse is not available for collection.";
}

}  // namespace

ParticipantInventory DiscoverParticipantInventory(
    const std::span<const std::byte> session_salt) {
    if (session_salt.size() < 16U) {
        throw std::invalid_argument("mouse discovery requires a fresh 128-bit salt");
    }

    ParticipantInventory result;
    result.discovery = device::DiscoverWindowsMouseInterfaces(session_salt);
    result.transports.resize(result.discovery.mice.size());
    std::vector<device::MouseCandidateReadiness> readiness(
        result.discovery.mice.size());

    for (std::size_t index = 0; index < result.discovery.mice.size(); ++index) {
        const auto& mouse = result.discovery.mice[index];
        auto& ready = readiness[index];
        if (!mouse.eligible_for_correlation_probe) {
            ready.reason_code = "mouse_inventory_incomplete";
            ready.concise_reason =
                "Windows could not prepare this mouse for collection.";
            continue;
        }
        try {
            result.transports[index] =
                device::ResolveWindowsUsbMouseTransport(mouse);
            ready.ready = result.transports[index].status ==
                          device::UsbTopologyResolutionStatus::Probeable;
            if (!ready.ready) {
                ready.reason_code =
                    device::ToString(result.transports[index].status);
                ready.concise_reason =
                    ConciseUnavailableReason(result.transports[index]);
            }
            for (const auto& diagnostic : result.transports[index].diagnostics) {
                result.diagnostics.push_back(diagnostic);
            }
        } catch (const std::exception&) {
            // Native discovery diagnostics can contain system topology detail.
            // Keep the participant-facing result intentionally concise.
            ready.reason_code = "mouse_preparation_failed";
            ready.concise_reason =
                "Windows could not prepare this mouse for collection.";
        }
    }

    result.choices =
        device::BuildPhysicalMouseChoices(result.discovery, readiness);
    result.participant_options.reserve(result.choices.size());
    for (const auto& choice : result.choices) {
        ParticipantMouseOption option;
        option.runtime_token = choice.physical_device_token;
        option.product_name = choice.product_name;
        option.available = choice.ready;
        option.unavailable_reason = choice.concise_reason;
        result.participant_options.push_back(std::move(option));
    }
    return result;
}

std::vector<device::CertificationTopology> CertificationTopologiesForChoice(
    const ParticipantInventory& inventory, const std::size_t choice_index) {
    if (inventory.transports.size() != inventory.discovery.mice.size() ||
        choice_index >= inventory.choices.size()) {
        throw std::invalid_argument("selected participant mouse is unavailable");
    }
    const auto& choice = inventory.choices[choice_index];
    if (!choice.ready || choice.physical_device_token.empty()) {
        throw std::invalid_argument("selected participant mouse is not probeable");
    }

    std::vector<device::CertificationTopology> result;
    for (const auto candidate_index : choice.candidate_indices) {
        if (candidate_index >= inventory.discovery.mice.size()) {
            throw std::runtime_error("physical mouse inventory index is invalid");
        }
        const auto& transport = inventory.transports[candidate_index];
        if (transport.status != device::UsbTopologyResolutionStatus::Probeable) {
            continue;
        }
        result.push_back({
            inventory.discovery.mice[candidate_index].session_token,
            transport,
        });
    }
    if (result.empty()) {
        throw std::runtime_error("selected participant mouse has no probeable route");
    }
    return result;
}

}  // namespace abdc::app
