#include "device/PhysicalMouseSelection.h"

#include <algorithm>
#include <map>
#include <stdexcept>
#include <tuple>
#include <unordered_map>

namespace abdc::device {

std::vector<PhysicalMouseChoice> BuildPhysicalMouseChoices(
    const DiscoverySnapshot& snapshot,
    const std::span<const bool> candidate_ready) {
    if (candidate_ready.size() != snapshot.mice.size()) {
        throw std::invalid_argument("physical mouse readiness does not match discovery inventory");
    }
    std::vector<MouseCandidateReadiness> readiness;
    readiness.reserve(candidate_ready.size());
    for (const bool ready : candidate_ready) readiness.push_back({ready, {}, {}});
    auto result = BuildPhysicalMouseChoices(snapshot, readiness);
    result.erase(std::remove_if(result.begin(), result.end(), [](const auto& choice) {
        return !choice.ready;
    }), result.end());
    return result;
}

std::vector<PhysicalMouseChoice> BuildPhysicalMouseChoices(
    const DiscoverySnapshot& snapshot,
    const std::span<const MouseCandidateReadiness> candidate_readiness) {
    if (candidate_readiness.size() != snapshot.mice.size()) {
        throw std::invalid_argument("physical mouse readiness does not match discovery inventory");
    }
    std::map<std::string, PhysicalMouseChoice> grouped;
    for (std::size_t index = 0; index < snapshot.mice.size(); ++index) {
        const auto& mouse = snapshot.mice[index];
        const auto key = mouse.topology.physical_device_token.empty()
            ? "unresolved:" + mouse.session_token
            : mouse.topology.physical_device_token;
        auto [entry, inserted] = grouped.try_emplace(key);
        auto& choice = entry->second;
        if (inserted) {
            choice.physical_device_token = mouse.topology.physical_device_token;
            choice.product_name = mouse.sanitized_product_name;
            choice.vendor_id = mouse.vendor_id;
            choice.product_id = mouse.product_id;
        }
        // Physical selection owns the full Raw Input collection group. Route
        // readiness decides whether the group is probeable, not which sibling
        // handles are visible to the active identity proof.
        choice.candidate_indices.push_back(index);
        const auto& status = candidate_readiness[index];
        if (status.ready) {
            choice.ready = true;
        } else if (choice.reason_code.empty()) {
            choice.reason_code = status.reason_code;
            choice.concise_reason = status.concise_reason;
        }
    }
    std::vector<PhysicalMouseChoice> result;
    result.reserve(grouped.size());
    for (auto& [_, choice] : grouped) {
        if (choice.ready) {
            choice.reason_code.clear();
            choice.concise_reason.clear();
        }
        result.push_back(std::move(choice));
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return std::tie(left.product_name, left.vendor_id, left.product_id,
                        left.physical_device_token) <
               std::tie(right.product_name, right.vendor_id, right.product_id,
                        right.physical_device_token);
    });
    return result;
}

std::vector<RawDeviceRoute> BuildRawDeviceRoutes(
    const DiscoverySnapshot& snapshot,
    const std::string& selected_interface_token,
    const std::string& selected_physical_device_token) {
    if (!snapshot.native_enumeration_complete || selected_interface_token.empty() ||
        selected_physical_device_token.empty()) {
        throw std::invalid_argument("Raw Input routing identity is incomplete");
    }
    std::vector<RawDeviceRoute> routes;
    std::unordered_map<std::uintptr_t, std::size_t> handles;
    std::size_t selected_count = 0U;
    for (const auto& mouse : snapshot.mice) {
        if (mouse.raw_input_handle == 0U) continue;
        RawDeviceRoute route;
        route.raw_input_handle = mouse.raw_input_handle;
        route.stable_interface_token = mouse.session_token;
        route.physical_device_token = mouse.topology.physical_device_token;
        route.layout_fingerprint = mouse.layout_fingerprint;
        if (mouse.session_token == selected_interface_token) {
            route.origin = RawDeviceOrigin::SelectedActive;
            ++selected_count;
        } else if (!mouse.topology.physical_device_token.empty() &&
                   mouse.topology.physical_device_token == selected_physical_device_token) {
            route.origin = RawDeviceOrigin::SelectedPhysicalSibling;
        } else if (!mouse.topology.physical_device_token.empty()) {
            route.origin = RawDeviceOrigin::OtherPhysical;
        } else {
            route.origin = RawDeviceOrigin::Unknown;
        }
        const auto [_, inserted] = handles.emplace(route.raw_input_handle, routes.size());
        if (!inserted) {
            throw std::runtime_error("one Raw Input handle mapped to multiple mouse interfaces");
        }
        routes.push_back(std::move(route));
    }
    if (selected_count != 1U) {
        throw std::runtime_error("selected stable Raw Input interface is missing or ambiguous");
    }
    std::sort(routes.begin(), routes.end(), [](const auto& left, const auto& right) {
        return left.raw_input_handle < right.raw_input_handle;
    });
    return routes;
}

RawDeviceOrigin OriginForRawHandle(
    const std::span<const RawDeviceRoute> routes,
    const std::uintptr_t raw_input_handle) noexcept {
    const auto found = std::lower_bound(
        routes.begin(), routes.end(), raw_input_handle,
        [](const RawDeviceRoute& route, const std::uintptr_t handle) {
            return route.raw_input_handle < handle;
        });
    return found != routes.end() && found->raw_input_handle == raw_input_handle
        ? found->origin
        : RawDeviceOrigin::Unknown;
}

SelectedInterfaceStatus ClassifySelectedInterface(
    const DiscoverySnapshot& snapshot,
    const std::string& selected_interface_token,
    const std::string& selected_physical_device_token,
    const std::uintptr_t previous_raw_input_handle) {
    if (!snapshot.native_enumeration_complete || selected_interface_token.empty() ||
        selected_physical_device_token.empty()) {
        return SelectedInterfaceStatus::Ambiguous;
    }
    const MouseInterfaceCandidate* selected = nullptr;
    for (const auto& mouse : snapshot.mice) {
        if (mouse.session_token != selected_interface_token) continue;
        if (selected != nullptr) return SelectedInterfaceStatus::Ambiguous;
        selected = &mouse;
    }
    if (selected == nullptr) return SelectedInterfaceStatus::Removed;
    if (selected->topology.physical_device_token != selected_physical_device_token) {
        return SelectedInterfaceStatus::PhysicalIdentityChanged;
    }
    return previous_raw_input_handle != 0U &&
                   selected->raw_input_handle != previous_raw_input_handle
        ? SelectedInterfaceStatus::HandleReplaced
        : SelectedInterfaceStatus::Present;
}

}  // namespace abdc::device
