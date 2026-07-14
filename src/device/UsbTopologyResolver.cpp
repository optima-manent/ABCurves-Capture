/*
 * USBPcap root-hub discovery and hub enumeration follow the public ABI and
 * sequencing in desowin/usbpcap 1.5.4.0 (BSD-2-Clause), whose enum.c is based
 * on Microsoft's USBView sample. The exact physical-identity boundary and
 * sanitized result model are original to ABCurves Capture Trainer.
 */

#include "device/UsbTopologyResolver.h"

#include "base/Sha256.h"
#include "capture/HidDescriptor.h"
#include "windows_capture/NativeUsbPcap.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>
#include <cfgmgr32.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <usbioctl.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cwctype>
#include <limits>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace abdc::device {
namespace {

constexpr std::uint32_t kIoctlUsbPcapGetHubSymlink = 0x0022200cU;
constexpr std::uint8_t kUsbInterfaceDescriptorType = 0x04U;
constexpr std::uint8_t kUsbEndpointDescriptorType = 0x05U;
constexpr std::uint8_t kHidDescriptorType = 0x21U;
constexpr std::uint8_t kHidReportDescriptorType = 0x22U;
constexpr std::size_t kMaximumDescriptorBytes = 65'535U;

class ScopedHandle final {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(const HANDLE handle) : handle_(handle) {}
    ~ScopedHandle() { if (Valid()) CloseHandle(handle_); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ScopedHandle(ScopedHandle&& other) noexcept : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}
    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            if (Valid()) CloseHandle(handle_);
            handle_ = std::exchange(other.handle_, INVALID_HANDLE_VALUE);
        }
        return *this;
    }
    [[nodiscard]] bool Valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }
    [[nodiscard]] HANDLE Get() const { return handle_; }
private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

class ScopedDeviceInfo final {
public:
    explicit ScopedDeviceInfo(const HDEVINFO value) : value_(value) {}
    ~ScopedDeviceInfo() { if (value_ != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(value_); }
    ScopedDeviceInfo(const ScopedDeviceInfo&) = delete;
    ScopedDeviceInfo& operator=(const ScopedDeviceInfo&) = delete;
    [[nodiscard]] HDEVINFO Get() const { return value_; }
private:
    HDEVINFO value_ = INVALID_HANDLE_VALUE;
};

[[nodiscard]] std::wstring LowerPath(std::wstring value) {
    std::replace(value.begin(), value.end(), L'/', L'\\');
    if (value.rfind(L"\\??\\", 0) == 0) value.replace(0, 4, L"\\\\?\\");
    for (auto& character : value) character = static_cast<wchar_t>(std::towlower(character));
    return value;
}

[[nodiscard]] std::wstring RawPathInstanceId(const std::wstring& path) {
    auto value = LowerPath(path);
    if (value.rfind(L"\\\\?\\", 0) == 0) value.erase(0, 4);
    const auto class_guid = value.rfind(L"#{");
    if (class_guid != std::wstring::npos) value.resize(class_guid);
    std::replace(value.begin(), value.end(), L'#', L'\\');
    return value;
}

[[nodiscard]] bool StartsWith(const std::wstring& value, const std::wstring& prefix) {
    return LowerPath(value).rfind(LowerPath(prefix), 0) == 0;
}

[[nodiscard]] bool Contains(const std::wstring& value, const std::wstring& needle) {
    return LowerPath(value).find(LowerPath(needle)) != std::wstring::npos;
}

[[nodiscard]] std::optional<std::wstring> DeviceId(const DEVINST device) {
    ULONG length = 0;
    if (CM_Get_Device_ID_Size(&length, device, 0) != CR_SUCCESS || length == 0U) return std::nullopt;
    std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 1U, L'\0');
    if (CM_Get_Device_IDW(device, buffer.data(), static_cast<ULONG>(buffer.size()), 0) != CR_SUCCESS) {
        return std::nullopt;
    }
    return std::wstring(buffer.data());
}

[[nodiscard]] std::optional<std::wstring> DevnodeRegistryString(const DEVINST device,
                                                                 const ULONG property) {
    ULONG bytes = 0;
    ULONG type = 0;
    const auto first = CM_Get_DevNode_Registry_PropertyW(device, property, &type, nullptr, &bytes, 0);
    if (first != CR_BUFFER_SMALL || bytes < sizeof(wchar_t) || type != REG_SZ) return std::nullopt;
    std::vector<std::byte> storage(bytes + sizeof(wchar_t), std::byte{0});
    if (CM_Get_DevNode_Registry_PropertyW(device, property, &type,
            reinterpret_cast<PBYTE>(storage.data()), &bytes, 0) != CR_SUCCESS || type != REG_SZ) {
        return std::nullopt;
    }
    return std::wstring(reinterpret_cast<const wchar_t*>(storage.data()));
}

[[nodiscard]] std::optional<std::uint8_t> InterfaceNumber(const std::wstring& instance_id) {
    const auto value = LowerPath(instance_id);
    const auto position = value.find(L"&mi_");
    if (position == std::wstring::npos || position + 6U > value.size()) return std::nullopt;
    const auto nibble = [](const wchar_t character) -> int {
        if (character >= L'0' && character <= L'9') return character - L'0';
        if (character >= L'a' && character <= L'f') return character - L'a' + 10;
        return -1;
    };
    const int high = nibble(value[position + 4U]);
    const int low = nibble(value[position + 5U]);
    if (high < 0 || low < 0) return std::nullopt;
    return static_cast<std::uint8_t>((high << 4) | low);
}

struct NativeAncestors {
    bool complete = false;
    DEVINST physical_node = 0;
    std::wstring physical_instance_id;
    std::wstring root_hub_instance_id;
    std::wstring physical_driver_key;
    std::optional<std::uint8_t> interface_number;
};

[[nodiscard]] NativeAncestors WalkAncestors(const DEVINST initial) {
    NativeAncestors result;
    DEVINST current = initial;
    std::set<DEVINST> visited;
    for (unsigned depth = 0; depth < 64U && visited.insert(current).second; ++depth) {
        const auto id = DeviceId(current);
        if (!id) return result;
        if (!result.interface_number) result.interface_number = InterfaceNumber(*id);
        if (StartsWith(*id, L"USB\\ROOT_HUB")) result.root_hub_instance_id = *id;
        // Retain the nearest physical USB device. External hubs are also
        // USB\VID_ devnodes farther up the ancestry chain and must not replace
        // the selected HID device.
        if (result.physical_node == 0 && StartsWith(*id, L"USB\\VID_") &&
            !Contains(*id, L"&MI_")) {
            result.physical_node = current;
            result.physical_instance_id = *id;
        }
        DEVINST parent = 0;
        const auto status = CM_Get_Parent(&parent, current, 0);
        if (status == CR_NO_SUCH_DEVNODE) break;
        if (status != CR_SUCCESS) return result;
        current = parent;
    }
    if (result.physical_node == 0 || result.physical_instance_id.empty() ||
        result.root_hub_instance_id.empty()) return result;
    result.physical_driver_key = DevnodeRegistryString(result.physical_node, CM_DRP_DRIVER).value_or(L"");
    result.complete = !result.physical_driver_key.empty();
    return result;
}

[[nodiscard]] std::optional<std::wstring> RawInputPath(const std::uintptr_t raw_handle) {
    if (raw_handle == 0U) return std::nullopt;
    const HANDLE handle = reinterpret_cast<HANDLE>(raw_handle);
    UINT characters = 0;
    if (GetRawInputDeviceInfoW(handle, RIDI_DEVICENAME, nullptr, &characters) == UINT_MAX ||
        characters == 0U || characters > 32'768U) return std::nullopt;
    std::vector<wchar_t> buffer(static_cast<std::size_t>(characters) + 1U, L'\0');
    UINT capacity = static_cast<UINT>(buffer.size());
    if (GetRawInputDeviceInfoW(handle, RIDI_DEVICENAME, buffer.data(), &capacity) == UINT_MAX) {
        return std::nullopt;
    }
    return std::wstring(buffer.data());
}

[[nodiscard]] std::vector<DEVINST> FindHidDevnodes(const std::wstring& raw_path) {
    GUID hid_guid{};
    HidD_GetHidGuid(&hid_guid);
    ScopedDeviceInfo devices(SetupDiGetClassDevsW(
        &hid_guid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    if (devices.Get() == INVALID_HANDLE_VALUE) return {};
    const auto normalized_path = LowerPath(raw_path);
    const auto normalized_instance = RawPathInstanceId(raw_path);
    std::vector<DEVINST> matches;
    for (DWORD index = 0;; ++index) {
        SP_DEVICE_INTERFACE_DATA interface_data{};
        interface_data.cbSize = sizeof(interface_data);
        if (!SetupDiEnumDeviceInterfaces(devices.Get(), nullptr, &hid_guid, index, &interface_data)) {
            break;
        }
        DWORD required = 0;
        SetupDiGetDeviceInterfaceDetailW(devices.Get(), &interface_data, nullptr, 0, &required, nullptr);
        if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) continue;
        std::vector<std::byte> storage(required);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(storage.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        SP_DEVINFO_DATA device_data{};
        device_data.cbSize = sizeof(device_data);
        if (!SetupDiGetDeviceInterfaceDetailW(devices.Get(), &interface_data, detail,
                                              required, nullptr, &device_data)) continue;
        const auto id = DeviceId(device_data.DevInst).value_or(L"");
        if (LowerPath(detail->DevicePath) == normalized_path ||
            (!id.empty() && LowerPath(id) == normalized_instance)) {
            matches.push_back(device_data.DevInst);
        }
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    return matches;
}

[[nodiscard]] std::optional<DEVINST> LocatePresentDevnode(
    const std::wstring& instance_id) {
    if (instance_id.empty()) return std::nullopt;
    std::vector<wchar_t> mutable_id(instance_id.begin(), instance_id.end());
    mutable_id.push_back(L'\0');
    DEVINST device = 0;
    if (CM_Locate_DevNodeW(&device, mutable_id.data(),
                           CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS) {
        return std::nullopt;
    }
    return device;
}

struct UsbPcapRoot {
    std::uint16_t index = 0;
    std::wstring hub_symbolic_link;
};

struct UsbPcapRootEnumeration {
    std::vector<UsbPcapRoot> roots;
    std::vector<std::string> diagnostics;
};

[[nodiscard]] UsbPcapRootEnumeration EnumerateUsbPcapRoots() {
    UsbPcapRootEnumeration result;
    for (std::uint16_t index = 1; index <= 255; ++index) {
        const auto path = windows_capture::BuildNativeUsbPcapPath(index);
        ScopedHandle filter(CreateFileW(path.c_str(), 0, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        if (!filter.Valid()) {
            const auto error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND &&
                error != ERROR_INVALID_NAME) {
                result.diagnostics.push_back(
                    "unrelated USBPcap root " + std::to_string(index) +
                    " was inaccessible (Win32 " + std::to_string(error) + ")");
            }
            continue;
        }
        std::array<wchar_t, 2048> output{};
        DWORD returned = 0;
        if (!DeviceIoControl(filter.Get(), kIoctlUsbPcapGetHubSymlink, nullptr, 0,
                             output.data(), static_cast<DWORD>(sizeof(output)), &returned, nullptr) ||
            returned < sizeof(wchar_t)) {
            result.diagnostics.push_back(
                "unrelated USBPcap root " + std::to_string(index) +
                " returned a malformed hub mapping");
            continue;
        }
        output.back() = L'\0';
        const std::wstring link(output.data());
        if (link.empty()) {
            result.diagnostics.push_back(
                "unrelated USBPcap root " + std::to_string(index) +
                " returned an empty hub mapping");
            continue;
        }
        result.roots.push_back({index, link});
    }
    return result;
}

[[nodiscard]] std::wstring HubOpenPath(const std::wstring& symbolic_link) {
    if (symbolic_link.rfind(L"\\??\\", 0) == 0) {
        return L"\\\\.\\" + symbolic_link.substr(4);
    }
    if (!symbolic_link.empty() && symbolic_link.front() == L'\\') return symbolic_link;
    return L"\\\\.\\" + symbolic_link;
}

[[nodiscard]] ScopedHandle OpenHub(const std::wstring& symbolic_link) {
    const auto path = HubOpenPath(symbolic_link);
    return ScopedHandle(CreateFileW(path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
}

struct ConnectionSnapshot {
    USB_DEVICE_DESCRIPTOR DeviceDescriptor{};
    UCHAR CurrentConfigurationValue = 0;
    BOOLEAN DeviceIsHub = FALSE;
    USHORT DeviceAddress = 0;
    USB_CONNECTION_STATUS ConnectionStatus = NoDeviceConnected;
};

[[nodiscard]] std::optional<ConnectionSnapshot> ConnectionInfo(
    const HANDLE hub, const ULONG port) {
    std::array<std::byte, 4096> buffer{};
    auto* information = reinterpret_cast<USB_NODE_CONNECTION_INFORMATION_EX*>(buffer.data());
    information->ConnectionIndex = port;
    DWORD returned = 0;
    if (!DeviceIoControl(hub, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
                         information, static_cast<DWORD>(buffer.size()),
                         information, static_cast<DWORD>(buffer.size()), &returned, nullptr) ||
        returned < sizeof(USB_NODE_CONNECTION_INFORMATION_EX)) return std::nullopt;
    return ConnectionSnapshot{information->DeviceDescriptor,
        information->CurrentConfigurationValue, information->DeviceIsHub,
        information->DeviceAddress, information->ConnectionStatus};
}

[[nodiscard]] std::optional<std::wstring> ConnectionDriverKey(const HANDLE hub,
                                                               const ULONG port) {
    USB_NODE_CONNECTION_DRIVERKEY_NAME initial{};
    initial.ConnectionIndex = port;
    DWORD returned = 0;
    if (!DeviceIoControl(hub, IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME,
                         &initial, sizeof(initial), &initial, sizeof(initial), &returned, nullptr) ||
        initial.ActualLength <= sizeof(initial) || initial.ActualLength > (1U << 20U)) return std::nullopt;
    std::vector<std::byte> storage(initial.ActualLength, std::byte{0});
    auto* name = reinterpret_cast<USB_NODE_CONNECTION_DRIVERKEY_NAME*>(storage.data());
    name->ConnectionIndex = port;
    if (!DeviceIoControl(hub, IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME,
                         name, static_cast<DWORD>(storage.size()), name,
                         static_cast<DWORD>(storage.size()), &returned, nullptr)) return std::nullopt;
    name->DriverKeyName[(storage.size() - offsetof(USB_NODE_CONNECTION_DRIVERKEY_NAME, DriverKeyName)) /
                        sizeof(wchar_t) - 1U] = L'\0';
    return std::wstring(name->DriverKeyName);
}

[[nodiscard]] std::optional<std::wstring> ExternalHubName(const HANDLE hub,
                                                           const ULONG port) {
    USB_NODE_CONNECTION_NAME initial{};
    initial.ConnectionIndex = port;
    DWORD returned = 0;
    if (!DeviceIoControl(hub, IOCTL_USB_GET_NODE_CONNECTION_NAME,
                         &initial, sizeof(initial), &initial, sizeof(initial), &returned, nullptr) ||
        initial.ActualLength <= sizeof(initial) || initial.ActualLength > (1U << 20U)) return std::nullopt;
    std::vector<std::byte> storage(initial.ActualLength, std::byte{0});
    auto* name = reinterpret_cast<USB_NODE_CONNECTION_NAME*>(storage.data());
    name->ConnectionIndex = port;
    if (!DeviceIoControl(hub, IOCTL_USB_GET_NODE_CONNECTION_NAME,
                         name, static_cast<DWORD>(storage.size()), name,
                         static_cast<DWORD>(storage.size()), &returned, nullptr)) return std::nullopt;
    name->NodeName[(storage.size() - offsetof(USB_NODE_CONNECTION_NAME, NodeName)) /
                   sizeof(wchar_t) - 1U] = L'\0';
    return std::wstring(name->NodeName);
}

struct PhysicalPort {
    std::uint16_t root_index = 0;
    std::wstring hub_symbolic_link;
    ULONG port = 0;
    std::uint8_t device_address = 0;
    std::uint8_t current_configuration = 0;
    USB_DEVICE_DESCRIPTOR device_descriptor{};
};

struct TraversalContext {
    std::wstring target_driver_key;
    std::uint16_t root_index = 0;
    bool complete = true;
    std::set<std::wstring> visited_hubs;
    std::vector<PhysicalPort> matches;
};

void TraverseHub(const std::wstring& symbolic_link, TraversalContext& context,
                 const unsigned depth) {
    if (depth > 16U || !context.visited_hubs.insert(LowerPath(symbolic_link)).second) {
        context.complete = false;
        return;
    }
    auto hub = OpenHub(symbolic_link);
    if (!hub.Valid()) {
        context.complete = false;
        return;
    }
    USB_NODE_INFORMATION node{};
    node.NodeType = UsbHub;
    DWORD returned = 0;
    if (!DeviceIoControl(hub.Get(), IOCTL_USB_GET_NODE_INFORMATION,
                         &node, sizeof(node), &node, sizeof(node), &returned, nullptr)) {
        context.complete = false;
        return;
    }
    const auto ports = node.u.HubInformation.HubDescriptor.bNumberOfPorts;
    for (ULONG port = 1; port <= ports; ++port) {
        const auto connection = ConnectionInfo(hub.Get(), port);
        if (!connection) {
            context.complete = false;
            continue;
        }
        if (connection->ConnectionStatus == NoDeviceConnected) continue;
        const auto driver_key = ConnectionDriverKey(hub.Get(), port);
        if (!driver_key) {
            context.complete = false;
        } else if (LowerPath(*driver_key) == LowerPath(context.target_driver_key)) {
            if (connection->DeviceAddress == 0U || connection->DeviceAddress > 127U) {
                context.complete = false;
            } else {
                context.matches.push_back({context.root_index, symbolic_link, port,
                    static_cast<std::uint8_t>(connection->DeviceAddress),
                    connection->CurrentConfigurationValue, connection->DeviceDescriptor});
            }
        }
        if (connection->DeviceIsHub && connection->ConnectionStatus == DeviceConnected) {
            const auto child = ExternalHubName(hub.Get(), port);
            if (!child || child->empty()) context.complete = false;
            else TraverseHub(*child, context, depth + 1U);
        }
    }
}

[[nodiscard]] std::optional<std::vector<std::byte>>
StandardConfigurationDescriptorRequest(
    const HANDLE hub, const ULONG port, const std::uint16_t value,
    const std::uint16_t index, const std::uint16_t length) {
    // Microsoft documents that this hub IOCTL overwrites bmRequest with 0x80.
    // Restrict it to standard configuration descriptors so a HID class report
    // descriptor can never enter the authoritative decision path here.
    if ((value >> 8U) != USB_CONFIGURATION_DESCRIPTOR_TYPE || length == 0U) {
        return std::nullopt;
    }
    const std::size_t total = sizeof(USB_DESCRIPTOR_REQUEST) + length;
    if (total > kMaximumDescriptorBytes + sizeof(USB_DESCRIPTOR_REQUEST)) return std::nullopt;
    std::vector<std::byte> storage(total, std::byte{0});
    auto* request = reinterpret_cast<USB_DESCRIPTOR_REQUEST*>(storage.data());
    request->ConnectionIndex = port;
    request->SetupPacket.bmRequest = 0x80U;
    request->SetupPacket.bRequest = 0x06U;
    request->SetupPacket.wValue = value;
    request->SetupPacket.wIndex = index;
    request->SetupPacket.wLength = length;
    DWORD returned = 0;
    if (!DeviceIoControl(hub, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
                         request, static_cast<DWORD>(storage.size()), request,
                         static_cast<DWORD>(storage.size()), &returned, nullptr)) {
        return std::nullopt;
    }
    if (returned != storage.size()) return std::nullopt;
    std::vector<std::byte> result(length);
    std::memcpy(result.data(), request->Data, length);
    return result;
}

[[nodiscard]] std::optional<std::vector<std::byte>> ConfigurationDescriptor(
    const HANDLE hub, const ULONG port, const std::uint8_t descriptor_index) {
    const auto value = static_cast<std::uint16_t>(
        (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8U) | descriptor_index);
    const auto header = StandardConfigurationDescriptorRequest(
        hub, port, value, 0U, sizeof(USB_CONFIGURATION_DESCRIPTOR));
    if (!header || header->size() < sizeof(USB_CONFIGURATION_DESCRIPTOR)) return std::nullopt;
    const auto* descriptor = reinterpret_cast<const USB_CONFIGURATION_DESCRIPTOR*>(header->data());
    if (descriptor->bLength < sizeof(USB_CONFIGURATION_DESCRIPTOR) ||
        descriptor->bDescriptorType != USB_CONFIGURATION_DESCRIPTOR_TYPE ||
        descriptor->wTotalLength < sizeof(USB_CONFIGURATION_DESCRIPTOR) ||
        descriptor->wTotalLength > kMaximumDescriptorBytes) return std::nullopt;
    return StandardConfigurationDescriptorRequest(
        hub, port, value, 0U, descriptor->wTotalLength);
}

[[nodiscard]] ResolvedUsbMouseTransport Failure(const UsbTopologyResolutionStatus status,
                                                 std::string explanation) {
    ResolvedUsbMouseTransport result;
    result.status = status;
    result.explanation = std::move(explanation);
    return result;
}

}  // namespace

UsbPortIdentitySelection SelectUsbPortIdentity(
    const std::span<const UsbPortIdentityEvidence> candidates,
    const std::uint16_t selected_vendor_id,
    const std::uint16_t selected_product_id,
    const std::uint16_t selected_version_number,
    const std::optional<std::uint8_t> tentative_bus_address) {
    UsbPortIdentitySelection result;
    if (candidates.empty()) return result;

    std::vector<std::size_t> descriptor_matches;
    if (selected_vendor_id != 0U && selected_product_id != 0U) {
        for (std::size_t index = 0; index < candidates.size(); ++index) {
            const auto& candidate = candidates[index];
            if (candidate.vendor_id != selected_vendor_id ||
                candidate.product_id != selected_product_id ||
                (selected_version_number != 0U &&
                 candidate.version_number != selected_version_number)) {
                continue;
            }
            descriptor_matches.push_back(index);
        }
    }

    // An exact driver-key join with only one live port is already a stronger
    // physical identity proof than collection-level descriptor attributes.
    const bool descriptor_narrows = !descriptor_matches.empty();
    if ((!descriptor_narrows && candidates.size() == 1U) ||
        descriptor_matches.size() == 1U) {
        result.status = UsbPortIdentitySelectionStatus::Ready;
        result.selected_index = descriptor_narrows
            ? descriptor_matches.front()
            : 0U;
        return result;
    }

    std::vector<std::size_t> all_candidates;
    if (!descriptor_narrows) {
        all_candidates.resize(candidates.size());
        std::iota(all_candidates.begin(), all_candidates.end(), 0U);
    }
    const auto& remaining = descriptor_narrows
        ? descriptor_matches
        : all_candidates;
    if (tentative_bus_address) {
        std::optional<std::size_t> address_match;
        for (const auto index : remaining) {
            if (candidates[index].device_address != *tentative_bus_address) continue;
            if (address_match) {
                result.status = UsbPortIdentitySelectionStatus::Ambiguous;
                return result;
            }
            address_match = index;
        }
        if (address_match) {
            result.status = UsbPortIdentitySelectionStatus::Ready;
            result.selected_index = *address_match;
            return result;
        }
    }

    result.status = UsbPortIdentitySelectionStatus::Ambiguous;
    return result;
}

std::wstring CanonicalUsbInstanceId(std::wstring value) {
    std::replace(value.begin(), value.end(), L'/', L'\\');
    if (value.rfind(L"\\??\\", 0) == 0) value.erase(0, 4);
    else if (value.rfind(L"\\\\?\\", 0) == 0 || value.rfind(L"\\\\.\\", 0) == 0) value.erase(0, 4);
    const auto class_guid = value.rfind(L"#{");
    if (class_guid != std::wstring::npos) value.resize(class_guid);
    std::replace(value.begin(), value.end(), L'#', L'\\');
    for (auto& character : value) character = static_cast<wchar_t>(std::towlower(character));
    while (!value.empty() && value.back() == L'\\') value.pop_back();
    return value;
}

ParsedUsbTransportCandidates ParseUsbTransportCandidates(
    const std::span<const std::byte> descriptor,
    const std::optional<std::uint8_t> proven_interface_number) {
    ParsedUsbTransportCandidates result;
    if (descriptor.size() < 9U ||
        std::to_integer<std::uint8_t>(descriptor[0]) < 9U ||
        std::to_integer<std::uint8_t>(descriptor[1]) !=
            USB_CONFIGURATION_DESCRIPTOR_TYPE) {
        result.error = "configuration descriptor header is missing or malformed";
        return result;
    }
    const auto little16 = [&](const std::size_t offset) {
        return static_cast<std::uint16_t>(
            std::to_integer<std::uint8_t>(descriptor[offset]) |
            (static_cast<std::uint16_t>(
                 std::to_integer<std::uint8_t>(descriptor[offset + 1U]))
             << 8U));
    };
    const std::size_t total = little16(2U);
    if (total != descriptor.size()) {
        result.error =
            "configuration wTotalLength does not equal the retained descriptor length";
        return result;
    }

    struct InterfaceState {
        bool present = false;
        std::uint8_t number = 0;
        std::uint8_t alternate = 0;
        std::uint8_t interface_class = 0;
        std::vector<std::uint16_t> advertised_report_lengths;
    } current;

    for (std::size_t offset = 0; offset < total;) {
        if (total - offset < 2U) {
            result.error = "truncated USB descriptor header";
            return result;
        }
        const auto length =
            std::to_integer<std::uint8_t>(descriptor[offset]);
        const auto type =
            std::to_integer<std::uint8_t>(descriptor[offset + 1U]);
        if (length < 2U || length > total - offset) {
            result.error = "invalid USB descriptor length";
            return result;
        }
        if (type == kUsbInterfaceDescriptorType) {
            if (length < 9U) {
                result.error = "short USB interface descriptor";
                return result;
            }
            current = {};
            current.present = true;
            current.number =
                std::to_integer<std::uint8_t>(descriptor[offset + 2U]);
            current.alternate =
                std::to_integer<std::uint8_t>(descriptor[offset + 3U]);
            current.interface_class =
                std::to_integer<std::uint8_t>(descriptor[offset + 5U]);
        } else if (current.present && type == kHidDescriptorType) {
            if (length < 6U) {
                result.error = "short HID class descriptor";
                return result;
            }
            const auto descriptor_count =
                std::to_integer<std::uint8_t>(descriptor[offset + 5U]);
            if (6U + static_cast<std::size_t>(descriptor_count) * 3U >
                length) {
                result.error = "truncated HID subordinate-descriptor list";
                return result;
            }
            for (std::size_t index = 0; index < descriptor_count; ++index) {
                const auto entry = offset + 6U + index * 3U;
                if (std::to_integer<std::uint8_t>(descriptor[entry]) ==
                    kHidReportDescriptorType) {
                    current.advertised_report_lengths.push_back(
                        little16(entry + 1U));
                }
            }
        } else if (current.present && type == kUsbEndpointDescriptorType) {
            if (length < 7U) {
                result.error = "short USB endpoint descriptor";
                return result;
            }
            const auto address =
                std::to_integer<std::uint8_t>(descriptor[offset + 2U]);
            const auto attributes =
                std::to_integer<std::uint8_t>(descriptor[offset + 3U]);
            if ((address & 0x80U) == 0U ||
                (attributes & 0x03U) != 0x03U) {
                offset += length;
                continue;
            }
            UsbEndpointCandidateDiagnostic diagnostic;
            diagnostic.interface_number = current.number;
            diagnostic.alternate_setting = current.alternate;
            diagnostic.endpoint_address = address;
            const auto max_packet = static_cast<std::uint16_t>(
                little16(offset + 4U) & 0x07ffU);
            if (proven_interface_number &&
                       current.number != *proven_interface_number) {
                diagnostic.reason =
                    "endpoint excluded by proven MI_xx interface";
            } else if (max_packet == 0U) {
                diagnostic.reason = "endpoint has zero packet capacity";
            } else {
                UsbInterruptInCandidate candidate;
                candidate.interface_number = current.number;
                candidate.alternate_setting = current.alternate;
                candidate.endpoint_address = address;
                candidate.endpoint_max_packet_bytes = max_packet;
                candidate.endpoint_interval =
                    std::to_integer<std::uint8_t>(descriptor[offset + 6U]);
                if (current.advertised_report_lengths.size() == 1U &&
                    current.advertised_report_lengths.front() != 0U) {
                    candidate.advertised_report_descriptor_bytes =
                        current.advertised_report_lengths.front();
                }
                result.candidates.push_back(candidate);
                diagnostic.retained = true;
                diagnostic.reason =
                    "live interrupt-IN route retained as optional decode metadata";
            }
            result.diagnostics.push_back(std::move(diagnostic));
        }
        offset += length;
    }
    result.valid_configuration = true;
    std::sort(result.candidates.begin(), result.candidates.end(),
              [](const auto& left, const auto& right) {
        return std::tie(left.interface_number, left.alternate_setting,
                        left.endpoint_address) <
               std::tie(right.interface_number, right.alternate_setting,
                        right.endpoint_address);
    });
    result.candidates.erase(
        std::unique(result.candidates.begin(), result.candidates.end(),
                    [](const auto& left, const auto& right) {
            return left.interface_number == right.interface_number &&
                   left.alternate_setting == right.alternate_setting &&
                   left.endpoint_address == right.endpoint_address;
        }),
        result.candidates.end());
    if (result.candidates.empty()) {
        result.error =
            proven_interface_number
                ? "proven interface has no listed interrupt-IN endpoint"
                : "active configuration has no listed interrupt-IN endpoint";
    }
    return result;
}

const char* ToString(const UsbTopologyResolutionStatus status) {
    switch (status) {
    case UsbTopologyResolutionStatus::Probeable: return "probeable";
    case UsbTopologyResolutionStatus::InvalidSelection: return "invalid_selection";
    case UsbTopologyResolutionStatus::DecoderEvidenceUnavailable: return "decoder_evidence_unavailable";
    case UsbTopologyResolutionStatus::RawInputHandleUnavailable: return "raw_input_handle_unavailable";
    case UsbTopologyResolutionStatus::HidInterfaceJoinFailed: return "hid_interface_join_failed";
    case UsbTopologyResolutionStatus::UsbAncestorUnavailable: return "usb_ancestor_unavailable";
    case UsbTopologyResolutionStatus::UsbPcapRootEnumerationFailed: return "usbpcap_root_enumeration_failed";
    case UsbTopologyResolutionStatus::UsbPcapRootAmbiguous: return "usbpcap_root_ambiguous";
    case UsbTopologyResolutionStatus::PhysicalPortNotFound: return "physical_port_not_found";
    case UsbTopologyResolutionStatus::PhysicalPortAmbiguous: return "physical_port_ambiguous";
    case UsbTopologyResolutionStatus::DeviceDescriptorMismatch: return "device_descriptor_mismatch";
    case UsbTopologyResolutionStatus::ConfigurationDescriptorUnavailable: return "configuration_descriptor_unavailable";
    case UsbTopologyResolutionStatus::InterfaceDescriptorUnsupported: return "interface_descriptor_unsupported";
    case UsbTopologyResolutionStatus::NoCompatibleInterruptInEndpoint:
        return "no_compatible_interrupt_in_endpoint";
    }
    return "unknown";
}

ResolvedUsbMouseTransport SelectUsbTransportCandidate(
    const ResolvedUsbMouseTransport& transport,
    const UsbInterruptInCandidate& candidate) {
    const auto found = std::find_if(
        transport.candidates.begin(), transport.candidates.end(),
        [&](const auto& current) {
            return current.interface_number == candidate.interface_number &&
                   current.alternate_setting == candidate.alternate_setting &&
                   current.endpoint_address == candidate.endpoint_address &&
                   current.endpoint_max_packet_bytes ==
                       candidate.endpoint_max_packet_bytes &&
                   current.endpoint_interval == candidate.endpoint_interval;
        });
    if (transport.status != UsbTopologyResolutionStatus::Probeable ||
        found == transport.candidates.end()) {
        return Failure(UsbTopologyResolutionStatus::InvalidSelection,
                       "USB route was not retained by this topology resolution");
    }
    auto selected = transport;
    selected.candidates = {*found};
    selected.interface_number = found->interface_number;
    selected.endpoint_address = found->endpoint_address;
    selected.endpoint_max_packet_bytes = found->endpoint_max_packet_bytes;
    selected.endpoint_interval = found->endpoint_interval;
    selected.explanation =
        "one plausible route selected for exact active proof; it is not verified yet";
    return selected;
}

ResolvedUsbMouseTransport ResolveWindowsUsbMouseTransport(
    const MouseInterfaceCandidate& selected) {
    if (selected.raw_input_handle == 0U) {
        return Failure(UsbTopologyResolutionStatus::InvalidSelection,
                       "selected Raw Input collection has no live handle");
    }
    const auto& decoder = selected.decoder_evidence;
    const bool decoder_ready =
        decoder.reconstruction_available && decoder.hidp_input_parity &&
        decoder.evidence_source != DescriptorEvidenceSource::None &&
        !decoder.descriptor.empty() && !decoder.descriptor_sha256.empty() &&
        !decoder.decoder_spec.empty() && !decoder.report_ids.empty() &&
        decoder.maximum_input_report_bytes != 0U;
    if (!selected.eligible_for_correlation_probe) {
        return Failure(
            UsbTopologyResolutionStatus::InvalidSelection,
            "selected Raw Input collection lacks a physical USB ancestor");
    }

    // Discovery already performed the privacy-sensitive Raw Input -> physical
    // USB ancestry walk. Reopen that exact physical devnode directly. This is
    // more tolerant of valid Raw Input/SetupAPI symbolic-link spellings while
    // preserving the identity boundary that matters for capture.
    NativeAncestors ancestors;
    bool joined_from_inventory = false;
    if (const auto physical = LocatePresentDevnode(
            selected.runtime_physical_usb_instance_id)) {
        ancestors = WalkAncestors(*physical);
        joined_from_inventory = ancestors.complete &&
            CanonicalUsbInstanceId(ancestors.physical_instance_id) ==
                CanonicalUsbInstanceId(
                    selected.runtime_physical_usb_instance_id);
    }
    if (!joined_from_inventory) {
        const auto raw_path = RawInputPath(selected.raw_input_handle);
        if (!raw_path) {
            return Failure(
                UsbTopologyResolutionStatus::RawInputHandleUnavailable,
                "selected Raw Input handle no longer resolves to a device path");
        }
        const auto hid_nodes = FindHidDevnodes(*raw_path);
        if (hid_nodes.empty()) {
            return Failure(
                UsbTopologyResolutionStatus::HidInterfaceJoinFailed,
                "selected Raw Input path did not join a present HID collection");
        }
        std::vector<NativeAncestors> matching_ancestors;
        for (const auto node : hid_nodes) {
            auto candidate = WalkAncestors(node);
            if (!candidate.complete) continue;
            if (!selected.runtime_physical_usb_instance_id.empty() &&
                CanonicalUsbInstanceId(candidate.physical_instance_id) !=
                    CanonicalUsbInstanceId(
                        selected.runtime_physical_usb_instance_id)) {
                continue;
            }
            matching_ancestors.push_back(std::move(candidate));
        }
        if (matching_ancestors.empty()) {
            return Failure(
                UsbTopologyResolutionStatus::HidInterfaceJoinFailed,
                "selected Raw Input path did not rejoin its physical USB device");
        }
        ancestors = std::move(matching_ancestors.front());
    }
    if (!ancestors.complete ||
        (ancestors.interface_number && selected.topology.interface_number &&
         ancestors.interface_number != selected.topology.interface_number)) {
        return Failure(
            UsbTopologyResolutionStatus::UsbAncestorUnavailable,
            "selected HID collection ancestry/physical driver key is incomplete or changed");
    }

    const auto root_enumeration = EnumerateUsbPcapRoots();
    if (root_enumeration.roots.empty()) {
        auto failure = Failure(
            UsbTopologyResolutionStatus::UsbPcapRootEnumerationFailed,
            "no USBPcap root control device could be mapped");
        failure.diagnostics = root_enumeration.diagnostics;
        return failure;
    }
    std::vector<UsbPcapRoot> matching_roots;
    const auto expected_root =
        CanonicalUsbInstanceId(ancestors.root_hub_instance_id);
    for (const auto& root : root_enumeration.roots) {
        if (CanonicalUsbInstanceId(root.hub_symbolic_link) == expected_root) {
            matching_roots.push_back(root);
        }
    }
    if (matching_roots.size() != 1U) {
        auto failure = Failure(
            UsbTopologyResolutionStatus::UsbPcapRootAmbiguous,
            matching_roots.empty()
                ? "the selected root hub was not accessible through USBPcap"
                : "the selected root hub mapped to more than one USBPcap root");
        failure.diagnostics = root_enumeration.diagnostics;
        return failure;
    }

    TraversalContext traversal;
    traversal.target_driver_key = ancestors.physical_driver_key;
    traversal.root_index = matching_roots.front().index;
    TraverseHub(matching_roots.front().hub_symbolic_link, traversal, 0U);
    if (traversal.matches.empty()) {
        auto failure = Failure(
            UsbTopologyResolutionStatus::PhysicalPortNotFound,
            traversal.complete
                ? "no live USB port has the selected physical device's exact driver key"
                : "the selected root traversal failed before its physical port was proven");
        failure.diagnostics = root_enumeration.diagnostics;
        return failure;
    }

    std::vector<UsbPortIdentityEvidence> port_identities;
    port_identities.reserve(traversal.matches.size());
    for (const auto& candidate : traversal.matches) {
        port_identities.push_back({
            candidate.device_descriptor.idVendor,
            candidate.device_descriptor.idProduct,
            candidate.device_descriptor.bcdDevice,
            candidate.device_address,
        });
    }
    const auto port_selection = SelectUsbPortIdentity(
        port_identities, selected.vendor_id, selected.product_id,
        selected.version_number, selected.topology.tentative_bus_address);
    if (port_selection.status ==
        UsbPortIdentitySelectionStatus::NoDescriptorMatch) {
        return Failure(
            UsbTopologyResolutionStatus::DeviceDescriptorMismatch,
            "no driver-key-matched live USB port has the selected device descriptor");
    }
    if (port_selection.status == UsbPortIdentitySelectionStatus::Ambiguous) {
        return Failure(
            UsbTopologyResolutionStatus::PhysicalPortAmbiguous,
            "multiple live ports remain identical after the advisory PnP-address tie-breaker");
    }

    const auto& port = traversal.matches[port_selection.selected_index];
    auto hub = OpenHub(port.hub_symbolic_link);
    std::vector<std::vector<std::byte>> active_configurations;
    if (hub.Valid()) {
        for (std::uint8_t index = 0;
             index < port.device_descriptor.bNumConfigurations; ++index) {
            const auto configuration =
                ConfigurationDescriptor(hub.Get(), port.port, index);
            if (!configuration) continue;
            if (configuration->size() >= 6U &&
                std::to_integer<std::uint8_t>((*configuration)[5]) ==
                    port.current_configuration) {
                active_configurations.push_back(*configuration);
            }
        }
    }

    ParsedUsbTransportCandidates parsed;
    if (active_configurations.size() == 1U) {
        // Retain all device interrupt-IN endpoints. The bounded activity probe
        // observes which one is live; MI_xx and HID class are metadata, not a
        // reason to reject a receiver or unusual gaming mouse.
        parsed = ParseUsbTransportCandidates(active_configurations.front());
    } else {
        parsed.error = hub.Valid()
            ? "active USB configuration was not retrieved uniquely"
            : "parent hub could not be reopened for optional endpoint metadata";
    }

    ResolvedUsbMouseTransport result;
    result.status = UsbTopologyResolutionStatus::Probeable;
    result.explanation = parsed.candidates.empty()
        ? "USB topology is mapped; device-wide movement/click proof will discover live interrupt traffic"
        : "USB topology is mapped; live interrupt traffic will be proven during movement/click";
    result.usbpcap_root_index = port.root_index;
    result.device_address = port.device_address;
    result.candidates = std::move(parsed.candidates);
    result.endpoint_diagnostics = std::move(parsed.diagnostics);
    result.diagnostics = root_enumeration.diagnostics;
    if (!parsed.error.empty()) result.diagnostics.push_back(parsed.error);
    if (decoder_ready) {
        result.descriptor_evidence = decoder.descriptor;
        result.descriptor_sha256 = decoder.descriptor_sha256;
        result.decoder_spec = decoder.decoder_spec;
        result.layout_fingerprint = decoder.layout_fingerprint;
        result.report_ids = decoder.report_ids;
        result.descriptor_evidence_source = decoder.evidence_source;
        result.descriptor_reconstructor = decoder.reconstructor;
        result.descriptor_reconstructor_version = decoder.reconstructor_version;
    } else {
        result.diagnostics.push_back(
            "reconstructed HID decoding is unavailable; raw USB capture remains supported");
    }
    result.raw_to_pnp_join_proven = true;
    result.root_mapping_proven = true;
    result.physical_port_driver_key_proven = true;
    result.device_address_proven = true;
    result.active_configuration_proven = active_configurations.size() == 1U;
    result.descriptor_layout_supported = decoder_ready;
    return result;
}

}  // namespace abdc::device
