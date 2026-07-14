#include "device/MouseDiscovery.h"

#include "base/Sha256.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devpkey.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <objbase.h>
#include <setupapi.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cwctype>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>

#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "hid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "user32.lib")
#endif

namespace abdc::device {
namespace {

constexpr std::uint16_t kGenericDesktopPage = 0x01;
constexpr std::uint16_t kMouseUsage = 0x02;
constexpr std::uint16_t kXUsage = 0x30;
constexpr std::uint16_t kYUsage = 0x31;
constexpr std::uint16_t kButtonPage = 0x09;

struct HidAssessment {
    bool top_level_mouse = false;
    bool relative_xy = false;
    bool left_button = false;
    bool ambiguous_xy = false;
    std::vector<std::uint8_t> relative_report_ids;
};

std::wstring CanonicalWide(std::wstring value) {
    std::replace(value.begin(), value.end(), L'/', L'\\');
    if (value.rfind(L"\\??\\", 0) == 0) value.replace(0, 4, L"\\\\?\\");
    for (wchar_t& character : value) {
        character = static_cast<wchar_t>(std::towlower(character));
    }
    return value;
}

bool StartsWithInsensitive(const std::wstring& value, const std::wstring& prefix) {
    const std::wstring normalized_value = CanonicalWide(value);
    const std::wstring normalized_prefix = CanonicalWide(prefix);
    return normalized_value.rfind(normalized_prefix, 0) == 0;
}

bool ContainsInsensitive(const std::wstring& value, const std::wstring& needle) {
    return CanonicalWide(value).find(CanonicalWide(needle)) != std::wstring::npos;
}

std::wstring RawPathInstanceId(const std::wstring& path) {
    std::wstring value = CanonicalWide(path);
    if (value.rfind(L"\\\\?\\", 0) == 0) value.erase(0, 4);
    const std::size_t class_guid = value.rfind(L"#{");
    if (class_guid != std::wstring::npos) value.resize(class_guid);
    std::replace(value.begin(), value.end(), L'#', L'\\');
    return value;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) return {};
    const int input_length = static_cast<int>(value.size());
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), input_length,
                                              nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), input_length,
                            result.data(), required, nullptr, nullptr) != required) {
        return {};
    }
    return result;
}

std::string SanitizeProductName(const std::wstring& source) {
    std::wstring clean;
    clean.reserve(std::min<std::size_t>(source.size(), 96));
    bool previous_space = false;
    for (const wchar_t character : source) {
        if (clean.size() >= 96) break;
        if (character == L'\r' || character == L'\n' || character == L'\t' ||
            character == L'\\' || character == L'/') {
            if (!clean.empty() && !previous_space) clean.push_back(L' ');
            previous_space = true;
            continue;
        }
        if (std::iswcntrl(character) != 0) continue;
        const bool space = std::iswspace(character) != 0;
        if (space) {
            if (!clean.empty() && !previous_space) clean.push_back(L' ');
        } else {
            clean.push_back(character);
        }
        previous_space = space;
    }
    while (!clean.empty() && clean.back() == L' ') clean.pop_back();
    std::string result = WideToUtf8(clean);
    if (result.empty()) result = "USB HID mouse";
    return result;
}

void AppendBytes(std::vector<std::byte>& target, const std::span<const std::byte> bytes) {
    const std::uint64_t size = static_cast<std::uint64_t>(bytes.size());
    for (unsigned shift = 0; shift < 64; shift += 8) {
        target.push_back(static_cast<std::byte>((size >> shift) & 0xffU));
    }
    target.insert(target.end(), bytes.begin(), bytes.end());
}

void AppendString(std::vector<std::byte>& target, const std::string& value) {
    AppendBytes(target, {reinterpret_cast<const std::byte*>(value.data()), value.size()});
}

std::string SessionToken(const std::span<const std::byte> salt, const std::string& domain,
                         const std::vector<std::wstring>& components) {
    std::vector<std::byte> material;
    material.reserve(salt.size() + 256);
    AppendBytes(material, salt);
    AppendString(material, "abdc.device.identity.v1");
    AppendString(material, domain);
    for (const auto& component : components) AppendString(material, WideToUtf8(CanonicalWide(component)));
    return abdc::Sha256Hex(material);
}

bool UsageContains(const std::uint16_t minimum, const std::uint16_t maximum,
                   const std::uint16_t wanted) {
    return minimum <= wanted && wanted <= maximum;
}

HidAssessment AssessHid(const HidCapsEvidence& hid) {
    HidAssessment assessment;
    assessment.top_level_mouse = (hid.caps_available || hid.available) &&
                                 hid.top_level_usage_page == kGenericDesktopPage &&
                                 hid.top_level_usage == kMouseUsage;
    std::map<std::uint8_t, std::pair<unsigned, unsigned>> xy_counts;
    bool any_x = false;
    bool any_y = false;
    for (const auto& value : hid.values) {
        if (value.usage_page != kGenericDesktopPage || !value.relative ||
            value.bit_size == 0 || value.bit_size > 32 || value.report_count == 0 ||
            value.logical_minimum >= 0 || value.logical_maximum <= 0) {
            continue;
        }
        auto& counts = xy_counts[value.report_id];
        if (UsageContains(value.usage_minimum, value.usage_maximum, kXUsage)) {
            ++counts.first;
            any_x = true;
        }
        if (UsageContains(value.usage_minimum, value.usage_maximum, kYUsage)) {
            ++counts.second;
            any_y = true;
        }
    }
    for (const auto& [report_id, counts] : xy_counts) {
        if (counts.first > 1 || counts.second > 1) assessment.ambiguous_xy = true;
        if (counts.first == 1 && counts.second == 1) assessment.relative_report_ids.push_back(report_id);
    }
    assessment.relative_xy = any_x && any_y && !assessment.relative_report_ids.empty();
    for (const auto& button : hid.buttons) {
        if (button.usage_page == kButtonPage &&
            UsageContains(button.usage_minimum, button.usage_maximum, 1)) {
            assessment.left_button = true;
            break;
        }
    }
    std::sort(assessment.relative_report_ids.begin(), assessment.relative_report_ids.end());
    assessment.relative_report_ids.erase(
        std::unique(assessment.relative_report_ids.begin(), assessment.relative_report_ids.end()),
        assessment.relative_report_ids.end());
    return assessment;
}

template <typename T>
void PushUnique(std::vector<T>& values, const T value) {
    if (std::find(values.begin(), values.end(), value) == values.end()) values.push_back(value);
}

bool HasCriticalIssue(const std::vector<DiscoveryIssue>& issues) {
    return std::any_of(issues.begin(), issues.end(), [](const DiscoveryIssue issue) {
        switch (issue) {
        case DiscoveryIssue::RawInputInterfaceNotResolved:
        case DiscoveryIssue::NotUsbTransport:
        case DiscoveryIssue::UsbAncestorUnavailable:
            return true;
        default:
            // HID caps, reconstructed decoding, tentative address, collection
            // shape, and receiver/composite details are useful metadata. The
            // exact physical-device USBPcap probe is allowed to resolve them.
            return false;
        }
    });
}

class ScopedHandle final {
public:
    explicit ScopedHandle(const HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}
    ~ScopedHandle() { if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) CloseHandle(handle_); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    [[nodiscard]] HANDLE Get() const { return handle_; }
    [[nodiscard]] bool Valid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr; }
private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

class ScopedDeviceInfo final {
public:
    explicit ScopedDeviceInfo(const HDEVINFO handle) : handle_(handle) {}
    ~ScopedDeviceInfo() { if (handle_ != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(handle_); }
    ScopedDeviceInfo(const ScopedDeviceInfo&) = delete;
    ScopedDeviceInfo& operator=(const ScopedDeviceInfo&) = delete;
    [[nodiscard]] HDEVINFO Get() const { return handle_; }
    [[nodiscard]] bool Valid() const { return handle_ != INVALID_HANDLE_VALUE; }
private:
    HDEVINFO handle_ = INVALID_HANDLE_VALUE;
};

std::optional<std::wstring> GetDeviceId(const DEVINST device) {
    ULONG length = 0;
    if (CM_Get_Device_ID_Size(&length, device, 0) != CR_SUCCESS || length == 0) return std::nullopt;
    std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 1U, L'\0');
    if (CM_Get_Device_IDW(device, buffer.data(), static_cast<ULONG>(buffer.size()), 0) != CR_SUCCESS) {
        return std::nullopt;
    }
    return std::wstring(buffer.data());
}

std::optional<std::vector<std::byte>> GetDeviceProperty(const DEVINST device,
                                                        const DEVPROPKEY& key,
                                                        DEVPROPTYPE& type) {
    ULONG bytes = 0;
    CONFIGRET result = CM_Get_DevNode_PropertyW(device, &key, &type, nullptr, &bytes, 0);
    if (result != CR_BUFFER_SMALL || bytes == 0) return std::nullopt;
    std::vector<std::byte> buffer(bytes);
    result = CM_Get_DevNode_PropertyW(
        device, &key, &type, reinterpret_cast<PBYTE>(buffer.data()), &bytes, 0);
    if (result != CR_SUCCESS) return std::nullopt;
    buffer.resize(bytes);
    return buffer;
}

std::optional<std::wstring> GetStringProperty(const DEVINST device, const DEVPROPKEY& key,
                                              const DEVPROPTYPE wanted_type) {
    DEVPROPTYPE type = 0;
    const auto bytes = GetDeviceProperty(device, key, type);
    if (!bytes || type != wanted_type || bytes->size() < sizeof(wchar_t)) return std::nullopt;
    const auto* text = reinterpret_cast<const wchar_t*>(bytes->data());
    const std::size_t characters = bytes->size() / sizeof(wchar_t);
    const auto end = std::find(text, text + characters, L'\0');
    if (end == text) return std::nullopt;
    return std::wstring(text, end);
}

std::optional<std::uint8_t> GetBusAddress(const DEVINST device) {
    DEVPROPTYPE type = 0;
    const auto bytes = GetDeviceProperty(device, DEVPKEY_Device_Address, type);
    if (!bytes || type != DEVPROP_TYPE_UINT32 || bytes->size() != sizeof(std::uint32_t)) return std::nullopt;
    std::uint32_t value = 0;
    std::memcpy(&value, bytes->data(), sizeof(value));
    if (value < 1U || value > 127U) return std::nullopt;
    return static_cast<std::uint8_t>(value);
}

std::wstring GetContainerId(const DEVINST device) {
    DEVPROPTYPE type = 0;
    const auto bytes = GetDeviceProperty(device, DEVPKEY_Device_ContainerId, type);
    if (!bytes || type != DEVPROP_TYPE_GUID || bytes->size() != sizeof(GUID)) return {};
    GUID value{};
    std::memcpy(&value, bytes->data(), sizeof(value));
    std::array<wchar_t, 64> text{};
    const int length = StringFromGUID2(value, text.data(), static_cast<int>(text.size()));
    return length > 1 ? std::wstring(text.data(), static_cast<std::size_t>(length - 1)) : std::wstring{};
}

std::optional<std::uint8_t> ParseInterfaceNumber(const std::wstring& instance_id) {
    const std::wstring normalized = CanonicalWide(instance_id);
    const std::size_t position = normalized.find(L"&mi_");
    if (position == std::wstring::npos || position + 6 > normalized.size()) return std::nullopt;
    const auto hex_value = [](const wchar_t value) -> int {
        if (value >= L'0' && value <= L'9') return value - L'0';
        if (value >= L'a' && value <= L'f') return value - L'a' + 10;
        return -1;
    };
    const int high = hex_value(normalized[position + 4]);
    const int low = hex_value(normalized[position + 5]);
    if (high < 0 || low < 0) return std::nullopt;
    return static_cast<std::uint8_t>((high << 4) | low);
}

struct TopologyWalk {
    std::wstring initial_id;
    std::wstring physical_usb_id;
    std::wstring root_hub_id;
    std::optional<std::uint8_t> interface_number;
    std::optional<DEVINST> physical_usb_node;
};

TopologyWalk WalkTopology(const DEVINST initial) {
    TopologyWalk result;
    DEVINST current = initial;
    std::set<DEVINST> visited;
    for (unsigned depth = 0; depth < 64 && visited.insert(current).second; ++depth) {
        const auto id = GetDeviceId(current);
        if (!id) break;
        if (depth == 0) result.initial_id = *id;
        if (!result.interface_number) result.interface_number = ParseInterfaceNumber(*id);
        if (StartsWithInsensitive(*id, L"USB\\ROOT_HUB")) result.root_hub_id = *id;
        // The nearest non-interface USB node is the physical HID device. Keep
        // it when walking through external hubs; replacing it with a farther
        // USB\VID_ ancestor binds the mouse collection to the hub itself.
        if (result.physical_usb_id.empty() && StartsWithInsensitive(*id, L"USB\\VID_") &&
            !ContainsInsensitive(*id, L"&MI_")) {
            result.physical_usb_id = *id;
            result.physical_usb_node = current;
        }
        DEVINST parent = 0;
        if (CM_Get_Parent(&parent, current, 0) != CR_SUCCESS) break;
        current = parent;
    }
    return result;
}

struct RawInterface {
    std::uintptr_t handle = 0;
    std::wstring path;
    bool matched = false;
};

bool EnumerateRawMice(std::vector<RawInterface>& output, std::string& diagnostic) {
    UINT count = 0;
    if (GetRawInputDeviceList(nullptr, &count, sizeof(RAWINPUTDEVICELIST)) == static_cast<UINT>(-1)) {
        diagnostic = "GetRawInputDeviceList size query failed";
        return false;
    }
    std::vector<RAWINPUTDEVICELIST> devices(count);
    if (count != 0) {
        const UINT copied = GetRawInputDeviceList(devices.data(), &count, sizeof(RAWINPUTDEVICELIST));
        if (copied == static_cast<UINT>(-1)) {
            diagnostic = "GetRawInputDeviceList enumeration failed";
            return false;
        }
        devices.resize(copied);
    }
    std::size_t unreadable_paths = 0U;
    for (const auto& device : devices) {
        if (device.dwType != RIM_TYPEMOUSE) continue;
        RawInterface item;
        item.handle = reinterpret_cast<std::uintptr_t>(device.hDevice);
        UINT characters = 0;
        if (GetRawInputDeviceInfoW(device.hDevice, RIDI_DEVICENAME, nullptr, &characters) ==
                static_cast<UINT>(-1) || characters == 0) {
            ++unreadable_paths;
            output.push_back(std::move(item));
            continue;
        }
        std::vector<wchar_t> name(static_cast<std::size_t>(characters) + 1U, L'\0');
        UINT capacity = static_cast<UINT>(name.size());
        const UINT copied = GetRawInputDeviceInfoW(device.hDevice, RIDI_DEVICENAME, name.data(), &capacity);
        if (copied == static_cast<UINT>(-1) || copied == 0) {
            ++unreadable_paths;
            output.push_back(std::move(item));
            continue;
        }
        // RIDI_DEVICENAME implementations differ on whether the returned count
        // includes the terminator. Constructing from the terminated buffer keeps
        // an embedded trailing NUL from defeating the SetupAPI path join.
        item.path.assign(name.data());
        output.push_back(std::move(item));
    }
    if (unreadable_paths != 0U) {
        diagnostic = std::to_string(unreadable_paths) +
                     " Raw Input mouse device path(s) could not be read; the handles were retained as unresolved";
    }
    return true;
}

std::wstring ReadProductName(const HANDLE handle) {
    std::array<wchar_t, 256> product{};
    if (!HidD_GetProductString(handle, product.data(), static_cast<ULONG>(sizeof(product)))) return {};
    product.back() = L'\0';
    return std::wstring(product.data());
}

void ReadAttributes(const HANDLE handle, EphemeralInterfaceRecord& record) {
    HIDD_ATTRIBUTES attributes{};
    attributes.Size = sizeof(attributes);
    if (HidD_GetAttributes(handle, &attributes)) {
        record.vendor_id = attributes.VendorID;
        record.product_id = attributes.ProductID;
        record.version_number = attributes.VersionNumber;
    }
}

}  // namespace

const char* ToString(const DiscoveryIssue issue) {
    switch (issue) {
    case DiscoveryIssue::RawInputInterfaceNotResolved: return "raw_input_interface_not_resolved";
    case DiscoveryIssue::HidCapsUnavailable: return "hid_caps_unavailable";
    case DiscoveryIssue::NotUsbTransport: return "not_usb_transport";
    case DiscoveryIssue::UsbAncestorUnavailable: return "usb_ancestor_unavailable";
    case DiscoveryIssue::RootHubUnavailable: return "root_hub_unavailable";
    case DiscoveryIssue::UsbAddressUnavailable: return "usb_address_unavailable";
    case DiscoveryIssue::UnsupportedTopLevelCollection: return "unsupported_top_level_collection";
    case DiscoveryIssue::RelativeXyUnavailable: return "relative_xy_unavailable";
    case DiscoveryIssue::LeftButtonUnavailable: return "left_button_unavailable";
    case DiscoveryIssue::AmbiguousRelativeLayout: return "ambiguous_relative_layout";
    case DiscoveryIssue::DecoderEvidenceUnavailable: return "decoder_evidence_unavailable";
    case DiscoveryIssue::DecoderParityFailed: return "decoder_parity_failed";
    case DiscoveryIssue::CompositeOrReceiver: return "composite_or_receiver";
    case DiscoveryIssue::MultipleMouseCollections: return "multiple_mouse_collections";
    }
    return "unknown_discovery_issue";
}

DiscoverySnapshot AnalyzeInventory(const std::span<const EphemeralInterfaceRecord> records,
                                   const std::span<const std::byte> session_salt) {
    if (session_salt.size() < 16) throw std::invalid_argument("device identity session salt is too short");
    DiscoverySnapshot result;
    result.native_enumeration_complete = true;

    std::map<std::wstring, std::vector<const EphemeralInterfaceRecord*>> physical_groups;
    for (const auto& record : records) {
        if (!record.physical_usb_instance_id.empty()) {
            physical_groups[CanonicalWide(record.physical_usb_instance_id)].push_back(&record);
        }
    }

    for (const auto& record : records) {
        if (!record.raw_input_mouse) continue;
        MouseInterfaceCandidate candidate;
        candidate.raw_input_handle = record.raw_input_handle;
        candidate.vendor_id = record.vendor_id;
        candidate.product_id = record.product_id;
        candidate.version_number = record.version_number;
        candidate.sanitized_product_name = SanitizeProductName(record.product_name);
        candidate.hid = record.hid;
        candidate.decoder_evidence = record.decoder_evidence;
        candidate.runtime_raw_interface_path = record.raw_interface_path;
        candidate.runtime_physical_usb_instance_id =
            record.physical_usb_instance_id;
        candidate.runtime_root_hub_instance_id = record.root_hub_instance_id;
        candidate.layout_fingerprint =
            !record.decoder_evidence.layout_fingerprint.empty()
                ? record.decoder_evidence.layout_fingerprint
                : FingerprintHidCaps(record.hid);
        const std::wstring layout_text(candidate.layout_fingerprint.begin(),
                                       candidate.layout_fingerprint.end());
        const std::wstring report_size_text = std::to_wstring(record.hid.input_report_bytes);
        const std::wstring unresolved_handle_text =
            record.raw_interface_path.empty() && record.pnp_instance_id.empty()
                ? std::to_wstring(record.raw_input_handle)
                : std::wstring{};
        candidate.session_token = SessionToken(
            session_salt, "raw-interface-v2",
            {record.raw_interface_path, record.pnp_instance_id,
             record.physical_usb_instance_id, layout_text, report_size_text,
             unresolved_handle_text});

        if (record.raw_interface_path.empty() || record.pnp_instance_id.empty()) {
            PushUnique(candidate.issues, DiscoveryIssue::RawInputInterfaceNotResolved);
        }
        if (!record.hid.caps_available && !record.hid.available) {
            PushUnique(candidate.issues, DiscoveryIssue::HidCapsUnavailable);
        }

        const HidAssessment hid = AssessHid(record.hid);
        candidate.relative_mouse_report_ids =
            record.decoder_evidence.hidp_input_parity
                ? record.decoder_evidence.report_ids
                : hid.relative_report_ids;
        if (!hid.top_level_mouse) PushUnique(candidate.issues, DiscoveryIssue::UnsupportedTopLevelCollection);
        if (!hid.relative_xy) PushUnique(candidate.issues, DiscoveryIssue::RelativeXyUnavailable);
        if (!hid.left_button) PushUnique(candidate.issues, DiscoveryIssue::LeftButtonUnavailable);
        if (hid.ambiguous_xy) PushUnique(candidate.issues, DiscoveryIssue::AmbiguousRelativeLayout);
        if (!record.decoder_evidence.reconstruction_available ||
            record.decoder_evidence.descriptor.empty() ||
            record.decoder_evidence.evidence_source == DescriptorEvidenceSource::None) {
            PushUnique(candidate.issues, DiscoveryIssue::DecoderEvidenceUnavailable);
        } else if (!record.decoder_evidence.hidp_input_parity) {
            PushUnique(candidate.issues, DiscoveryIssue::DecoderParityFailed);
        }

        candidate.topology.usb_transport =
            StartsWithInsensitive(record.physical_usb_instance_id, L"USB\\");
        if (!candidate.topology.usb_transport) PushUnique(candidate.issues, DiscoveryIssue::NotUsbTransport);
        if (record.physical_usb_instance_id.empty()) {
            PushUnique(candidate.issues, DiscoveryIssue::UsbAncestorUnavailable);
        } else {
            candidate.topology.physical_device_token = SessionToken(
                session_salt, "physical-usb",
                {record.physical_usb_instance_id, record.container_id});
        }
        if (record.root_hub_instance_id.empty()) {
            PushUnique(candidate.issues, DiscoveryIssue::RootHubUnavailable);
        } else {
            candidate.topology.root_hub_token = SessionToken(
                session_salt, "root-hub", {record.root_hub_instance_id});
        }
        if (!record.location_path.empty()) {
            candidate.topology.location_path_token = SessionToken(
                session_salt, "location-path", {record.location_path});
        }
        candidate.topology.interface_number = record.interface_number;
        candidate.topology.tentative_bus_address = record.tentative_bus_address;
        if (!record.tentative_bus_address) PushUnique(candidate.issues, DiscoveryIssue::UsbAddressUnavailable);

        if (!record.physical_usb_instance_id.empty()) {
            const auto group_it = physical_groups.find(CanonicalWide(record.physical_usb_instance_id));
            if (group_it != physical_groups.end()) {
                const std::size_t hid_count = group_it->second.size();
                candidate.topology.hid_collections_on_physical_device = static_cast<std::uint16_t>(
                    std::min<std::size_t>(hid_count, std::numeric_limits<std::uint16_t>::max()));
                std::size_t mouse_count = 0;
                for (const auto* grouped : group_it->second) {
                    const HidAssessment grouped_hid = AssessHid(grouped->hid);
                    if (grouped_hid.top_level_mouse) ++mouse_count;
                }
                candidate.topology.mouse_collections_on_physical_device = static_cast<std::uint16_t>(
                    std::min<std::size_t>(mouse_count, std::numeric_limits<std::uint16_t>::max()));
                candidate.topology.composite_or_receiver = hid_count > 1 || record.interface_number.has_value();
                if (candidate.topology.composite_or_receiver) {
                    PushUnique(candidate.issues, DiscoveryIssue::CompositeOrReceiver);
                }
                if (mouse_count > 1) PushUnique(candidate.issues, DiscoveryIssue::MultipleMouseCollections);
            }
        }
        candidate.eligible_for_correlation_probe = !HasCriticalIssue(candidate.issues);
        result.mice.push_back(std::move(candidate));
    }
    std::sort(result.mice.begin(), result.mice.end(), [](const auto& left, const auto& right) {
        return left.session_token < right.session_token;
    });
    return result;
}

DiscoverySnapshot DiscoverWindowsMouseInterfaces(const std::span<const std::byte> session_salt) {
    if (session_salt.size() < 16) throw std::invalid_argument("device identity session salt is too short");
    std::vector<RawInterface> raw_mice;
    std::string raw_diagnostic;
    const bool raw_ok = EnumerateRawMice(raw_mice, raw_diagnostic);

    GUID hid_guid{};
    HidD_GetHidGuid(&hid_guid);
    ScopedDeviceInfo devices(SetupDiGetClassDevsW(
        &hid_guid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    std::vector<EphemeralInterfaceRecord> records;
    if (!devices.Valid()) {
        for (const auto& raw : raw_mice) {
            EphemeralInterfaceRecord unresolved;
            unresolved.raw_input_mouse = true;
            unresolved.raw_input_handle = raw.handle;
            unresolved.raw_interface_path = raw.path;
            unresolved.decoder_evidence =
                BuildWindowsHidDecoderEvidence(raw.handle);
            unresolved.hid = unresolved.decoder_evidence.hid;
            records.push_back(std::move(unresolved));
        }
        DiscoverySnapshot partial = AnalyzeInventory(records, session_salt);
        partial.native_enumeration_complete = raw_ok;
        if (!raw_diagnostic.empty()) partial.diagnostics.push_back(raw_diagnostic);
        partial.diagnostics.push_back(
            "SetupAPI HID enumeration failed; each Raw Input collection remains independently visible");
        return partial;
    }

    std::size_t setup_record_failures = 0;
    for (DWORD index = 0;; ++index) {
        SP_DEVICE_INTERFACE_DATA interface_data{};
        interface_data.cbSize = sizeof(interface_data);
        if (!SetupDiEnumDeviceInterfaces(devices.Get(), nullptr, &hid_guid, index, &interface_data)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) ++setup_record_failures;
            break;
        }
        DWORD required = 0;
        SetupDiGetDeviceInterfaceDetailW(
            devices.Get(), &interface_data, nullptr, 0, &required, nullptr);
        if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
            ++setup_record_failures;
            continue;
        }
        std::vector<std::byte> detail_storage(required);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(detail_storage.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        SP_DEVINFO_DATA device_data{};
        device_data.cbSize = sizeof(device_data);
        if (!SetupDiGetDeviceInterfaceDetailW(
                devices.Get(), &interface_data, detail, required, nullptr, &device_data)) {
            ++setup_record_failures;
            continue;
        }

        EphemeralInterfaceRecord base;
        base.raw_interface_path = detail->DevicePath;
        const TopologyWalk topology = WalkTopology(device_data.DevInst);
        const std::wstring normalized_path = CanonicalWide(base.raw_interface_path);
        const std::wstring normalized_instance = CanonicalWide(topology.initial_id);
        std::vector<std::size_t> matching_raw;
        for (std::size_t raw_index = 0; raw_index < raw_mice.size(); ++raw_index) {
            if (CanonicalWide(raw_mice[raw_index].path) == normalized_path ||
                (!normalized_instance.empty() && RawPathInstanceId(raw_mice[raw_index].path) == normalized_instance)) {
                matching_raw.push_back(raw_index);
            }
        }
        base.pnp_instance_id = topology.initial_id;
        base.physical_usb_instance_id = topology.physical_usb_id;
        base.root_hub_instance_id = topology.root_hub_id;
        base.interface_number = topology.interface_number;
        if (topology.physical_usb_node) {
            base.tentative_bus_address = GetBusAddress(*topology.physical_usb_node);
            base.location_path = GetStringProperty(
                *topology.physical_usb_node, DEVPKEY_Device_LocationPaths,
                DEVPROP_TYPE_STRING_LIST).value_or(L"");
            base.container_id = GetContainerId(*topology.physical_usb_node);
            base.product_name = GetStringProperty(
                *topology.physical_usb_node, DEVPKEY_Device_BusReportedDeviceDesc,
                DEVPROP_TYPE_STRING).value_or(L"");
        }

        ScopedHandle hid(CreateFileW(detail->DevicePath, 0,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (hid.Valid()) {
            ReadAttributes(hid.Get(), base);
            const std::wstring product = ReadProductName(hid.Get());
            if (!product.empty()) base.product_name = product;
        }
        if (matching_raw.empty()) {
            records.push_back(std::move(base));
        } else {
            // Do not collapse multiple Raw Input handles that happen to expose
            // the same canonical HID path. Activity routing is handle-specific.
            for (const std::size_t raw_index : matching_raw) {
                auto joined = base;
                joined.raw_input_mouse = true;
                joined.raw_input_handle = raw_mice[raw_index].handle;
                joined.decoder_evidence = BuildWindowsHidDecoderEvidence(
                    joined.raw_input_handle);
                joined.hid = joined.decoder_evidence.hid;
                records.push_back(std::move(joined));
                raw_mice[raw_index].matched = true;
            }
        }
    }

    for (const auto& raw : raw_mice) {
        if (raw.matched) continue;
        EphemeralInterfaceRecord unresolved;
        unresolved.raw_input_mouse = true;
        unresolved.raw_input_handle = raw.handle;
        unresolved.raw_interface_path = raw.path;
        unresolved.decoder_evidence =
            BuildWindowsHidDecoderEvidence(raw.handle);
        unresolved.hid = unresolved.decoder_evidence.hid;
        records.push_back(std::move(unresolved));
    }

    DiscoverySnapshot result = AnalyzeInventory(records, session_salt);
    // Only Raw Input enumeration completeness is global. Missing evidence for
    // a particular selected collection still blocks that collection through
    // its own issues, but unrelated SetupAPI records cannot poison all mice.
    result.native_enumeration_complete = raw_ok;
    if (!raw_diagnostic.empty()) result.diagnostics.push_back(raw_diagnostic);
    if (setup_record_failures != 0) {
        result.diagnostics.push_back(
            std::to_string(setup_record_failures) +
            " unrelated or candidate SetupAPI HID record(s) could not be read");
    }
    const std::size_t unresolved = std::count_if(result.mice.begin(), result.mice.end(), [](const auto& mouse) {
        return std::find(mouse.issues.begin(), mouse.issues.end(),
                         DiscoveryIssue::RawInputInterfaceNotResolved) != mouse.issues.end();
    });
    if (unresolved != 0) {
        result.diagnostics.push_back(std::to_string(unresolved) +
                                     " Raw Input mouse interface(s) could not be joined to SetupAPI HID evidence");
    }
    for (const auto& mouse : result.mice) {
        const auto& evidence = mouse.decoder_evidence;
        std::ostringstream diagnostic;
        diagnostic << "raw_token=" << mouse.session_token
                   << ",preparsed_source=" << ToString(evidence.preparsed_data_source)
                   << ",preparsed_error=" << evidence.acquisition_win32_error
                   << ",caps_status=" << evidence.hid.caps_status.ntstatus
                   << ",value_caps_status=" << evidence.hid.value_caps_status.ntstatus
                   << ",button_caps_status=" << evidence.hid.button_caps_status.ntstatus
                   << ",reconstruction_source=" << ToString(evidence.evidence_source)
                   << ",reconstructor=" << evidence.reconstructor
                   << ",reconstructor_version=" << evidence.reconstructor_version
                   << ",evidence_sha256=" << evidence.descriptor_sha256
                   << ",layout_fingerprint=" << evidence.layout_fingerprint;
        result.diagnostics.push_back(diagnostic.str());
    }
    return result;
}

}  // namespace abdc::device
