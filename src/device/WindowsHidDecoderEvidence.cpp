#include "device/WindowsHidDecoderEvidence.h"

#include "base/Sha256.h"
#include "capture/HidDescriptor.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <hidsdi.h>
#include <hidpi.h>

#include "hidapi_descriptor_reconstruct.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace abdc::device {
namespace {

constexpr std::size_t kMaximumPreparsedDataBytes = 1024U * 1024U;
constexpr std::size_t kMaximumInternalCaps = 8192U;
// HIDAPI allocates a 256-report-ID table per link collection. A mouse TLC with
// hundreds of link collections is not a safe bounded preflight input.
constexpr std::size_t kMaximumLinkCollections = 256U;
constexpr std::uint16_t kGenericDesktopPage = 0x01;
constexpr std::uint16_t kMouseUsage = 0x02;
constexpr std::uint16_t kXUsage = 0x30;
constexpr std::uint16_t kYUsage = 0x31;
constexpr std::uint16_t kButtonPage = 0x09;
constexpr char kReconstructorName[] = "hidapi_windows_preparsed_descriptor_reconstructor";
constexpr char kReconstructorVersion[] = "hidapi-0.15.0+d6b2a97";

class ScopedHandle final {
public:
    explicit ScopedHandle(const HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~ScopedHandle() {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    [[nodiscard]] HANDLE Get() const { return value_; }
    [[nodiscard]] bool Valid() const {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE value_ = INVALID_HANDLE_VALUE;
};

class ScopedHidPreparsedData final {
public:
    ~ScopedHidPreparsedData() {
        if (value_ != nullptr) HidD_FreePreparsedData(value_);
    }
    ScopedHidPreparsedData(const ScopedHidPreparsedData&) = delete;
    ScopedHidPreparsedData& operator=(const ScopedHidPreparsedData&) = delete;
    ScopedHidPreparsedData() = default;
    [[nodiscard]] PHIDP_PREPARSED_DATA* Put() { return &value_; }
    [[nodiscard]] PHIDP_PREPARSED_DATA Get() const { return value_; }

private:
    PHIDP_PREPARSED_DATA value_ = nullptr;
};

[[nodiscard]] bool ContainsUsage(const std::uint16_t minimum,
                                 const std::uint16_t maximum,
                                 const std::uint16_t wanted) {
    return minimum <= wanted && wanted <= maximum;
}

[[nodiscard]] std::string NtStatusDiagnostic(const char* operation,
                                             const std::int32_t status) {
    std::ostringstream out;
    out << operation << " returned NTSTATUS 0x" << std::hex << std::setw(8)
        << std::setfill('0') << static_cast<std::uint32_t>(status);
    return out.str();
}

void SetStatus(HidCapabilityQueryStatus& destination,
               const char* operation,
               const NTSTATUS status) {
    destination.attempted = true;
    destination.ntstatus = static_cast<std::int32_t>(status);
    destination.available = status == HIDP_STATUS_SUCCESS;
    if (!destination.available) {
        destination.diagnostic = NtStatusDiagnostic(operation, destination.ntstatus);
    }
}

[[nodiscard]] std::optional<std::size_t> CheckedAdd(const std::size_t left,
                                                    const std::size_t right) {
    if (left > std::numeric_limits<std::size_t>::max() - right) return std::nullopt;
    return left + right;
}

[[nodiscard]] std::optional<std::size_t> CheckedMultiply(const std::size_t left,
                                                         const std::size_t right) {
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) {
        return std::nullopt;
    }
    return left * right;
}

struct InternalPreparsedValidation {
    bool valid = false;
    std::size_t required_bytes = 0;
    std::string diagnostic;
};

// HIDAPI's pinned implementation consumes the private Windows preparsed-data
// layout. Validate every length/count exposed by that layout before entering
// upstream code. The bytes still originate only from Windows, never a file or
// an on-device descriptor.
[[nodiscard]] InternalPreparsedValidation ValidateInternalPreparsedData(
    const void* pointer,
    const std::optional<std::size_t> available_bytes) {
    InternalPreparsedValidation result;
    if (pointer == nullptr) {
        result.diagnostic = "preparsed-data pointer is null";
        return result;
    }
    if ((reinterpret_cast<std::uintptr_t>(pointer) % alignof(DWORD)) != 0) {
        result.diagnostic = "preparsed-data pointer is not DWORD aligned";
        return result;
    }
    constexpr std::size_t header_bytes = offsetof(hidp_preparsed_data, caps);
    if (available_bytes && *available_bytes < header_bytes) {
        result.diagnostic = "preparsed-data block is shorter than the HIDAPI header";
        return result;
    }
    const auto* data = static_cast<const hidp_preparsed_data*>(pointer);
    static constexpr std::array<UCHAR, 8> kMagic{
        static_cast<UCHAR>('H'), static_cast<UCHAR>('i'), static_cast<UCHAR>('d'),
        static_cast<UCHAR>('P'), static_cast<UCHAR>(' '), static_cast<UCHAR>('K'),
        static_cast<UCHAR>('D'), static_cast<UCHAR>('R')};
    if (!std::equal(kMagic.begin(), kMagic.end(), data->MagicKey)) {
        result.diagnostic = "preparsed-data magic does not match the Windows HidP layout";
        return result;
    }
    if (data->NumberLinkCollectionNodes == 0 ||
        data->NumberLinkCollectionNodes > kMaximumLinkCollections) {
        result.diagnostic = "preparsed-data link-collection count is unsafe";
        return result;
    }
    if ((data->FirstByteOfLinkCollectionArray % alignof(hid_pp_link_collection_node)) != 0) {
        result.diagnostic = "preparsed-data link-collection offset is misaligned";
        return result;
    }
    const std::size_t caps_bytes = data->FirstByteOfLinkCollectionArray;
    if (caps_bytes % sizeof(hid_pp_cap) != 0 ||
        caps_bytes / sizeof(hid_pp_cap) > kMaximumInternalCaps) {
        result.diagnostic = "preparsed-data capability array has an unsafe size";
        return result;
    }
    const std::size_t cap_count = caps_bytes / sizeof(hid_pp_cap);
    for (const auto& info : data->caps_info) {
        if (info.FirstCap > info.LastCap || info.LastCap > cap_count ||
            info.NumberOfCaps > cap_count ||
            static_cast<std::size_t>(info.FirstCap) + info.NumberOfCaps > cap_count) {
            result.diagnostic = "preparsed-data capability range is out of bounds";
            return result;
        }
        if (info.ReportByteLength > HID_API_MAX_REPORT_DESCRIPTOR_SIZE) {
            result.diagnostic = "preparsed-data report length exceeds the supported maximum";
            return result;
        }
    }
    for (std::size_t index = 0; index < cap_count; ++index) {
        const auto& cap = data->caps[index];
        if (cap.LinkCollection >= data->NumberLinkCollectionNodes ||
            cap.ReportSize > 32U || cap.ReportCount > 4096U) {
            result.diagnostic = "preparsed-data capability contains an unsafe field";
            return result;
        }
    }
    const auto link_bytes = CheckedMultiply(
        static_cast<std::size_t>(data->NumberLinkCollectionNodes),
        sizeof(hid_pp_link_collection_node));
    const auto before_links = CheckedAdd(header_bytes, caps_bytes);
    const auto total = link_bytes && before_links ? CheckedAdd(*before_links, *link_bytes)
                                                  : std::nullopt;
    if (!total || *total > kMaximumPreparsedDataBytes) {
        result.diagnostic = "preparsed-data total size overflows or exceeds the safety bound";
        return result;
    }
    if (available_bytes && *total > *available_bytes) {
        result.diagnostic = "preparsed-data internal arrays exceed the returned Raw Input bytes";
        return result;
    }
    const auto* links = reinterpret_cast<const hid_pp_link_collection_node*>(
        reinterpret_cast<const std::byte*>(&data->caps[0]) + caps_bytes);
    const std::size_t link_count = data->NumberLinkCollectionNodes;
    for (std::size_t index = 0; index < link_count; ++index) {
        const auto& link = links[index];
        if (link.Parent >= link_count || link.FirstChild >= link_count ||
            link.NextSibling >= link_count ||
            link.NumberOfChildren >= link_count) {
            result.diagnostic =
                "preparsed-data link-collection reference is out of bounds";
            return result;
        }
        if (index == 0U && link.Parent != 0U) {
            result.diagnostic =
                "preparsed-data root collection has a nonroot parent";
            return result;
        }
        if (link.NumberOfChildren != 0U && link.FirstChild == 0U) {
            result.diagnostic =
                "preparsed-data collection has children but no first child";
            return result;
        }
        if (link.FirstChild != 0U && links[link.FirstChild].Parent != index) {
            result.diagnostic =
                "preparsed-data first-child parent link is inconsistent";
            return result;
        }
        if (link.NextSibling != 0U &&
            links[link.NextSibling].Parent != link.Parent) {
            result.diagnostic =
                "preparsed-data sibling parent link is inconsistent";
            return result;
        }
        std::size_t ancestor = index;
        for (std::size_t depth = 0; ancestor != 0U; ++depth) {
            if (depth >= link_count) {
                result.diagnostic =
                    "preparsed-data collection parent chain is cyclic";
                return result;
            }
            ancestor = links[ancestor].Parent;
        }
        std::size_t sibling = link.FirstChild;
        for (std::size_t count = 0; sibling != 0U; ++count) {
            if (count >= link_count) {
                result.diagnostic =
                    "preparsed-data collection sibling chain is cyclic";
                return result;
            }
            sibling = links[sibling].NextSibling;
        }
    }
    result.valid = true;
    result.required_bytes = *total;
    return result;
}

[[nodiscard]] HidCapsEvidence QueryPublicHidCaps(PHIDP_PREPARSED_DATA data) {
    HidCapsEvidence evidence;
    HIDP_CAPS caps{};
    const NTSTATUS caps_status = HidP_GetCaps(data, &caps);
    SetStatus(evidence.caps_status, "HidP_GetCaps", caps_status);
    evidence.caps_available = evidence.caps_status.available;
    evidence.available = evidence.caps_available;
    if (!evidence.caps_available) return evidence;

    evidence.top_level_usage_page = caps.UsagePage;
    evidence.top_level_usage = caps.Usage;
    evidence.input_report_bytes = caps.InputReportByteLength;

    evidence.value_caps_status.attempted = true;
    if (caps.NumberInputValueCaps == 0) {
        evidence.value_caps_status.available = true;
        evidence.value_caps_status.ntstatus = static_cast<std::int32_t>(HIDP_STATUS_SUCCESS);
    } else {
        USHORT count = caps.NumberInputValueCaps;
        std::vector<HIDP_VALUE_CAPS> values(count);
        const NTSTATUS status = HidP_GetValueCaps(HidP_Input, values.data(), &count, data);
        SetStatus(evidence.value_caps_status, "HidP_GetValueCaps", status);
        if (evidence.value_caps_status.available) {
            if (count > values.size()) {
                evidence.value_caps_status.available = false;
                evidence.value_caps_status.diagnostic =
                    "HidP_GetValueCaps returned more records than requested";
            } else {
                values.resize(count);
                for (const auto& value : values) {
                    HidValueCapability converted;
                    converted.report_id = value.ReportID;
                    converted.usage_page = value.UsagePage;
                    converted.usage_minimum =
                        value.IsRange ? value.Range.UsageMin : value.NotRange.Usage;
                    converted.usage_maximum =
                        value.IsRange ? value.Range.UsageMax : value.NotRange.Usage;
                    converted.bit_size = value.BitSize;
                    converted.report_count = value.ReportCount;
                    converted.logical_minimum = value.LogicalMin;
                    converted.logical_maximum = value.LogicalMax;
                    converted.relative = value.IsAbsolute == FALSE;
                    evidence.values.push_back(converted);
                }
            }
        }
    }
    evidence.value_caps_available = evidence.value_caps_status.available;

    evidence.button_caps_status.attempted = true;
    if (caps.NumberInputButtonCaps == 0) {
        evidence.button_caps_status.available = true;
        evidence.button_caps_status.ntstatus = static_cast<std::int32_t>(HIDP_STATUS_SUCCESS);
    } else {
        USHORT count = caps.NumberInputButtonCaps;
        std::vector<HIDP_BUTTON_CAPS> buttons(count);
        const NTSTATUS status = HidP_GetButtonCaps(HidP_Input, buttons.data(), &count, data);
        SetStatus(evidence.button_caps_status, "HidP_GetButtonCaps", status);
        if (evidence.button_caps_status.available) {
            if (count > buttons.size()) {
                evidence.button_caps_status.available = false;
                evidence.button_caps_status.diagnostic =
                    "HidP_GetButtonCaps returned more records than requested";
            } else {
                buttons.resize(count);
                for (const auto& button : buttons) {
                    HidButtonCapability converted;
                    converted.report_id = button.ReportID;
                    converted.usage_page = button.UsagePage;
                    converted.usage_minimum =
                        button.IsRange ? button.Range.UsageMin : button.NotRange.Usage;
                    converted.usage_maximum =
                        button.IsRange ? button.Range.UsageMax : button.NotRange.Usage;
                    evidence.buttons.push_back(converted);
                }
            }
        }
    }
    evidence.button_caps_available = evidence.button_caps_status.available;
    return evidence;
}

[[nodiscard]] bool ValueMatchesField(const HidValueCapability& value,
                                     const capture::HidField& field,
                                     const std::uint16_t usage) {
    const auto usage_count =
        value.usage_maximum >= value.usage_minimum
            ? static_cast<std::uint32_t>(value.usage_maximum) -
                  value.usage_minimum + 1U
            : 0U;
    return value.report_id == field.report_id &&
           value.usage_page == kGenericDesktopPage &&
           ContainsUsage(value.usage_minimum, value.usage_maximum, usage) &&
           usage_count != 0U && value.report_count >= usage_count &&
           value.relative && value.bit_size == field.bit_size &&
           value.logical_minimum == field.logical_minimum &&
           value.logical_maximum == field.logical_maximum;
}

[[nodiscard]] bool HasButton(const HidCapsEvidence& hid,
                             const std::uint8_t report_id,
                             const std::uint16_t usage) {
    return std::any_of(hid.buttons.begin(), hid.buttons.end(), [&](const auto& button) {
        return button.report_id == report_id && button.usage_page == kButtonPage &&
               ContainsUsage(button.usage_minimum, button.usage_maximum, usage);
    });
}

[[nodiscard]] WindowsHidDecoderEvidence BuildFromPreparsedData(
    PHIDP_PREPARSED_DATA data,
    const std::optional<std::size_t> available_bytes,
    const PreparsedDataSource source) {
    WindowsHidDecoderEvidence evidence;
    evidence.preparsed_data_source = source;
    evidence.reconstructor = kReconstructorName;
    evidence.reconstructor_version = kReconstructorVersion;

    const auto internal = ValidateInternalPreparsedData(data, available_bytes);
    if (!internal.valid) {
        evidence.acquisition_diagnostic = internal.diagnostic;
        return evidence;
    }
    evidence.preparsed_data_available = true;
    evidence.hid = QueryPublicHidCaps(data);

    std::array<unsigned char, HID_API_MAX_REPORT_DESCRIPTOR_SIZE> reconstructed{};
    const int size = hid_winapi_descriptor_reconstruct_pp_data(
        data, reconstructed.data(), reconstructed.size());
    evidence.reconstruction_status = size;
    if (size <= 0 || static_cast<std::size_t>(size) > reconstructed.size()) {
        evidence.acquisition_diagnostic =
            "HIDAPI preparsed-data descriptor reconstruction failed or overflowed its buffer";
        return evidence;
    }
    evidence.reconstruction_available = true;
    evidence.evidence_source = DescriptorEvidenceSource::WindowsPreparsedReconstruction;
    evidence.descriptor.resize(static_cast<std::size_t>(size));
    std::transform(reconstructed.begin(), reconstructed.begin() + size,
                   evidence.descriptor.begin(),
                   [](const unsigned char value) { return static_cast<std::byte>(value); });
    evidence.descriptor_sha256 = abdc::Sha256Hex(evidence.descriptor);

    try {
        const auto parsed = capture::HidDescriptor::Parse(evidence.descriptor);
        evidence.decoder_spec = parsed.CanonicalDecoderSpec();
        const auto parity = ValidateReconstructedDescriptorParity(
            evidence.hid, evidence.descriptor);
        evidence.hidp_input_parity = parity.valid;
        evidence.parity_diagnostic = parity.diagnostic;
        evidence.report_ids = parity.report_ids;
        evidence.maximum_input_report_bytes = parity.maximum_input_report_bytes;
        evidence.layout_fingerprint = FingerprintHidCaps(evidence.hid);
    } catch (const std::exception& error) {
        evidence.parity_diagnostic = error.what();
    }
    return evidence;
}

[[nodiscard]] bool HasResearchMouseSemantics(const HidCapsEvidence& hid) {
    if (!hid.caps_available || !hid.value_caps_available ||
        !hid.button_caps_available || hid.input_report_bytes == 0 ||
        hid.top_level_usage_page != kGenericDesktopPage ||
        hid.top_level_usage != kMouseUsage) {
        return false;
    }
    bool relative_x = false;
    bool relative_y = false;
    for (const auto& value : hid.values) {
        if (value.usage_page != kGenericDesktopPage || !value.relative ||
            value.bit_size == 0 || value.bit_size > 32 ||
            value.logical_minimum >= 0 || value.logical_maximum <= 0) {
            continue;
        }
        relative_x = relative_x ||
            ContainsUsage(value.usage_minimum, value.usage_maximum, kXUsage);
        relative_y = relative_y ||
            ContainsUsage(value.usage_minimum, value.usage_maximum, kYUsage);
    }
    const bool left = std::any_of(hid.buttons.begin(), hid.buttons.end(),
                                  [](const auto& button) {
        return button.usage_page == kButtonPage &&
               ContainsUsage(button.usage_minimum, button.usage_maximum, 1);
    });
    return relative_x && relative_y && left;
}

[[nodiscard]] std::optional<std::wstring> ExactRawInputCollectionPath(
    const HANDLE raw_handle,
    std::uint32_t& win32_error,
    std::string& diagnostic) {
    UINT required_characters = 0;
    SetLastError(ERROR_SUCCESS);
    const UINT query = GetRawInputDeviceInfoW(
        raw_handle, RIDI_DEVICENAME, nullptr, &required_characters);
    const DWORD query_error = GetLastError();
    if (query == static_cast<UINT>(-1) || required_characters == 0U ||
        required_characters > 32'767U) {
        win32_error = query_error;
        diagnostic =
            "exact Raw Input collection-name query failed or returned an unsafe length";
        return std::nullopt;
    }

    // RIDI_DEVICENAME implementations differ on whether the queried count
    // includes the terminator. The extra zero-initialized wchar_t safely
    // supports both conventions without accepting truncation.
    std::vector<wchar_t> path(
        static_cast<std::size_t>(required_characters) + 1U, L'\0');
    UINT capacity = static_cast<UINT>(path.size());
    SetLastError(ERROR_SUCCESS);
    const UINT copied = GetRawInputDeviceInfoW(
        raw_handle, RIDI_DEVICENAME, path.data(), &capacity);
    const DWORD fill_error = GetLastError();
    if (copied == static_cast<UINT>(-1) || copied == 0U ||
        copied > required_characters || capacity > path.size()) {
        win32_error = fill_error;
        diagnostic =
            "exact Raw Input collection-name fill failed or was truncated";
        return std::nullopt;
    }
    path.back() = L'\0';
    const std::wstring exact_path(path.data());
    if (exact_path.empty()) {
        diagnostic = "exact Raw Input collection name was empty";
        return std::nullopt;
    }
    return exact_path;
}

}  // namespace

const char* ToString(const DescriptorEvidenceSource source) {
    switch (source) {
    case DescriptorEvidenceSource::None: return "none";
    case DescriptorEvidenceSource::UsbObserved: return "usb_observed";
    case DescriptorEvidenceSource::WindowsPreparsedReconstruction:
        return "windows_preparsed_reconstruction";
    case DescriptorEvidenceSource::QualifiedFixture: return "qualified_fixture";
    }
    return "unknown";
}

const char* ToString(const PreparsedDataSource source) {
    switch (source) {
    case PreparsedDataSource::None: return "none";
    case PreparsedDataSource::RawInputPreparsedData: return "raw_input_preparsed_data";
    case PreparsedDataSource::ExactHidPathFallback: return "exact_hid_path_fallback";
    }
    return "unknown";
}

bool WindowsHidDecoderEvidence::ResearchCapable() const {
    return preparsed_data_available && reconstruction_available &&
           evidence_source == DescriptorEvidenceSource::WindowsPreparsedReconstruction &&
           hidp_input_parity && HasResearchMouseSemantics(hid) &&
           !descriptor.empty() && descriptor_sha256.size() == 64 &&
           !decoder_spec.empty() && !report_ids.empty() &&
           maximum_input_report_bytes != 0;
}

std::string FingerprintHidCaps(const HidCapsEvidence& caps) {
    std::ostringstream canonical;
    canonical << "abdc.hidp.semantic.v2\n"
              << "caps=" << (caps.caps_available ? 1 : 0)
              << ",values=" << (caps.value_caps_available ? 1 : 0)
              << ",buttons=" << (caps.button_caps_available ? 1 : 0)
              << ",usage_page=" << caps.top_level_usage_page
              << ",usage=" << caps.top_level_usage
              << ",input_bytes=" << caps.input_report_bytes << '\n';
    auto values = caps.values;
    std::sort(values.begin(), values.end(), [](const auto& left, const auto& right) {
        return std::tie(left.report_id, left.usage_page, left.usage_minimum,
                        left.usage_maximum, left.bit_size, left.report_count,
                        left.logical_minimum, left.logical_maximum, left.relative) <
               std::tie(right.report_id, right.usage_page, right.usage_minimum,
                        right.usage_maximum, right.bit_size, right.report_count,
                        right.logical_minimum, right.logical_maximum, right.relative);
    });
    for (const auto& value : values) {
        canonical << "v," << static_cast<unsigned>(value.report_id) << ','
                  << value.usage_page << ',' << value.usage_minimum << ','
                  << value.usage_maximum << ',' << value.bit_size << ','
                  << value.report_count << ',' << value.logical_minimum << ','
                  << value.logical_maximum << ',' << (value.relative ? 1 : 0) << '\n';
    }
    auto buttons = caps.buttons;
    std::sort(buttons.begin(), buttons.end(), [](const auto& left, const auto& right) {
        return std::tie(left.report_id, left.usage_page, left.usage_minimum,
                        left.usage_maximum) <
               std::tie(right.report_id, right.usage_page, right.usage_minimum,
                        right.usage_maximum);
    });
    for (const auto& button : buttons) {
        canonical << "b," << static_cast<unsigned>(button.report_id) << ','
                  << button.usage_page << ',' << button.usage_minimum << ','
                  << button.usage_maximum << '\n';
    }
    const std::string text = canonical.str();
    return abdc::Sha256Hex(
        {reinterpret_cast<const std::byte*>(text.data()), text.size()});
}

DescriptorParityResult ValidateReconstructedDescriptorParity(
    const HidCapsEvidence& hid,
    const std::span<const std::byte> reconstructed_descriptor) {
    DescriptorParityResult result;
    if (!hid.caps_available || !hid.value_caps_available ||
        !hid.button_caps_available) {
        result.diagnostic =
            "public HidP caps, value caps, and button caps are all required for parity";
        return result;
    }
    if (hid.top_level_usage_page != kGenericDesktopPage ||
        hid.top_level_usage != kMouseUsage) {
        result.diagnostic = "HidP top-level collection is not Generic Desktop / Mouse";
        return result;
    }
    if (hid.input_report_bytes == 0) {
        result.diagnostic = "HidP input report length is zero";
        return result;
    }

    const auto parsed = capture::HidDescriptor::Parse(reconstructed_descriptor);
    const auto& applications = parsed.TopLevelApplicationCollections();
    if (applications.size() != 1U ||
        applications.front().usage_page != kGenericDesktopPage ||
        applications.front().usage != kMouseUsage) {
        result.diagnostic =
            "reconstructed top-level application collection does not match Generic Desktop / Mouse";
        return result;
    }
    const auto layouts = parsed.RelativeMouseLayouts();
    std::vector<std::uint8_t> public_ids;
    for (const auto& value : hid.values) {
        if (value.usage_page != kGenericDesktopPage || !value.relative) continue;
        if (ContainsUsage(value.usage_minimum, value.usage_maximum, kXUsage) &&
            ContainsUsage(value.usage_minimum, value.usage_maximum, kYUsage)) {
            public_ids.push_back(value.report_id);
        }
    }
    // Some stacks expose X and Y as separate value-cap records.
    for (const auto& x : hid.values) {
        if (x.usage_page != kGenericDesktopPage || !x.relative ||
            !ContainsUsage(x.usage_minimum, x.usage_maximum, kXUsage)) {
            continue;
        }
        if (std::any_of(hid.values.begin(), hid.values.end(), [&](const auto& y) {
                return y.report_id == x.report_id &&
                       y.usage_page == kGenericDesktopPage && y.relative &&
                       ContainsUsage(y.usage_minimum, y.usage_maximum, kYUsage);
            })) {
            public_ids.push_back(x.report_id);
        }
    }
    std::sort(public_ids.begin(), public_ids.end());
    public_ids.erase(std::unique(public_ids.begin(), public_ids.end()), public_ids.end());
    public_ids.erase(std::remove_if(public_ids.begin(), public_ids.end(),
                                    [&](const std::uint8_t id) {
        return !HasButton(hid, id, 1);
    }), public_ids.end());

    std::vector<std::uint8_t> descriptor_ids;
    for (const auto& layout : layouts) {
        descriptor_ids.push_back(layout.report_id);
        const auto matching_x = std::count_if(
            hid.values.begin(), hid.values.end(), [&](const auto& value) {
                return ValueMatchesField(value, layout.x, kXUsage);
            });
        const auto matching_y = std::count_if(
            hid.values.begin(), hid.values.end(), [&](const auto& value) {
                return ValueMatchesField(value, layout.y, kYUsage);
            });
        if (matching_x == 0 || matching_y == 0) {
            result.diagnostic =
                "reconstructed X/Y bit sizes or logical ranges do not match HidP value caps";
            return result;
        }
        const auto left = std::find_if(
            layout.buttons.begin(), layout.buttons.end(),
            [](const auto& button) {
                return button.usage_page == kButtonPage && button.usage == 1;
            });
        if (left == layout.buttons.end() || left->bit_size != 1 ||
            !HasButton(hid, layout.report_id, 1)) {
            result.diagnostic =
                "reconstructed left-button field does not match HidP button caps";
            return result;
        }
    }
    std::sort(descriptor_ids.begin(), descriptor_ids.end());
    descriptor_ids.erase(std::unique(descriptor_ids.begin(), descriptor_ids.end()),
                         descriptor_ids.end());
    if (descriptor_ids != public_ids || descriptor_ids.empty()) {
        result.diagnostic =
            "reconstructed relative-mouse report IDs do not match HidP input caps";
        return result;
    }

    const std::size_t descriptor_maximum = parsed.MaximumInputReportByteLength();
    const std::size_t windows_length =
        descriptor_maximum + (parsed.UsesReportIds() ? 0U : 1U);
    if (windows_length != hid.input_report_bytes) {
        result.diagnostic =
            "reconstructed maximum input report length does not match the Windows leading-ID convention";
        return result;
    }
    result.valid = true;
    result.diagnostic = "reconstructed input layout matches public HidP evidence";
    result.report_ids = std::move(descriptor_ids);
    result.maximum_input_report_bytes = descriptor_maximum;
    return result;
}

WindowsHidDecoderEvidence BuildWindowsHidDecoderEvidence(
    const std::uintptr_t raw_input_handle) {
    WindowsHidDecoderEvidence result;
    result.reconstructor = kReconstructorName;
    result.reconstructor_version = kReconstructorVersion;
    const HANDLE raw_handle = reinterpret_cast<HANDLE>(raw_input_handle);

    UINT required = 0;
    SetLastError(ERROR_SUCCESS);
    const UINT size_result =
        GetRawInputDeviceInfoW(raw_handle, RIDI_PREPARSEDDATA, nullptr, &required);
    DWORD raw_error = GetLastError();
    bool raw_acquired = false;
    if (size_result == 0 && required != 0 &&
        required <= kMaximumPreparsedDataBytes) {
        const std::size_t word_count =
            (static_cast<std::size_t>(required) + sizeof(DWORD) - 1U) /
            sizeof(DWORD);
        if (word_count <= kMaximumPreparsedDataBytes / sizeof(DWORD)) {
            std::vector<DWORD> aligned_storage(word_count, 0);
            UINT filled_bytes = required;
            SetLastError(ERROR_SUCCESS);
            const UINT copied = GetRawInputDeviceInfoW(
                raw_handle, RIDI_PREPARSEDDATA, aligned_storage.data(), &filled_bytes);
            raw_error = GetLastError();
            if (copied != static_cast<UINT>(-1) && copied == required &&
                filled_bytes == required) {
                result = BuildFromPreparsedData(
                    reinterpret_cast<PHIDP_PREPARSED_DATA>(aligned_storage.data()),
                    static_cast<std::size_t>(required),
                    PreparsedDataSource::RawInputPreparsedData);
                raw_acquired = result.preparsed_data_available;
            } else {
                result.acquisition_win32_error = raw_error;
                result.acquisition_diagnostic =
                    "GetRawInputDeviceInfoW(RIDI_PREPARSEDDATA) fill failed or was truncated";
            }
            SecureZeroMemory(aligned_storage.data(),
                             aligned_storage.size() * sizeof(DWORD));
        } else {
            result.acquisition_diagnostic =
                "Raw Input preparsed-data allocation arithmetic is unsafe";
        }
    } else {
        result.acquisition_win32_error = raw_error;
        if (size_result == static_cast<UINT>(-1)) {
            result.acquisition_diagnostic =
                "GetRawInputDeviceInfoW(RIDI_PREPARSEDDATA) size query failed";
        } else if (required == 0U) {
            result.acquisition_diagnostic =
                "RIDI_PREPARSEDDATA returned no collection bytes";
        } else {
            result.acquisition_diagnostic =
                "Raw Input preparsed-data size or query result is unsafe";
        }
    }
    if (raw_acquired) return result;

    std::uint32_t path_error = 0;
    std::string path_diagnostic;
    const auto exact_collection_path = ExactRawInputCollectionPath(
        raw_handle, path_error, path_diagnostic);
    if (!exact_collection_path) {
        if (path_error != 0U) result.acquisition_win32_error = path_error;
        result.acquisition_diagnostic +=
            (result.acquisition_diagnostic.empty() ? std::string{} : "; ") +
            path_diagnostic;
        return result;
    }

    ScopedHandle hid(CreateFileW(exact_collection_path->c_str(), 0,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!hid.Valid()) {
        result.acquisition_win32_error = GetLastError();
        result.acquisition_diagnostic +=
            "; exact HID collection fallback could not be opened";
        return result;
    }
    ScopedHidPreparsedData fallback;
    if (!HidD_GetPreparsedData(hid.Get(), fallback.Put())) {
        result.acquisition_win32_error = GetLastError();
        result.acquisition_diagnostic +=
            "; HidD_GetPreparsedData exact-collection fallback failed";
        return result;
    }
    auto fallback_result = BuildFromPreparsedData(
        fallback.Get(), std::nullopt, PreparsedDataSource::ExactHidPathFallback);
    fallback_result.acquisition_win32_error = result.acquisition_win32_error;
    if (!result.acquisition_diagnostic.empty()) {
        fallback_result.acquisition_diagnostic =
            result.acquisition_diagnostic +
            (fallback_result.acquisition_diagnostic.empty() ? std::string{}
                                                             : "; " + fallback_result.acquisition_diagnostic);
    }
    if (fallback_result.preparsed_data_available) {
        fallback_result.acquisition_diagnostic +=
            (fallback_result.acquisition_diagnostic.empty() ? std::string{} : "; ") +
            std::string("exact Raw Input collection HidD fallback succeeded");
    }
    return fallback_result;
}

}  // namespace abdc::device
