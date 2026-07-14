#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abdc::device {

struct HidCapabilityQueryStatus {
    bool attempted = false;
    bool available = false;
    std::int32_t ntstatus = 0;
    std::uint32_t win32_error = 0;
    std::string diagnostic;
};

struct HidValueCapability {
    std::uint8_t report_id = 0;
    std::uint16_t usage_page = 0;
    std::uint16_t usage_minimum = 0;
    std::uint16_t usage_maximum = 0;
    std::uint16_t bit_size = 0;
    std::uint16_t report_count = 0;
    std::int32_t logical_minimum = 0;
    std::int32_t logical_maximum = 0;
    bool relative = false;
};

struct HidButtonCapability {
    std::uint8_t report_id = 0;
    std::uint16_t usage_page = 0;
    std::uint16_t usage_minimum = 0;
    std::uint16_t usage_maximum = 0;
};

struct HidCapsEvidence {
    // `available` is retained for source compatibility with qualified test
    // fixtures. Runtime code sets it to the independent caps query result.
    bool available = false;
    bool caps_available = false;
    bool value_caps_available = false;
    bool button_caps_available = false;
    HidCapabilityQueryStatus caps_status;
    HidCapabilityQueryStatus value_caps_status;
    HidCapabilityQueryStatus button_caps_status;
    std::uint16_t top_level_usage_page = 0;
    std::uint16_t top_level_usage = 0;
    std::uint16_t input_report_bytes = 0;
    std::vector<HidValueCapability> values;
    std::vector<HidButtonCapability> buttons;
};

enum class DescriptorEvidenceSource {
    None,
    UsbObserved,
    WindowsPreparsedReconstruction,
    QualifiedFixture,
};

enum class PreparsedDataSource {
    None,
    RawInputPreparsedData,
    ExactHidPathFallback,
};

[[nodiscard]] const char* ToString(DescriptorEvidenceSource source);
[[nodiscard]] const char* ToString(PreparsedDataSource source);

struct DescriptorParityResult {
    bool valid = false;
    std::string diagnostic;
    std::vector<std::uint8_t> report_ids;
    std::size_t maximum_input_report_bytes = 0;
};

struct WindowsHidDecoderEvidence {
    DescriptorEvidenceSource evidence_source = DescriptorEvidenceSource::None;
    PreparsedDataSource preparsed_data_source = PreparsedDataSource::None;
    bool preparsed_data_available = false;
    std::uint32_t acquisition_win32_error = 0;
    std::string acquisition_diagnostic;
    HidCapsEvidence hid;
    bool reconstruction_available = false;
    int reconstruction_status = -1;
    std::string reconstructor;
    std::string reconstructor_version;
    std::vector<std::byte> descriptor;
    std::string descriptor_sha256;
    std::string decoder_spec;
    std::vector<std::uint8_t> report_ids;
    std::string layout_fingerprint;
    std::size_t maximum_input_report_bytes = 0;
    bool hidp_input_parity = false;
    std::string parity_diagnostic;

    [[nodiscard]] bool ResearchCapable() const;
};

// Canonical semantic fingerprint shared by public HIDP evidence and the
// descriptor-derived capture route. It contains no device identifier.
[[nodiscard]] std::string FingerprintHidCaps(const HidCapsEvidence& caps);

// Validates only public input semantics. Reconstructed output and feature
// reports are deliberately outside the collection decoder contract.
[[nodiscard]] DescriptorParityResult ValidateReconstructedDescriptorParity(
    const HidCapsEvidence& hid,
    std::span<const std::byte> reconstructed_descriptor);

// RIDI_PREPARSEDDATA is authoritative when Windows supplies it. If that query
// fails or returns no bytes, the implementation obtains RIDI_DEVICENAME from
// the same Raw Input handle and opens that exact collection for the secondary
// HidD_GetPreparsedData path. No caller-supplied name, VID/PID, or instance-only
// join participates in the fallback.
[[nodiscard]] WindowsHidDecoderEvidence BuildWindowsHidDecoderEvidence(
    std::uintptr_t raw_input_handle);

}  // namespace abdc::device
