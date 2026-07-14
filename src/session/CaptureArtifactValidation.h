#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace abdc::session {

// The independently certified identity that every published capture artifact
// must describe.  Validation is intentionally about framing and provenance;
// it never grades movement quality or reconciles Windows Raw Input.
struct CaptureArtifactIdentity final {
    std::uint16_t usb_bus = 0;
    std::uint16_t usb_device = 0;
    std::uint8_t interrupt_in_endpoint = 0;
    std::string hid_descriptor_sha256;
    std::int64_t qpc_frequency = 0;
};

struct CaptureArtifactValidationResult final {
    std::uint64_t raw_pcap_records = 0;
    std::uint64_t decoded_reports = 0;
    std::uint64_t anomaly_records = 0;
    std::uint64_t derivative_failures = 0;
};

[[nodiscard]] std::uint64_t ValidateDevicePcap(
    const std::filesystem::path& device_pcap,
    const CaptureArtifactIdentity& expected_identity);

// Transitional source compatibility; validation is device-wide.
[[nodiscard]] inline std::uint64_t ValidateEndpointPcap(
    const std::filesystem::path& device_pcap,
    const CaptureArtifactIdentity& expected_identity) {
    return ValidateDevicePcap(device_pcap, expected_identity);
}

[[nodiscard]] std::uint64_t ValidateDecodedReportStream(
    const std::filesystem::path& report_stream,
    const CaptureArtifactIdentity& expected_identity);

[[nodiscard]] std::uint64_t ValidateCaptureAnomalyJournal(
    const std::filesystem::path& anomaly_journal);

// Strictly re-reads the authoritative device PCAP. Optional ABCRPT2/anomaly
// derivatives are validated when present but cannot invalidate preserved raw
// capture merely because they were unavailable.
[[nodiscard]] CaptureArtifactValidationResult ValidateCaptureArtifacts(
    const std::filesystem::path& absolute_capture_directory,
    const CaptureArtifactIdentity& expected_identity);

}  // namespace abdc::session
