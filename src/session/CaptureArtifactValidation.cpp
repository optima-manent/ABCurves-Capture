#include "session/CaptureArtifactValidation.h"

#include "base/Sha256.h"
#include "capture/PcapReader.h"
#include "capture/ReportStream.h"
#include "capture/UsbPcapPacket.h"
#include "session/AppendOnlyJsonl.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <string_view>

namespace abdc::session {
namespace {

constexpr std::string_view kAnomalySchema =
    "abcurves.capture.anomaly.v1";

bool IsSha256(const std::string_view value) noexcept {
    return value.size() == 64U &&
        std::all_of(value.begin(), value.end(), [](const char character) {
            return std::isxdigit(static_cast<unsigned char>(character)) != 0;
        });
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](const char character) {
                       return static_cast<char>(std::tolower(
                           static_cast<unsigned char>(character)));
                   });
    return value;
}

void RequireRegularFile(const std::filesystem::path& path,
                        const char* description) {
    const auto status = std::filesystem::symlink_status(path);
    if (std::filesystem::is_symlink(status) ||
        status.type() != std::filesystem::file_type::regular) {
        throw std::runtime_error(std::string(description) +
                                 " is missing or not a regular file");
    }
}

void RequireNoPartial(const std::filesystem::path& path,
                      const char* description) {
    const auto status = std::filesystem::symlink_status(path);
    if (status.type() != std::filesystem::file_type::not_found) {
        throw std::runtime_error(std::string(description) +
                                 " remains after capture publication");
    }
}

void ValidateIdentity(const CaptureArtifactIdentity& identity) {
    if (identity.usb_bus == 0U || identity.usb_device == 0U ||
        (identity.interrupt_in_endpoint != 0U &&
         ((identity.interrupt_in_endpoint & 0x80U) == 0U ||
          (identity.interrupt_in_endpoint & 0x0fU) == 0U ||
          (identity.interrupt_in_endpoint & 0x70U) != 0U)) ||
        (!identity.hid_descriptor_sha256.empty() &&
         !IsSha256(identity.hid_descriptor_sha256)) ||
        identity.qpc_frequency <= 0) {
        throw std::invalid_argument("capture artifact identity is invalid");
    }
}

}  // namespace

std::uint64_t ValidateDevicePcap(
    const std::filesystem::path& device_pcap,
    const CaptureArtifactIdentity& expected_identity) {
    ValidateIdentity(expected_identity);
    RequireRegularFile(device_pcap, "authoritative device PCAP");
    std::ifstream input(device_pcap, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open authoritative device PCAP");
    }
    capture::PcapReader reader(input);
    std::uint64_t count = 0U;
    while (const auto record = reader.Next()) {
        const auto packet = capture::UsbPcapPacket::Parse(
            record->data, record->original_length);
        if (packet.bus != expected_identity.usb_bus ||
            packet.device != expected_identity.usb_device) {
            throw std::runtime_error(
                "device PCAP record disagrees with the certified mouse");
        }
        ++count;
    }
    return count;
}

std::uint64_t ValidateDecodedReportStream(
    const std::filesystem::path& report_stream,
    const CaptureArtifactIdentity& expected_identity) {
    ValidateIdentity(expected_identity);
    if (expected_identity.interrupt_in_endpoint == 0U ||
        expected_identity.hid_descriptor_sha256.empty()) {
        throw std::invalid_argument(
            "decoded report validation requires decoder identity");
    }
    RequireRegularFile(report_stream, "decoded report stream");
    capture::ReportStreamReader reader(report_stream);
    const auto& identity = reader.Identity();
    const auto expected_hash = Lower(expected_identity.hid_descriptor_sha256);
    if (identity.bus != expected_identity.usb_bus ||
        identity.device != expected_identity.usb_device ||
        identity.endpoint != expected_identity.interrupt_in_endpoint ||
        identity.qpc_frequency != expected_identity.qpc_frequency ||
        Lower(identity.descriptor_sha256) != expected_hash ||
        Lower(Sha256Hex(identity.descriptor_evidence)) != expected_hash ||
        identity.decoder_spec.empty()) {
        throw std::runtime_error(
            "decoded report stream identity disagrees with certification");
    }
    std::uint64_t count = 0U;
    while (reader.Next()) ++count;
    reader.Close();
    return count;
}

std::uint64_t ValidateCaptureAnomalyJournal(
    const std::filesystem::path& anomaly_journal) {
    RequireRegularFile(anomaly_journal, "capture anomaly journal");
    AppendOnlyJsonlReader reader(anomaly_journal, std::string(kAnomalySchema));
    std::uint64_t count = 0U;
    while (reader.Next()) ++count;
    return count;
}

CaptureArtifactValidationResult ValidateCaptureArtifacts(
    const std::filesystem::path& absolute_capture_directory,
    const CaptureArtifactIdentity& expected_identity) {
    const auto directory_status =
        std::filesystem::symlink_status(absolute_capture_directory);
    if (!absolute_capture_directory.is_absolute() ||
        std::filesystem::is_symlink(directory_status) ||
        directory_status.type() != std::filesystem::file_type::directory) {
        throw std::invalid_argument(
            "capture artifact validation identity or directory is invalid");
    }
    ValidateIdentity(expected_identity);

    const auto device_pcap =
        absolute_capture_directory / "mouse_usb.pcap";
    const auto reports_path =
        absolute_capture_directory / "mouse_reports.abcr2";
    const auto anomalies_path =
        absolute_capture_directory / "capture_anomalies.jsonl";
    RequireRegularFile(device_pcap, "authoritative device PCAP");
    RequireNoPartial(device_pcap.wstring() + L".partial",
                     "authoritative device PCAP partial");

    CaptureArtifactValidationResult result;
    result.raw_pcap_records =
        ValidateDevicePcap(device_pcap, expected_identity);
    if (std::filesystem::is_regular_file(reports_path) &&
        expected_identity.interrupt_in_endpoint != 0U &&
        !expected_identity.hid_descriptor_sha256.empty()) {
        try {
            result.decoded_reports =
                ValidateDecodedReportStream(reports_path, expected_identity);
        } catch (const std::exception&) {
            ++result.derivative_failures;
        }
    }
    if (std::filesystem::is_regular_file(anomalies_path)) {
        try {
            result.anomaly_records =
                ValidateCaptureAnomalyJournal(anomalies_path);
        } catch (const std::exception&) {
            ++result.derivative_failures;
        }
    }
    return result;
}

}  // namespace abdc::session
