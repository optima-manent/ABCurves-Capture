#include "capture/MouseReportExtractor.h"

#include <algorithm>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>

namespace abdc::capture {

const char* ToString(const CaptureAnomalyCode code) noexcept {
    switch (code) {
    case CaptureAnomalyCode::FailedTransfer: return "failed_transfer";
    case CaptureAnomalyCode::EmptyCompletion: return "empty_completion";
    case CaptureAnomalyCode::DecodeFailed: return "decode_failed";
    case CaptureAnomalyCode::TimestampRegressed: return "pcap_timestamp_regressed";
    case CaptureAnomalyCode::DuplicateLike: return "duplicate_like";
    }
    return "unknown";
}

MouseReportExtractor::MouseReportExtractor(const std::uint16_t bus,
                                           const std::uint16_t device,
                                           const std::uint8_t endpoint,
                                           HidMouseDecoder decoder)
    : bus_(bus), device_(device), endpoint_(endpoint), decoder_(std::move(decoder)) {
    if (bus_ == 0U || device_ == 0U || (endpoint_ & 0x80U) == 0U ||
        (endpoint_ & 0x0fU) == 0U) {
        throw std::invalid_argument("invalid certified USB mouse endpoint");
    }
}

CaptureAnomaly MouseReportExtractor::Anomaly(const CaptureAnomalyCode code,
                                             const PcapRecord& record,
                                             const UsbPcapPacket& packet,
                                             std::string detail) const {
    CaptureAnomaly result;
    result.code = code;
    result.pcap_sequence = record.sequence;
    result.capture_unix_ns = record.UnixNanoseconds();
    result.observed_qpc = record.observed_qpc;
    result.irp_id = packet.irp_id;
    result.detail = std::move(detail);
    return result;
}

MouseExtractionResult MouseReportExtractor::Process(const PcapRecord& record,
                                                     const UsbPcapPacket& packet) {
    if (packet.bus != bus_ || packet.device != device_ ||
        packet.endpoint != endpoint_ || packet.transfer != UsbTransfer::Interrupt) {
        throw std::invalid_argument("extractor received a record outside its endpoint");
    }
    if (record.observed_qpc <= 0) {
        throw std::invalid_argument("extractor requires a positive observation QPC");
    }

    MouseExtractionResult result;
    ++counters_.endpoint_records;
    if (!packet.IsCompletion()) {
        ++counters_.requests;
        return result;
    }

    ++counters_.completions;
    const auto timestamp = record.UnixNanoseconds();
    std::uint32_t quality_flags = ReportQualityNone;
    if (maximum_timestamp_ && timestamp < *maximum_timestamp_) {
        quality_flags |= ReportQualityPcapTimestampRegressed;
        ++counters_.timestamp_regressions;
        result.anomalies.push_back(Anomaly(
            CaptureAnomalyCode::TimestampRegressed, record, packet,
            "native PCAP time moved backward; original time was retained"));
    }
    maximum_timestamp_ = maximum_timestamp_
        ? std::max(*maximum_timestamp_, timestamp)
        : timestamp;

    const bool duplicate_like = last_irp_id_ && *last_irp_id_ == packet.irp_id &&
        last_timestamp_ && *last_timestamp_ == timestamp &&
        last_payload_.size() == packet.payload.size() &&
        std::equal(last_payload_.begin(), last_payload_.end(), packet.payload.begin());
    if (duplicate_like) {
        quality_flags |= ReportQualityDuplicateLike;
        ++counters_.duplicate_like_records;
        result.anomalies.push_back(Anomaly(
            CaptureAnomalyCode::DuplicateLike, record, packet,
            "record resembles its predecessor; both source records were retained"));
    }
    last_irp_id_ = packet.irp_id;
    last_timestamp_ = timestamp;
    last_payload_.assign(packet.payload.begin(), packet.payload.end());

    if (packet.status != 0U) {
        ++counters_.failed_transfers;
        result.anomalies.push_back(Anomaly(
            CaptureAnomalyCode::FailedTransfer, record, packet,
            "interrupt-IN completion has a non-success status"));
        return result;
    }
    if (packet.payload.empty()) {
        ++counters_.empty_completions;
        result.anomalies.push_back(Anomaly(
            CaptureAnomalyCode::EmptyCompletion, record, packet,
            "successful interrupt-IN completion has no report payload"));
        return result;
    }

    std::vector<DecodedMouseReport> decoded;
    try {
        decoded = decoder_.DecodeBatch(packet.payload);
    } catch (const std::exception& error) {
        ++counters_.decode_failures;
        result.anomalies.push_back(Anomaly(
            CaptureAnomalyCode::DecodeFailed, record, packet, error.what()));
        return result;
    }
    if (decoded.size() > std::numeric_limits<std::uint16_t>::max()) {
        ++counters_.decode_failures;
        result.anomalies.push_back(Anomaly(
            CaptureAnomalyCode::DecodeFailed, record, packet,
            "transfer contains too many logical HID reports"));
        return result;
    }

    ++counters_.decoded_transfers;
    result.reports.reserve(decoded.size());
    for (std::size_t index = 0; index < decoded.size(); ++index) {
        AuthoritativeReport report;
        report.capture_sequence = logical_sequence_++;
        report.pcap_sequence = record.sequence;
        report.report_index_in_transfer = static_cast<std::uint16_t>(index);
        report.reports_in_transfer = static_cast<std::uint16_t>(decoded.size());
        report.capture_unix_ns = timestamp;
        report.observed_qpc = record.observed_qpc;
        report.irp_id = packet.irp_id;
        report.status = packet.status;
        report.function = packet.function;
        report.bus = packet.bus;
        report.device = packet.device;
        report.endpoint = packet.endpoint;
        report.transfer = static_cast<std::uint8_t>(packet.transfer);
        report.info = packet.info;
        report.report_id = decoded[index].report_id;
        report.hid_dx = decoded[index].dx;
        report.hid_dy = decoded[index].dy;
        report.hid_wheel = decoded[index].wheel;
        report.hid_horizontal_wheel = decoded[index].horizontal_wheel;
        report.buttons = decoded[index].buttons;
        report.quality_flags = quality_flags;
        report.payload = std::move(decoded[index].payload);
        result.reports.push_back(std::move(report));
        ++counters_.decoded_reports;
    }
    return result;
}

}  // namespace abdc::capture

