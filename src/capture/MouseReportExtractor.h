#pragma once

#include "capture/HidDescriptor.h"
#include "capture/PcapReader.h"
#include "capture/ReportStream.h"
#include "capture/UsbPcapPacket.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace abdc::capture {

enum class CaptureAnomalyCode {
    FailedTransfer,
    EmptyCompletion,
    DecodeFailed,
    TimestampRegressed,
    DuplicateLike,
};

[[nodiscard]] const char* ToString(CaptureAnomalyCode code) noexcept;

struct CaptureAnomaly {
    CaptureAnomalyCode code = CaptureAnomalyCode::DecodeFailed;
    std::uint64_t pcap_sequence = 0;
    std::int64_t capture_unix_ns = 0;
    std::int64_t observed_qpc = 0;
    std::uint64_t irp_id = 0;
    std::string detail;
};

struct MouseExtractionCounters {
    std::uint64_t endpoint_records = 0;
    std::uint64_t requests = 0;
    std::uint64_t completions = 0;
    std::uint64_t decoded_transfers = 0;
    std::uint64_t decoded_reports = 0;
    std::uint64_t failed_transfers = 0;
    std::uint64_t empty_completions = 0;
    std::uint64_t decode_failures = 0;
    std::uint64_t timestamp_regressions = 0;
    std::uint64_t duplicate_like_records = 0;
};

struct MouseExtractionResult {
    std::vector<AuthoritativeReport> reports;
    std::vector<CaptureAnomaly> anomalies;
};

// Decoder failures are observations, not control flow. Callers write the PCAP
// record before invoking this extractor, then append any successfully decoded
// reports and anomaly records independently.
class MouseReportExtractor final {
public:
    MouseReportExtractor(std::uint16_t bus,
                         std::uint16_t device,
                         std::uint8_t endpoint,
                         HidMouseDecoder decoder);

    [[nodiscard]] MouseExtractionResult Process(const PcapRecord& record,
                                                const UsbPcapPacket& packet);
    [[nodiscard]] const MouseExtractionCounters& Counters() const noexcept {
        return counters_;
    }

private:
    CaptureAnomaly Anomaly(CaptureAnomalyCode code,
                           const PcapRecord& record,
                           const UsbPcapPacket& packet,
                           std::string detail) const;

    std::uint16_t bus_ = 0;
    std::uint16_t device_ = 0;
    std::uint8_t endpoint_ = 0;
    HidMouseDecoder decoder_;
    MouseExtractionCounters counters_{};
    std::uint64_t logical_sequence_ = 0;
    std::optional<std::int64_t> maximum_timestamp_;
    std::optional<std::uint64_t> last_irp_id_;
    std::optional<std::int64_t> last_timestamp_;
    std::vector<std::byte> last_payload_;
};

}  // namespace abdc::capture

