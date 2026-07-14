#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace abdc::capture {

enum ReportQualityFlag : std::uint32_t {
    ReportQualityNone = 0U,
    ReportQualityPcapTimestampRegressed = 1U << 0U,
    ReportQualityDuplicateLike = 1U << 1U,
};

struct ReportStreamIdentity {
    std::uint16_t bus = 0;
    std::uint16_t device = 0;
    std::uint8_t endpoint = 0;
    std::string descriptor_sha256;
    std::vector<std::byte> descriptor_evidence;
    std::string decoder_spec;
    std::int64_t qpc_frequency = 0;
};

struct AuthoritativeReport {
    std::uint64_t capture_sequence = 0;
    std::uint64_t pcap_sequence = 0;
    std::uint16_t report_index_in_transfer = 0;
    std::uint16_t reports_in_transfer = 1;
    std::int64_t capture_unix_ns = 0;
    std::int64_t observed_qpc = 0;
    std::uint64_t irp_id = 0;
    std::uint32_t status = 0;
    std::uint16_t function = 0;
    std::uint16_t bus = 0;
    std::uint16_t device = 0;
    std::uint8_t endpoint = 0;
    std::uint8_t transfer = 0;
    std::uint8_t info = 0;
    std::uint8_t report_id = 0;
    std::int32_t hid_dx = 0;
    std::int32_t hid_dy = 0;
    std::int32_t hid_wheel = 0;
    std::int32_t hid_horizontal_wheel = 0;
    std::uint32_t buttons = 0;
    std::uint32_t quality_flags = 0;
    std::vector<std::byte> payload;
};

class ReportStreamWriter final {
public:
    ReportStreamWriter(std::filesystem::path partial_path, ReportStreamIdentity identity,
                       std::size_t block_records = 4096);
    ~ReportStreamWriter();
    ReportStreamWriter(const ReportStreamWriter&) = delete;
    ReportStreamWriter& operator=(const ReportStreamWriter&) = delete;

    void Append(const AuthoritativeReport& report);
    void Checkpoint();
    void Finalize(const std::filesystem::path& final_path);
    [[nodiscard]] std::uint64_t RecordCount() const { return record_count_; }
    [[nodiscard]] bool Finalized() const { return finalized_; }

private:
    void WriteHeader();
    void FlushBlock();
    std::filesystem::path partial_path_;
    ReportStreamIdentity identity_;
    std::ofstream output_;
    std::size_t block_records_ = 0;
    std::vector<std::byte> block_;
    std::uint32_t block_count_ = 0;
    std::uint64_t record_count_ = 0;
    std::optional<std::uint64_t> previous_sequence_;
    std::optional<std::uint64_t> previous_pcap_sequence_;
    std::optional<std::int64_t> previous_timestamp_;
    std::optional<std::int64_t> previous_observed_qpc_;
    bool finalized_ = false;
};

class ReportStreamReader final {
public:
    explicit ReportStreamReader(const std::filesystem::path& path);
    [[nodiscard]] const ReportStreamIdentity& Identity() const { return identity_; }
    std::optional<AuthoritativeReport> Next();
    void Close() { input_.close(); }

private:
    void LoadBlock();
    std::ifstream input_;
    ReportStreamIdentity identity_;
    std::vector<std::byte> block_;
    std::size_t block_offset_ = 0;
    std::uint32_t block_remaining_ = 0;
    std::optional<std::uint64_t> previous_sequence_;
    std::optional<std::uint64_t> previous_pcap_sequence_;
    std::optional<std::int64_t> previous_timestamp_;
    std::optional<std::int64_t> previous_observed_qpc_;
};

}  // namespace abdc::capture
