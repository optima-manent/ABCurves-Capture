#include "capture/ReportStream.h"

#include "base/Binary.h"
#include "base/Crc32.h"

#include <windows.h>

#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace abdc::capture {
namespace {

constexpr std::array<char, 8> kMagic{'A','B','C','R','P','T','2','\0'};
constexpr std::array<char, 4> kBlockMagic{'R','B','L','K'};
constexpr std::uint16_t kVersion = 2;
constexpr std::size_t kMaxEvidence = 1U << 20U;
constexpr std::size_t kMaxSpec = 1U << 20U;
constexpr std::size_t kMaxBlock = 16U << 20U;

void WriteAll(std::ostream& output, const void* data, const std::size_t size, const char* context) {
    output.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!output) throw std::runtime_error(std::string("report stream write failed: ") + context);
}

std::vector<std::byte> ReadExact(std::istream& input, const std::size_t size, const char* context) {
    std::vector<std::byte> bytes(size);
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    if (input.gcount() != static_cast<std::streamsize>(size)) {
        throw std::runtime_error(std::string("truncated report stream ") + context);
    }
    return bytes;
}

std::uint32_t ReadU32Stream(std::istream& input, const char* context) {
    const auto bytes = ReadExact(input, 4, context);
    return binary::ReadU32(bytes, 0);
}

void AppendBytes(std::vector<std::byte>& out, const std::span<const std::byte> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

}  // namespace

ReportStreamWriter::ReportStreamWriter(std::filesystem::path partial_path, ReportStreamIdentity identity,
                                       const std::size_t block_records)
    : partial_path_(std::move(partial_path)), identity_(std::move(identity)), block_records_(block_records) {
    if (block_records_ == 0 || block_records_ > 65536) throw std::invalid_argument("unsafe report block size");
    if (identity_.endpoint < 0x80U || identity_.descriptor_sha256.size() != 64 ||
        identity_.descriptor_evidence.empty() || identity_.descriptor_evidence.size() > kMaxEvidence ||
        identity_.decoder_spec.empty() || identity_.decoder_spec.size() > kMaxSpec ||
        identity_.qpc_frequency <= 0) {
        throw std::invalid_argument("invalid report stream identity");
    }
    std::filesystem::create_directories(partial_path_.parent_path());
    output_.open(partial_path_, std::ios::binary | std::ios::trunc);
    if (!output_) throw std::runtime_error("cannot create report stream partial file");
    WriteHeader();
}

ReportStreamWriter::~ReportStreamWriter() {
    try { if (output_.is_open()) output_.close(); } catch (...) {}
}

void ReportStreamWriter::WriteHeader() {
    WriteAll(output_, kMagic.data(), kMagic.size(), "magic");
    std::vector<std::byte> fixed;
    binary::AppendU16(fixed, kVersion);
    binary::AppendU16(fixed, identity_.bus);
    binary::AppendU16(fixed, identity_.device);
    fixed.push_back(static_cast<std::byte>(identity_.endpoint));
    fixed.push_back(std::byte{0});
    binary::AppendU32(fixed, static_cast<std::uint32_t>(identity_.descriptor_evidence.size()));
    binary::AppendU32(fixed, static_cast<std::uint32_t>(identity_.decoder_spec.size()));
    binary::AppendU64(fixed, static_cast<std::uint64_t>(identity_.qpc_frequency));
    WriteAll(output_, fixed.data(), fixed.size(), "fixed header");
    WriteAll(output_, identity_.descriptor_sha256.data(), identity_.descriptor_sha256.size(), "descriptor hash");
    WriteAll(output_, identity_.descriptor_evidence.data(), identity_.descriptor_evidence.size(), "descriptor evidence");
    WriteAll(output_, identity_.decoder_spec.data(), identity_.decoder_spec.size(), "decoder spec");
}

void ReportStreamWriter::Append(const AuthoritativeReport& report) {
    if (finalized_) throw std::logic_error("cannot append to finalized report stream");
    if (report.bus != identity_.bus || report.device != identity_.device || report.endpoint != identity_.endpoint) {
        throw std::runtime_error("report identity changed during locked session");
    }
    if (report.transfer != 1 || (report.info & 1U) == 0 || (report.endpoint & 0x80U) == 0 ||
        report.status != 0 || report.payload.empty() || report.payload.size() > 4096) {
        throw std::runtime_error("non-successful interrupt-IN completion passed to report stream");
    }
    if (previous_sequence_ && report.capture_sequence <= *previous_sequence_) {
        throw std::runtime_error("capture sequence regression");
    }
    if (report.observed_qpc <= 0 ||
        (previous_observed_qpc_ && report.observed_qpc < *previous_observed_qpc_)) {
        throw std::runtime_error("report observation QPC is invalid or regressed");
    }
    binary::AppendVarUInt(block_, previous_sequence_ ? report.capture_sequence - *previous_sequence_
                                                     : report.capture_sequence);
    if (report.reports_in_transfer == 0 || report.report_index_in_transfer >= report.reports_in_transfer) {
        throw std::runtime_error("invalid logical report position within USB transfer");
    }
    if (previous_pcap_sequence_ && report.pcap_sequence < *previous_pcap_sequence_) {
        throw std::runtime_error("PCAP sequence regression");
    }
    binary::AppendVarUInt(block_, previous_pcap_sequence_ ? report.pcap_sequence - *previous_pcap_sequence_
                                                          : report.pcap_sequence);
    binary::AppendVarUInt(block_, report.report_index_in_transfer);
    binary::AppendVarUInt(block_, report.reports_in_transfer);
    binary::AppendVarInt(block_, previous_timestamp_ ? report.capture_unix_ns - *previous_timestamp_
                                                     : report.capture_unix_ns);
    binary::AppendVarInt(block_, previous_observed_qpc_
        ? report.observed_qpc - *previous_observed_qpc_
        : report.observed_qpc);
    binary::AppendU64(block_, report.irp_id);
    binary::AppendU32(block_, report.status);
    binary::AppendU16(block_, report.function);
    binary::AppendU16(block_, report.bus);
    binary::AppendU16(block_, report.device);
    block_.push_back(static_cast<std::byte>(report.endpoint));
    block_.push_back(static_cast<std::byte>(report.transfer));
    block_.push_back(static_cast<std::byte>(report.info));
    block_.push_back(static_cast<std::byte>(report.report_id));
    binary::AppendVarInt(block_, report.hid_dx);
    binary::AppendVarInt(block_, report.hid_dy);
    binary::AppendVarInt(block_, report.hid_wheel);
    binary::AppendVarInt(block_, report.hid_horizontal_wheel);
    binary::AppendVarUInt(block_, report.buttons);
    binary::AppendVarUInt(block_, report.quality_flags);
    binary::AppendVarUInt(block_, report.payload.size());
    AppendBytes(block_, report.payload);
    previous_sequence_ = report.capture_sequence;
    previous_pcap_sequence_ = report.pcap_sequence;
    previous_timestamp_ = report.capture_unix_ns;
    previous_observed_qpc_ = report.observed_qpc;
    ++record_count_;
    ++block_count_;
    if (block_.size() > kMaxBlock) throw std::runtime_error("report block exceeded safety limit");
    if (block_count_ >= block_records_) FlushBlock();
}

void ReportStreamWriter::FlushBlock() {
    if (block_count_ == 0) return;
    WriteAll(output_, kBlockMagic.data(), kBlockMagic.size(), "block magic");
    std::vector<std::byte> header;
    binary::AppendU32(header, static_cast<std::uint32_t>(block_.size()));
    binary::AppendU32(header, block_count_);
    binary::AppendU32(header, Crc32(block_));
    WriteAll(output_, header.data(), header.size(), "block header");
    WriteAll(output_, block_.data(), block_.size(), "block payload");
    block_.clear();
    block_count_ = 0;
}

void ReportStreamWriter::Checkpoint() {
    FlushBlock();
    output_.flush();
    if (!output_) throw std::runtime_error("report stream checkpoint flush failed");
    const HANDLE handle = CreateFileW(partial_path_.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open report stream for durable flush");
    const BOOL ok = FlushFileBuffers(handle);
    CloseHandle(handle);
    if (!ok) throw std::runtime_error("FlushFileBuffers failed for report stream");
}

void ReportStreamWriter::Finalize(const std::filesystem::path& final_path) {
    if (finalized_) throw std::logic_error("report stream already finalized");
    Checkpoint();
    output_.close();
    if (std::filesystem::exists(final_path)) throw std::runtime_error("refusing to overwrite report stream");
    if (!MoveFileExW(partial_path_.c_str(), final_path.c_str(), MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("atomic report stream rename failed");
    }
    finalized_ = true;
}

ReportStreamReader::ReportStreamReader(const std::filesystem::path& path) {
    input_.open(path, std::ios::binary);
    if (!input_) throw std::runtime_error("cannot open report stream");
    const auto magic = ReadExact(input_, kMagic.size(), "magic");
    if (std::memcmp(magic.data(), kMagic.data(), kMagic.size()) != 0) throw std::runtime_error("bad report stream magic");
    const auto fixed = ReadExact(input_, 24, "fixed header");
    const auto version = binary::ReadU16(fixed, 0);
    if (version != kVersion) throw std::runtime_error("unsupported report stream version");
    identity_.bus = binary::ReadU16(fixed, 2);
    identity_.device = binary::ReadU16(fixed, 4);
    identity_.endpoint = std::to_integer<std::uint8_t>(fixed[6]);
    if (fixed[7] != std::byte{0}) throw std::runtime_error("report stream reserved byte is nonzero");
    const auto evidence_length = binary::ReadU32(fixed, 8);
    const auto spec_length = binary::ReadU32(fixed, 12);
    identity_.qpc_frequency = static_cast<std::int64_t>(binary::ReadU64(fixed, 16));
    if (evidence_length == 0 || evidence_length > kMaxEvidence || spec_length == 0 || spec_length > kMaxSpec) {
        throw std::runtime_error("unsafe report stream variable header lengths");
    }
    if (identity_.qpc_frequency <= 0) throw std::runtime_error("invalid report-stream QPC frequency");
    const auto hash = ReadExact(input_, 64, "descriptor hash");
    identity_.descriptor_sha256.assign(reinterpret_cast<const char*>(hash.data()), hash.size());
    identity_.descriptor_evidence = ReadExact(input_, evidence_length, "descriptor evidence");
    const auto spec = ReadExact(input_, spec_length, "decoder spec");
    identity_.decoder_spec.assign(reinterpret_cast<const char*>(spec.data()), spec.size());
}

void ReportStreamReader::LoadBlock() {
    std::array<char, 4> magic{};
    input_.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    if (input_.gcount() == 0 && input_.eof()) return;
    if (input_.gcount() != static_cast<std::streamsize>(magic.size()) || magic != kBlockMagic) {
        throw std::runtime_error("truncated or invalid report block magic");
    }
    const auto size = ReadU32Stream(input_, "block size");
    const auto count = ReadU32Stream(input_, "block count");
    const auto expected_crc = ReadU32Stream(input_, "block CRC");
    if (size == 0 || size > kMaxBlock || count == 0 || count > 65536) throw std::runtime_error("unsafe report block header");
    block_ = ReadExact(input_, size, "block payload");
    if (Crc32(block_) != expected_crc) throw std::runtime_error("report block CRC mismatch");
    block_offset_ = 0;
    block_remaining_ = count;
}

std::optional<AuthoritativeReport> ReportStreamReader::Next() {
    if (block_remaining_ == 0) {
        if (block_offset_ != block_.size()) throw std::runtime_error("report block has trailing bytes");
        LoadBlock();
        if (block_remaining_ == 0) return std::nullopt;
    }
    AuthoritativeReport report;
    const auto span = std::span<const std::byte>(block_);
    const auto sequence_delta = binary::ReadVarUInt(span, block_offset_);
    const auto pcap_sequence_delta = binary::ReadVarUInt(span, block_offset_);
    const auto report_index = binary::ReadVarUInt(span, block_offset_);
    const auto reports_in_transfer = binary::ReadVarUInt(span, block_offset_);
    const auto timestamp_delta = binary::ReadVarInt(span, block_offset_);
    const auto observed_qpc_delta = binary::ReadVarInt(span, block_offset_);
    report.capture_sequence = previous_sequence_ ? *previous_sequence_ + sequence_delta : sequence_delta;
    report.pcap_sequence = previous_pcap_sequence_ ? *previous_pcap_sequence_ + pcap_sequence_delta
                                                   : pcap_sequence_delta;
    if (report_index > std::numeric_limits<std::uint16_t>::max() || reports_in_transfer == 0 ||
        reports_in_transfer > std::numeric_limits<std::uint16_t>::max() || report_index >= reports_in_transfer) {
        throw std::runtime_error("invalid stored logical report position");
    }
    report.report_index_in_transfer = static_cast<std::uint16_t>(report_index);
    report.reports_in_transfer = static_cast<std::uint16_t>(reports_in_transfer);
    report.capture_unix_ns = previous_timestamp_ ? *previous_timestamp_ + timestamp_delta : timestamp_delta;
    report.observed_qpc = previous_observed_qpc_
        ? *previous_observed_qpc_ + observed_qpc_delta
        : observed_qpc_delta;
    report.irp_id = binary::ReadU64(span, block_offset_); block_offset_ += 8;
    report.status = binary::ReadU32(span, block_offset_); block_offset_ += 4;
    report.function = binary::ReadU16(span, block_offset_); block_offset_ += 2;
    report.bus = binary::ReadU16(span, block_offset_); block_offset_ += 2;
    report.device = binary::ReadU16(span, block_offset_); block_offset_ += 2;
    binary::RequireAvailable(span, block_offset_, 4, "report identity bytes");
    report.endpoint = std::to_integer<std::uint8_t>(span[block_offset_++]);
    report.transfer = std::to_integer<std::uint8_t>(span[block_offset_++]);
    report.info = std::to_integer<std::uint8_t>(span[block_offset_++]);
    report.report_id = std::to_integer<std::uint8_t>(span[block_offset_++]);
    const auto dx = binary::ReadVarInt(span, block_offset_);
    const auto dy = binary::ReadVarInt(span, block_offset_);
    const auto wheel = binary::ReadVarInt(span, block_offset_);
    const auto horizontal_wheel = binary::ReadVarInt(span, block_offset_);
    if (dx < std::numeric_limits<std::int32_t>::min() || dx > std::numeric_limits<std::int32_t>::max() ||
        dy < std::numeric_limits<std::int32_t>::min() || dy > std::numeric_limits<std::int32_t>::max() ||
        wheel < std::numeric_limits<std::int32_t>::min() || wheel > std::numeric_limits<std::int32_t>::max() ||
        horizontal_wheel < std::numeric_limits<std::int32_t>::min() ||
        horizontal_wheel > std::numeric_limits<std::int32_t>::max()) {
        throw std::runtime_error("decoded report delta overflow");
    }
    report.hid_dx = static_cast<std::int32_t>(dx);
    report.hid_dy = static_cast<std::int32_t>(dy);
    report.hid_wheel = static_cast<std::int32_t>(wheel);
    report.hid_horizontal_wheel = static_cast<std::int32_t>(horizontal_wheel);
    const auto buttons = binary::ReadVarUInt(span, block_offset_);
    if (buttons > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("button mask overflow");
    report.buttons = static_cast<std::uint32_t>(buttons);
    const auto quality_flags = binary::ReadVarUInt(span, block_offset_);
    if (quality_flags > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("report quality flags overflow");
    }
    report.quality_flags = static_cast<std::uint32_t>(quality_flags);
    const auto payload_size = binary::ReadVarUInt(span, block_offset_);
    if (payload_size == 0 || payload_size > 4096) throw std::runtime_error("unsafe report payload length");
    binary::RequireAvailable(span, block_offset_, static_cast<std::size_t>(payload_size), "report payload");
    report.payload.assign(span.begin() + static_cast<std::ptrdiff_t>(block_offset_),
                          span.begin() + static_cast<std::ptrdiff_t>(block_offset_ + payload_size));
    block_offset_ += static_cast<std::size_t>(payload_size);
    if (previous_sequence_ && report.capture_sequence <= *previous_sequence_) throw std::runtime_error("stored sequence regression");
    if (report.observed_qpc <= 0 ||
        (previous_observed_qpc_ && report.observed_qpc < *previous_observed_qpc_)) {
        throw std::runtime_error("stored observation QPC regression");
    }
    if (report.bus != identity_.bus || report.device != identity_.device || report.endpoint != identity_.endpoint ||
        report.status != 0 || report.transfer != 1 || (report.info & 1U) == 0) {
        throw std::runtime_error("stored report violates locked successful interrupt-IN identity");
    }
    previous_sequence_ = report.capture_sequence;
    previous_pcap_sequence_ = report.pcap_sequence;
    previous_timestamp_ = report.capture_unix_ns;
    previous_observed_qpc_ = report.observed_qpc;
    --block_remaining_;
    return report;
}

}  // namespace abdc::capture
