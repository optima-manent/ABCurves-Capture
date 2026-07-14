#include "capture/LiveReportMirror.h"

#include "base/Binary.h"
#include "base/Crc32.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace abdc::capture {
namespace {

constexpr std::array<char, 8> kMagic{'A','B','D','C','L','I','V','1'};
constexpr std::uint16_t kVersion = 1U;
constexpr std::uint16_t kRecordPayloadBytes = 40U;
constexpr std::uint32_t kRecordFrameBytes = 8U + kRecordPayloadBytes;

void WriteExact(const HANDLE file, const void* bytes, const DWORD size, const char* context) {
    DWORD written = 0;
    if (!WriteFile(file, bytes, size, &written, nullptr) || written != size) {
        throw std::runtime_error(std::string("live report mirror write failed: ") + context);
    }
}

void ReadExactAt(const HANDLE file, const std::uint64_t offset, void* bytes,
                 const DWORD size, const char* context) {
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) {
        throw std::runtime_error(std::string("live report mirror seek failed: ") + context);
    }
    DWORD read = 0;
    if (!ReadFile(file, bytes, size, &read, nullptr) || read != size) {
        throw std::runtime_error(std::string("live report mirror read failed: ") + context);
    }
}

std::uint64_t FileSize(const HANDLE file) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0) {
        throw std::runtime_error("live report mirror size query failed");
    }
    return static_cast<std::uint64_t>(size.QuadPart);
}

std::vector<std::byte> Header(const ReportStreamIdentity& identity) {
    if (identity.bus == 0U || identity.device == 0U || (identity.endpoint & 0x80U) == 0U ||
        identity.descriptor_sha256.size() != 64U) {
        throw std::invalid_argument("invalid live report mirror identity");
    }
    std::vector<std::byte> result;
    result.insert(result.end(), reinterpret_cast<const std::byte*>(kMagic.data()),
                  reinterpret_cast<const std::byte*>(kMagic.data() + kMagic.size()));
    binary::AppendU16(result, kVersion);
    binary::AppendU16(result, kRecordPayloadBytes);
    binary::AppendU16(result, identity.bus);
    binary::AppendU16(result, identity.device);
    result.push_back(static_cast<std::byte>(identity.endpoint));
    result.push_back(std::byte{0});
    binary::AppendU16(result, 0U);
    result.insert(result.end(), reinterpret_cast<const std::byte*>(identity.descriptor_sha256.data()),
                  reinterpret_cast<const std::byte*>(identity.descriptor_sha256.data() + 64U));
    binary::AppendU32(result, Crc32(result));
    return result;
}

constexpr std::size_t kHeaderBytes = 8U + 2U + 2U + 2U + 2U + 1U + 1U + 2U + 64U + 4U;

}  // namespace

struct LiveReportMirrorWriter::Impl { HANDLE file = INVALID_HANDLE_VALUE; };
struct LiveReportMirrorReader::Impl { HANDLE file = INVALID_HANDLE_VALUE; std::uint64_t offset = kHeaderBytes; };

LiveReportMirrorWriter::LiveReportMirrorWriter(const std::filesystem::path& path,
                                               const ReportStreamIdentity& identity)
    : impl_(std::make_unique<Impl>()), identity_(identity) {
    if (!path.is_absolute()) throw std::invalid_argument("live mirror path must be absolute");
    impl_->file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                             nullptr, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (impl_->file == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot create live report mirror");
    const auto header = Header(identity_);
    WriteExact(impl_->file, header.data(), static_cast<DWORD>(header.size()), "header");
}

LiveReportMirrorWriter::~LiveReportMirrorWriter() {
    if (impl_ && impl_->file != INVALID_HANDLE_VALUE) CloseHandle(impl_->file);
}

void LiveReportMirrorWriter::Append(const AuthoritativeReport& report) {
    if (finalized_) throw std::logic_error("live report mirror is finalized");
    if (report.bus != identity_.bus || report.device != identity_.device ||
        report.endpoint != identity_.endpoint || report.transfer != 1U ||
        (report.info & 1U) == 0U || report.status != 0U) {
        throw std::runtime_error("invalid report entered live mirror");
    }
    if ((previous_sequence_ && report.capture_sequence <= *previous_sequence_) ||
        (previous_timestamp_ && report.capture_unix_ns < *previous_timestamp_)) {
        throw std::runtime_error("live report mirror sequence/timestamp regression");
    }
    std::vector<std::byte> payload;
    payload.reserve(kRecordPayloadBytes);
    binary::AppendU64(payload, report.capture_sequence);
    binary::AppendU64(payload, report.pcap_sequence);
    binary::AppendU64(payload, static_cast<std::uint64_t>(report.capture_unix_ns));
    binary::AppendU32(payload, static_cast<std::uint32_t>(report.hid_dx));
    binary::AppendU32(payload, static_cast<std::uint32_t>(report.hid_dy));
    binary::AppendU32(payload, report.buttons);
    payload.push_back(static_cast<std::byte>(report.report_id));
    payload.push_back(std::byte{0});
    payload.push_back(std::byte{0});
    payload.push_back(std::byte{0});
    if (payload.size() != kRecordPayloadBytes) throw std::logic_error("live mirror record size bug");
    std::array<std::byte, 8> frame_header{};
    std::vector<std::byte> encoded;
    binary::AppendU32(encoded, kRecordPayloadBytes);
    binary::AppendU32(encoded, Crc32(payload));
    std::memcpy(frame_header.data(), encoded.data(), frame_header.size());
    WriteExact(impl_->file, frame_header.data(), static_cast<DWORD>(frame_header.size()), "record header");
    WriteExact(impl_->file, payload.data(), static_cast<DWORD>(payload.size()), "record payload");
    previous_sequence_ = report.capture_sequence;
    previous_timestamp_ = report.capture_unix_ns;
    ++record_count_;
}

void LiveReportMirrorWriter::Flush() {
    if (impl_->file == INVALID_HANDLE_VALUE || !FlushFileBuffers(impl_->file)) {
        throw std::runtime_error("live report mirror flush failed");
    }
}

void LiveReportMirrorWriter::Finalize() {
    if (finalized_) throw std::logic_error("live report mirror already finalized");
    Flush();
    if (!CloseHandle(impl_->file)) throw std::runtime_error("live report mirror close failed");
    impl_->file = INVALID_HANDLE_VALUE;
    finalized_ = true;
}

LiveReportMirrorReader::LiveReportMirrorReader(const std::filesystem::path& path)
    : impl_(std::make_unique<Impl>()) {
    impl_->file = CreateFileW(path.c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (impl_->file == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open live report mirror");
    if (FileSize(impl_->file) < kHeaderBytes) throw std::runtime_error("live report mirror header is incomplete");
    std::array<std::byte, kHeaderBytes> bytes{};
    ReadExactAt(impl_->file, 0U, bytes.data(), static_cast<DWORD>(bytes.size()), "header");
    if (std::memcmp(bytes.data(), kMagic.data(), kMagic.size()) != 0 ||
        binary::ReadU16(bytes, 8U) != kVersion ||
        binary::ReadU16(bytes, 10U) != kRecordPayloadBytes ||
        Crc32(std::span<const std::byte>(bytes).first(bytes.size() - 4U)) !=
            binary::ReadU32(bytes, bytes.size() - 4U)) {
        throw std::runtime_error("live report mirror header failed validation");
    }
    identity_.bus = binary::ReadU16(bytes, 12U);
    identity_.device = binary::ReadU16(bytes, 14U);
    identity_.endpoint = std::to_integer<std::uint8_t>(bytes[16U]);
    identity_.descriptor_sha256.assign(reinterpret_cast<const char*>(bytes.data() + 20U), 64U);
}

LiveReportMirrorReader::~LiveReportMirrorReader() {
    if (impl_ && impl_->file != INVALID_HANDLE_VALUE) CloseHandle(impl_->file);
}

std::vector<AuthoritativeReport> LiveReportMirrorReader::TakeAvailable() {
    std::vector<AuthoritativeReport> reports;
    const auto size = FileSize(impl_->file);
    while (size >= impl_->offset && size - impl_->offset >= kRecordFrameBytes) {
        std::array<std::byte, kRecordFrameBytes> frame{};
        ReadExactAt(impl_->file, impl_->offset, frame.data(), static_cast<DWORD>(frame.size()), "record");
        if (binary::ReadU32(frame, 0U) != kRecordPayloadBytes ||
            Crc32(std::span<const std::byte>(frame).subspan(8U)) != binary::ReadU32(frame, 4U)) {
            throw std::runtime_error("live report mirror record failed CRC/length validation");
        }
        const auto payload = std::span<const std::byte>(frame).subspan(8U);
        AuthoritativeReport report;
        report.capture_sequence = binary::ReadU64(payload, 0U);
        report.pcap_sequence = binary::ReadU64(payload, 8U);
        report.capture_unix_ns = static_cast<std::int64_t>(binary::ReadU64(payload, 16U));
        report.hid_dx = static_cast<std::int32_t>(binary::ReadU32(payload, 24U));
        report.hid_dy = static_cast<std::int32_t>(binary::ReadU32(payload, 28U));
        report.buttons = binary::ReadU32(payload, 32U);
        report.report_id = std::to_integer<std::uint8_t>(payload[36U]);
        report.bus = identity_.bus;
        report.device = identity_.device;
        report.endpoint = identity_.endpoint;
        report.transfer = 1U;
        report.info = 1U;
        if ((previous_sequence_ && report.capture_sequence <= *previous_sequence_) ||
            (previous_timestamp_ && report.capture_unix_ns < *previous_timestamp_)) {
            throw std::runtime_error("live report mirror sequence/timestamp regression");
        }
        previous_sequence_ = report.capture_sequence;
        previous_timestamp_ = report.capture_unix_ns;
        ++record_count_;
        impl_->offset += kRecordFrameBytes;
        reports.push_back(report);
    }
    return reports;
}

void LiveReportMirrorReader::RequireCleanFinalTail() {
    (void)TakeAvailable();
    if (FileSize(impl_->file) != impl_->offset) {
        throw std::runtime_error("live report mirror ended with a partial record");
    }
}

}  // namespace abdc::capture
