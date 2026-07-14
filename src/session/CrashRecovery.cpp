#include "session/CrashRecovery.h"

#include "base/Binary.h"
#include "base/Crc32.h"
#include "base/Json.h"
#include "capture/PcapReader.h"
#include "session/AppendOnlyJsonl.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace abdc::session {
namespace {

constexpr std::array<char, 8> kReportMagic{'A','B','C','R','P','T','2','\0'};
constexpr std::array<char, 4> kBlockMagic{'R','B','L','K'};
constexpr std::uint16_t kReportVersion = 2U;
constexpr std::uint64_t kMaxVariableHeader = 1U << 20U;
constexpr std::uint64_t kMaxBlock = 16U << 20U;
constexpr std::size_t kMaximumJournalRecordBytes = 4U << 20U;

void RequirePartialPath(const std::filesystem::path& path) {
    if (!path.is_absolute() || path.extension() != L".partial") {
        throw std::invalid_argument("recovery is restricted to absolute .partial paths");
    }
    const auto status = std::filesystem::symlink_status(path);
    if (std::filesystem::is_symlink(status) ||
        status.type() != std::filesystem::file_type::regular) {
        throw std::runtime_error("partial artifact is not a regular file");
    }
}

void DurableResize(const std::filesystem::path& path,
                   const std::uint64_t old_size,
                   const std::uint64_t new_size) {
    if (new_size > old_size) throw std::logic_error("recovery cannot grow an artifact");
    if (new_size == old_size) return;
    std::filesystem::resize_file(path, new_size);
    const HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                      FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot open recovered artifact for durable flush");
    }
    const BOOL flushed = FlushFileBuffers(handle);
    const BOOL closed = CloseHandle(handle);
    if (!flushed || !closed) {
        throw std::runtime_error("durable recovery flush failed");
    }
}

std::vector<std::byte> ReadExact(std::istream& input,
                                 const std::size_t size,
                                 const char* context) {
    std::vector<std::byte> result(size);
    input.read(reinterpret_cast<char*>(result.data()),
               static_cast<std::streamsize>(size));
    if (input.gcount() != static_cast<std::streamsize>(size)) {
        throw std::runtime_error(std::string("truncated ") + context);
    }
    return result;
}

bool StartsWith(const std::string_view value, const std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

TailRecoveryResult Result(const std::uint64_t original,
                          const std::uint64_t retained,
                          const std::uint64_t records) {
    return TailRecoveryResult{original, retained, records, retained != original};
}

}  // namespace

TailRecoveryResult RecoverJsonlPartial(const std::filesystem::path& partial_path,
                                       const std::string& expected_schema) {
    RequirePartialPath(partial_path);
    if (expected_schema.empty() || expected_schema.size() > 128U) {
        throw std::invalid_argument("expected journal schema is invalid");
    }
    const auto original = std::filesystem::file_size(partial_path);
    std::ifstream input(partial_path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open partial journal for recovery");

    std::uint64_t retained = 0;
    std::uint64_t sequence = 0;
    std::vector<char> line_buffer(kMaximumJournalRecordBytes + 2U, '\0');
    while (retained < original) {
        const auto line_start = retained;
        input.getline(line_buffer.data(),
                      static_cast<std::streamsize>(line_buffer.size()), '\n');
        if (input.bad()) {
            throw std::runtime_error("partial journal read failed");
        }
        if (input.eof()) {
            retained = line_start;
            break;
        }
        if (input.fail()) {
            throw std::runtime_error(
                "partial journal record exceeds its safety limit");
        }
        const auto extracted = input.gcount();
        if (extracted <= 0 ||
            static_cast<std::uint64_t>(extracted) > original - line_start) {
            throw std::runtime_error("partial journal offset overflow");
        }
        const auto line_size = static_cast<std::size_t>(extracted - 1);
        std::string line(line_buffer.data(), line_size);
        if (line.empty()) throw std::runtime_error("journal contains an empty record");

        auto record = json::Parse(line);
        auto& fields = record.AsObject();
        const auto crc = record.At("_crc32").AsString();
        fields.erase("_crc32");
        if (crc.size() != 8U || JournalCrc32(record) != crc) {
            throw std::runtime_error("journal CRC mismatch during recovery");
        }
        if (record.At("schema").AsString() != expected_schema) {
            throw std::runtime_error("journal schema mismatch during recovery");
        }
        const auto stored_sequence = record.At("sequence").AsInt();
        if (stored_sequence < 0 ||
            static_cast<std::uint64_t>(stored_sequence) != sequence) {
            throw std::runtime_error("journal sequence mismatch during recovery");
        }
        ++sequence;
        retained = line_start + static_cast<std::uint64_t>(extracted);
    }
    input.close();
    DurableResize(partial_path, original, retained);
    return Result(original, retained, sequence);
}

TailRecoveryResult RecoverPcapPartial(const std::filesystem::path& partial_path) {
    RequirePartialPath(partial_path);
    const auto original = std::filesystem::file_size(partial_path);
    std::ifstream input(partial_path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open partial PCAP for recovery");

    capture::PcapReader reader(input);  // A partial global header is unrecoverable.
    std::uint64_t records = 0;
    std::uint64_t retained = 24U;
    while (retained < original) {
        const auto record_start = retained;
        try {
            const auto record = reader.Next();
            if (!record.has_value()) break;
            const auto position = input.tellg();
            if (position < 0) throw std::runtime_error("PCAP recovery position failed");
            retained = static_cast<std::uint64_t>(position);
            ++records;
        } catch (const std::runtime_error& error) {
            if (!StartsWith(error.what(), "truncated PCAP")) throw;
            retained = record_start;
            break;
        }
    }
    input.close();
    DurableResize(partial_path, original, retained);
    return Result(original, retained, records);
}

TailRecoveryResult RecoverReportStreamPartial(
    const std::filesystem::path& partial_path) {
    RequirePartialPath(partial_path);
    const auto original = std::filesystem::file_size(partial_path);
    std::ifstream input(partial_path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open report stream for recovery");

    const auto magic = ReadExact(input, kReportMagic.size(), "report stream magic");
    if (std::memcmp(magic.data(), kReportMagic.data(), kReportMagic.size()) != 0) {
        throw std::runtime_error("bad report stream magic during recovery");
    }
    const auto fixed = ReadExact(input, 24U, "report stream fixed header");
    if (binary::ReadU16(fixed, 0U) != kReportVersion || fixed[7] != std::byte{0}) {
        throw std::runtime_error("unsupported report stream header during recovery");
    }
    const auto evidence_size = binary::ReadU32(fixed, 8U);
    const auto spec_size = binary::ReadU32(fixed, 12U);
    const auto qpc_frequency = binary::ReadU64(fixed, 16U);
    if (evidence_size == 0U || evidence_size > kMaxVariableHeader ||
        spec_size == 0U || spec_size > kMaxVariableHeader || qpc_frequency == 0U) {
        throw std::runtime_error("unsafe report stream header during recovery");
    }
    const std::uint64_t header_size = 8U + 24U + 64U + evidence_size + spec_size;
    if (header_size > original ||
        header_size > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        throw std::runtime_error("truncated report stream variable header");
    }
    input.seekg(static_cast<std::streamoff>(header_size), std::ios::beg);
    if (!input) throw std::runtime_error("report stream recovery seek failed");

    std::uint64_t retained = header_size;
    std::uint64_t records = 0;
    while (retained < original) {
        constexpr std::uint64_t block_header_size = 16U;
        if (original - retained < block_header_size) break;
        const auto header = ReadExact(input, static_cast<std::size_t>(block_header_size),
                                      "report block header");
        if (std::memcmp(header.data(), kBlockMagic.data(), kBlockMagic.size()) != 0) {
            throw std::runtime_error("invalid report block magic during recovery");
        }
        const auto payload_size = binary::ReadU32(header, 4U);
        const auto block_count = binary::ReadU32(header, 8U);
        const auto expected_crc = binary::ReadU32(header, 12U);
        if (payload_size == 0U || payload_size > kMaxBlock ||
            block_count == 0U || block_count > 65'536U) {
            throw std::runtime_error("unsafe report block header during recovery");
        }
        if (original - retained - block_header_size < payload_size) break;
        const auto payload = ReadExact(input, payload_size, "report block payload");
        if (Crc32(payload) != expected_crc) {
            throw std::runtime_error("report block CRC mismatch during recovery");
        }
        if (records > std::numeric_limits<std::uint64_t>::max() - block_count) {
            throw std::runtime_error("report count overflow during recovery");
        }
        records += block_count;
        retained += block_header_size + payload_size;
    }
    input.close();
    DurableResize(partial_path, original, retained);
    return Result(original, retained, records);
}

}  // namespace abdc::session
