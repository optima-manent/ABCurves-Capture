#include "session/SessionArchive.h"

#include "base/Binary.h"
#include "base/Crc32.h"
#include "base/Sha256.h"

#include <zlib.h>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <limits>
#include <set>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace abdc::session {
namespace {

constexpr std::uint16_t kZipVersion = 20U;
constexpr std::uint16_t kUtf8Flag = 0x0800U;
constexpr std::uint16_t kStoredMethod = 0U;
constexpr std::uint16_t kDeflatedMethod = 8U;
constexpr std::uint16_t kDosTime = 0U;
constexpr std::uint16_t kDosDate = 33U;  // 1980-01-01
constexpr std::uint32_t kMaximumMembers = 10'000U;
constexpr std::uint64_t kMaximumArchiveBytes = UINT32_MAX;
constexpr std::size_t kMaximumMemberNameBytes = 4096U;

struct ArchiveMember {
    std::filesystem::path source;
    std::string name;
    std::uint32_t crc32 = 0;
    std::uint32_t size = 0;
    std::uint32_t compressed_size = 0;
    std::uint16_t method = kDeflatedMethod;
    std::uint32_t local_offset = 0;
};

struct CentralMember {
    std::string name;
    std::uint32_t crc32 = 0;
    std::uint32_t size = 0;
    std::uint32_t compressed_size = 0;
    std::uint16_t method = kStoredMethod;
    std::uint32_t local_offset = 0;
};

class DeflateFailure final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class UniqueHandle final {
public:
    explicit UniqueHandle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~UniqueHandle() { Reset(); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    [[nodiscard]] HANDLE Get() const noexcept { return value_; }
    [[nodiscard]] bool Valid() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }
    HANDLE Release() noexcept {
        const auto result = value_;
        value_ = INVALID_HANDLE_VALUE;
        return result;
    }
    void Reset(HANDLE value = INVALID_HANDLE_VALUE) noexcept {
        if (Valid()) CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_ = INVALID_HANDLE_VALUE;
};

std::runtime_error Win32Failure(const char* operation, const DWORD error) {
    return std::runtime_error(std::string(operation) +
                              " failed with Win32 error " +
                              std::to_string(error));
}

std::wstring RandomHexToken() {
    std::array<unsigned char, 16> bytes{};
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("archive temporary-name randomness failed");
    }
    static constexpr wchar_t kHex[] = L"0123456789abcdef";
    std::wstring result;
    result.reserve(bytes.size() * 2U);
    for (const auto value : bytes) {
        result.push_back(kHex[value >> 4U]);
        result.push_back(kHex[value & 0x0fU]);
    }
    return result;
}

std::string Utf8Generic(const std::filesystem::path& path) {
    const auto value = path.generic_u8string();
    return {reinterpret_cast<const char*>(value.data()), value.size()};
}

void RequireSafeMemberName(const std::string_view name) {
    if (name.empty() || name.size() > kMaximumMemberNameBytes ||
        name.front() == '/' || name.back() == '/' ||
        name.find('\\') != std::string_view::npos ||
        name.find(':') != std::string_view::npos ||
        name.find('\0') != std::string_view::npos ||
        name.find("//") != std::string_view::npos) {
        throw std::runtime_error("unsafe ZIP member name");
    }
    std::size_t begin = 0U;
    while (begin < name.size()) {
        const auto end = name.find('/', begin);
        const auto part = name.substr(begin, end == std::string_view::npos
                                                ? name.size() - begin
                                                : end - begin);
        if (part.empty() || part == "." || part == "..") {
            throw std::runtime_error("unsafe ZIP member path component");
        }
        begin = end == std::string_view::npos ? name.size() : end + 1U;
    }
}

std::vector<std::byte> ReadExact(std::istream& input,
                                 const std::size_t size,
                                 const char* context) {
    std::vector<std::byte> result(size);
    input.read(reinterpret_cast<char*>(result.data()),
               static_cast<std::streamsize>(size));
    if (input.gcount() != static_cast<std::streamsize>(size)) {
        throw std::runtime_error(std::string("truncated ZIP ") + context);
    }
    return result;
}

void WriteAll(const HANDLE output, const void* data, const std::size_t size) {
    std::size_t offset = 0U;
    while (offset < size) {
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(
            size - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0U;
        if (!WriteFile(output, static_cast<const std::byte*>(data) + offset,
                       chunk, &written, nullptr) || written != chunk) {
            throw Win32Failure("archive write", GetLastError());
        }
        offset += written;
    }
}

void WriteAll(const HANDLE output, const std::vector<std::byte>& bytes) {
    WriteAll(output, bytes.data(), bytes.size());
}

void SeekAbsolute(const HANDLE file, const std::uint64_t offset) {
    if (offset > static_cast<std::uint64_t>(
                     std::numeric_limits<LONGLONG>::max())) {
        throw std::runtime_error("archive seek offset overflow");
    }
    LARGE_INTEGER distance{};
    distance.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, distance, nullptr, FILE_BEGIN)) {
        throw Win32Failure("archive seek", GetLastError());
    }
}

void TruncateAt(const HANDLE file, const std::uint64_t offset) {
    SeekAbsolute(file, offset);
    if (!SetEndOfFile(file)) {
        throw Win32Failure("archive truncate", GetLastError());
    }
}

std::pair<std::uint32_t, std::uint32_t> CrcAndSize(
    const std::filesystem::path& path) {
    const auto size = std::filesystem::file_size(path);
    if (size > UINT32_MAX) throw std::runtime_error("ZIP member requires ZIP64");
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read session artifact for ZIP");
    std::array<char, 64U * 1024U> buffer{};
    std::uint32_t crc = 0U;
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            crc = Crc32({reinterpret_cast<const std::byte*>(buffer.data()),
                         static_cast<std::size_t>(count)}, crc);
        }
    }
    if (!input.eof()) throw std::runtime_error("session artifact read failed");
    return {crc, static_cast<std::uint32_t>(size)};
}

void CopyFileToHandle(const std::filesystem::path& path, const HANDLE output) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot reopen session artifact for ZIP");
    std::array<char, 64U * 1024U> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            WriteAll(output, buffer.data(), static_cast<std::size_t>(count));
        }
    }
    if (!input.eof()) throw std::runtime_error("session artifact copy failed");
}

std::vector<std::byte> BuildLocalHeader(const ArchiveMember& member) {
    std::vector<std::byte> header;
    binary::AppendU32(header, 0x04034b50U);
    binary::AppendU16(header, kZipVersion);
    binary::AppendU16(header, kUtf8Flag);
    binary::AppendU16(header, member.method);
    binary::AppendU16(header, kDosTime);
    binary::AppendU16(header, kDosDate);
    binary::AppendU32(header, member.crc32);
    binary::AppendU32(header, member.compressed_size);
    binary::AppendU32(header, member.size);
    binary::AppendU16(header, static_cast<std::uint16_t>(member.name.size()));
    binary::AppendU16(header, 0U);
    return header;
}

std::uint32_t DeflateFileToHandle(const std::filesystem::path& path,
                                  const HANDLE output) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot reopen session artifact for ZIP");

    z_stream stream{};
    const auto initialized = deflateInit2(
        &stream, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
        Z_DEFAULT_STRATEGY);
    if (initialized != Z_OK) {
        throw DeflateFailure("ZIP Deflate initialization failed");
    }

    std::uint64_t compressed_size = 0U;
    std::array<unsigned char, 64U * 1024U> input_buffer{};
    std::array<unsigned char, 64U * 1024U> output_buffer{};
    try {
        for (;;) {
            input.read(reinterpret_cast<char*>(input_buffer.data()),
                       static_cast<std::streamsize>(input_buffer.size()));
            const auto count = input.gcount();
            if (count < 0) {
                throw std::runtime_error("session artifact read failed during ZIP Deflate");
            }
            if (!input && !input.eof()) {
                throw std::runtime_error("session artifact read failed during ZIP Deflate");
            }

            stream.next_in = input_buffer.data();
            stream.avail_in = static_cast<uInt>(count);
            const auto flush = input.eof() ? Z_FINISH : Z_NO_FLUSH;
            int status = Z_OK;
            do {
                stream.next_out = output_buffer.data();
                stream.avail_out = static_cast<uInt>(output_buffer.size());
                status = deflate(&stream, flush);
                if (status != Z_OK && status != Z_STREAM_END) {
                    throw DeflateFailure("ZIP Deflate stream failed");
                }
                const auto produced = output_buffer.size() - stream.avail_out;
                if (compressed_size > UINT32_MAX - produced) {
                    throw DeflateFailure("deflated ZIP member requires ZIP64");
                }
                if (produced > 0U) {
                    WriteAll(output, output_buffer.data(), produced);
                    compressed_size += produced;
                }
            } while (stream.avail_out == 0U);

            if (stream.avail_in != 0U) {
                throw DeflateFailure("ZIP Deflate did not consume its input");
            }
            if (flush == Z_FINISH) {
                if (status != Z_STREAM_END) {
                    throw DeflateFailure("ZIP Deflate stream did not finish");
                }
                break;
            }
        }
    } catch (...) {
        (void)deflateEnd(&stream);
        throw;
    }
    if (deflateEnd(&stream) != Z_OK) {
        throw DeflateFailure("ZIP Deflate finalization failed");
    }
    return static_cast<std::uint32_t>(compressed_size);
}

void ExtractStoredMember(std::istream& input,
                         std::ofstream& extracted,
                         const CentralMember& member) {
    std::array<char, 64U * 1024U> buffer{};
    std::uint32_t remaining = member.size;
    std::uint32_t crc = 0U;
    while (remaining > 0U) {
        const auto chunk = std::min<std::uint32_t>(
            remaining, static_cast<std::uint32_t>(buffer.size()));
        input.read(buffer.data(), chunk);
        if (input.gcount() != chunk) {
            throw std::runtime_error("truncated stored ZIP member");
        }
        extracted.write(buffer.data(), chunk);
        if (!extracted) throw std::runtime_error("ZIP extraction write failed");
        crc = Crc32({reinterpret_cast<const std::byte*>(buffer.data()), chunk}, crc);
        remaining -= chunk;
    }
    if (crc != member.crc32) throw std::runtime_error("ZIP member CRC mismatch");
}

void ExtractDeflatedMember(std::istream& input,
                           std::ofstream& extracted,
                           const CentralMember& member) {
    z_stream stream{};
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
        throw std::runtime_error("ZIP Inflate initialization failed");
    }

    std::array<unsigned char, 64U * 1024U> input_buffer{};
    std::array<unsigned char, 64U * 1024U> output_buffer{};
    std::uint32_t compressed_remaining = member.compressed_size;
    std::uint64_t produced_total = 0U;
    std::uint32_t crc = 0U;
    try {
        for (;;) {
            if (stream.avail_in == 0U && compressed_remaining > 0U) {
                const auto chunk = std::min<std::uint32_t>(
                    compressed_remaining,
                    static_cast<std::uint32_t>(input_buffer.size()));
                input.read(reinterpret_cast<char*>(input_buffer.data()), chunk);
                if (input.gcount() != chunk) {
                    throw std::runtime_error("truncated deflated ZIP member");
                }
                stream.next_in = input_buffer.data();
                stream.avail_in = chunk;
                compressed_remaining -= chunk;
            }

            stream.next_out = output_buffer.data();
            stream.avail_out = static_cast<uInt>(output_buffer.size());
            const auto status = inflate(&stream, Z_NO_FLUSH);
            const auto produced = output_buffer.size() - stream.avail_out;
            if (produced_total > member.size ||
                produced > static_cast<std::uint64_t>(member.size) - produced_total) {
                throw std::runtime_error("deflated ZIP member exceeds its declared size");
            }
            if (produced > 0U) {
                extracted.write(reinterpret_cast<const char*>(output_buffer.data()),
                                static_cast<std::streamsize>(produced));
                if (!extracted) throw std::runtime_error("ZIP extraction write failed");
                crc = Crc32(
                    {reinterpret_cast<const std::byte*>(output_buffer.data()), produced},
                    crc);
                produced_total += produced;
            }

            if (status == Z_STREAM_END) {
                if (compressed_remaining != 0U || stream.avail_in != 0U) {
                    throw std::runtime_error("deflated ZIP member has trailing data");
                }
                break;
            }
            if (status != Z_OK) {
                throw std::runtime_error("invalid deflated ZIP member");
            }
            if (compressed_remaining == 0U && stream.avail_in == 0U &&
                produced == 0U) {
                throw std::runtime_error("truncated deflated ZIP stream");
            }
        }
    } catch (...) {
        (void)inflateEnd(&stream);
        throw;
    }
    if (inflateEnd(&stream) != Z_OK) {
        throw std::runtime_error("ZIP Inflate finalization failed");
    }
    if (produced_total != member.size) {
        throw std::runtime_error("deflated ZIP member size mismatch");
    }
    if (crc != member.crc32) throw std::runtime_error("ZIP member CRC mismatch");
}

std::vector<ArchiveMember> InventoryMembers(
    const std::filesystem::path& session_directory) {
    std::vector<ArchiveMember> members;
    const auto root_name = Utf8Generic(session_directory.filename());
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(session_directory)) {
        const auto status = entry.symlink_status();
        if (std::filesystem::is_symlink(status) ||
            (status.type() != std::filesystem::file_type::regular &&
             status.type() != std::filesystem::file_type::directory)) {
            throw std::runtime_error("session contains a non-regular ZIP artifact");
        }
        if (!entry.is_regular_file()) continue;
        const auto relative =
            std::filesystem::relative(entry.path(), session_directory);
        ArchiveMember member;
        member.source = entry.path();
        member.name = root_name + "/" + Utf8Generic(relative);
        RequireSafeMemberName(member.name);
        const auto [crc, size] = CrcAndSize(member.source);
        member.crc32 = crc;
        member.size = size;
        members.push_back(std::move(member));
    }
    std::sort(members.begin(), members.end(), [](const auto& left, const auto& right) {
        return left.name < right.name;
    });
    if (members.empty() || members.size() > kMaximumMembers) {
        throw std::runtime_error("session ZIP member count is outside limits");
    }
    return members;
}

std::filesystem::path CreateArchiveTemporary(const std::filesystem::path& output,
                                             UniqueHandle& handle) {
    for (int attempt = 0; attempt < 32; ++attempt) {
        const auto temporary = output.parent_path() /
            (output.filename().wstring() + L"." + RandomHexToken() + L".partial");
        handle.Reset(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0U, nullptr,
                                 CREATE_NEW,
                                 FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH,
                                 nullptr));
        if (handle.Valid()) return temporary;
        const auto error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
            throw Win32Failure("archive temporary create", error);
        }
    }
    throw std::runtime_error("archive temporary-name collision limit exceeded");
}

std::filesystem::path CreateExtractionRoot() {
    const auto parent = std::filesystem::temp_directory_path();
    for (int attempt = 0; attempt < 32; ++attempt) {
        const auto path = parent / (L"ABCT_archive_" + RandomHexToken());
        if (std::filesystem::create_directory(path)) return path;
    }
    throw std::runtime_error("archive extraction-directory collision limit exceeded");
}

std::string TopLevelDirectory(const std::vector<CentralMember>& members) {
    if (members.empty()) throw std::runtime_error("ZIP has no members");
    std::string top;
    for (const auto& member : members) {
        const auto slash = member.name.find('/');
        if (slash == std::string::npos || slash == 0U) {
            throw std::runtime_error("ZIP member lacks its session directory");
        }
        const auto candidate = member.name.substr(0U, slash);
        if (top.empty()) top = candidate;
        if (candidate != top) {
            throw std::runtime_error("ZIP contains more than one top-level directory");
        }
    }
    constexpr std::string_view prefix = "session_";
    if (!std::string_view(top).starts_with(prefix) ||
        !IsSafeSessionId(std::string_view(top).substr(prefix.size()))) {
        throw std::runtime_error("ZIP top-level session identity is invalid");
    }
    return top;
}

SessionArchiveValidation ValidateArchiveImpl(const std::filesystem::path& archive) {
    SessionArchiveValidation result;
    std::filesystem::path extraction_root;
    try {
        if (!archive.is_absolute() ||
            std::filesystem::symlink_status(archive).type() !=
                std::filesystem::file_type::regular ||
            std::filesystem::is_symlink(std::filesystem::symlink_status(archive))) {
            throw std::runtime_error("session ZIP is missing or not a regular file");
        }
        const auto archive_size = std::filesystem::file_size(archive);
        if (archive_size < 22U || archive_size > kMaximumArchiveBytes) {
            throw std::runtime_error("session ZIP size is outside limits");
        }
        std::ifstream input(archive, std::ios::binary);
        if (!input) throw std::runtime_error("cannot open session ZIP");

        const auto tail_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(archive_size, 65'557U));
        input.seekg(static_cast<std::streamoff>(archive_size - tail_size),
                    std::ios::beg);
        auto tail = ReadExact(input, tail_size, "tail");
        std::optional<std::size_t> end_offset;
        for (std::size_t index = tail.size() - 22U;; --index) {
            if (binary::ReadU32(tail, index) == 0x06054b50U) {
                end_offset = index;
                break;
            }
            if (index == 0U) break;
        }
        if (!end_offset.has_value()) throw std::runtime_error("ZIP end record missing");
        const auto end = *end_offset;
        if (end + 22U != tail.size()) {
            throw std::runtime_error("ZIP has trailing data or an end comment");
        }
        const auto disk = binary::ReadU16(tail, end + 4U);
        const auto central_disk = binary::ReadU16(tail, end + 6U);
        const auto disk_count = binary::ReadU16(tail, end + 8U);
        const auto total_count = binary::ReadU16(tail, end + 10U);
        const auto central_size = binary::ReadU32(tail, end + 12U);
        const auto central_offset = binary::ReadU32(tail, end + 16U);
        const auto comment_size = binary::ReadU16(tail, end + 20U);
        const auto global_end = archive_size - tail_size + end;
        if (disk != 0U || central_disk != 0U || disk_count != total_count ||
            comment_size != 0U || total_count == 0U ||
            total_count > kMaximumMembers ||
            static_cast<std::uint64_t>(central_offset) + central_size != global_end) {
            throw std::runtime_error("ZIP central-directory extent is invalid");
        }

        input.clear();
        input.seekg(central_offset, std::ios::beg);
        std::vector<CentralMember> members;
        std::set<std::string> names;
        std::uint64_t total_uncompressed_size = 0U;
        for (std::uint16_t index = 0U; index < total_count; ++index) {
            const auto header = ReadExact(input, 46U, "central header");
            if (binary::ReadU32(header, 0U) != 0x02014b50U ||
                binary::ReadU16(header, 4U) != kZipVersion ||
                binary::ReadU16(header, 6U) != kZipVersion ||
                binary::ReadU16(header, 8U) != kUtf8Flag ||
                binary::ReadU16(header, 12U) != kDosTime ||
                binary::ReadU16(header, 14U) != kDosDate ||
                binary::ReadU16(header, 34U) != 0U ||
                binary::ReadU16(header, 36U) != 0U ||
                binary::ReadU32(header, 38U) != 0U) {
                throw std::runtime_error("ZIP central member is not canonical");
            }
            const auto name_size = binary::ReadU16(header, 28U);
            const auto extra_size = binary::ReadU16(header, 30U);
            const auto member_comment_size = binary::ReadU16(header, 32U);
            if (name_size == 0U || name_size > kMaximumMemberNameBytes ||
                extra_size != 0U || member_comment_size != 0U) {
                throw std::runtime_error("ZIP central member lengths are invalid");
            }
            const auto name_bytes = ReadExact(input, name_size, "member name");
            CentralMember member;
            member.name.assign(reinterpret_cast<const char*>(name_bytes.data()),
                               name_bytes.size());
            RequireSafeMemberName(member.name);
            if (!names.insert(member.name).second ||
                (!members.empty() && members.back().name >= member.name)) {
                throw std::runtime_error("ZIP member names are duplicated or unsorted");
            }
            member.crc32 = binary::ReadU32(header, 16U);
            member.compressed_size = binary::ReadU32(header, 20U);
            member.size = binary::ReadU32(header, 24U);
            member.method = binary::ReadU16(header, 10U);
            if ((member.method != kStoredMethod &&
                 member.method != kDeflatedMethod) ||
                (member.method == kStoredMethod &&
                 member.compressed_size != member.size)) {
                throw std::runtime_error("ZIP central member method is not canonical");
            }
            if (total_uncompressed_size > kMaximumArchiveBytes - member.size) {
                throw std::runtime_error("ZIP expanded size is outside limits");
            }
            total_uncompressed_size += member.size;
            member.local_offset = binary::ReadU32(header, 42U);
            members.push_back(std::move(member));
        }
        const auto central_end = input.tellg();
        if (central_end < 0 ||
            static_cast<std::uint64_t>(central_end) !=
                static_cast<std::uint64_t>(central_offset) + central_size) {
            throw std::runtime_error("ZIP central-directory size mismatch");
        }
        const auto top_level = TopLevelDirectory(members);

        extraction_root = CreateExtractionRoot();
        std::uint64_t expected_local_offset = 0U;
        for (const auto& member : members) {
            if (member.local_offset != expected_local_offset ||
                member.local_offset >= central_offset) {
                throw std::runtime_error("ZIP local members are not contiguous");
            }
            input.clear();
            input.seekg(member.local_offset, std::ios::beg);
            const auto header = ReadExact(input, 30U, "local header");
            if (binary::ReadU32(header, 0U) != 0x04034b50U ||
                binary::ReadU16(header, 4U) != kZipVersion ||
                binary::ReadU16(header, 6U) != kUtf8Flag ||
                binary::ReadU16(header, 8U) != member.method ||
                binary::ReadU16(header, 10U) != kDosTime ||
                binary::ReadU16(header, 12U) != kDosDate ||
                binary::ReadU32(header, 14U) != member.crc32 ||
                binary::ReadU32(header, 18U) != member.compressed_size ||
                binary::ReadU32(header, 22U) != member.size) {
                throw std::runtime_error("ZIP local and central members differ");
            }
            const auto name_size = binary::ReadU16(header, 26U);
            const auto extra_size = binary::ReadU16(header, 28U);
            if (name_size == 0U || name_size > kMaximumMemberNameBytes ||
                extra_size != 0U) {
                throw std::runtime_error("ZIP local member lengths are invalid");
            }
            const auto name_bytes = ReadExact(input, name_size, "local name");
            const std::string local_name(
                reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size());
            if (local_name != member.name) {
                throw std::runtime_error("ZIP local member name mismatch");
            }
            expected_local_offset = static_cast<std::uint64_t>(member.local_offset) +
                                    30U + name_size + member.compressed_size;
            if (expected_local_offset > central_offset) {
                throw std::runtime_error("ZIP member overlaps its central directory");
            }

            const std::u8string utf8_name(
                reinterpret_cast<const char8_t*>(member.name.data()),
                member.name.size());
            const auto output = extraction_root / std::filesystem::path(utf8_name);
            std::filesystem::create_directories(output.parent_path());
            std::ofstream extracted(output, std::ios::binary | std::ios::trunc);
            if (!extracted) throw std::runtime_error("cannot extract ZIP member");
            if (member.method == kStoredMethod) {
                ExtractStoredMember(input, extracted, member);
            } else {
                ExtractDeflatedMember(input, extracted, member);
            }
            extracted.close();
            if (!extracted) throw std::runtime_error("ZIP extraction close failed");
        }
        if (expected_local_offset != central_offset) {
            throw std::runtime_error("ZIP has a gap before its central directory");
        }

        result.session = ValidateSealedSession(extraction_root / top_level);
        result.valid = true;
        std::filesystem::remove_all(extraction_root);
        return result;
    } catch (const std::exception& error) {
        std::error_code ignored;
        if (!extraction_root.empty()) std::filesystem::remove_all(extraction_root, ignored);
        result.valid = false;
        result.error = error.what();
        result.session.reset();
        return result;
    }
}

}  // namespace

std::filesystem::path SubmissionArchivePath(
    const std::filesystem::path& sealed_session_directory) {
    if (!sealed_session_directory.is_absolute() ||
        sealed_session_directory.filename().empty()) {
        throw std::invalid_argument("submission archive requires an absolute session path");
    }
    return sealed_session_directory.parent_path() /
        (sealed_session_directory.filename().wstring() + L"_SEND_THIS.zip");
}

SessionArchiveResult CreateSessionArchive(
    const std::filesystem::path& sealed_session_directory,
    const std::filesystem::path& output_archive) {
    (void)ValidateSealedSession(sealed_session_directory);
    if (!output_archive.is_absolute() || output_archive.filename().empty() ||
        output_archive.extension() != L".zip") {
        throw std::invalid_argument("submission ZIP path is invalid");
    }
    if (std::filesystem::exists(output_archive)) {
        throw std::runtime_error("refusing to overwrite a submission ZIP");
    }
    std::filesystem::create_directories(output_archive.parent_path());
    auto members = InventoryMembers(sealed_session_directory);

    UniqueHandle output;
    std::filesystem::path temporary;
    try {
        temporary = CreateArchiveTemporary(output_archive, output);
        std::uint64_t position = 0U;
        for (auto& member : members) {
            if (position > UINT32_MAX) throw std::runtime_error("ZIP requires ZIP64");
            member.local_offset = static_cast<std::uint32_t>(position);

            auto write_stored = [&] {
                TruncateAt(output.Get(), member.local_offset);
                member.method = kStoredMethod;
                member.compressed_size = member.size;
                const auto header = BuildLocalHeader(member);
                WriteAll(output.Get(), header);
                WriteAll(output.Get(), member.name.data(), member.name.size());
                CopyFileToHandle(member.source, output.Get());
                position = static_cast<std::uint64_t>(member.local_offset) +
                           header.size() + member.name.size() + member.size;
            };

            if (member.size == 0U) {
                write_stored();
            } else {
                member.method = kDeflatedMethod;
                member.compressed_size = 0U;
                auto header = BuildLocalHeader(member);
                WriteAll(output.Get(), header);
                WriteAll(output.Get(), member.name.data(), member.name.size());
                bool use_stored_fallback = false;
                try {
                    member.compressed_size =
                        DeflateFileToHandle(member.source, output.Get());
                    use_stored_fallback = member.compressed_size >= member.size;
                } catch (const DeflateFailure&) {
                    // A compression resource/codec failure must never cost the
                    // participant's validated session. The same member is
                    // safely rewound and emitted with ZIP's stored method.
                    use_stored_fallback = true;
                }

                if (use_stored_fallback) {
                    write_stored();
                } else {
                    position = static_cast<std::uint64_t>(member.local_offset) +
                               header.size() + member.name.size() +
                               member.compressed_size;
                    header = BuildLocalHeader(member);
                    SeekAbsolute(output.Get(), member.local_offset);
                    WriteAll(output.Get(), header);
                    SeekAbsolute(output.Get(), position);
                }
            }
            if (position > kMaximumArchiveBytes) throw std::runtime_error("ZIP requires ZIP64");
        }

        const auto central_offset = static_cast<std::uint32_t>(position);
        for (const auto& member : members) {
            std::vector<std::byte> header;
            binary::AppendU32(header, 0x02014b50U);
            binary::AppendU16(header, kZipVersion);
            binary::AppendU16(header, kZipVersion);
            binary::AppendU16(header, kUtf8Flag);
            binary::AppendU16(header, member.method);
            binary::AppendU16(header, kDosTime);
            binary::AppendU16(header, kDosDate);
            binary::AppendU32(header, member.crc32);
            binary::AppendU32(header, member.compressed_size);
            binary::AppendU32(header, member.size);
            binary::AppendU16(header, static_cast<std::uint16_t>(member.name.size()));
            binary::AppendU16(header, 0U);  // extra
            binary::AppendU16(header, 0U);  // comment
            binary::AppendU16(header, 0U);  // disk
            binary::AppendU16(header, 0U);  // internal attributes
            binary::AppendU32(header, 0U);  // external attributes
            binary::AppendU32(header, member.local_offset);
            WriteAll(output.Get(), header);
            WriteAll(output.Get(), member.name.data(), member.name.size());
            position += header.size() + member.name.size();
            if (position > kMaximumArchiveBytes) throw std::runtime_error("ZIP requires ZIP64");
        }
        const auto central_size = static_cast<std::uint32_t>(position - central_offset);
        std::vector<std::byte> end;
        binary::AppendU32(end, 0x06054b50U);
        binary::AppendU16(end, 0U);
        binary::AppendU16(end, 0U);
        binary::AppendU16(end, static_cast<std::uint16_t>(members.size()));
        binary::AppendU16(end, static_cast<std::uint16_t>(members.size()));
        binary::AppendU32(end, central_size);
        binary::AppendU32(end, central_offset);
        binary::AppendU16(end, 0U);
        WriteAll(output.Get(), end);
        if (!FlushFileBuffers(output.Get())) {
            throw Win32Failure("archive durable flush", GetLastError());
        }
        const auto raw_handle = output.Release();
        if (!CloseHandle(raw_handle)) {
            throw Win32Failure("archive temporary close", GetLastError());
        }

        const auto validation = ValidateArchiveImpl(temporary);
        if (!validation.valid) {
            throw std::runtime_error("created ZIP failed validation: " + validation.error);
        }
        if (!MoveFileExW(temporary.c_str(), output_archive.c_str(),
                         MOVEFILE_WRITE_THROUGH)) {
            throw Win32Failure("archive atomic publication", GetLastError());
        }
    } catch (...) {
        output.Reset();
        std::error_code ignored;
        if (!temporary.empty()) std::filesystem::remove(temporary, ignored);
        throw;
    }

    SessionArchiveResult result;
    result.path = output_archive;
    result.sha256 = Sha256FileHex(output_archive);
    result.size_bytes = std::filesystem::file_size(output_archive);
    result.member_count = static_cast<std::uint32_t>(members.size());
    return result;
}

SessionArchiveValidation ValidateSessionArchive(
    const std::filesystem::path& archive) {
    return ValidateArchiveImpl(archive);
}

}  // namespace abdc::session
