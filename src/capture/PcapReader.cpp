#include "capture/PcapReader.h"

#include "base/Binary.h"

#include <array>
#include <limits>
#include <stdexcept>

namespace abdc::capture {
namespace {

std::vector<std::byte> ReadExact(std::istream& input, const std::size_t count, const char* context) {
    std::vector<std::byte> bytes(count);
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(count));
    if (input.gcount() != static_cast<std::streamsize>(count)) {
        throw std::runtime_error(std::string("truncated PCAP ") + context);
    }
    return bytes;
}

}  // namespace

std::int64_t PcapRecord::UnixNanoseconds() const {
    constexpr std::int64_t kBillion = 1'000'000'000LL;
    if (timestamp_seconds > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max() / kBillion)) {
        throw std::overflow_error("PCAP timestamp overflow");
    }
    const std::int64_t fraction = resolution == TimestampResolution::Nanoseconds
                                      ? timestamp_fraction
                                      : static_cast<std::int64_t>(timestamp_fraction) * 1000LL;
    if (fraction < 0 || fraction >= kBillion) throw std::runtime_error("invalid PCAP timestamp fraction");
    return static_cast<std::int64_t>(timestamp_seconds) * kBillion + fraction;
}

PcapReader::PcapReader(std::istream& input) : input_(input) {
    const auto bytes = ReadExact(input_, 24, "global header");
    const auto b0 = std::to_integer<std::uint8_t>(bytes[0]);
    const auto b1 = std::to_integer<std::uint8_t>(bytes[1]);
    const auto b2 = std::to_integer<std::uint8_t>(bytes[2]);
    const auto b3 = std::to_integer<std::uint8_t>(bytes[3]);
    if (b0 == 0xd4 && b1 == 0xc3 && b2 == 0xb2 && b3 == 0xa1) {
        header_.little_endian = true; header_.resolution = TimestampResolution::Microseconds;
    } else if (b0 == 0xa1 && b1 == 0xb2 && b2 == 0xc3 && b3 == 0xd4) {
        header_.little_endian = false; header_.resolution = TimestampResolution::Microseconds;
    } else if (b0 == 0x4d && b1 == 0x3c && b2 == 0xb2 && b3 == 0xa1) {
        header_.little_endian = true; header_.resolution = TimestampResolution::Nanoseconds;
    } else if (b0 == 0xa1 && b1 == 0xb2 && b2 == 0x3c && b3 == 0x4d) {
        header_.little_endian = false; header_.resolution = TimestampResolution::Nanoseconds;
    } else {
        throw std::runtime_error("unsupported PCAP magic");
    }
    const std::span<const std::byte> span(bytes);
    header_.major = binary::ReadU16(span, 4, header_.little_endian);
    header_.minor = binary::ReadU16(span, 6, header_.little_endian);
    header_.snap_length = binary::ReadU32(span, 16, header_.little_endian);
    header_.link_type = binary::ReadU32(span, 20, header_.little_endian);
    if (header_.major != 2 || header_.minor != 4) throw std::runtime_error("unsupported PCAP version");
    if (header_.snap_length < 27 || header_.snap_length > (16U << 20U)) {
        throw std::runtime_error("unsafe PCAP snapshot length");
    }
    if (header_.link_type != kUsbPcapLinkType) throw std::runtime_error("PCAP is not LINKTYPE_USBPCAP");
}

std::optional<PcapRecord> PcapReader::Next() {
    std::array<std::byte, 16> raw{};
    input_.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
    if (input_.gcount() == 0 && input_.eof()) return std::nullopt;
    if (input_.gcount() != static_cast<std::streamsize>(raw.size())) {
        throw std::runtime_error("truncated PCAP record header");
    }
    const std::span<const std::byte> span(raw);
    const auto seconds = binary::ReadU32(span, 0, header_.little_endian);
    const auto fraction = binary::ReadU32(span, 4, header_.little_endian);
    const auto included = binary::ReadU32(span, 8, header_.little_endian);
    const auto original = binary::ReadU32(span, 12, header_.little_endian);
    if (included > header_.snap_length || included > original) throw std::runtime_error("invalid PCAP record lengths");
    PcapRecord record;
    record.sequence = sequence_++;
    record.timestamp_seconds = seconds;
    record.timestamp_fraction = fraction;
    record.resolution = header_.resolution;
    record.original_length = original;
    record.data = ReadExact(input_, included, "record payload");
    (void)record.UnixNanoseconds();
    return record;
}

}  // namespace abdc::capture

