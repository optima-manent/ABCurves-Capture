#pragma once

#include <cstddef>
#include <cstdint>
#include <istream>
#include <optional>
#include <vector>

namespace abdc::capture {

enum class TimestampResolution { Microseconds, Nanoseconds };

struct PcapHeader {
    bool little_endian = true;
    TimestampResolution resolution = TimestampResolution::Microseconds;
    std::uint16_t major = 0;
    std::uint16_t minor = 0;
    std::uint32_t snap_length = 0;
    std::uint32_t link_type = 0;
};

struct PcapRecord {
    std::uint64_t sequence = 0;
    std::uint32_t timestamp_seconds = 0;
    std::uint32_t timestamp_fraction = 0;
    TimestampResolution resolution = TimestampResolution::Microseconds;
    std::uint32_t original_length = 0;
    // QPC sampled by the consumer when this complete record became available.
    // It is an observation bound, not a replacement for the native PCAP time.
    std::int64_t observed_qpc = 0;
    std::vector<std::byte> data;

    [[nodiscard]] std::int64_t UnixNanoseconds() const;
};

class PcapReader final {
public:
    static constexpr std::uint32_t kUsbPcapLinkType = 249;
    explicit PcapReader(std::istream& input);
    [[nodiscard]] const PcapHeader& Header() const { return header_; }
    std::optional<PcapRecord> Next();

private:
    std::istream& input_;
    PcapHeader header_{};
    std::uint64_t sequence_ = 0;
};

}  // namespace abdc::capture
