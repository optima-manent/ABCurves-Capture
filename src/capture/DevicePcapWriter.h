#pragma once

#include "capture/PcapReader.h"
#include "capture/UsbPcapPacket.h"

#include <cstdint>
#include <filesystem>
#include <fstream>

namespace abdc::capture {

// Writes a canonical PCAP containing every original USBPcap record for one
// certified physical USB device address. This is the authoritative artifact;
// endpoint decoding is optional and always happens after the raw append.
class DevicePcapWriter final {
public:
    DevicePcapWriter(std::filesystem::path partial_path,
                     PcapHeader source_header,
                     std::uint16_t bus,
                     std::uint16_t device);
    ~DevicePcapWriter();

    DevicePcapWriter(const DevicePcapWriter&) = delete;
    DevicePcapWriter& operator=(const DevicePcapWriter&) = delete;

    void Append(const PcapRecord& record, const UsbPcapPacket& packet);
    void Checkpoint();
    void Finalize(const std::filesystem::path& final_path);

    [[nodiscard]] std::uint64_t RecordCount() const noexcept {
        return record_count_;
    }
    [[nodiscard]] std::uint64_t PayloadBytes() const noexcept {
        return payload_bytes_;
    }

private:
    void WriteHeader();
    void WriteU16(std::uint16_t value);
    void WriteU32(std::uint32_t value);
    void Write(const void* data, std::size_t size, const char* context);

    std::filesystem::path partial_path_;
    PcapHeader header_;
    std::uint16_t bus_ = 0;
    std::uint16_t device_ = 0;
    std::ofstream output_;
    std::uint64_t record_count_ = 0;
    std::uint64_t payload_bytes_ = 0;
    bool finalized_ = false;
};

}  // namespace abdc::capture
