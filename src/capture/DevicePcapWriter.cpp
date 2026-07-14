#include "capture/DevicePcapWriter.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <limits>
#include <stdexcept>

namespace abdc::capture {

DevicePcapWriter::DevicePcapWriter(std::filesystem::path partial_path,
                                   PcapHeader source_header,
                                   const std::uint16_t bus,
                                   const std::uint16_t device)
    : partial_path_(std::move(partial_path)),
      header_(source_header),
      bus_(bus),
      device_(device) {
    if (header_.major != 2U || header_.minor != 4U ||
        header_.link_type != PcapReader::kUsbPcapLinkType ||
        header_.snap_length < 27U || bus_ == 0U || device_ == 0U) {
        throw std::invalid_argument("invalid device PCAP identity/header");
    }
    std::filesystem::create_directories(partial_path_.parent_path());
    output_.open(partial_path_, std::ios::binary | std::ios::trunc);
    if (!output_) throw std::runtime_error("cannot create device PCAP partial");
    WriteHeader();
}

DevicePcapWriter::~DevicePcapWriter() {
    try {
        if (output_.is_open()) output_.close();
    } catch (...) {
    }
}

void DevicePcapWriter::Write(const void* data, const std::size_t size,
                             const char* context) {
    output_.write(static_cast<const char*>(data),
                  static_cast<std::streamsize>(size));
    if (!output_) {
        throw std::runtime_error(std::string("device PCAP write failed: ") +
                                 context);
    }
}

void DevicePcapWriter::WriteU16(const std::uint16_t value) {
    std::array<unsigned char, 2> bytes{};
    if (header_.little_endian) {
        bytes = {static_cast<unsigned char>(value),
                 static_cast<unsigned char>(value >> 8U)};
    } else {
        bytes = {static_cast<unsigned char>(value >> 8U),
                 static_cast<unsigned char>(value)};
    }
    Write(bytes.data(), bytes.size(), "u16");
}

void DevicePcapWriter::WriteU32(const std::uint32_t value) {
    std::array<unsigned char, 4> bytes{};
    if (header_.little_endian) {
        bytes = {static_cast<unsigned char>(value),
                 static_cast<unsigned char>(value >> 8U),
                 static_cast<unsigned char>(value >> 16U),
                 static_cast<unsigned char>(value >> 24U)};
    } else {
        bytes = {static_cast<unsigned char>(value >> 24U),
                 static_cast<unsigned char>(value >> 16U),
                 static_cast<unsigned char>(value >> 8U),
                 static_cast<unsigned char>(value)};
    }
    Write(bytes.data(), bytes.size(), "u32");
}

void DevicePcapWriter::WriteHeader() {
    const std::array<unsigned char, 4> little_micro{0xd4, 0xc3, 0xb2, 0xa1};
    const std::array<unsigned char, 4> big_micro{0xa1, 0xb2, 0xc3, 0xd4};
    const std::array<unsigned char, 4> little_nano{0x4d, 0x3c, 0xb2, 0xa1};
    const std::array<unsigned char, 4> big_nano{0xa1, 0xb2, 0x3c, 0x4d};
    const auto& magic = header_.resolution == TimestampResolution::Nanoseconds
        ? (header_.little_endian ? little_nano : big_nano)
        : (header_.little_endian ? little_micro : big_micro);
    Write(magic.data(), magic.size(), "magic");
    WriteU16(header_.major);
    WriteU16(header_.minor);
    WriteU32(0U);
    WriteU32(0U);
    WriteU32(header_.snap_length);
    WriteU32(header_.link_type);
}

void DevicePcapWriter::Append(const PcapRecord& record,
                              const UsbPcapPacket& packet) {
    if (finalized_) throw std::logic_error("device PCAP is finalized");
    if (packet.bus != bus_ || packet.device != device_) {
        throw std::invalid_argument(
            "record does not belong to certified USB device");
    }
    if (record.resolution != header_.resolution ||
        record.data.size() > header_.snap_length ||
        record.data.size() > record.original_length ||
        record.data.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("device PCAP record violates source header");
    }
    (void)record.UnixNanoseconds();
    WriteU32(record.timestamp_seconds);
    WriteU32(record.timestamp_fraction);
    WriteU32(static_cast<std::uint32_t>(record.data.size()));
    WriteU32(record.original_length);
    Write(record.data.data(), record.data.size(), "record payload");
    ++record_count_;
    payload_bytes_ += record.data.size();
}

void DevicePcapWriter::Checkpoint() {
    output_.flush();
    if (!output_) throw std::runtime_error("device PCAP stream flush failed");
    const HANDLE file = CreateFileW(partial_path_.c_str(), GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot open device PCAP for durable flush");
    }
    const BOOL flushed = FlushFileBuffers(file);
    const BOOL closed = CloseHandle(file);
    if (!flushed || !closed) {
        throw std::runtime_error("durable device PCAP flush failed");
    }
}

void DevicePcapWriter::Finalize(const std::filesystem::path& final_path) {
    if (finalized_) throw std::logic_error("device PCAP already finalized");
    Checkpoint();
    output_.close();
    if (std::filesystem::exists(final_path)) {
        throw std::runtime_error("refusing to overwrite device PCAP");
    }
    if (!MoveFileExW(partial_path_.c_str(), final_path.c_str(),
                     MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("atomic device PCAP rename failed");
    }
    finalized_ = true;
}

}  // namespace abdc::capture
