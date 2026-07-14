#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace abdc::capture {

enum class UsbTransfer : std::uint8_t {
    Isochronous = 0,
    Interrupt = 1,
    Control = 2,
    Bulk = 3,
    IrpInfo = 254,
    Unknown = 255,
};

struct UsbPcapPacket {
    std::uint16_t header_length = 0;
    std::uint64_t irp_id = 0;
    std::uint32_t status = 0;
    std::uint16_t function = 0;
    std::uint8_t info = 0;
    std::uint16_t bus = 0;
    std::uint16_t device = 0;
    std::uint8_t endpoint = 0;
    UsbTransfer transfer = UsbTransfer::Unknown;
    std::uint32_t declared_data_length = 0;
    bool payload_truncated = false;
    std::span<const std::byte> payload;

    [[nodiscard]] bool IsCompletion() const { return (info & 0x01U) != 0; }
    [[nodiscard]] bool IsInEndpoint() const { return (endpoint & 0x80U) != 0; }
    [[nodiscard]] bool IsSuccessfulInterruptInCompletion() const {
        return transfer == UsbTransfer::Interrupt && IsCompletion() && IsInEndpoint() &&
               status == 0 && !payload.empty();
    }

    static UsbPcapPacket Parse(std::span<const std::byte> bytes);
    static UsbPcapPacket Parse(std::span<const std::byte> bytes,
                               std::uint32_t original_length);
};

}  // namespace abdc::capture
