#include "capture/UsbPcapPacket.h"

#include "base/Binary.h"

#include <optional>
#include <stdexcept>

namespace abdc::capture {
namespace {

UsbPcapPacket ParsePacket(
    const std::span<const std::byte> bytes,
    const std::optional<std::uint32_t> original_length) {
    constexpr std::size_t kBaseHeaderLength = 27;
    binary::RequireAvailable(bytes, 0, kBaseHeaderLength, "USBPcap base header");
    UsbPcapPacket packet;
    packet.header_length = binary::ReadU16(bytes, 0);
    packet.irp_id = binary::ReadU64(bytes, 2);
    packet.status = binary::ReadU32(bytes, 10);
    packet.function = binary::ReadU16(bytes, 14);
    packet.info = std::to_integer<std::uint8_t>(bytes[16]);
    packet.bus = binary::ReadU16(bytes, 17);
    packet.device = binary::ReadU16(bytes, 19);
    packet.endpoint = std::to_integer<std::uint8_t>(bytes[21]);
    packet.transfer = static_cast<UsbTransfer>(std::to_integer<std::uint8_t>(bytes[22]));
    packet.declared_data_length = binary::ReadU32(bytes, 23);
    if ((packet.info & 0xfeU) != 0) throw std::runtime_error("USBPcap info reserved bits are nonzero");
    if (packet.header_length < kBaseHeaderLength || packet.header_length > bytes.size()) {
        throw std::runtime_error("invalid USBPcap header length");
    }
    const auto captured_payload_length = bytes.size() - packet.header_length;
    const auto expected_original_length =
        static_cast<std::uint64_t>(packet.header_length) +
        packet.declared_data_length;
    if (packet.declared_data_length > captured_payload_length) {
        // USBPcap leaves dataLength at the full transfer size when libpcap's
        // snapshot length clips a record. Only the independent PCAP orig_len
        // field is strong enough to distinguish that valid case from a
        // malformed included record.
        if (!original_length ||
            static_cast<std::uint64_t>(*original_length) !=
                expected_original_length ||
            *original_length <= bytes.size()) {
            throw std::runtime_error("truncated USBPcap transfer payload");
        }
        packet.payload_truncated = true;
        packet.payload = bytes.subspan(packet.header_length);
        return packet;
    }
    if (packet.declared_data_length != captured_payload_length) {
        throw std::runtime_error("USBPcap payload has unexplained trailing bytes");
    }
    if (original_length && *original_length != bytes.size()) {
        throw std::runtime_error("USBPcap PCAP original length is inconsistent");
    }
    packet.payload = bytes.subspan(packet.header_length, packet.declared_data_length);
    return packet;
}

}  // namespace

UsbPcapPacket UsbPcapPacket::Parse(const std::span<const std::byte> bytes) {
    return ParsePacket(bytes, std::nullopt);
}

UsbPcapPacket UsbPcapPacket::Parse(const std::span<const std::byte> bytes,
                                   const std::uint32_t original_length) {
    return ParsePacket(bytes, original_length);
}

}  // namespace abdc::capture
