#include "base/Binary.h"

#include <limits>

namespace abdc::binary {

void RequireAvailable(const std::span<const std::byte> bytes, const std::size_t offset,
                      const std::size_t count, const char* context) {
    if (offset > bytes.size() || count > bytes.size() - offset) {
        throw Error(std::string("truncated ") + context);
    }
}

std::uint16_t ReadU16(const std::span<const std::byte> bytes, const std::size_t offset,
                      const bool little_endian) {
    RequireAvailable(bytes, offset, 2, "u16");
    const auto a = std::to_integer<std::uint8_t>(bytes[offset]);
    const auto b = std::to_integer<std::uint8_t>(bytes[offset + 1]);
    return little_endian ? static_cast<std::uint16_t>(a | (b << 8U))
                         : static_cast<std::uint16_t>((a << 8U) | b);
}

std::uint32_t ReadU32(const std::span<const std::byte> bytes, const std::size_t offset,
                      const bool little_endian) {
    RequireAvailable(bytes, offset, 4, "u32");
    std::uint32_t value = 0;
    if (little_endian) {
        for (unsigned i = 0; i < 4; ++i) {
            value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + i])) << (8U * i);
        }
    } else {
        for (unsigned i = 0; i < 4; ++i) {
            value = (value << 8U) | std::to_integer<std::uint8_t>(bytes[offset + i]);
        }
    }
    return value;
}

std::uint64_t ReadU64(const std::span<const std::byte> bytes, const std::size_t offset,
                      const bool little_endian) {
    RequireAvailable(bytes, offset, 8, "u64");
    std::uint64_t value = 0;
    if (little_endian) {
        for (unsigned i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[offset + i])) << (8U * i);
        }
    } else {
        for (unsigned i = 0; i < 8; ++i) {
            value = (value << 8U) | std::to_integer<std::uint8_t>(bytes[offset + i]);
        }
    }
    return value;
}

void AppendU16(std::vector<std::byte>& out, const std::uint16_t value) {
    out.push_back(static_cast<std::byte>(value & 0xffU));
    out.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
}

void AppendU32(std::vector<std::byte>& out, const std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) out.push_back(static_cast<std::byte>((value >> (8U * i)) & 0xffU));
}

void AppendU64(std::vector<std::byte>& out, const std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) out.push_back(static_cast<std::byte>((value >> (8U * i)) & 0xffU));
}

void AppendI32(std::vector<std::byte>& out, const std::int32_t value) {
    AppendU32(out, static_cast<std::uint32_t>(value));
}

void AppendVarUInt(std::vector<std::byte>& out, std::uint64_t value) {
    do {
        std::uint8_t byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0) byte |= 0x80U;
        out.push_back(static_cast<std::byte>(byte));
    } while (value != 0);
}

void AppendVarInt(std::vector<std::byte>& out, const std::int64_t value) {
    const auto encoded = (static_cast<std::uint64_t>(value) << 1U) ^
                         static_cast<std::uint64_t>(value >> 63U);
    AppendVarUInt(out, encoded);
}

std::uint64_t ReadVarUInt(const std::span<const std::byte> bytes, std::size_t& offset) {
    std::uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 7) {
        RequireAvailable(bytes, offset, 1, "varuint");
        const auto byte = std::to_integer<std::uint8_t>(bytes[offset++]);
        if (shift == 63 && (byte & 0xfeU) != 0) throw Error("varuint overflow");
        value |= static_cast<std::uint64_t>(byte & 0x7fU) << shift;
        if ((byte & 0x80U) == 0) return value;
    }
    throw Error("varuint overflow");
}

std::int64_t ReadVarInt(const std::span<const std::byte> bytes, std::size_t& offset) {
    const auto encoded = ReadVarUInt(bytes, offset);
    return static_cast<std::int64_t>((encoded >> 1U) ^ (~(encoded & 1U) + 1U));
}

}  // namespace abdc::binary

