#include "base/Crc32.h"

#include <array>

namespace abdc {
namespace {

constexpr auto MakeTable() {
    std::array<std::uint32_t, 256> table{};
    for (std::uint32_t i = 0; i < table.size(); ++i) {
        std::uint32_t value = i;
        for (int bit = 0; bit < 8; ++bit) {
            value = (value >> 1U) ^ ((value & 1U) ? 0xedb88320U : 0U);
        }
        table[i] = value;
    }
    return table;
}

constexpr auto kTable = MakeTable();

}  // namespace

std::uint32_t Crc32(const std::span<const std::byte> bytes, const std::uint32_t seed) {
    std::uint32_t crc = ~seed;
    for (const auto value : bytes) {
        crc = kTable[(crc ^ std::to_integer<std::uint8_t>(value)) & 0xffU] ^ (crc >> 8U);
    }
    return ~crc;
}

}  // namespace abdc

