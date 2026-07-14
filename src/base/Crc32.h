#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace abdc {

std::uint32_t Crc32(std::span<const std::byte> bytes, std::uint32_t seed = 0);

}  // namespace abdc

