#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace abdc::binary {

class Error final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::uint16_t ReadU16(std::span<const std::byte> bytes, std::size_t offset, bool little_endian = true);
std::uint32_t ReadU32(std::span<const std::byte> bytes, std::size_t offset, bool little_endian = true);
std::uint64_t ReadU64(std::span<const std::byte> bytes, std::size_t offset, bool little_endian = true);

void AppendU16(std::vector<std::byte>& out, std::uint16_t value);
void AppendU32(std::vector<std::byte>& out, std::uint32_t value);
void AppendU64(std::vector<std::byte>& out, std::uint64_t value);
void AppendI32(std::vector<std::byte>& out, std::int32_t value);
void AppendVarUInt(std::vector<std::byte>& out, std::uint64_t value);
void AppendVarInt(std::vector<std::byte>& out, std::int64_t value);

std::uint64_t ReadVarUInt(std::span<const std::byte> bytes, std::size_t& offset);
std::int64_t ReadVarInt(std::span<const std::byte> bytes, std::size_t& offset);

void RequireAvailable(std::span<const std::byte> bytes, std::size_t offset, std::size_t count,
                      const char* context);

}  // namespace abdc::binary

