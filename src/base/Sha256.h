#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>

namespace abdc {

std::string Sha256Hex(std::span<const std::byte> bytes);
std::string Sha256FileHex(const std::filesystem::path& path);

}  // namespace abdc

