#pragma once

#include <cstdint>
#include <filesystem>
#include <string_view>

namespace abdc {

void AtomicWriteFile(const std::filesystem::path& path, std::string_view bytes);
std::string ReadUtf8File(const std::filesystem::path& path, std::uint64_t maximum_bytes = 16U << 20U);
void ProbeWritableDirectory(const std::filesystem::path& directory, std::uint64_t minimum_free_bytes);
std::filesystem::path DefaultSessionRoot();

}  // namespace abdc

