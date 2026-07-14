#include "session/PseudonymousIdentity.h"

#include "base/AtomicFile.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <fstream>
#include <stdexcept>
#include <string_view>

namespace abdc::session {
namespace {

std::string RandomId(const std::string_view prefix) {
    std::array<unsigned char, 16> bytes{};
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("cryptographic identity generation failed");
    }
    constexpr char hex[] = "0123456789abcdef";
    std::string result(prefix);
    result.reserve(prefix.size() + bytes.size() * 2U);
    for (const auto byte : bytes) {
        result.push_back(hex[byte >> 4U]);
        result.push_back(hex[byte & 0x0fU]);
    }
    return result;
}

}  // namespace

bool IsPseudonymousId(const std::string_view value,
                      const std::string_view prefix) noexcept {
    if (!value.starts_with(prefix) || value.size() != prefix.size() + 32U) {
        return false;
    }
    for (const char character : value.substr(prefix.size())) {
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::string LoadOrCreateParticipantId(
    const std::filesystem::path& settings_directory) {
    if (!settings_directory.is_absolute()) {
        throw std::invalid_argument("settings directory must be absolute");
    }
    std::filesystem::create_directories(settings_directory);
    const auto path = settings_directory / "participant_id.txt";
    if (std::filesystem::exists(path)) {
        std::ifstream input(path, std::ios::binary);
        std::string value;
        std::getline(input, value);
        if (!input && !input.eof()) {
            throw std::runtime_error("participant identity read failed");
        }
        if (!IsPseudonymousId(value, "u-")) {
            throw std::runtime_error("participant identity file is malformed");
        }
        return value;
    }
    const auto value = RandomId("u-");
    AtomicWriteFile(path, value + "\n");
    return value;
}

std::string CreateSessionId() {
    return RandomId("s-");
}

}  // namespace abdc::session
