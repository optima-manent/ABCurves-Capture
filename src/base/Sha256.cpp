#include "base/Sha256.h"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace abdc {
namespace {

class Algorithm final {
public:
    Algorithm() {
        if (BCryptOpenAlgorithmProvider(&handle_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
            throw std::runtime_error("BCryptOpenAlgorithmProvider(SHA-256) failed");
        }
    }
    ~Algorithm() { if (handle_) BCryptCloseAlgorithmProvider(handle_, 0); }
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
    BCRYPT_ALG_HANDLE get() const { return handle_; }
private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class Hash final {
public:
    explicit Hash(BCRYPT_ALG_HANDLE algorithm) : algorithm_(algorithm) {
        DWORD copied = 0;
        DWORD object_size = 0;
        if (BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH,
                              reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &copied, 0) < 0) {
            throw std::runtime_error("BCryptGetProperty(object length) failed");
        }
        object_.resize(object_size);
        if (BCryptCreateHash(algorithm_, &hash_, object_.data(), object_size, nullptr, 0, 0) < 0) {
            throw std::runtime_error("BCryptCreateHash failed");
        }
    }
    ~Hash() { if (hash_) BCryptDestroyHash(hash_); }
    void Update(const std::span<const std::byte> bytes) {
        if (bytes.size() > std::numeric_limits<ULONG>::max()) throw std::runtime_error("SHA-256 input chunk too large");
        if (BCryptHashData(hash_, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
                           static_cast<ULONG>(bytes.size()), 0) < 0) {
            throw std::runtime_error("BCryptHashData failed");
        }
    }
    std::array<std::byte, 32> Finish() {
        std::array<std::byte, 32> digest{};
        if (BCryptFinishHash(hash_, reinterpret_cast<PUCHAR>(digest.data()),
                             static_cast<ULONG>(digest.size()), 0) < 0) {
            throw std::runtime_error("BCryptFinishHash failed");
        }
        return digest;
    }
private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<UCHAR> object_;
};

std::string Hex(const std::span<const std::byte> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto value = std::to_integer<unsigned>(bytes[i]);
        result[i * 2] = kDigits[value >> 4U];
        result[i * 2 + 1] = kDigits[value & 0xfU];
    }
    return result;
}

}  // namespace

std::string Sha256Hex(const std::span<const std::byte> bytes) {
    Algorithm algorithm;
    Hash hash(algorithm.get());
    hash.Update(bytes);
    const auto digest = hash.Finish();
    return Hex(digest);
}

std::string Sha256FileHex(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("cannot open file for SHA-256");
    Algorithm algorithm;
    Hash hash(algorithm.get());
    std::array<char, 1U << 16U> buffer{};
    while (file) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto read = file.gcount();
        if (read > 0) {
            hash.Update({reinterpret_cast<const std::byte*>(buffer.data()), static_cast<std::size_t>(read)});
        }
    }
    if (!file.eof()) throw std::runtime_error("read failed while hashing");
    const auto digest = hash.Finish();
    return Hex(digest);
}

}  // namespace abdc
