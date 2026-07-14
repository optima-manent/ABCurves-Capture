#pragma once

#include "base/Json.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace abdc::session {

// Human-readable append journal with per-record sequence/schema/CRC. A torn
// final line is recoverable without trusting any earlier in-memory state.
class AppendOnlyJsonlWriter final {
public:
    AppendOnlyJsonlWriter(std::filesystem::path partial_path, std::string schema);
    ~AppendOnlyJsonlWriter();

    AppendOnlyJsonlWriter(const AppendOnlyJsonlWriter&) = delete;
    AppendOnlyJsonlWriter& operator=(const AppendOnlyJsonlWriter&) = delete;

    std::uint64_t Append(json::Value object);
    void Checkpoint();
    void Finalize(const std::filesystem::path& final_path);

    [[nodiscard]] std::uint64_t Count() const noexcept { return count_; }
    [[nodiscard]] const std::string& Schema() const noexcept { return schema_; }

private:
    std::filesystem::path partial_path_;
    std::string schema_;
    std::ofstream output_;
    std::uint64_t count_ = 0;
    bool finalized_ = false;
};

class AppendOnlyJsonlReader final {
public:
    AppendOnlyJsonlReader(const std::filesystem::path& path, std::string expected_schema);
    std::optional<json::Value> Next();
    [[nodiscard]] std::uint64_t Count() const noexcept { return count_; }

private:
    std::ifstream input_;
    std::string expected_schema_;
    std::vector<char> line_buffer_;
    std::uint64_t count_ = 0;
};

[[nodiscard]] std::string JournalCrc32(const json::Value& object_without_crc);

}  // namespace abdc::session
