#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace abdc::session {

struct TailRecoveryResult {
    std::uint64_t original_bytes = 0;
    std::uint64_t retained_bytes = 0;
    std::uint64_t record_count = 0;
    bool trimmed_incomplete_tail = false;
};

// Recovery is intentionally conservative: only an incomplete final write is
// removed. A complete record with a bad checksum, schema, sequence, or header
// is corruption and is reported to the caller instead of being hidden.
[[nodiscard]] TailRecoveryResult RecoverJsonlPartial(
    const std::filesystem::path& partial_path,
    const std::string& expected_schema);

[[nodiscard]] TailRecoveryResult RecoverPcapPartial(
    const std::filesystem::path& partial_path);

[[nodiscard]] TailRecoveryResult RecoverReportStreamPartial(
    const std::filesystem::path& partial_path);

}  // namespace abdc::session
