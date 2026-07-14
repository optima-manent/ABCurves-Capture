#pragma once

#include "platform/ClockAnchor.h"
#include "session/AppendOnlyJsonl.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace abdc::session {

struct ClockJournalRecord {
    std::int64_t qpc_frequency = 0;
    platform::ClockAnchor anchor;
};

class ClockJournal final {
public:
    static constexpr const char* kSchema = "abcurves.clock.anchor.v1";

    ClockJournal(std::filesystem::path clocks_directory,
                 std::int64_t qpc_frequency);
    ~ClockJournal();
    ClockJournal(const ClockJournal&) = delete;
    ClockJournal& operator=(const ClockJournal&) = delete;

    std::uint64_t Append(const platform::ClockAnchor& anchor);
    std::uint64_t SampleAndAppend(std::string source);
    void Checkpoint();
    void Finalize();

    [[nodiscard]] std::uint64_t Count() const noexcept;
    [[nodiscard]] bool IsFinalized() const noexcept { return finalized_; }

private:
    std::filesystem::path partial_path_;
    std::filesystem::path final_path_;
    std::int64_t qpc_frequency_ = 0;
    std::unique_ptr<AppendOnlyJsonlWriter> writer_;
    bool finalized_ = false;
};

[[nodiscard]] std::vector<ClockJournalRecord> ReadClockJournal(
    const std::filesystem::path& path);

}  // namespace abdc::session
