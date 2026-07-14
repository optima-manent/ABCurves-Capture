#pragma once

#include "capture/ReportStream.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <vector>

namespace abdc::capture {

// Ephemeral low-latency bridge from the elevated capture helper to the
// standard-user trainer. It is never authoritative and never enters a final
// bundle; reports.abcr remains the lossless source. Each fixed record has a CRC
// so the reader waits on a partial tail and fails on corruption.
class LiveReportMirrorWriter final {
public:
    LiveReportMirrorWriter(const std::filesystem::path& path,
                           const ReportStreamIdentity& identity);
    ~LiveReportMirrorWriter();
    LiveReportMirrorWriter(const LiveReportMirrorWriter&) = delete;
    LiveReportMirrorWriter& operator=(const LiveReportMirrorWriter&) = delete;

    void Append(const AuthoritativeReport& report);
    void Flush();
    void Finalize();
    [[nodiscard]] std::uint64_t RecordCount() const { return record_count_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    ReportStreamIdentity identity_;
    std::uint64_t record_count_ = 0;
    std::optional<std::uint64_t> previous_sequence_;
    std::optional<std::int64_t> previous_timestamp_;
    bool finalized_ = false;
};

class LiveReportMirrorReader final {
public:
    explicit LiveReportMirrorReader(const std::filesystem::path& path);
    ~LiveReportMirrorReader();
    LiveReportMirrorReader(const LiveReportMirrorReader&) = delete;
    LiveReportMirrorReader& operator=(const LiveReportMirrorReader&) = delete;

    [[nodiscard]] const ReportStreamIdentity& Identity() const { return identity_; }
    std::vector<AuthoritativeReport> TakeAvailable();
    void RequireCleanFinalTail();
    [[nodiscard]] std::uint64_t RecordCount() const { return record_count_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    ReportStreamIdentity identity_;
    std::uint64_t record_count_ = 0;
    std::optional<std::uint64_t> previous_sequence_;
    std::optional<std::int64_t> previous_timestamp_;
};

}  // namespace abdc::capture
