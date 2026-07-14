#pragma once

#include "capture/PcapReader.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace abdc::capture {

class StreamingPcapParser final {
public:
    void Append(std::span<const std::byte> bytes);
    std::vector<PcapRecord> TakeRecords();
    void Finalize() const;
    [[nodiscard]] bool HeaderReady() const { return header_ready_; }
    [[nodiscard]] bool AtRecordBoundary() const {
        return header_ready_ && buffer_.size() == offset_;
    }
    [[nodiscard]] const PcapHeader& Header() const;
    [[nodiscard]] std::uint64_t RecordCount() const { return sequence_; }

private:
    void ParseAvailable(std::vector<PcapRecord>& out);
    std::vector<std::byte> buffer_;
    std::size_t offset_ = 0;
    PcapHeader header_{};
    bool header_ready_ = false;
    std::uint64_t sequence_ = 0;
};

}  // namespace abdc::capture
