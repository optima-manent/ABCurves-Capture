#include "session/ClockJournal.h"

#include <stdexcept>

namespace abdc::session {

ClockJournal::ClockJournal(std::filesystem::path clocks_directory,
                           const std::int64_t qpc_frequency)
    : partial_path_(std::move(clocks_directory) / "anchors.jsonl.partial"),
      final_path_(partial_path_.parent_path() / "anchors.jsonl"),
      qpc_frequency_(qpc_frequency) {
    if (!partial_path_.parent_path().is_absolute() || qpc_frequency_ <= 0) {
        throw std::invalid_argument("clock journal identity is invalid");
    }
    if (std::filesystem::exists(final_path_)) {
        throw std::runtime_error("refusing to replace a finalized clock journal");
    }
    writer_ = std::make_unique<AppendOnlyJsonlWriter>(partial_path_, kSchema);
}

ClockJournal::~ClockJournal() = default;

std::uint64_t ClockJournal::Append(const platform::ClockAnchor& anchor) {
    if (finalized_) throw std::logic_error("clock journal is finalized");
    auto object = platform::ClockAnchorToJson(anchor);
    object["qpc_frequency"] = qpc_frequency_;
    return writer_->Append(std::move(object));
}

std::uint64_t ClockJournal::SampleAndAppend(std::string source) {
    return Append(platform::SamplePreciseClockAnchor(std::move(source)));
}

void ClockJournal::Checkpoint() {
    if (finalized_) throw std::logic_error("clock journal is finalized");
    writer_->Checkpoint();
}

void ClockJournal::Finalize() {
    if (finalized_) throw std::logic_error("clock journal is finalized");
    writer_->Finalize(final_path_);
    finalized_ = true;
}

std::uint64_t ClockJournal::Count() const noexcept {
    return writer_ ? writer_->Count() : 0U;
}

std::vector<ClockJournalRecord> ReadClockJournal(
    const std::filesystem::path& path) {
    AppendOnlyJsonlReader reader(path, ClockJournal::kSchema);
    std::vector<ClockJournalRecord> result;
    std::int64_t expected_frequency = 0;
    while (auto value = reader.Next()) {
        ClockJournalRecord record;
        record.qpc_frequency = value->At("qpc_frequency").AsInt();
        if (record.qpc_frequency <= 0 ||
            (expected_frequency > 0 && record.qpc_frequency != expected_frequency)) {
            throw std::runtime_error("clock journal QPC frequency changed");
        }
        expected_frequency = record.qpc_frequency;
        auto& fields = value->AsObject();
        fields.erase("qpc_frequency");
        fields.erase("schema");
        fields.erase("sequence");
        fields.erase("_crc32");
        record.anchor = platform::ClockAnchorFromJson(*value);
        result.push_back(std::move(record));
    }
    return result;
}

}  // namespace abdc::session
