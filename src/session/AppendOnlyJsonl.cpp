#include "session/AppendOnlyJsonl.h"

#include "base/Crc32.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace abdc::session {

namespace {

constexpr std::size_t kMaximumJournalRecordBytes = 4U << 20U;

std::span<const std::byte> AsBytes(const std::string& text) {
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

}  // namespace

std::string JournalCrc32(const json::Value& object_without_crc) {
    const auto canonical = json::DumpCanonical(object_without_crc, false);
    std::ostringstream value;
    value << std::hex << std::setfill('0') << std::setw(8) << Crc32(AsBytes(canonical));
    return value.str();
}

AppendOnlyJsonlWriter::AppendOnlyJsonlWriter(std::filesystem::path partial_path,
                                             std::string schema)
    : partial_path_(std::move(partial_path)), schema_(std::move(schema)) {
    if (schema_.empty() || schema_.size() > 128U) {
        throw std::invalid_argument("journal schema is invalid");
    }
    std::filesystem::create_directories(partial_path_.parent_path());
    output_.open(partial_path_, std::ios::binary | std::ios::trunc);
    if (!output_) throw std::runtime_error("cannot create append journal");
}

AppendOnlyJsonlWriter::~AppendOnlyJsonlWriter() {
    try {
        if (output_.is_open()) output_.close();
    } catch (...) {
    }
}

std::uint64_t AppendOnlyJsonlWriter::Append(json::Value object) {
    if (finalized_) throw std::logic_error("journal is finalized");
    if (!std::holds_alternative<json::Value::Object>(object.Data())) {
        throw std::invalid_argument("journal record must be an object");
    }
    auto& fields = object.AsObject();
    if (fields.contains("sequence") || fields.contains("schema") ||
        fields.contains("_crc32")) {
        throw std::invalid_argument("journal record uses a reserved field");
    }
    const auto sequence = count_;
    object["sequence"] = static_cast<std::int64_t>(sequence);
    object["schema"] = schema_;
    object["_crc32"] = JournalCrc32(object);
    const auto line = json::DumpCanonical(object, false);
    if (line.size() > kMaximumJournalRecordBytes) {
        throw std::length_error("append journal record exceeds its safety limit");
    }
    output_.write(line.data(), static_cast<std::streamsize>(line.size()));
    output_.put('\n');
    if (!output_) throw std::runtime_error("append journal write failed");
    ++count_;
    return sequence;
}

void AppendOnlyJsonlWriter::Checkpoint() {
    output_.flush();
    if (!output_) throw std::runtime_error("append journal stream flush failed");
    const HANDLE file = CreateFileW(partial_path_.c_str(), GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot open append journal for durable flush");
    }
    const BOOL flushed = FlushFileBuffers(file);
    const BOOL closed = CloseHandle(file);
    if (!flushed || !closed) throw std::runtime_error("append journal durable flush failed");
}

void AppendOnlyJsonlWriter::Finalize(const std::filesystem::path& final_path) {
    if (finalized_) throw std::logic_error("journal already finalized");
    Checkpoint();
    output_.close();
    if (std::filesystem::exists(final_path)) {
        throw std::runtime_error("refusing to overwrite append journal");
    }
    if (!MoveFileExW(partial_path_.c_str(), final_path.c_str(),
                     MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("atomic append journal rename failed");
    }
    finalized_ = true;
}

AppendOnlyJsonlReader::AppendOnlyJsonlReader(const std::filesystem::path& path,
                                             std::string expected_schema)
    : expected_schema_(std::move(expected_schema)),
      line_buffer_(kMaximumJournalRecordBytes + 2U, '\0') {
    input_.open(path, std::ios::binary);
    if (!input_) throw std::runtime_error("cannot open append journal");
}

std::optional<json::Value> AppendOnlyJsonlReader::Next() {
    if (input_.peek() == std::char_traits<char>::eof()) {
        if (input_.eof()) return std::nullopt;
        throw std::runtime_error("append journal read failed");
    }
    input_.getline(line_buffer_.data(),
                   static_cast<std::streamsize>(line_buffer_.size()), '\n');
    if (input_.bad()) throw std::runtime_error("append journal read failed");
    if (input_.eof()) {
        throw std::runtime_error("append journal lacks a final newline");
    }
    if (input_.fail()) {
        throw std::runtime_error(
            "append journal record exceeds its safety limit");
    }
    const auto extracted = input_.gcount();
    if (extracted <= 0) {
        throw std::runtime_error("append journal read made no progress");
    }
    // getline's gcount includes the extracted delimiter.
    std::string line(line_buffer_.data(),
                     static_cast<std::size_t>(extracted - 1));
    if (line.empty()) throw std::runtime_error("append journal contains an empty record");
    auto record = json::Parse(line);
    auto& fields = record.AsObject();
    const auto crc = record.At("_crc32").AsString();
    fields.erase("_crc32");
    if (crc.size() != 8U || JournalCrc32(record) != crc) {
        throw std::runtime_error("append journal CRC mismatch");
    }
    if (record.At("schema").AsString() != expected_schema_) {
        throw std::runtime_error("append journal schema mismatch");
    }
    const auto sequence = record.At("sequence").AsInt();
    if (sequence < 0 || static_cast<std::uint64_t>(sequence) != count_) {
        throw std::runtime_error("append journal sequence mismatch");
    }
    fields["_crc32"] = crc;
    ++count_;
    return record;
}

}  // namespace abdc::session
