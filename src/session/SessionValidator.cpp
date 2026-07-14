#include "session/SessionValidator.h"

#include "base/Json.h"
#include "base/Sha256.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace abdc::session {
namespace {

constexpr std::uint64_t kMaxControlFileBytes = 16U << 20U;

std::string ReadControlFile(const std::filesystem::path& path) {
    const auto status = std::filesystem::symlink_status(path);
    if (std::filesystem::is_symlink(status) ||
        status.type() != std::filesystem::file_type::regular) {
        throw std::runtime_error("session control artifact is missing or not regular");
    }
    const auto size = std::filesystem::file_size(path);
    if (size == 0U || size > kMaxControlFileBytes) {
        throw std::runtime_error("session control artifact has an unsafe size");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read session control artifact");
    std::string text(static_cast<std::size_t>(size), '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (input.gcount() != static_cast<std::streamsize>(text.size())) {
        throw std::runtime_error("short read of session control artifact");
    }
    return text;
}

bool IsLowerHexDigest(const std::string_view value) {
    return value.size() == 64U &&
           std::all_of(value.begin(), value.end(), [](const char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

bool IsSafeRelativeArtifact(const std::string_view value) {
    if (value.empty() || value.front() == '/' || value.back() == '/' ||
        value.find('\\') != std::string_view::npos ||
        value.find(':') != std::string_view::npos ||
        value.find('\0') != std::string_view::npos) {
        return false;
    }
    std::size_t begin = 0;
    while (begin < value.size()) {
        const auto end = value.find('/', begin);
        const auto part = value.substr(begin, end == std::string_view::npos
                                                  ? value.size() - begin
                                                  : end - begin);
        if (part.empty() || part == "." || part == "..") return false;
        begin = end == std::string_view::npos ? value.size() : end + 1U;
    }
    return true;
}

SessionStatus ParseStatus(const std::string_view value) {
    if (value == "complete") return SessionStatus::Complete;
    if (value == "complete_with_warnings") return SessionStatus::CompleteWithWarnings;
    if (value == "interrupted") return SessionStatus::Interrupted;
    if (value == "capture_lost") return SessionStatus::CaptureLost;
    throw std::runtime_error("sealed session has an invalid status");
}

std::vector<SessionArtifact> ParseChecksumList(const std::string& text) {
    std::vector<SessionArtifact> artifacts;
    std::set<std::string> names;
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) throw std::runtime_error("checksum list contains an empty line");
        if (!line.empty() && line.back() == '\r') {
            throw std::runtime_error("checksum list is not canonical LF text");
        }
        if (line.size() < 67U || line[64] != ' ' || line[65] != ' ') {
            throw std::runtime_error("checksum list line is malformed");
        }
        SessionArtifact artifact;
        artifact.sha256 = line.substr(0U, 64U);
        artifact.relative_path = line.substr(66U);
        if (!IsLowerHexDigest(artifact.sha256) ||
            !IsSafeRelativeArtifact(artifact.relative_path) ||
            artifact.relative_path == "checksums.sha256" ||
            artifact.relative_path == "COMPLETE" ||
            !names.insert(artifact.relative_path).second) {
            throw std::runtime_error("checksum list contains an unsafe artifact");
        }
        artifacts.push_back(std::move(artifact));
    }
    if (artifacts.empty() || text.back() != '\n') {
        throw std::runtime_error("checksum list is empty or lacks its final newline");
    }
    if (!std::is_sorted(artifacts.begin(), artifacts.end(),
                        [](const auto& left, const auto& right) {
                            return left.relative_path < right.relative_path;
                        })) {
        throw std::runtime_error("checksum list is not canonically sorted");
    }
    return artifacts;
}

std::vector<std::string> InventoryNames(const std::filesystem::path& root) {
    std::vector<std::string> names;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        const auto status = entry.symlink_status();
        if (std::filesystem::is_symlink(status) ||
            (status.type() != std::filesystem::file_type::regular &&
             status.type() != std::filesystem::file_type::directory)) {
            throw std::runtime_error("sealed session contains a non-regular artifact");
        }
        if (!entry.is_regular_file()) continue;
        auto relative = std::filesystem::relative(entry.path(), root).generic_string();
        if (!IsSafeRelativeArtifact(relative)) {
            throw std::runtime_error("sealed session artifact escaped containment");
        }
        if (relative == "checksums.sha256" || relative == "COMPLETE") continue;
        names.push_back(std::move(relative));
    }
    std::sort(names.begin(), names.end());
    if (std::adjacent_find(names.begin(), names.end()) != names.end()) {
        throw std::runtime_error("sealed session contains duplicate artifact names");
    }
    return names;
}

}  // namespace

ValidatedSession ValidateSealedSession(
    const std::filesystem::path& session_directory) {
    if (!session_directory.is_absolute()) {
        throw std::invalid_argument("session validation requires an absolute path");
    }
    const auto root_status = std::filesystem::symlink_status(session_directory);
    if (std::filesystem::is_symlink(root_status) ||
        root_status.type() != std::filesystem::file_type::directory) {
        throw std::runtime_error("sealed session path is not a regular directory");
    }

    const auto complete_text = ReadControlFile(session_directory / "COMPLETE");
    const auto manifest_text = ReadControlFile(session_directory / "manifest.json");
    const auto checksums_text = ReadControlFile(session_directory / "checksums.sha256");
    const auto complete = json::Parse(complete_text);
    const auto manifest = json::Parse(manifest_text);
    if (complete.At("schema").AsString() != "abcurves.capture.complete.v2" ||
        manifest.At("schema").AsString() != "abcurves.capture.session.v2") {
        throw std::runtime_error("session publication schema mismatch");
    }
    const auto session_id = complete.At("session_id").AsString();
    if (!IsSafeSessionId(session_id) ||
        manifest.At("session_id").AsString() != session_id ||
        session_directory.filename().string() != "session_" + session_id) {
        throw std::runtime_error("session publication identity mismatch");
    }
    const auto status_name = complete.At("status").AsString();
    if (manifest.At("status").AsString() != status_name) {
        throw std::runtime_error("session manifest and completion status differ");
    }
    const auto status = ParseStatus(status_name);
    const auto claimed_checksum_hash = complete.At("checksums_sha256").AsString();
    if (!IsLowerHexDigest(claimed_checksum_hash) ||
        Sha256FileHex(session_directory / "checksums.sha256") != claimed_checksum_hash) {
        throw std::runtime_error("session checksum-list digest mismatch");
    }

    auto artifacts = ParseChecksumList(checksums_text);
    const auto claimed_count = complete.At("artifact_count").AsInt();
    if (claimed_count < 0 ||
        static_cast<std::uint64_t>(claimed_count) != artifacts.size()) {
        throw std::runtime_error("session artifact count mismatch");
    }
    std::vector<std::string> listed_names;
    std::uint64_t total_bytes = 0;
    for (auto& artifact : artifacts) {
        const auto path = session_directory / std::filesystem::path(artifact.relative_path);
        const auto file_status = std::filesystem::symlink_status(path);
        if (std::filesystem::is_symlink(file_status) ||
            file_status.type() != std::filesystem::file_type::regular) {
            throw std::runtime_error("listed session artifact is missing or not regular");
        }
        artifact.size_bytes = std::filesystem::file_size(path);
        if (total_bytes > std::numeric_limits<std::uint64_t>::max() - artifact.size_bytes) {
            throw std::runtime_error("session artifact size overflow");
        }
        total_bytes += artifact.size_bytes;
        if (Sha256FileHex(path) != artifact.sha256) {
            throw std::runtime_error("session artifact digest mismatch: " +
                                     artifact.relative_path);
        }
        listed_names.push_back(artifact.relative_path);
    }
    if (InventoryNames(session_directory) != listed_names) {
        throw std::runtime_error("sealed session contains unlisted or missing artifacts");
    }

    ValidatedSession result;
    result.session_id = session_id;
    result.status = status;
    result.total_artifact_bytes = total_bytes;
    result.artifacts = std::move(artifacts);
    return result;
}

}  // namespace abdc::session
