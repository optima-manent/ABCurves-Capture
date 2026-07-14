#include "session/CapturePrefixRecovery.h"

#include "acquisition/CaptureWorker.h"
#include "base/AtomicFile.h"
#include "base/Json.h"
#include "session/CrashRecovery.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <functional>
#include <stdexcept>

namespace abdc::session {
namespace {

using RecoveryFunction =
    std::function<TailRecoveryResult(const std::filesystem::path&)>;

void DurableMove(const std::filesystem::path& source,
                 const std::filesystem::path& destination) {
    if (std::filesystem::exists(destination)) {
        throw std::runtime_error("recovery destination already exists");
    }
    if (!MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("recovery artifact publication failed with Win32 error " +
                                 std::to_string(GetLastError()));
    }
}

std::filesystem::path UnverifiedPath(const std::filesystem::path& final_path) {
    auto candidate = final_path;
    candidate += L".unverified";
    if (!std::filesystem::exists(candidate)) return candidate;
    for (unsigned index = 1U; index < 1000U; ++index) {
        auto numbered = final_path;
        numbered += L".unverified." + std::to_wstring(index);
        if (!std::filesystem::exists(numbered)) return numbered;
    }
    throw std::runtime_error("unverified artifact name limit exceeded");
}

RecoveredArtifact RecoverOne(const std::string& kind,
                             const std::filesystem::path& partial_path,
                             const std::filesystem::path& final_path,
                             const RecoveryFunction& recover) {
    RecoveredArtifact result;
    result.kind = kind;
    if (std::filesystem::exists(final_path)) {
        result.state = RecoveredArtifactState::FinalAlreadyPresent;
        result.published_path = final_path;
        result.retained_bytes = std::filesystem::file_size(final_path);
        result.original_bytes = result.retained_bytes;
        if (std::filesystem::exists(partial_path)) {
            result.unverified_path = UnverifiedPath(final_path);
            result.original_bytes += std::filesystem::file_size(partial_path);
            DurableMove(partial_path, result.unverified_path);
            result.state = RecoveredArtifactState::UnverifiedBytesPreserved;
            result.detail = "both final and partial artifacts existed; the unexpected partial was preserved";
        } else {
            result.detail = "artifact was already finalized";
        }
        return result;
    }
    if (!std::filesystem::exists(partial_path)) {
        result.state = RecoveredArtifactState::Missing;
        result.detail = "artifact was not created before capture stopped";
        return result;
    }
    result.original_bytes = std::filesystem::file_size(partial_path);
    try {
        const auto recovered = recover(partial_path);
        result.retained_bytes = recovered.retained_bytes;
        result.record_count = recovered.record_count;
        DurableMove(partial_path, final_path);
        result.published_path = final_path;
        result.state = RecoveredArtifactState::VerifiedPrefixPublished;
        result.detail = recovered.trimmed_incomplete_tail
            ? "incomplete final write was trimmed to the last verified boundary"
            : "complete durable prefix was published unchanged";
    } catch (const std::exception& error) {
        result.unverified_path = UnverifiedPath(final_path);
        DurableMove(partial_path, result.unverified_path);
        result.state = RecoveredArtifactState::UnverifiedBytesPreserved;
        result.retained_bytes = 0U;
        result.detail = std::string("verification failed; original bytes preserved: ") +
                        error.what();
    }
    return result;
}

std::string Relative(const std::filesystem::path& root,
                     const std::filesystem::path& path) {
    return path.empty() ? std::string{} :
        std::filesystem::relative(path, root).generic_string();
}

}  // namespace

const char* ToString(const RecoveredArtifactState state) noexcept {
    switch (state) {
    case RecoveredArtifactState::FinalAlreadyPresent: return "final_already_present";
    case RecoveredArtifactState::VerifiedPrefixPublished: return "verified_prefix_published";
    case RecoveredArtifactState::UnverifiedBytesPreserved: return "unverified_bytes_preserved";
    case RecoveredArtifactState::Missing: return "missing";
    }
    return "unknown";
}

CapturePrefixRecoveryResult RecoverCapturePrefix(
    const std::filesystem::path& absolute_capture_directory) {
    if (!absolute_capture_directory.is_absolute() ||
        !std::filesystem::is_directory(absolute_capture_directory)) {
        throw std::invalid_argument("capture recovery requires an absolute existing directory");
    }
    const auto paths = acquisition::OutputPathsIn(absolute_capture_directory);
    CapturePrefixRecoveryResult result;
    result.artifacts.push_back(RecoverOne(
        "device_pcap", paths.device_pcap_partial, paths.device_pcap_final,
        [](const auto& path) { return RecoverPcapPartial(path); }));
    result.artifacts.push_back(RecoverOne(
        "decoded_reports", paths.reports_partial, paths.reports_final,
        [](const auto& path) { return RecoverReportStreamPartial(path); }));
    result.artifacts.push_back(RecoverOne(
        "capture_anomalies", paths.anomalies_partial, paths.anomalies_final,
        [](const auto& path) {
            return RecoverJsonlPartial(path, "abcurves.capture.anomaly.v1");
        }));

    json::Value entries = json::Value::Array{};
    for (const auto& artifact : result.artifacts) {
        // A published path remains a verified source even when an unexpected
        // second partial had to be preserved separately as unverified bytes.
        // The state describes the incident, not the trustworthiness of the
        // already-published file.
        const bool verified = !artifact.published_path.empty();
        result.any_verified_source = result.any_verified_source ||
            (verified && artifact.kind == "device_pcap");
        if (artifact.state == RecoveredArtifactState::UnverifiedBytesPreserved) {
            result.any_unverified_bytes = true;
            ++result.warning_count;
        } else if (artifact.state == RecoveredArtifactState::Missing) {
            ++result.warning_count;
        } else if (artifact.original_bytes != artifact.retained_bytes) {
            ++result.warning_count;
        }
        json::Value entry = json::Value::Object{};
        entry["kind"] = artifact.kind;
        entry["state"] = ToString(artifact.state);
        entry["published_path"] = Relative(absolute_capture_directory,
                                            artifact.published_path);
        entry["unverified_path"] = Relative(absolute_capture_directory,
                                             artifact.unverified_path);
        entry["original_bytes"] = std::to_string(artifact.original_bytes);
        entry["retained_bytes"] = std::to_string(artifact.retained_bytes);
        entry["record_count"] = std::to_string(artifact.record_count);
        entry["detail"] = artifact.detail;
        entries.AsArray().push_back(std::move(entry));
    }
    json::Value document = json::Value::Object{};
    document["schema"] = "abcurves.capture.recovery.v1";
    document["artifacts"] = std::move(entries);
    document["warning_count"] = static_cast<std::int64_t>(result.warning_count);
    document["any_verified_source"] = result.any_verified_source;
    document["any_unverified_bytes"] = result.any_unverified_bytes;
    AtomicWriteFile(absolute_capture_directory / "recovery.json",
                    json::DumpCanonical(document, true) + "\n");
    return result;
}

}  // namespace abdc::session
