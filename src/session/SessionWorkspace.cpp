#include "session/SessionWorkspace.h"

#include "base/AtomicFile.h"
#include "base/Sha256.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace abdc::session {
namespace {

constexpr std::string_view kSchema = "abcurves.capture.session.v2";
constexpr std::wstring_view kLeaseDirectory = L".leases";

bool IsPartialPath(const std::filesystem::path& path) {
    return path.extension() == L".partial" || path.extension() == L".tmp";
}

bool IsKnownSessionStatus(const std::string_view value) noexcept {
    return value == ToString(SessionStatus::Recording) ||
           value == ToString(SessionStatus::Complete) ||
           value == ToString(SessionStatus::CompleteWithWarnings) ||
           value == ToString(SessionStatus::Interrupted) ||
           value == ToString(SessionStatus::CaptureLost);
}

std::filesystem::path LeasePathFor(const std::filesystem::path& output_root,
                                   const std::string_view session_id) {
    return output_root / kLeaseDirectory /
           (L"session_" + std::filesystem::path(std::string(session_id)).wstring() +
            L".lock");
}

std::wstring ExtendedPath(const std::filesystem::path& path) {
    auto value = std::filesystem::absolute(path).wstring();
    if (value.starts_with(L"\\\\?\\")) return value;
    if (value.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + value.substr(2);
    return L"\\\\?\\" + value;
}

std::optional<DWORD> ExistingPathAttributes(
    const std::filesystem::path& path) {
    const auto native = ExtendedPath(path);
    const DWORD attributes = GetFileAttributesW(native.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) return attributes;
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
        return std::nullopt;
    }
    throw std::runtime_error("session path attributes could not be inspected");
}

void RequireDirectoryWithoutReparse(const std::filesystem::path& path,
                                    const std::string_view label) {
    const auto attributes = ExistingPathAttributes(path);
    if (!attributes || (*attributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
        (*attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) !=
            0U) {
        throw std::runtime_error(std::string(label) +
                                 " must be a regular non-reparse directory");
    }
}

void RequireRegularFileWithoutReparse(const std::filesystem::path& path,
                                      const std::string_view label) {
    const auto attributes = ExistingPathAttributes(path);
    if (!attributes ||
        (*attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT |
                        FILE_ATTRIBUTE_DEVICE)) != 0U) {
        throw std::runtime_error(std::string(label) +
                                 " must be a regular non-reparse file");
    }
}

std::shared_ptr<void> AdoptLeaseHandle(const HANDLE handle) {
    return std::shared_ptr<void>(handle, [](void* value) noexcept {
        if (value != nullptr && value != INVALID_HANDLE_VALUE) {
            CloseHandle(static_cast<HANDLE>(value));
        }
    });
}

void RequireRegularLeaseHandle(const HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (GetFileType(handle) != FILE_TYPE_DISK ||
        !GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes,
                                      sizeof(attributes)) ||
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT |
          FILE_ATTRIBUTE_DEVICE)) != 0U) {
        throw SessionLeaseError(SessionLeaseFailure::Invalid,
                                "session lease is not a regular file");
    }
}

std::shared_ptr<void> AcquireWriterLease(
    const std::filesystem::path& output_root,
    const std::string_view session_id,
    std::filesystem::path& lease_path) {
    const auto lease_directory = output_root / kLeaseDirectory;
    std::error_code error;
    std::filesystem::create_directories(lease_directory, error);
    if (error) {
        throw SessionLeaseError(SessionLeaseFailure::Invalid,
                                "session lease directory could not be created");
    }
    try {
        RequireDirectoryWithoutReparse(lease_directory,
                                       "session lease directory");
    } catch (const std::exception&) {
        throw SessionLeaseError(SessionLeaseFailure::Invalid,
                                "session lease directory is not a regular directory");
    }

    lease_path = LeasePathFor(output_root, session_id);
    const auto native = ExtendedPath(lease_path);
    const HANDLE raw = CreateFileW(
        native.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (raw == INVALID_HANDLE_VALUE) {
        throw SessionLeaseError(SessionLeaseFailure::Invalid,
                                "session writer lease could not be acquired");
    }
    auto handle = AdoptLeaseHandle(raw);
    RequireRegularLeaseHandle(raw);
    return handle;
}

std::shared_ptr<void> AcquireRecoveryLease(
    const std::filesystem::path& lease_path) {
    const auto native = ExtendedPath(lease_path);
    const HANDLE raw = CreateFileW(
        native.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (raw == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            throw SessionLeaseError(
                SessionLeaseFailure::Missing,
                "session has no lease and cannot be recovered automatically");
        }
        if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) {
            throw SessionLeaseError(SessionLeaseFailure::Busy,
                                    "session still has an active writer");
        }
        throw SessionLeaseError(SessionLeaseFailure::Invalid,
                                "session recovery lease could not be acquired");
    }
    auto handle = AdoptLeaseHandle(raw);
    RequireRegularLeaseHandle(raw);
    return handle;
}

std::string GenericRelative(const std::filesystem::path& root,
                            const std::filesystem::path& path) {
    const auto relative = std::filesystem::relative(path, root).generic_string();
    if (relative.empty() || relative.starts_with("../") || relative == ".." ||
        relative.find('\\') != std::string::npos) {
        throw std::runtime_error("session artifact escaped its workspace");
    }
    return relative;
}

}  // namespace

SessionLeaseError::SessionLeaseError(const SessionLeaseFailure failure,
                                     std::string message)
    : std::runtime_error(std::move(message)), failure_(failure) {}

const char* ToString(const SessionStatus status) noexcept {
    switch (status) {
    case SessionStatus::Recording: return "recording";
    case SessionStatus::Complete: return "complete";
    case SessionStatus::CompleteWithWarnings: return "complete_with_warnings";
    case SessionStatus::Interrupted: return "interrupted";
    case SessionStatus::CaptureLost: return "capture_lost";
    }
    return "unknown";
}

bool IsSafeSessionId(const std::string_view value) noexcept {
    if (value.size() < 8U || value.size() > 96U || value.front() == '-' ||
        value.back() == '-') {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](const char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= '0' && character <= '9') || character == '-';
    });
}

SessionWorkspace::SessionWorkspace(std::filesystem::path path,
                                   std::filesystem::path lease_path,
                                   std::shared_ptr<void> lease_handle,
                                   const bool exclusive_lease,
                                   SessionCreateOptions options,
                                   json::Value manifest)
    : path_(std::move(path)),
      capture_directory_(path_ / "capture"),
      gameplay_directory_(path_ / "gameplay"),
      clocks_directory_(path_ / "clocks"),
      derived_directory_(path_ / "derived"),
      lease_path_(std::move(lease_path)),
      lease_handle_(std::move(lease_handle)),
      exclusive_lease_(exclusive_lease),
      options_(std::move(options)),
      manifest_(std::move(manifest)) {}

SessionWorkspace SessionWorkspace::Create(const SessionCreateOptions& options) {
    if (!options.output_root.is_absolute() || !IsSafeSessionId(options.session_id) ||
        !IsSafeSessionId(options.user_id) || options.application_version.empty() ||
        options.protocol_id.empty() || options.protocol_sha256.size() != 64U ||
        options.qpc_frequency <= 0 || options.started_utc_ns <= 0 ||
        !(options.trainer_sensitivity >= 0.01 && options.trainer_sensitivity <= 3.0)) {
        throw std::invalid_argument("session creation options are incomplete or invalid");
    }
    std::filesystem::create_directories(options.output_root);
    ProbeWritableDirectory(options.output_root, 64U * 1024U * 1024U);
    std::filesystem::path lease_path;
    auto lease_handle = AcquireWriterLease(
        options.output_root, options.session_id, lease_path);
    const auto path = options.output_root / ("session_" + options.session_id + ".partial");
    if (!std::filesystem::create_directory(path)) {
        throw std::runtime_error("session workspace already exists");
    }
    try {
        std::filesystem::create_directory(path / "capture");
        std::filesystem::create_directory(path / "gameplay");
        std::filesystem::create_directory(path / "clocks");
        std::filesystem::create_directory(path / "derived");
        json::Value manifest = json::Value::Object{};
        manifest["schema"] = std::string(kSchema);
        manifest["status"] = ToString(SessionStatus::Recording);
        manifest["session_id"] = options.session_id;
        manifest["user_id"] = options.user_id;
        manifest["application_version"] = options.application_version;
        manifest["source_revision"] = options.source_revision;
        manifest["protocol_id"] = options.protocol_id;
        manifest["protocol_sha256"] = options.protocol_sha256;
        manifest["scenario_seed"] = std::to_string(options.scenario_seed);
        manifest["trainer_sensitivity"] = options.trainer_sensitivity;
        manifest["sensitivity_definition"] =
            "multiplier_on_base_0.00125_radians_per_raw_count";
        manifest["qpc_frequency"] = options.qpc_frequency;
        manifest["started_utc_ns"] = std::to_string(options.started_utc_ns);
        manifest["device"] = options.device;
        if (!options.protocol_plan.IsNull()) {
            manifest["protocol_plan"] = options.protocol_plan;
        }
        if (!options.presentation.IsNull()) {
            manifest["presentation"] = options.presentation;
        }
        manifest["event_count"] = static_cast<std::int64_t>(0);
        manifest["warning_count"] = static_cast<std::int64_t>(0);
        manifest["runtime_detail"] = "recording";
        manifest["owner_pid"] =
            static_cast<std::int64_t>(GetCurrentProcessId());
        SessionWorkspace workspace(path, std::move(lease_path),
                                   std::move(lease_handle), false, options,
                                   std::move(manifest));
        workspace.PersistManifest();
        return workspace;
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        throw;
    }
}

SessionWorkspace SessionWorkspace::OpenAbandoned(
    const std::filesystem::path& partial_workspace) {
    const auto path = std::filesystem::absolute(partial_workspace);
    const auto filename = path.filename().string();
    constexpr std::string_view prefix = "session_";
    constexpr std::string_view suffix = ".partial";
    if (!filename.starts_with(prefix) || !filename.ends_with(suffix) ||
        filename.size() <= prefix.size() + suffix.size()) {
        throw std::invalid_argument(
            "abandoned session must have a canonical .partial name");
    }
    const std::string session_id = filename.substr(
        prefix.size(), filename.size() - prefix.size() - suffix.size());
    if (!IsSafeSessionId(session_id)) {
        throw std::invalid_argument("abandoned session ID is invalid");
    }
    const auto lease_path = LeasePathFor(path.parent_path(), session_id);
    // This is deliberately the first filesystem open/inspection involving the
    // partial workspace. A live participant/helper therefore cannot race any
    // recovery reads or mutations below.
    auto lease_handle = AcquireRecoveryLease(lease_path);
    RequireDirectoryWithoutReparse(path, "abandoned session root");
    RequireRegularFileWithoutReparse(path / "manifest.json",
                                     "abandoned session manifest");
    for (const auto* child : {"capture", "gameplay", "clocks", "derived"}) {
        RequireDirectoryWithoutReparse(
            path / child, "abandoned session child directory");
    }

    auto manifest = json::Parse(ReadUtf8File(path / "manifest.json"));
    if (manifest.At("schema").AsString() != kSchema ||
        !IsKnownSessionStatus(manifest.At("status").AsString())) {
        throw std::runtime_error(
            "abandoned session manifest schema or status is invalid");
    }
    const auto manifest_session_id = manifest.At("session_id").AsString();
    if (manifest_session_id != session_id ||
        path.filename().string() != "session_" + session_id + ".partial") {
        throw std::runtime_error("abandoned session identity is inconsistent");
    }
    // A crash can occur after terminal manifest/control publication but before
    // the directory rename. Preserve those controls for recovery inspection;
    // Seal deterministically overwrites both only after recovery has validated
    // and repaired all artifacts.
    for (const auto* control : {"COMPLETE", "checksums.sha256"}) {
        const auto control_path = path / control;
        if (const auto attributes = ExistingPathAttributes(control_path);
            attributes &&
            (*attributes &
             (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT |
              FILE_ATTRIBUTE_DEVICE)) != 0U) {
            throw std::runtime_error(
                "abandoned session publication control is not a regular "
                "non-reparse file");
        }
    }
    SessionCreateOptions options;
    options.output_root = path.parent_path();
    options.session_id = session_id;
    return SessionWorkspace(path, lease_path, std::move(lease_handle), true,
                            std::move(options), std::move(manifest));
}

void SessionWorkspace::PersistManifest() {
    AtomicWriteFile(path_ / "manifest.json",
                    json::DumpCanonical(manifest_, true) + "\n");
}

void SessionWorkspace::UpdateRuntimeSummary(const std::uint64_t event_count,
                                            const std::uint64_t warning_count,
                                            std::string detail) {
    if (sealed_) throw std::logic_error("cannot update a sealed session");
    if (event_count > static_cast<std::uint64_t>(INT64_MAX) ||
        warning_count > static_cast<std::uint64_t>(INT64_MAX) ||
        detail.size() > 1'024U) {
        throw std::invalid_argument("runtime summary is outside manifest limits");
    }
    manifest_["event_count"] = static_cast<std::int64_t>(event_count);
    manifest_["warning_count"] = static_cast<std::int64_t>(warning_count);
    manifest_["runtime_detail"] = std::move(detail);
    PersistManifest();
}

void SessionWorkspace::UpdateCaptureHelperPid(const std::uint32_t helper_pid) {
    if (sealed_ || helper_pid == 0U) {
        throw std::invalid_argument("capture helper PID update is invalid");
    }
    manifest_["capture_helper_pid"] =
        static_cast<std::int64_t>(helper_pid);
    PersistManifest();
}

std::vector<SessionArtifact> SessionWorkspace::InventoryArtifacts() const {
    std::vector<SessionArtifact> artifacts;
    std::set<std::string> names;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(path_)) {
        const auto status = entry.symlink_status();
        if (std::filesystem::is_symlink(status) ||
            (status.type() != std::filesystem::file_type::regular &&
             status.type() != std::filesystem::file_type::directory)) {
            throw std::runtime_error("session contains a non-regular artifact");
        }
        if (!entry.is_regular_file()) continue;
        const auto relative = GenericRelative(path_, entry.path());
        if (relative == "checksums.sha256" || relative == "COMPLETE") continue;
        if (IsPartialPath(entry.path())) {
            throw std::runtime_error("session still contains an unfinished artifact: " + relative);
        }
        if (!names.insert(relative).second) {
            throw std::runtime_error("duplicate session artifact name");
        }
        SessionArtifact artifact;
        artifact.relative_path = relative;
        artifact.size_bytes = std::filesystem::file_size(entry.path());
        artifact.sha256 = Sha256FileHex(entry.path());
        artifacts.push_back(std::move(artifact));
    }
    std::sort(artifacts.begin(), artifacts.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    return artifacts;
}

SessionSealResult SessionWorkspace::Seal(const SessionSealOptions& options) {
    if (sealed_) throw std::logic_error("session workspace already sealed");
    if (options.status == SessionStatus::Recording || options.ended_utc_ns <= 0 ||
        options.stop_reason.empty() || options.stop_reason.size() > 1'024U) {
        throw std::invalid_argument("session seal options are invalid");
    }
    if (options.status == SessionStatus::Complete && options.warning_count != 0U) {
        throw std::invalid_argument("a warning-free status cannot claim warnings");
    }
    manifest_.AsObject().erase("owner_pid");
    manifest_.AsObject().erase("capture_helper_pid");
    manifest_["status"] = ToString(options.status);
    manifest_["ended_utc_ns"] = std::to_string(options.ended_utc_ns);
    manifest_["raw_pcap_records"] = std::to_string(options.raw_pcap_records);
    manifest_["decoded_reports"] = std::to_string(options.decoded_reports);
    manifest_["event_count"] = static_cast<std::int64_t>(options.gameplay_events);
    manifest_["warning_count"] = static_cast<std::int64_t>(options.warning_count);
    manifest_["recovery_was_required"] = options.recovery_was_required;
    manifest_["verified_authoritative_source"] =
        options.verified_authoritative_source;
    manifest_["stop_reason"] = options.stop_reason;
    PersistManifest();

    auto artifacts = InventoryArtifacts();
    if (artifacts.empty()) throw std::runtime_error("cannot seal an empty session");
    std::string checksum_list;
    for (const auto& artifact : artifacts) {
        checksum_list += artifact.sha256 + "  " + artifact.relative_path + "\n";
    }
    AtomicWriteFile(path_ / "checksums.sha256", checksum_list);
    const auto checksum_list_sha256 = Sha256FileHex(path_ / "checksums.sha256");

    json::Value complete = json::Value::Object{};
    complete["schema"] = "abcurves.capture.complete.v2";
    complete["session_id"] = options_.session_id;
    complete["status"] = ToString(options.status);
    complete["artifact_count"] = static_cast<std::int64_t>(artifacts.size());
    complete["checksums_sha256"] = checksum_list_sha256;
    AtomicWriteFile(path_ / "COMPLETE", json::DumpCanonical(complete, true) + "\n");

    const auto final_path = options_.output_root / ("session_" + options_.session_id);
    if (std::filesystem::exists(final_path)) {
        throw std::runtime_error("refusing to overwrite a finalized session");
    }
    bool moved = false;
    for (int attempt = 0; attempt < 20 && !moved; ++attempt) {
        moved = MoveFileExW(path_.c_str(), final_path.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
        if (!moved) Sleep(25U);
    }
    if (!moved) throw std::runtime_error("atomic session directory publication failed");
    path_ = final_path;
    capture_directory_ = path_ / "capture";
    gameplay_directory_ = path_ / "gameplay";
    clocks_directory_ = path_ / "clocks";
    derived_directory_ = path_ / "derived";
    sealed_ = true;
    // Directory publication is only the first half of finalization. Keep both
    // normal shared writer leases and abandoned-session exclusive leases alive
    // with the workspace so startup recovery cannot race archive creation or
    // its independent validation. The normal owning finalizer releases its
    // lease explicitly after that validation; recovery holds until destruction.

    SessionSealResult result;
    result.directory = path_;
    result.status = options.status;
    result.artifacts = std::move(artifacts);
    result.checksum_list_sha256 = checksum_list_sha256;
    return result;
}

void SessionWorkspace::ReleaseFinalizationLease() {
    if (!sealed_) {
        throw std::logic_error(
            "cannot release a session lease before directory publication");
    }
    if (exclusive_lease_) {
        throw std::logic_error(
            "abandoned-session recovery must retain its exclusive lease");
    }
    lease_handle_.reset();
}

}  // namespace abdc::session
