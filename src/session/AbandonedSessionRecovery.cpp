#include "session/AbandonedSessionRecovery.h"

#include "acquisition/CaptureWorker.h"
#include "base/AtomicFile.h"
#include "base/Json.h"
#include "capture/PcapReader.h"
#include "capture/ReportStream.h"
#include "capture/UsbPcapPacket.h"
#include "protocol/protocol_v1.hpp"
#include "session/AppendOnlyJsonl.h"
#include "session/CaptureArtifactValidation.h"
#include "session/CapturePrefixRecovery.h"
#include "session/ClockJournal.h"
#include "session/CrashRecovery.h"
#include "session/GameplayJournal.h"
#include "session/SessionArchive.h"
#include "session/SessionValidator.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <functional>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace abdc::session {
namespace {

constexpr std::size_t kMaximumWorkspaceEntries = 10'000U;
constexpr std::string_view kRecoverySchema =
    "abcurves.session.abandoned_recovery.v1";

struct ExpectedIdentity final {
    std::string session_id;
    std::string user_id;
    std::int64_t qpc_frequency = 0;
    double trainer_sensitivity = 0.0;
    CaptureArtifactIdentity capture;
};

struct ArtifactRecovery final {
    std::string kind;
    std::filesystem::path published_path;
    std::filesystem::path unverified_path;
    std::uint64_t record_count = 0;
    std::uint64_t warning_count = 0;
    std::string state;
    std::string detail;
};

using Validator =
    std::function<std::uint64_t(const std::filesystem::path&)>;

class ExclusiveLease final {
public:
    explicit ExclusiveLease(const HANDLE handle) : handle_(handle) {}
    ~ExclusiveLease() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }
    ExclusiveLease(ExclusiveLease&& other) noexcept
        : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}
    ExclusiveLease& operator=(ExclusiveLease&&) = delete;
    ExclusiveLease(const ExclusiveLease&) = delete;
    ExclusiveLease& operator=(const ExclusiveLease&) = delete;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

[[nodiscard]] std::wstring ExtendedPath(const std::filesystem::path& path) {
    auto value = std::filesystem::absolute(path).wstring();
    if (value.starts_with(L"\\\\?\\")) return value;
    if (value.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + value.substr(2U);
    return L"\\\\?\\" + value;
}

[[nodiscard]] ExclusiveLease AcquireSealedRecoveryLease(
    const std::filesystem::path& sessions_root,
    const std::string_view session_id) {
    const auto lease_path = sessions_root / ".leases" /
        (L"session_" + std::filesystem::path(std::string(session_id)).wstring() +
         L".lock");
    const auto native = ExtendedPath(lease_path);
    const HANDLE handle = CreateFileW(
        native.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            throw SessionLeaseError(
                SessionLeaseFailure::Missing,
                "sealed session has no lease and cannot be completed automatically");
        }
        if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) {
            throw SessionLeaseError(
                SessionLeaseFailure::Busy,
                "sealed session publication still has an active writer");
        }
        throw SessionLeaseError(
            SessionLeaseFailure::Invalid,
            "sealed session recovery lease could not be acquired");
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (GetFileType(handle) != FILE_TYPE_DISK ||
        !GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
                                      &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT |
          FILE_ATTRIBUTE_DEVICE)) != 0U) {
        CloseHandle(handle);
        throw SessionLeaseError(SessionLeaseFailure::Invalid,
                                "sealed session lease is not a regular file");
    }
    return ExclusiveLease(handle);
}

[[nodiscard]] bool IsReparsePoint(const std::filesystem::path& path) {
    const auto native = ExtendedPath(path);
    const DWORD attributes = GetFileAttributesW(native.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        throw std::runtime_error(
            "cannot inspect abandoned session entry, Win32 error " +
            std::to_string(GetLastError()));
    }
    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U;
}

void PreflightWorkspace(const std::filesystem::path& root) {
    if (IsReparsePoint(root)) {
        throw std::runtime_error(
            "abandoned session root is a reparse point");
    }
    std::size_t entry_count = 0U;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(root)) {
        if (++entry_count > kMaximumWorkspaceEntries) {
            throw std::runtime_error(
                "abandoned session contains too many entries");
        }
        const auto status = entry.symlink_status();
        if (std::filesystem::is_symlink(status) ||
            IsReparsePoint(entry.path()) ||
            (status.type() != std::filesystem::file_type::directory &&
             status.type() != std::filesystem::file_type::regular)) {
            throw std::runtime_error(
                "abandoned session contains a link, reparse point, or "
                "non-regular entry");
        }
    }
}

[[nodiscard]] ExpectedIdentity ReadExpectedIdentity(
    const std::filesystem::path& workspace) {
    const auto manifest = json::Parse(ReadUtf8File(workspace / "manifest.json"));
    ExpectedIdentity result;
    result.session_id = manifest.At("session_id").AsString();
    result.user_id = manifest.At("user_id").AsString();
    result.qpc_frequency = manifest.At("qpc_frequency").AsInt();
    result.trainer_sensitivity =
        manifest.At("trainer_sensitivity").AsDouble();
    const auto& device = manifest.At("device");
    const auto bus = device.At("usb_bus").AsInt();
    const auto usb_device = device.At("usb_device").AsInt();
    const auto endpoint = device.At("interrupt_in_endpoint").AsInt();
    if (bus <= 0 ||
        bus > static_cast<std::int64_t>(
                  std::numeric_limits<std::uint16_t>::max()) ||
        usb_device <= 0 ||
        usb_device > static_cast<std::int64_t>(
                         std::numeric_limits<std::uint16_t>::max()) ||
        endpoint < 0 ||
        endpoint > static_cast<std::int64_t>(
                       std::numeric_limits<std::uint8_t>::max())) {
        throw std::runtime_error(
            "abandoned session certified USB identity is invalid");
    }
    result.capture.usb_bus = static_cast<std::uint16_t>(bus);
    result.capture.usb_device = static_cast<std::uint16_t>(usb_device);
    result.capture.interrupt_in_endpoint =
        static_cast<std::uint8_t>(endpoint);
    result.capture.hid_descriptor_sha256 =
        device.At("hid_descriptor_sha256").AsString();
    result.capture.qpc_frequency = result.qpc_frequency;
    const auto endpoint_value = result.capture.interrupt_in_endpoint;
    const auto& descriptor_hash = result.capture.hid_descriptor_sha256;
    const bool descriptor_is_hex = descriptor_hash.empty() ||
        (descriptor_hash.size() == 64U &&
        std::all_of(descriptor_hash.begin(), descriptor_hash.end(),
                    [](const char character) {
                        return (character >= '0' && character <= '9') ||
                               (character >= 'a' && character <= 'f') ||
                               (character >= 'A' && character <= 'F');
                    }));
    if (!IsSafeSessionId(result.session_id) ||
        !IsSafeSessionId(result.user_id) || result.qpc_frequency <= 0 ||
        !std::isfinite(result.trainer_sensitivity) ||
        result.trainer_sensitivity <
            protocol::V1Constants::minimum_trainer_sensitivity ||
        result.trainer_sensitivity >
            protocol::V1Constants::maximum_trainer_sensitivity ||
        (device.At("identity_scope").AsString() !=
             "certified_usb_device" &&
         device.At("identity_scope").AsString() !=
             "certified_interrupt_endpoint") ||
        (endpoint_value != 0U &&
         ((endpoint_value & 0x80U) == 0U ||
          (endpoint_value & 0x0fU) == 0U ||
          (endpoint_value & 0x70U) != 0U)) ||
        !descriptor_is_hex) {
        throw std::runtime_error(
            "abandoned session manifest identity is invalid");
    }
    return result;
}

[[nodiscard]] std::filesystem::path UniqueUnverifiedPath(
    const std::filesystem::path& source) {
    auto candidate = source;
    candidate += L".unverified";
    if (!std::filesystem::exists(candidate)) return candidate;
    for (unsigned index = 1U; index < 10'000U; ++index) {
        candidate = source;
        candidate += L".unverified." + std::to_wstring(index);
        if (!std::filesystem::exists(candidate)) return candidate;
    }
    throw std::runtime_error("unverified artifact name limit exceeded");
}

void DurableMove(const std::filesystem::path& source,
                 const std::filesystem::path& destination) {
    if (std::filesystem::exists(destination)) {
        throw std::runtime_error(
            "recovery destination already exists");
    }
    if (!MoveFileExW(source.c_str(), destination.c_str(),
                     MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error(
            "recovery artifact move failed with Win32 error " +
            std::to_string(GetLastError()));
    }
}

[[nodiscard]] std::filesystem::path PreserveUnverified(
    const std::filesystem::path& source) {
    const auto destination = UniqueUnverifiedPath(source);
    DurableMove(source, destination);
    return destination;
}

[[nodiscard]] bool IsSafeToken(const std::string_view value,
                               const std::size_t maximum = 128U) {
    if (value.empty() || value.size() > maximum) return false;
    return std::all_of(value.begin(), value.end(), [](const char character) {
        const auto c = static_cast<unsigned char>(character);
        return (c >= static_cast<unsigned char>('a') &&
                c <= static_cast<unsigned char>('z')) ||
               (c >= static_cast<unsigned char>('A') &&
                c <= static_cast<unsigned char>('Z')) ||
               (c >= static_cast<unsigned char>('0') &&
                c <= static_cast<unsigned char>('9')) ||
               c == static_cast<unsigned char>('-') ||
               c == static_cast<unsigned char>('_') ||
               c == static_cast<unsigned char>('.');
    });
}

void ValidateCommonIdentity(const json::Value& record,
                            const ExpectedIdentity& expected) {
    if (record.At("session_id").AsString() != expected.session_id ||
        record.At("user_id").AsString() != expected.user_id ||
        record.At("qpc_frequency").AsInt() != expected.qpc_frequency ||
        record.At("trainer_sensitivity").AsDouble() !=
            expected.trainer_sensitivity) {
        throw std::runtime_error(
            "gameplay record identity does not match its session manifest");
    }
}

void ValidateNonnegative(const std::int64_t value, const char* label) {
    if (value < 0) {
        throw std::runtime_error(std::string(label) + " is negative");
    }
}

void ValidateOptionalEventId(const json::Value& value) {
    if (!value.IsNull()) ValidateNonnegative(value.AsInt(), "event ID");
}

void ValidateUnsignedJson(const json::Value& value, const char* label) {
    if (std::holds_alternative<std::int64_t>(value.Data())) {
        ValidateNonnegative(value.AsInt(), label);
        return;
    }
    const auto& text = value.AsString();
    if (text.empty() || text.size() > 20U ||
        !std::all_of(text.begin(), text.end(), [](const char character) {
            return character >= '0' && character <= '9';
        })) {
        throw std::runtime_error(std::string(label) + " is not unsigned");
    }
    std::size_t consumed = 0U;
    (void)std::stoull(text, &consumed);
    if (consumed != text.size()) {
        throw std::runtime_error(std::string(label) + " is not canonical");
    }
}

void ValidateRenderEvidence(const json::Value& value) {
    const auto width = value.At("viewport_width_px").AsInt();
    const auto height = value.At("viewport_height_px").AsInt();
    const auto ppc_x = value.At("pixels_per_count_x").AsDouble();
    const auto ppc_y = value.At("pixels_per_count_y").AsDouble();
    const auto cpp_x = value.At("counts_per_pixel_x").AsDouble();
    const auto cpp_y = value.At("counts_per_pixel_y").AsDouble();
    const auto radians =
        value.At("effective_radians_per_count").AsDouble();
    const auto crosshair = value.At("crosshair_scale").AsDouble();
    const auto& revision = value.At("transform_revision").AsString();
    (void)value.At("target_highlight_enabled").AsBool();
    (void)value.At("fullscreen").AsBool();
    const auto reciprocal = [](const double left, const double right) {
        const auto product = left * right;
        return std::isfinite(product) &&
               std::abs(product - 1.0) <=
                   1.0e-9 * std::max(1.0, std::abs(product));
    };
    if (width <= 0 || width > 1'000'000 || height <= 0 ||
        height > 1'000'000 || !std::isfinite(ppc_x) ||
        !std::isfinite(ppc_y) || !std::isfinite(cpp_x) ||
        !std::isfinite(cpp_y) || ppc_x <= 0.0 || ppc_y <= 0.0 ||
        cpp_x <= 0.0 || cpp_y <= 0.0 || !reciprocal(ppc_x, cpp_x) ||
        !reciprocal(ppc_y, cpp_y) || !std::isfinite(radians) ||
        radians <= 0.0 || !std::isfinite(crosshair) ||
        crosshair < 0.25 || crosshair > 2.0 ||
        !IsSafeToken(revision)) {
        throw std::runtime_error(
            "presentation render evidence is invalid");
    }
}

[[nodiscard]] std::uint64_t ReadJsonlSemantically(
    const std::filesystem::path& path, const std::string_view schema,
    const std::function<void(const json::Value&)>& validate) {
    AppendOnlyJsonlReader reader(path, std::string(schema));
    std::uint64_t count = 0U;
    while (auto record = reader.Next()) {
        validate(*record);
        ++count;
    }
    return count;
}

[[nodiscard]] std::uint64_t ValidateEvents(
    const std::filesystem::path& path, const ExpectedIdentity& expected) {
    const auto events = ReadGameplayEvents(path);
    for (const auto& event : events) {
        const GameplayJournalIdentity identity{
            expected.session_id, expected.user_id, expected.qpc_frequency,
            expected.trainer_sensitivity};
        if (event.identity != identity) {
            throw std::runtime_error(
                "trainer event identity does not match the session manifest");
        }
    }
    return static_cast<std::uint64_t>(events.size());
}

[[nodiscard]] std::uint64_t ValidateBlocks(
    const std::filesystem::path& path, const ExpectedIdentity& expected) {
    const auto blocks = ReadGameplayBlockResults(path);
    for (const auto& block : blocks) {
        const GameplayJournalIdentity identity{
            expected.session_id, expected.user_id, expected.qpc_frequency,
            expected.trainer_sensitivity};
        if (block.identity != identity) {
            throw std::runtime_error(
                "block result identity does not match the session manifest");
        }
    }
    return static_cast<std::uint64_t>(blocks.size());
}

[[nodiscard]] std::uint64_t ValidateRawInputWitness(
    const std::filesystem::path& path, const ExpectedIdentity& expected) {
    return ReadJsonlSemantically(
        path, GameplayJournal::kRawInputWitnessSchema,
        [&expected](const json::Value& record) {
            ValidateCommonIdentity(record, expected);
            if (record.At("record_type").AsString() !=
                    "raw_input_witness_packet" ||
                record.At("authoritative").AsBool() ||
                record.At("authority").AsString() !=
                    "non_authoritative_windows_raw_input_witness" ||
                record.At("source").AsString() != "windows_raw_input" ||
                !IsSafeToken(record.At("device_token").AsString())) {
                throw std::runtime_error(
                    "Raw Input witness semantics are invalid");
            }
            (void)record.At("selected_device").AsBool();
            ValidateNonnegative(record.At("receipt_qpc").AsInt(),
                                "Raw Input receipt QPC");
            const auto dx = record.At("dx_counts").AsInt();
            const auto dy = record.At("dy_counts").AsInt();
            const auto flags = record.At("button_flags").AsInt();
            const auto data = record.At("button_data").AsInt();
            if (dx < std::numeric_limits<std::int32_t>::min() ||
                dx > std::numeric_limits<std::int32_t>::max() ||
                dy < std::numeric_limits<std::int32_t>::min() ||
                dy > std::numeric_limits<std::int32_t>::max() || flags < 0 ||
                static_cast<std::uint64_t>(flags) >
                    std::numeric_limits<std::uint32_t>::max() ||
                data < std::numeric_limits<std::int32_t>::min() ||
                data > std::numeric_limits<std::int32_t>::max()) {
                throw std::runtime_error(
                    "Raw Input witness numeric value is invalid");
            }
        });
}

[[nodiscard]] std::uint64_t ValidateLifecycle(
    const std::filesystem::path& path, const ExpectedIdentity& expected) {
    return ReadJsonlSemantically(
        path, GameplayJournal::kLifecycleSchema,
        [&expected](const json::Value& record) {
            ValidateCommonIdentity(record, expected);
            if (record.At("record_type").AsString() !=
                    "lifecycle_annotation" ||
                !IsSafeToken(record.At("name").AsString(), 64U) ||
                record.At("detail").AsString().size() > 2'048U) {
                throw std::runtime_error(
                    "lifecycle annotation semantics are invalid");
            }
            ValidateNonnegative(record.At("qpc").AsInt(),
                                "lifecycle QPC");
            ValidateOptionalEventId(record.At("event_id"));
            const auto& ordinal = record.At("block_ordinal");
            if (!ordinal.IsNull()) {
                const auto value = ordinal.AsInt();
                if (value < 0 || static_cast<std::size_t>(value) >=
                                     protocol::OrderedBlocksV1().size()) {
                    throw std::runtime_error(
                        "lifecycle block ordinal is invalid");
                }
            }
        });
}

[[nodiscard]] std::uint64_t ValidatePauses(
    const std::filesystem::path& path, const ExpectedIdentity& expected) {
    return ReadJsonlSemantically(
        path, GameplayJournal::kPauseSchema,
        [&expected](const json::Value& record) {
            ValidateCommonIdentity(record, expected);
            if (record.At("record_type").AsString() != "pause_annotation" ||
                !IsSafeToken(record.At("reason").AsString(), 64U)) {
                throw std::runtime_error("pause annotation semantics are invalid");
            }
            (void)record.At("paused").AsBool();
            ValidateNonnegative(record.At("qpc").AsInt(), "pause QPC");
            ValidateOptionalEventId(record.At("event_id"));
        });
}

[[nodiscard]] std::uint64_t ValidateFocus(
    const std::filesystem::path& path, const ExpectedIdentity& expected) {
    return ReadJsonlSemantically(
        path, GameplayJournal::kFocusSchema,
        [&expected](const json::Value& record) {
            ValidateCommonIdentity(record, expected);
            if (record.At("record_type").AsString() != "focus_annotation") {
                throw std::runtime_error("focus annotation semantics are invalid");
            }
            (void)record.At("focused").AsBool();
            (void)record.At("minimized").AsBool();
            ValidateNonnegative(record.At("qpc").AsInt(), "focus QPC");
            ValidateOptionalEventId(record.At("event_id"));
        });
}

[[nodiscard]] std::uint64_t ValidatePresentation(
    const std::filesystem::path& path, const ExpectedIdentity& expected) {
    return ReadJsonlSemantically(
        path, GameplayJournal::kPresentationSchema,
        [&expected](const json::Value& record) {
            ValidateCommonIdentity(record, expected);
            if (record.At("record_type").AsString() !=
                    "presentation_annotation" ||
                record.At("detail").AsString().size() > 2'048U) {
                throw std::runtime_error(
                    "presentation annotation semantics are invalid");
            }
            ValidateNonnegative(record.At("qpc").AsInt(),
                                "presentation QPC");
            ValidateNonnegative(record.At("event_id").AsInt(),
                                "presentation event ID");
            (void)record.At("successful").AsBool();
            ValidateRenderEvidence(record.At("render_evidence"));
        });
}

[[nodiscard]] std::uint64_t ValidateClockAnchors(
    const std::filesystem::path& path, const ExpectedIdentity& expected) {
    const auto records = ReadClockJournal(path);
    for (const auto& record : records) {
        if (record.qpc_frequency != expected.qpc_frequency) {
            throw std::runtime_error(
                "clock journal frequency does not match the session manifest");
        }
    }
    return static_cast<std::uint64_t>(records.size());
}

[[nodiscard]] std::uint64_t ValidateCaptureAnomalies(
    const std::filesystem::path& path) {
    return ReadJsonlSemantically(
        path, "abcurves.capture.anomaly.v1",
        [](const json::Value& record) {
            if (!IsSafeToken(record.At("code").AsString(), 128U) ||
                record.At("detail").AsString().size() > 4'096U) {
                throw std::runtime_error(
                    "capture anomaly semantics are invalid");
            }
            ValidateUnsignedJson(record.At("pcap_sequence"),
                                 "anomaly PCAP sequence");
            ValidateUnsignedJson(record.At("irp_id"), "anomaly IRP ID");
            ValidateNonnegative(record.At("observed_qpc").AsInt(),
                                "anomaly observation QPC");
            const auto& timestamp = record.At("capture_unix_ns");
            if (!timestamp.IsNull()) (void)timestamp.AsInt();
        });
}

[[nodiscard]] ArtifactRecovery RecoverJournal(
    std::string kind, const std::filesystem::path& partial_path,
    const std::filesystem::path& final_path, const std::string_view schema,
    const Validator& validate) {
    ArtifactRecovery result;
    result.kind = std::move(kind);

    if (std::filesystem::exists(final_path)) {
        try {
            result.record_count = validate(final_path);
            result.published_path = final_path;
            result.state = "final_already_present";
            result.detail = "existing final artifact passed semantic validation";
            if (std::filesystem::exists(partial_path)) {
                result.unverified_path = PreserveUnverified(partial_path);
                ++result.warning_count;
                result.state = "final_valid_unexpected_partial_preserved";
                result.detail +=
                    "; an unexpected second partial was preserved separately";
            }
            return result;
        } catch (const std::exception& error) {
            result.unverified_path = PreserveUnverified(final_path);
            ++result.warning_count;
            result.detail =
                std::string("existing final artifact was invalid and preserved: ") +
                error.what();
        }
    }

    if (!std::filesystem::exists(partial_path)) {
        if (result.unverified_path.empty()) {
            result.state = "missing";
            result.detail = "artifact was not created before the session stopped";
            ++result.warning_count;
        } else {
            result.state = "invalid_preserved";
        }
        return result;
    }

    try {
        const auto tail = RecoverJsonlPartial(partial_path, std::string(schema));
        if (tail.trimmed_incomplete_tail) ++result.warning_count;
        DurableMove(partial_path, final_path);
        result.record_count = validate(final_path);
        result.published_path = final_path;
        result.state = "verified_prefix_published";
        result.detail += result.detail.empty() ? std::string{} : "; ";
        result.detail += tail.trimmed_incomplete_tail
            ? "incomplete tail trimmed; verified prefix published"
            : "complete framed prefix published";
    } catch (const std::exception& error) {
        const auto failed_path = std::filesystem::exists(final_path)
            ? final_path
            : partial_path;
        if (std::filesystem::exists(failed_path)) {
            const auto preserved = PreserveUnverified(failed_path);
            if (result.unverified_path.empty()) result.unverified_path = preserved;
        }
        ++result.warning_count;
        result.state = "invalid_preserved";
        result.detail += result.detail.empty() ? std::string{} : "; ";
        result.detail +=
            std::string("verification failed; bytes preserved: ") + error.what();
    }
    return result;
}

[[nodiscard]] ArtifactRecovery ValidateRecoveredCaptureArtifact(
    std::string kind, const std::filesystem::path& path,
    const Validator& validate) {
    ArtifactRecovery result;
    result.kind = std::move(kind);
    if (!std::filesystem::exists(path)) {
        result.state = "missing";
        result.detail = "no published capture artifact survived recovery";
        return result;
    }
    try {
        result.record_count = validate(path);
        result.published_path = path;
        result.state = "semantic_validation_passed";
        result.detail = "published capture artifact passed strict reading";
    } catch (const std::exception& error) {
        result.unverified_path = PreserveUnverified(path);
        result.warning_count = 1U;
        result.state = "semantic_validation_failed_preserved";
        result.detail =
            std::string("published capture artifact was invalid and preserved: ") +
            error.what();
    }
    return result;
}

[[nodiscard]] std::optional<ArtifactRecovery> QuarantineInvalidFinal(
    std::string kind, const std::filesystem::path& final_path,
    const Validator& validate) {
    if (!std::filesystem::exists(final_path)) return std::nullopt;
    try {
        (void)validate(final_path);
        return std::nullopt;
    } catch (const std::exception& error) {
        ArtifactRecovery result;
        result.kind = std::move(kind);
        result.unverified_path = PreserveUnverified(final_path);
        result.warning_count = 1U;
        result.state = "invalid_existing_final_quarantined";
        result.detail =
            std::string("invalid final was quarantined before prefix recovery: ") +
            error.what();
        return result;
    }
}

[[nodiscard]] std::string RelativeOrEmpty(
    const std::filesystem::path& root, const std::filesystem::path& path) {
    return path.empty() ? std::string{}
                        : std::filesystem::relative(path, root).generic_string();
}

void AddArtifactJson(json::Value::Array& artifacts,
                     const std::filesystem::path& root,
                     const ArtifactRecovery& artifact) {
    json::Value value = json::Value::Object{};
    value["kind"] = artifact.kind;
    value["state"] = artifact.state;
    value["published_path"] =
        RelativeOrEmpty(root, artifact.published_path);
    value["unverified_path"] =
        RelativeOrEmpty(root, artifact.unverified_path);
    value["record_count"] = std::to_string(artifact.record_count);
    value["warning_count"] =
        static_cast<std::int64_t>(artifact.warning_count);
    value["detail"] = artifact.detail;
    artifacts.push_back(std::move(value));
}

void AddCaptureRecoveryJson(json::Value::Array& artifacts,
                            const std::filesystem::path& root,
                            const RecoveredArtifact& artifact) {
    json::Value value = json::Value::Object{};
    value["kind"] = artifact.kind + "_framing_recovery";
    value["state"] = ToString(artifact.state);
    value["published_path"] =
        RelativeOrEmpty(root, artifact.published_path);
    value["unverified_path"] =
        RelativeOrEmpty(root, artifact.unverified_path);
    value["record_count"] = std::to_string(artifact.record_count);
    value["original_bytes"] = std::to_string(artifact.original_bytes);
    value["retained_bytes"] = std::to_string(artifact.retained_bytes);
    value["detail"] = artifact.detail;
    artifacts.push_back(std::move(value));
}

[[nodiscard]] std::vector<ArtifactRecovery> PreserveUnknownPartials(
    const std::filesystem::path& root) {
    std::vector<std::filesystem::path> unfinished;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
        const auto extension = entry.path().extension();
        if (extension == L".partial" || extension == L".tmp") {
            unfinished.push_back(entry.path());
        }
    }
    std::sort(unfinished.begin(), unfinished.end());
    std::vector<ArtifactRecovery> result;
    result.reserve(unfinished.size());
    for (const auto& path : unfinished) {
        ArtifactRecovery artifact;
        artifact.kind = "unexpected_unfinished_artifact";
        artifact.unverified_path = PreserveUnverified(path);
        artifact.warning_count = 1U;
        artifact.state = "unverified_bytes_preserved";
        artifact.detail =
            "unknown unfinished artifact was preserved without interpretation";
        result.push_back(std::move(artifact));
    }
    return result;
}

[[nodiscard]] bool IsCandidateName(const std::filesystem::path& path) {
    const auto filename = path.filename().string();
    constexpr std::string_view prefix = "session_";
    constexpr std::string_view suffix = ".partial";
    if (!filename.starts_with(prefix) || !filename.ends_with(suffix) ||
        filename.size() <= prefix.size() + suffix.size()) {
        return false;
    }
    const auto id = std::string_view(filename).substr(
        prefix.size(), filename.size() - prefix.size() - suffix.size());
    return IsSafeSessionId(id);
}

[[nodiscard]] std::optional<std::string> SealedCandidateId(
    const std::filesystem::path& path) {
    const auto filename = path.filename().string();
    constexpr std::string_view prefix = "session_";
    if (!filename.starts_with(prefix) ||
        filename.size() <= prefix.size()) {
        return std::nullopt;
    }
    const auto id = filename.substr(prefix.size());
    if (!IsSafeSessionId(id)) return std::nullopt;
    return id;
}

[[nodiscard]] std::uint64_t ParseUnsignedDecimal(
    const json::Value& value, const char* label) {
    const auto& text = value.AsString();
    if (text.empty() || text.size() > 20U ||
        !std::all_of(text.begin(), text.end(), [](const char character) {
            return character >= '0' && character <= '9';
        })) {
        throw std::runtime_error(std::string(label) + " is not unsigned");
    }
    std::size_t consumed = 0U;
    const auto result = std::stoull(text, &consumed);
    if (consumed != text.size()) {
        throw std::runtime_error(std::string(label) + " is not canonical");
    }
    return result;
}

[[nodiscard]] bool IsRegularNonReparseFile(
    const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(status) ||
        status.type() != std::filesystem::file_type::regular) {
        return false;
    }
    return !IsReparsePoint(path);
}

[[nodiscard]] AbandonedSessionRecoveryResult RecoverMissingArchive(
    const std::filesystem::path& sealed_session,
    const std::string& session_id) {
    AbandonedSessionRecoveryResult result;
    result.partial_workspace = sealed_session;
    result.sealed_session = sealed_session;
    result.status = SessionStatus::Interrupted;
    try {
        auto lease = AcquireSealedRecoveryLease(
            sealed_session.parent_path(), session_id);
        (void)lease;
        PreflightWorkspace(sealed_session);
        const auto validated = ValidateSealedSession(sealed_session);
        if (validated.session_id != session_id) {
            throw std::runtime_error(
                "sealed session identity changed during archive recovery");
        }
        result.status = validated.status;

        const auto manifest = json::Parse(
            ReadUtf8File(sealed_session / "manifest.json"));
        result.verified_authoritative_source =
            manifest.At("verified_authoritative_source").AsBool();
        result.raw_pcap_records = ParseUnsignedDecimal(
            manifest.At("raw_pcap_records"), "raw PCAP record count");
        result.decoded_reports = ParseUnsignedDecimal(
            manifest.At("decoded_reports"), "decoded report count");
        const auto event_count = manifest.At("event_count").AsInt();
        const auto warning_count = manifest.At("warning_count").AsInt();
        if (event_count < 0 || warning_count < 0) {
            throw std::runtime_error(
                "sealed session contains a negative scientific count");
        }
        result.gameplay_events = static_cast<std::uint64_t>(event_count);
        result.warning_count = static_cast<std::uint64_t>(warning_count);

        const auto archive = SubmissionArchivePath(sealed_session);
        const auto archive_status = std::filesystem::symlink_status(archive);
        if (archive_status.type() != std::filesystem::file_type::not_found &&
            !IsRegularNonReparseFile(archive)) {
            throw std::runtime_error(
                "expected submission archive path is occupied by an unsafe entry");
        }
        if (archive_status.type() == std::filesystem::file_type::not_found) {
            try {
                (void)CreateSessionArchive(sealed_session, archive);
            } catch (const std::exception&) {
                // The normal finalizer may have published the same canonical
                // archive after this scan observed it missing. Its publication
                // is atomic, so accepting the winner is safe only after the
                // same independent archive validation below.
                if (!IsRegularNonReparseFile(archive)) throw;
            }
        }
        const auto archive_validation = ValidateSessionArchive(archive);
        if (!archive_validation.valid || !archive_validation.session ||
            archive_validation.session->session_id != session_id ||
            archive_validation.session->status != result.status) {
            throw std::runtime_error(
                "completed submission archive failed independent validation: " +
                archive_validation.error);
        }
        result.archive = archive;
        result.state = AbandonedRecoveryState::Recovered;
        result.detail =
            "Completed and validated the missing archive for an already sealed session.";
        return result;
    } catch (const SessionLeaseError& error) {
        result.state = error.failure() == SessionLeaseFailure::Busy
            ? AbandonedRecoveryState::SkippedActiveWriter
            : AbandonedRecoveryState::Failed;
        result.detail = error.what();
        return result;
    } catch (const std::exception& error) {
        result.state = AbandonedRecoveryState::Failed;
        result.detail = error.what();
        return result;
    }
}

}  // namespace

AbandonedSessionRecoveryResult RecoverAbandonedSession(
    const std::filesystem::path& partial_workspace,
    const std::int64_t ended_utc_ns) {
    AbandonedSessionRecoveryResult result;
    std::error_code absolute_error;
    result.partial_workspace =
        std::filesystem::absolute(partial_workspace, absolute_error);
    if (absolute_error) result.partial_workspace = partial_workspace;
    result.status = SessionStatus::Interrupted;
    if (ended_utc_ns <= 0) {
        result.detail = "recovery end time is invalid";
        return result;
    }

    try {
        // OpenAbandoned acquires and retains the exclusive OS lease before it
        // reads the workspace. Nothing below runs while a participant or
        // elevated capture helper still owns a shared writer lease.
        auto workspace = SessionWorkspace::OpenAbandoned(
            result.partial_workspace);
        PreflightWorkspace(workspace.Path());
        const auto expected = ReadExpectedIdentity(workspace.Path());
        json::Value::Array recovery_artifacts;
        std::uint64_t warnings = 1U;  // The abandoned-session incident itself.

        const auto capture_paths =
            acquisition::OutputPathsIn(workspace.CaptureDirectory());
        const std::array<std::optional<ArtifactRecovery>, 3> quarantined{
            QuarantineInvalidFinal(
                "device_pcap_pre_recovery_validation",
                capture_paths.device_pcap_final,
                [&expected](const auto& path) {
                    return ValidateDevicePcap(path, expected.capture);
                }),
            QuarantineInvalidFinal(
                "decoded_reports_pre_recovery_validation",
                capture_paths.reports_final,
                [&expected](const auto& path) {
                    return ValidateDecodedReportStream(path, expected.capture);
                }),
            QuarantineInvalidFinal(
                "capture_anomalies_pre_recovery_validation",
                capture_paths.anomalies_final, ValidateCaptureAnomalies),
        };
        for (const auto& artifact : quarantined) {
            if (!artifact) continue;
            warnings += artifact->warning_count;
            AddArtifactJson(recovery_artifacts, workspace.Path(), *artifact);
        }

        const auto capture_recovery =
            RecoverCapturePrefix(workspace.CaptureDirectory());
        warnings += capture_recovery.warning_count;
        for (const auto& artifact : capture_recovery.artifacts) {
            AddCaptureRecoveryJson(recovery_artifacts, workspace.Path(),
                                   artifact);
        }

        auto pcap = ValidateRecoveredCaptureArtifact(
            "device_pcap_semantic_validation",
            capture_paths.device_pcap_final,
            [&expected](const auto& path) {
                return ValidateDevicePcap(path, expected.capture);
            });
        warnings += pcap.warning_count;
        result.raw_pcap_records = pcap.record_count;
        result.verified_authoritative_source =
            !pcap.published_path.empty() && pcap.record_count != 0U;
        AddArtifactJson(recovery_artifacts, workspace.Path(), pcap);

        auto reports = ValidateRecoveredCaptureArtifact(
            "decoded_reports_semantic_validation", capture_paths.reports_final,
            [&expected](const auto& path) {
                return ValidateDecodedReportStream(path, expected.capture);
            });
        warnings += reports.warning_count;
        result.decoded_reports = reports.record_count;
        AddArtifactJson(recovery_artifacts, workspace.Path(), reports);

        auto anomalies = ValidateRecoveredCaptureArtifact(
            "capture_anomalies_semantic_validation",
            capture_paths.anomalies_final, ValidateCaptureAnomalies);
        warnings += anomalies.warning_count;
        AddArtifactJson(recovery_artifacts, workspace.Path(), anomalies);

        const auto gameplay = workspace.GameplayDirectory();
        std::vector<ArtifactRecovery> journals;
        journals.push_back(RecoverJournal(
            "gameplay_events", gameplay / "events.jsonl.partial",
            gameplay / "events.jsonl", GameplayJournal::kEventSchema,
            [&expected](const auto& path) {
                return ValidateEvents(path, expected);
            }));
        journals.push_back(RecoverJournal(
            "gameplay_blocks", gameplay / "blocks.jsonl.partial",
            gameplay / "blocks.jsonl", GameplayJournal::kBlockSchema,
            [&expected](const auto& path) {
                return ValidateBlocks(path, expected);
            }));
        journals.push_back(RecoverJournal(
            "raw_input_witness",
            gameplay / "raw_input_witness.jsonl.partial",
            gameplay / "raw_input_witness.jsonl",
            GameplayJournal::kRawInputWitnessSchema,
            [&expected](const auto& path) {
                return ValidateRawInputWitness(path, expected);
            }));
        journals.push_back(RecoverJournal(
            "lifecycle", gameplay / "lifecycle.jsonl.partial",
            gameplay / "lifecycle.jsonl", GameplayJournal::kLifecycleSchema,
            [&expected](const auto& path) {
                return ValidateLifecycle(path, expected);
            }));
        journals.push_back(RecoverJournal(
            "pauses", gameplay / "pauses.jsonl.partial",
            gameplay / "pauses.jsonl", GameplayJournal::kPauseSchema,
            [&expected](const auto& path) {
                return ValidatePauses(path, expected);
            }));
        journals.push_back(RecoverJournal(
            "focus", gameplay / "focus.jsonl.partial",
            gameplay / "focus.jsonl", GameplayJournal::kFocusSchema,
            [&expected](const auto& path) {
                return ValidateFocus(path, expected);
            }));
        journals.push_back(RecoverJournal(
            "presentation", gameplay / "presentation.jsonl.partial",
            gameplay / "presentation.jsonl",
            GameplayJournal::kPresentationSchema,
            [&expected](const auto& path) {
                return ValidatePresentation(path, expected);
            }));
        for (const auto& journal : journals) {
            if (journal.kind == "gameplay_events") {
                result.gameplay_events = journal.record_count;
            }
            warnings += journal.warning_count;
            AddArtifactJson(recovery_artifacts, workspace.Path(), journal);
        }

        auto clocks = RecoverJournal(
            "clock_anchors",
            workspace.ClocksDirectory() / "anchors.jsonl.partial",
            workspace.ClocksDirectory() / "anchors.jsonl",
            ClockJournal::kSchema,
            [&expected](const auto& path) {
                return ValidateClockAnchors(path, expected);
            });
        warnings += clocks.warning_count;
        AddArtifactJson(recovery_artifacts, workspace.Path(), clocks);

        for (const auto& unknown : PreserveUnknownPartials(workspace.Path())) {
            warnings += unknown.warning_count;
            AddArtifactJson(recovery_artifacts, workspace.Path(), unknown);
        }

        result.status = result.verified_authoritative_source
            ? SessionStatus::CaptureLost
            : SessionStatus::Interrupted;
        result.warning_count = warnings;

        json::Value recovery = json::Value::Object{};
        recovery["schema"] = std::string(kRecoverySchema);
        recovery["ended_utc_ns"] = std::to_string(ended_utc_ns);
        recovery["status"] = ToString(result.status);
        recovery["verified_authoritative_source"] =
            result.verified_authoritative_source;
        recovery["raw_pcap_records"] =
            std::to_string(result.raw_pcap_records);
        recovery["decoded_reports"] =
            std::to_string(result.decoded_reports);
        recovery["gameplay_events"] =
            std::to_string(result.gameplay_events);
        recovery["warning_count"] =
            static_cast<std::int64_t>(warnings);
        recovery["artifacts"] = std::move(recovery_artifacts);
        AtomicWriteFile(workspace.Path() / "recovery.json",
                        json::DumpCanonical(recovery, true) + "\n");

        workspace.UpdateRuntimeSummary(
            result.gameplay_events, warnings,
            "abandoned session recovered without resuming gameplay");
        SessionSealOptions seal_options;
        seal_options.status = result.status;
        seal_options.ended_utc_ns = ended_utc_ns;
        seal_options.raw_pcap_records = result.raw_pcap_records;
        seal_options.decoded_reports = result.decoded_reports;
        seal_options.gameplay_events = result.gameplay_events;
        seal_options.warning_count = warnings;
        seal_options.recovery_was_required = true;
        seal_options.verified_authoritative_source =
            result.verified_authoritative_source;
        seal_options.stop_reason = "abandoned_session_recovered";
        const auto sealed = workspace.Seal(seal_options);
        result.sealed_session = sealed.directory;
        (void)ValidateSealedSession(sealed.directory);

        const auto archive_path = SubmissionArchivePath(sealed.directory);
        const auto archive =
            CreateSessionArchive(sealed.directory, archive_path);
        result.archive = archive.path;
        const auto archive_validation = ValidateSessionArchive(archive.path);
        if (!archive_validation.valid || !archive_validation.session ||
            archive_validation.session->session_id != expected.session_id ||
            archive_validation.session->status != result.status) {
            throw std::runtime_error(
                "recovered session archive did not pass independent validation: " +
                archive_validation.error);
        }

        // workspace remains alive here, so its exclusive lease covers the
        // entire seal, archive creation, and archive validation sequence.
        result.state = AbandonedRecoveryState::Recovered;
        result.detail = result.verified_authoritative_source
            ? "Recovered and archived a verified authoritative PCAP prefix."
            : "Recovered and archived metadata without claiming a verified "
              "authoritative PCAP prefix.";
        return result;
    } catch (const SessionLeaseError& error) {
        result.state = error.failure() == SessionLeaseFailure::Busy
            ? AbandonedRecoveryState::SkippedActiveWriter
            : AbandonedRecoveryState::Failed;
        result.detail = error.what();
        return result;
    } catch (const std::exception& error) {
        result.state = AbandonedRecoveryState::Failed;
        result.detail = error.what();
        return result;
    }
}

std::vector<AbandonedSessionRecoveryResult> RecoverAbandonedSessions(
    const std::filesystem::path& sessions_root,
    const std::int64_t ended_utc_ns) {
    const auto root = std::filesystem::absolute(sessions_root);
    if (!std::filesystem::exists(root)) return {};
    const auto root_status = std::filesystem::symlink_status(root);
    if (std::filesystem::is_symlink(root_status) || IsReparsePoint(root) ||
        root_status.type() != std::filesystem::file_type::directory) {
        throw std::invalid_argument(
            "session recovery root must be a regular existing directory");
    }

    std::vector<std::filesystem::path> candidates;
    std::vector<std::pair<std::filesystem::path, std::string>>
        sealed_candidates;
    std::vector<AbandonedSessionRecoveryResult> results;
    for (const auto& entry : std::filesystem::directory_iterator(root)) {
        const bool partial_candidate = IsCandidateName(entry.path());
        const auto sealed_id = SealedCandidateId(entry.path());
        if (!partial_candidate && !sealed_id) continue;
        const auto status = entry.symlink_status();
        if (std::filesystem::is_symlink(status) ||
            IsReparsePoint(entry.path()) ||
            status.type() != std::filesystem::file_type::directory) {
            AbandonedSessionRecoveryResult rejected;
            rejected.partial_workspace = entry.path();
            rejected.state = AbandonedRecoveryState::Failed;
            rejected.detail =
                "session recovery candidate is a link, reparse point, or "
                "non-directory and was not inspected";
            results.push_back(std::move(rejected));
            continue;
        }
        if (partial_candidate) {
            candidates.push_back(entry.path());
            continue;
        }
        const auto archive = SubmissionArchivePath(entry.path());
        const auto archive_status = std::filesystem::symlink_status(archive);
        if (archive_status.type() == std::filesystem::file_type::regular &&
            IsRegularNonReparseFile(archive)) {
            continue;
        }
        sealed_candidates.emplace_back(entry.path(), *sealed_id);
    }
    std::sort(candidates.begin(), candidates.end());
    for (const auto& candidate : candidates) {
        results.push_back(RecoverAbandonedSession(candidate, ended_utc_ns));
    }
    std::sort(sealed_candidates.begin(), sealed_candidates.end());
    for (const auto& [candidate, session_id] : sealed_candidates) {
        results.push_back(RecoverMissingArchive(candidate, session_id));
    }
    std::sort(results.begin(), results.end(), [](const auto& left,
                                                  const auto& right) {
        return left.partial_workspace < right.partial_workspace;
    });
    return results;
}

}  // namespace abdc::session
