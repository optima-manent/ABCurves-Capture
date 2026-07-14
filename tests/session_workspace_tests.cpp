#include "TestHarness.h"

#include "base/AtomicFile.h"
#include "base/Json.h"
#include "session/AbandonedSessionRecovery.h"
#include "session/SessionArchive.h"
#include "session/SessionValidator.h"
#include "session/SessionWorkspace.h"
#include "session/PseudonymousIdentity.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string_view>

namespace {

std::filesystem::path TempRoot() {
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() /
        ("abcurves_session_" + std::to_string(suffix));
    std::filesystem::create_directories(path);
    return path;
}

abdc::session::SessionCreateOptions Options(const std::filesystem::path& root) {
    abdc::session::SessionCreateOptions options;
    options.output_root = root;
    options.session_id = "01j2-session-test";
    options.user_id = "01j2-user-test";
    options.application_version = "0.2.0-test";
    options.source_revision = "test";
    options.protocol_id = "aim-protocol-v2";
    options.protocol_sha256 = std::string(64U, 'a');
    options.scenario_seed = 42U;
    options.trainer_sensitivity = 1.25;
    options.qpc_frequency = 10'000'000;
    options.started_utc_ns = 1'700'000'000'000'000'000LL;
    options.device = abdc::json::Value::Object{{"product", "Mouse"}};
    return options;
}

}  // namespace

TEST_CASE("session workspace seals warning and interrupted evidence without grading it") {
    using namespace abdc::session;
    const auto root = TempRoot();
    auto workspace = SessionWorkspace::Create(Options(root));
    abdc::AtomicWriteFile(workspace.CaptureDirectory() / "mouse.pcap", "raw-usb");
    abdc::AtomicWriteFile(workspace.GameplayDirectory() / "events.jsonl", "event\n");
    abdc::AtomicWriteFile(workspace.ClocksDirectory() / "anchors.jsonl", "anchor\n");
    workspace.UpdateRuntimeSummary(1U, 2U, "capture completed with annotations");
    SessionSealOptions seal;
    seal.status = SessionStatus::CompleteWithWarnings;
    seal.ended_utc_ns = 1'700'000'001'000'000'000LL;
    seal.raw_pcap_records = 2U;
    seal.decoded_reports = 1U;
    seal.gameplay_events = 1U;
    seal.warning_count = 2U;
    seal.stop_reason = "participant_finished";
    const auto result = workspace.Seal(seal);
    EXPECT_EQ(result.status, SessionStatus::CompleteWithWarnings);
    EXPECT_TRUE(std::filesystem::exists(result.directory / "COMPLETE"));
    EXPECT_TRUE(std::filesystem::exists(result.directory / "checksums.sha256"));
    EXPECT_TRUE(!std::filesystem::exists(root / "session_01j2-session-test.partial"));
    EXPECT_TRUE(result.artifacts.size() >= 4U);
    {
        std::ifstream manifest_file(result.directory / "manifest.json");
        std::ostringstream manifest_text;
        manifest_text << manifest_file.rdbuf();
        const auto manifest = abdc::json::Parse(manifest_text.str());
        EXPECT_EQ(manifest.At("status").AsString(),
                  std::string("complete_with_warnings"));
    }
    const auto validated = ValidateSealedSession(result.directory);
    EXPECT_EQ(validated.session_id, std::string("01j2-session-test"));
    EXPECT_EQ(validated.status, SessionStatus::CompleteWithWarnings);
    EXPECT_EQ(validated.artifacts.size(), result.artifacts.size());
    const auto archive_path = SubmissionArchivePath(result.directory);
    const auto archive = CreateSessionArchive(result.directory, archive_path);
    EXPECT_TRUE(std::filesystem::exists(archive.path));
    EXPECT_TRUE(archive.member_count >= validated.artifacts.size() + 2U);
    const auto archive_validation = ValidateSessionArchive(archive.path);
    EXPECT_TRUE(archive_validation.valid);
    EXPECT_TRUE(archive_validation.session.has_value());
    EXPECT_EQ(archive_validation.session->session_id,
              std::string("01j2-session-test"));
    workspace.ReleaseFinalizationLease();
    const auto second_archive =
        CreateSessionArchive(result.directory, root / "deterministic-copy.zip");
    EXPECT_EQ(second_archive.sha256, archive.sha256);
    abdc::AtomicWriteFile(result.directory / "capture" / "mouse.pcap", "tampered");
    EXPECT_THROW(ValidateSealedSession(result.directory));
    std::filesystem::remove_all(root);
}

TEST_CASE("submission ZIP Deflate is compact deterministic and lossless") {
    using namespace abdc::session;
    const auto root = TempRoot();
    auto workspace = SessionWorkspace::Create(Options(root));

    std::string repetitive_source;
    constexpr std::string_view record =
        "{\"device\":\"selected_mouse\",\"dx\":1,\"dy\":-1,\"qpc\":123456789}\n";
    repetitive_source.reserve(record.size() * 65'536U);
    for (std::size_t index = 0U; index < 65'536U; ++index) {
        repetitive_source.append(record);
    }
    abdc::AtomicWriteFile(
        workspace.GameplayDirectory() / "raw_input_witness.jsonl",
        repetitive_source);
    // Empty and incompressible members use the stored method, which also
    // keeps legacy stored-member validation exercised in normal tests.
    abdc::AtomicWriteFile(workspace.CaptureDirectory() / "empty.jsonl", "");

    SessionSealOptions seal;
    seal.status = SessionStatus::Complete;
    seal.ended_utc_ns = 1'700'000'001'000'000'000LL;
    seal.stop_reason = "participant_finished";
    const auto sealed = workspace.Seal(seal);
    const auto first = CreateSessionArchive(
        sealed.directory, SubmissionArchivePath(sealed.directory));
    EXPECT_TRUE(first.size_bytes < repetitive_source.size() / 10U);
    const auto validated = ValidateSessionArchive(first.path);
    EXPECT_TRUE(validated.valid);
    EXPECT_TRUE(validated.session.has_value());
    EXPECT_EQ(validated.session->session_id, std::string("01j2-session-test"));

    workspace.ReleaseFinalizationLease();
    const auto second =
        CreateSessionArchive(sealed.directory, root / "deterministic-deflate.zip");
    EXPECT_EQ(second.sha256, first.sha256);

    const auto tampered_path = root / "tampered-deflate.zip";
    std::filesystem::copy_file(first.path, tampered_path);
    {
        std::fstream tampered(
            tampered_path, std::ios::binary | std::ios::in | std::ios::out);
        EXPECT_TRUE(static_cast<bool>(tampered));
        std::array<unsigned char, 30U> local_header{};
        tampered.read(reinterpret_cast<char*>(local_header.data()),
                      static_cast<std::streamsize>(local_header.size()));
        EXPECT_EQ(tampered.gcount(),
                  static_cast<std::streamsize>(local_header.size()));
        const auto read_u16 = [&](const std::size_t offset) {
            return static_cast<std::uint16_t>(local_header[offset]) |
                   static_cast<std::uint16_t>(local_header[offset + 1U] << 8U);
        };
        const auto read_u32 = [&](const std::size_t offset) {
            return static_cast<std::uint32_t>(local_header[offset]) |
                   (static_cast<std::uint32_t>(local_header[offset + 1U]) << 8U) |
                   (static_cast<std::uint32_t>(local_header[offset + 2U]) << 16U) |
                   (static_cast<std::uint32_t>(local_header[offset + 3U]) << 24U);
        };
        EXPECT_EQ(read_u32(0U), std::uint32_t{0x04034b50U});
        EXPECT_EQ(read_u16(8U), std::uint16_t{8U});
        const auto compressed_size = read_u32(18U);
        EXPECT_TRUE(compressed_size > 0U);
        const auto payload_offset = 30U + read_u16(26U) + read_u16(28U);
        tampered.seekg(static_cast<std::streamoff>(
            payload_offset + compressed_size / 2U));
        char byte = 0;
        tampered.read(&byte, 1);
        EXPECT_EQ(tampered.gcount(), std::streamsize{1});
        byte = static_cast<char>(static_cast<unsigned char>(byte) ^ 0x40U);
        tampered.seekp(static_cast<std::streamoff>(
            payload_offset + compressed_size / 2U));
        tampered.write(&byte, 1);
        tampered.close();
        EXPECT_TRUE(static_cast<bool>(tampered));
    }
    EXPECT_TRUE(!ValidateSessionArchive(tampered_path).valid);
    std::filesystem::remove_all(root);
}

TEST_CASE("participant grouping key is random local and stable") {
    const auto root = TempRoot();
    const auto first = abdc::session::LoadOrCreateParticipantId(root);
    const auto second = abdc::session::LoadOrCreateParticipantId(root);
    EXPECT_EQ(first, second);
    EXPECT_TRUE(abdc::session::IsPseudonymousId(first, "u-"));
    const auto session = abdc::session::CreateSessionId();
    EXPECT_TRUE(abdc::session::IsPseudonymousId(session, "s-"));
    EXPECT_TRUE(session != first);
    std::filesystem::remove_all(root);
}

TEST_CASE("session lease excludes recovery until every writer releases it") {
    using namespace abdc::session;
    const auto root = TempRoot();
    const auto partial = root / "session_01j2-session-test.partial";
    const auto lease = root / ".leases" / "session_01j2-session-test.lock";
    HANDLE helper_lease = INVALID_HANDLE_VALUE;
    {
        auto writer = SessionWorkspace::Create(Options(root));
        EXPECT_EQ(writer.LeasePath(), lease);
        EXPECT_TRUE(std::filesystem::is_regular_file(lease));
        helper_lease = CreateFileW(
            lease.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        EXPECT_TRUE(helper_lease != INVALID_HANDLE_VALUE);
        bool busy = false;
        try {
            (void)SessionWorkspace::OpenAbandoned(partial);
        } catch (const SessionLeaseError& error) {
            busy = error.failure() == SessionLeaseFailure::Busy;
        }
        EXPECT_TRUE(busy);
    }

    // The participant writer is gone, but the independently held helper lease
    // still excludes recovery.
    bool helper_busy = false;
    try {
        (void)SessionWorkspace::OpenAbandoned(partial);
    } catch (const SessionLeaseError& error) {
        helper_busy = error.failure() == SessionLeaseFailure::Busy;
    }
    EXPECT_TRUE(helper_busy);
    EXPECT_TRUE(CloseHandle(helper_lease) != 0);

    {
        auto recovery = SessionWorkspace::OpenAbandoned(partial);
        bool busy = false;
        try {
            (void)SessionWorkspace::OpenAbandoned(partial);
        } catch (const SessionLeaseError& error) {
            busy = error.failure() == SessionLeaseFailure::Busy;
        }
        EXPECT_TRUE(busy);
    }

    std::filesystem::remove(lease);
    bool missing = false;
    try {
        (void)SessionWorkspace::OpenAbandoned(partial);
    } catch (const SessionLeaseError& error) {
        missing = error.failure() == SessionLeaseFailure::Missing;
    }
    EXPECT_TRUE(missing);
    std::filesystem::remove_all(root);
}

TEST_CASE("normal finalization lease covers the sealed archive publication window") {
    using namespace abdc::session;
    const auto root = TempRoot();
    std::filesystem::path sealed_directory;
    {
        auto writer = SessionWorkspace::Create(Options(root));
        abdc::AtomicWriteFile(writer.CaptureDirectory() / "mouse.pcap",
                              "raw-usb");
        SessionSealOptions seal;
        seal.status = SessionStatus::Interrupted;
        seal.ended_utc_ns = 1'700'000'001'000'000'000LL;
        seal.warning_count = 1U;
        seal.stop_reason = "test_archive_window";
        sealed_directory = writer.Seal(seal).directory;

        const auto while_writer_alive = RecoverAbandonedSessions(
            root, 1'700'000'001'100'000'000LL);
        EXPECT_EQ(while_writer_alive.size(), std::size_t{1});
        EXPECT_EQ(while_writer_alive.front().state,
                  AbandonedRecoveryState::SkippedActiveWriter);
        EXPECT_TRUE(!std::filesystem::exists(
            SubmissionArchivePath(sealed_directory)));
    }

    const auto after_writer_release = RecoverAbandonedSessions(
        root, 1'700'000'001'200'000'000LL);
    EXPECT_EQ(after_writer_release.size(), std::size_t{1});
    EXPECT_EQ(after_writer_release.front().state,
              AbandonedRecoveryState::Recovered);
    EXPECT_TRUE(std::filesystem::exists(
        SubmissionArchivePath(sealed_directory)));
    EXPECT_TRUE(ValidateSessionArchive(
        SubmissionArchivePath(sealed_directory)).valid);
    std::filesystem::remove_all(root);
}

TEST_CASE("abandoned finalization controls survive admission and are resealed") {
    using namespace abdc::session;
    const auto root = TempRoot();
    const auto partial = root / "session_01j2-session-test.partial";
    {
        auto writer = SessionWorkspace::Create(Options(root));
        abdc::AtomicWriteFile(writer.CaptureDirectory() / "mouse.pcap", "raw-usb");
    }

    auto manifest = abdc::json::Parse(abdc::ReadUtf8File(partial / "manifest.json"));
    manifest["status"] = "future_unknown_status";
    abdc::AtomicWriteFile(partial / "manifest.json",
                          abdc::json::DumpCanonical(manifest, true) + "\n");
    EXPECT_THROW(SessionWorkspace::OpenAbandoned(partial));

    manifest["status"] = "capture_lost";
    abdc::AtomicWriteFile(partial / "manifest.json",
                          abdc::json::DumpCanonical(manifest, true) + "\n");
    abdc::AtomicWriteFile(partial / "checksums.sha256", "stale\n");
    abdc::AtomicWriteFile(partial / "COMPLETE", "{\"stale\":true}\n");

    {
        auto recovery = SessionWorkspace::OpenAbandoned(partial);
        EXPECT_EQ(recovery.Path(), partial);
        EXPECT_TRUE(std::filesystem::exists(partial / "checksums.sha256"));
        EXPECT_TRUE(std::filesystem::exists(partial / "COMPLETE"));

        SessionSealOptions seal;
        seal.status = SessionStatus::Interrupted;
        seal.ended_utc_ns = 1'700'000'001'000'000'000LL;
        seal.warning_count = 1U;
        seal.recovery_was_required = true;
        seal.stop_reason = "abandoned_session_recovered";
        const auto sealed = recovery.Seal(seal);
        const auto validated = ValidateSealedSession(sealed.directory);
        EXPECT_EQ(validated.status, SessionStatus::Interrupted);
        EXPECT_EQ(validated.session_id, std::string("01j2-session-test"));
    }

    std::filesystem::remove_all(root);
}

TEST_CASE("abandoned admission rejects a reparse manifest before reading it") {
    using namespace abdc::session;
    const auto root = TempRoot();
    const auto partial = root / "session_01j2-session-test.partial";
    const auto manifest = partial / "manifest.json";
    const auto outside = root / "outside-manifest.json";
    {
        auto writer = SessionWorkspace::Create(Options(root));
    }
    std::filesystem::rename(manifest, outside);
    if (!CreateSymbolicLinkW(
            manifest.c_str(), outside.c_str(),
            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        // Older locked-down Windows configurations cannot create a test
        // symlink. Restore the fixture; production rejection remains based on
        // FILE_ATTRIBUTE_REPARSE_POINT rather than this optional facility.
        std::filesystem::rename(outside, manifest);
        std::filesystem::remove_all(root);
        return;
    }

    EXPECT_THROW(SessionWorkspace::OpenAbandoned(partial));
    EXPECT_TRUE(std::filesystem::is_regular_file(outside));
    std::filesystem::remove_all(root);
}
