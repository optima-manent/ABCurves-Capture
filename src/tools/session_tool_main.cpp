#include "base/BuildInfo.h"
#include "session/SessionArchive.h"
#include "session/SessionValidator.h"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

std::string Utf8(const std::filesystem::path& path) {
    const auto value = path.generic_u8string();
    return {reinterpret_cast<const char*>(value.data()), value.size()};
}

void PrintUsage() {
    std::cout
        << "ABCurves session tool\n"
        << "  abct_session_tool validate <session-directory-or-zip>\n"
        << "  abct_session_tool archive <sealed-session-directory> [output.zip]\n";
}

int Validate(const std::filesystem::path& input) {
    if (std::filesystem::is_directory(input)) {
        const auto session = abdc::session::ValidateSealedSession(input);
        std::cout << "VALID session=" << session.session_id
                  << " status=" << abdc::session::ToString(session.status)
                  << " artifacts=" << session.artifacts.size()
                  << " bytes=" << session.total_artifact_bytes << '\n';
        return 0;
    }
    const auto archive = abdc::session::ValidateSessionArchive(input);
    if (!archive.valid || !archive.session.has_value()) {
        std::cerr << "INVALID " << (archive.error.empty() ? "unknown ZIP error"
                                                           : archive.error)
                  << '\n';
        return 2;
    }
    std::cout << "VALID session=" << archive.session->session_id
              << " status=" << abdc::session::ToString(archive.session->status)
              << " artifacts=" << archive.session->artifacts.size()
              << " bytes=" << archive.session->total_artifact_bytes << '\n';
    return 0;
}

int Archive(const std::filesystem::path& session,
            const std::filesystem::path& output) {
    const auto result = abdc::session::CreateSessionArchive(session, output);
    std::cout << "CREATED " << Utf8(result.path)
              << " sha256=" << result.sha256
              << " members=" << result.member_count
              << " bytes=" << result.size_bytes << '\n';
    return 0;
}

}  // namespace

int wmain(const int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring_view(argv[1]) == L"--version") {
            return abdc::PrintBuildVersion("abct_session_tool");
        }
        if (argc == 3 && std::wstring_view(argv[1]) == L"validate") {
            return Validate(std::filesystem::absolute(argv[2]));
        }
        if ((argc == 3 || argc == 4) &&
            std::wstring_view(argv[1]) == L"archive") {
            const auto session = std::filesystem::absolute(argv[2]);
            const auto output = argc == 4
                ? std::filesystem::absolute(argv[3])
                : abdc::session::SubmissionArchivePath(session);
            return Archive(session, output);
        }
        PrintUsage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "ERROR " << error.what() << '\n';
        return 1;
    }
}
