#include "app/ApplicationPaths.h"

#include "base/AtomicFile.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <stdexcept>
#include <vector>

namespace abdc::app {
namespace {

std::filesystem::path ExecutablePath() {
    std::vector<wchar_t> buffer(512U, L'\0');
    for (;;) {
        const auto count = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (count == 0U) throw std::runtime_error("executable path lookup failed");
        if (count < buffer.size() - 1U) {
            return std::filesystem::absolute(std::filesystem::path(
                std::wstring(buffer.data(), static_cast<std::size_t>(count))));
        }
        if (buffer.size() >= 32'768U) {
            throw std::runtime_error("executable path exceeds the Windows limit");
        }
        buffer.resize(std::min<std::size_t>(buffer.size() * 2U, 32'768U), L'\0');
    }
}

std::filesystem::path KnownFolder(const KNOWNFOLDERID& id,
                                  const char* description) {
    PWSTR native = nullptr;
    const auto status = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &native);
    if (FAILED(status) || native == nullptr) {
        if (native != nullptr) CoTaskMemFree(native);
        throw std::runtime_error(std::string(description) + " folder is unavailable");
    }
    std::filesystem::path result(native);
    CoTaskMemFree(native);
    if (!result.is_absolute()) {
        throw std::runtime_error(std::string(description) + " folder is not absolute");
    }
    return result;
}

}  // namespace

ApplicationPaths ResolveApplicationPaths() {
    ApplicationPaths result;
    result.executable = ExecutablePath();
    result.executable_directory = result.executable.parent_path();
    result.local_state_directory =
        KnownFolder(FOLDERID_LocalAppData, "local application data") /
        L"ABCurves Capture Trainer";
    result.settings_file = result.local_state_directory / L"settings.json";
    result.participant_identity_directory = result.local_state_directory / L"identity";
    result.highscores_file = result.local_state_directory / L"highscores.json";
    result.sessions_directory =
        KnownFolder(FOLDERID_Documents, "Documents") /
        L"ABCurves Research Sessions";
    result.media_directory = result.executable_directory / L"media";
    return result;
}

void PrepareApplicationPaths(const ApplicationPaths& paths,
                             const std::uint64_t minimum_session_free_bytes) {
    if (!paths.local_state_directory.is_absolute() ||
        !paths.participant_identity_directory.is_absolute() ||
        !paths.sessions_directory.is_absolute() || minimum_session_free_bytes == 0U) {
        throw std::invalid_argument("application paths are invalid");
    }
    std::filesystem::create_directories(paths.local_state_directory);
    std::filesystem::create_directories(paths.participant_identity_directory);
    ProbeWritableDirectory(paths.sessions_directory, minimum_session_free_bytes);
}

}  // namespace abdc::app
