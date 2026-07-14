#include "app/ParticipantApplication.h"

#include "base/BuildInfo.h"

#include <algorithm>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <windows.h>

namespace {

std::wstring WideDetail(const std::string_view detail) {
    const auto bounded_size = std::min<std::size_t>(detail.size(), 2'048U);
    if (bounded_size == 0U) return L"No technical detail was available.";
    const int input_size = static_cast<int>(bounded_size);
    const int required = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, detail.data(), input_size, nullptr, 0);
    if (required > 0) {
        std::wstring result(static_cast<std::size_t>(required), L'\0');
        (void)MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                  detail.data(), input_size,
                                  result.data(), required);
        return result;
    }
    std::wstring fallback;
    fallback.reserve(bounded_size);
    for (std::size_t index = 0; index < bounded_size; ++index) {
        const auto character = static_cast<unsigned char>(detail[index]);
        fallback.push_back(character >= 0x20U && character < 0x7fU
                               ? static_cast<wchar_t>(character)
                               : L'?');
    }
    return fallback;
}

std::filesystem::path WriteFatalDiagnostic(
    const std::string_view detail) noexcept {
    try {
        std::wstring local_app_data(32'768U, L'\0');
        const DWORD count = GetEnvironmentVariableW(
            L"LOCALAPPDATA", local_app_data.data(),
            static_cast<DWORD>(local_app_data.size()));
        std::filesystem::path directory;
        if (count > 0U && count < local_app_data.size()) {
            local_app_data.resize(count);
            directory = std::filesystem::path(local_app_data) /
                L"ABCurves Capture Trainer";
        } else {
            std::wstring temporary(32'768U, L'\0');
            const DWORD temporary_count = GetTempPathW(
                static_cast<DWORD>(temporary.size()), temporary.data());
            if (temporary_count == 0U || temporary_count >= temporary.size()) {
                return {};
            }
            temporary.resize(temporary_count);
            directory = std::filesystem::path(temporary) /
                L"ABCurves Capture Trainer";
        }
        std::filesystem::create_directories(directory);
        const auto path = directory / L"last_error.txt";
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) return {};
        output << "ABCurves Capture Trainer " << ABDC_VERSION << '\n'
               << "unix_time_ns="
               << std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count()
               << '\n'
               << "detail=" << detail << '\n';
        output.flush();
        if (!output) return {};
        return path;
    } catch (...) {
        return {};
    }
}

void ShowFatalError(const std::string_view detail) noexcept {
    const auto diagnostic = WriteFatalDiagnostic(detail);
    std::wstring message =
        L"ABCurves Capture Trainer encountered an unexpected error.\n\n"
        L"Any session files already created were preserved and will be checked "
        L"the next time the trainer starts.\n\nTechnical detail: ";
    message += WideDetail(detail);
    if (!diagnostic.empty()) {
        message += L"\n\nDiagnostic file: ";
        message += diagnostic.wstring();
    }
    MessageBoxW(nullptr, message.c_str(), L"ABCurves Capture Trainer",
                MB_OK | MB_ICONERROR);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    try {
        abdc::app::ParticipantApplication application;
        return application.Run(instance, show_command);
    } catch (const std::exception& error) {
        ShowFatalError(error.what());
        return 1;
    } catch (...) {
        ShowFatalError("unknown non-standard exception");
        return 1;
    }
}
