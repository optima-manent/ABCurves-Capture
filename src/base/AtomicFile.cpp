#include "base/AtomicFile.h"

#include <windows.h>
#include <shlobj.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace abdc {
namespace {

std::filesystem::path TempSibling(const std::filesystem::path& path) {
    static std::atomic<std::uint64_t> sequence{0U};
    LARGE_INTEGER counter{};
    QueryPerformanceCounter(&counter);
    const auto token = std::to_wstring(GetCurrentProcessId()) + L"." +
        std::to_wstring(GetCurrentThreadId()) + L"." +
        std::to_wstring(counter.QuadPart) + L"." +
        std::to_wstring(sequence.fetch_add(1U, std::memory_order_relaxed));
    return path.parent_path() / (path.filename().wstring() + L"." + token + L".partial");
}

std::runtime_error Win32Failure(const char* operation, const DWORD error) {
    return std::runtime_error(std::string(operation) + " failed with Win32 error " +
                              std::to_string(error));
}

std::wstring ExtendedLengthPath(const std::filesystem::path& path) {
    auto value = std::filesystem::absolute(path).wstring();
    if (value.starts_with(L"\\\\?\\")) return value;
    if (value.starts_with(L"\\\\")) {
        return L"\\\\?\\UNC\\" + value.substr(2U);
    }
    return L"\\\\?\\" + value;
}

}  // namespace

void AtomicWriteFile(const std::filesystem::path& path, const std::string_view bytes) {
    if (path.empty() || path.filename().empty()) throw std::invalid_argument("invalid atomic output path");
    if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path());
    const auto temporary = TempSibling(path);
    const auto temporary_native = ExtendedLengthPath(temporary);
    const auto destination_native = ExtendedLengthPath(path);
    HANDLE output = INVALID_HANDLE_VALUE;
    try {
        output = CreateFileW(temporary_native.c_str(), GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_DELETE,
                             nullptr, CREATE_NEW,
                             FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (output == INVALID_HANDLE_VALUE) throw Win32Failure("atomic temporary create", GetLastError());
        std::size_t offset = 0U;
        while (offset < bytes.size()) {
            const auto chunk = static_cast<DWORD>(std::min<std::size_t>(
                bytes.size() - offset, static_cast<std::size_t>(MAXDWORD)));
            DWORD written = 0U;
            if (!WriteFile(output, bytes.data() + offset, chunk, &written, nullptr) ||
                written != chunk) {
                const DWORD error = GetLastError();
                CloseHandle(output);
                output = INVALID_HANDLE_VALUE;
                throw Win32Failure("atomic temporary write", error);
            }
            offset += written;
        }
        if (!FlushFileBuffers(output)) {
            const DWORD error = GetLastError();
            CloseHandle(output);
            output = INVALID_HANDLE_VALUE;
            throw Win32Failure("atomic durable flush", error);
        }
        CloseHandle(output);
        output = INVALID_HANDLE_VALUE;

        DWORD replace_error = ERROR_SUCCESS;
        for (unsigned attempt = 0U; attempt < 50U; ++attempt) {
            if (MoveFileExW(temporary_native.c_str(), destination_native.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return;
            replace_error = GetLastError();
            if (replace_error != ERROR_SHARING_VIOLATION &&
                replace_error != ERROR_LOCK_VIOLATION && replace_error != ERROR_ACCESS_DENIED) break;
            Sleep(10U);
        }
        throw Win32Failure("atomic replace", replace_error);
    } catch (...) {
        if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
        static_cast<void>(DeleteFileW(temporary_native.c_str()));
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}

std::string ReadUtf8File(const std::filesystem::path& path, const std::uint64_t maximum_bytes) {
    const auto native_path = ExtendedLengthPath(path);
    const HANDLE input = CreateFileW(native_path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) throw Win32Failure("UTF-8 input open", GetLastError());
    LARGE_INTEGER file_size{};
    if (!GetFileSizeEx(input, &file_size) || file_size.QuadPart < 0) {
        const DWORD error = GetLastError();
        CloseHandle(input);
        throw Win32Failure("UTF-8 input size query", error);
    }
    const auto size = static_cast<std::uint64_t>(file_size.QuadPart);
    if (size > maximum_bytes || size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        CloseHandle(input);
        throw std::runtime_error("input file exceeds safety limit");
    }
    std::string data(static_cast<std::size_t>(size), '\0');
    std::size_t offset = 0U;
    while (offset < data.size()) {
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(
            data.size() - offset, static_cast<std::size_t>(MAXDWORD)));
        DWORD read = 0U;
        if (!ReadFile(input, data.data() + offset, chunk, &read, nullptr) || read == 0U) {
            const DWORD error = GetLastError();
            CloseHandle(input);
            throw Win32Failure("UTF-8 input read", error);
        }
        offset += read;
    }
    CloseHandle(input);
    if (data.size() >= 3 && static_cast<unsigned char>(data[0]) == 0xef &&
        static_cast<unsigned char>(data[1]) == 0xbb && static_cast<unsigned char>(data[2]) == 0xbf) {
        data.erase(0, 3);
    }
    return data;
}

void ProbeWritableDirectory(const std::filesystem::path& directory, const std::uint64_t minimum_free_bytes) {
    std::filesystem::create_directories(directory);
    const auto space = std::filesystem::space(directory);
    if (space.available < minimum_free_bytes) throw std::runtime_error("insufficient free space for collection");
    const auto destination = directory / L".abct_write_probe";
    AtomicWriteFile(destination, "ABCT atomic write probe\n");
    const auto contents = ReadUtf8File(destination, 1024);
    if (contents != "ABCT atomic write probe\n") throw std::runtime_error("output-path readback mismatch");
    if (!std::filesystem::remove(destination)) throw std::runtime_error("cannot delete output-path probe");
}

std::filesystem::path DefaultSessionRoot() {
    PWSTR documents = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT,
                                       nullptr, &documents)) &&
        documents != nullptr) {
        std::filesystem::path root(documents);
        CoTaskMemFree(documents);
        return root / L"ABCurves Research Sessions";
    }
    if (documents != nullptr) CoTaskMemFree(documents);
    std::vector<wchar_t> buffer(512U, L'\0');
    for (;;) {
        const DWORD count = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (count == 0U) {
            throw Win32Failure("executable path lookup", GetLastError());
        }
        if (count < buffer.size() - 1U) {
            const std::filesystem::path executable(
                std::wstring(buffer.data(), static_cast<std::size_t>(count)));
            if (executable.parent_path().empty()) {
                throw std::runtime_error("executable directory is unavailable");
            }
            return std::filesystem::absolute(
                executable.parent_path() / L"ABCurves Research Sessions");
        }
        if (buffer.size() >= 32'768U) {
            throw std::runtime_error("executable path exceeds the supported Windows limit");
        }
        buffer.resize(std::min<std::size_t>(buffer.size() * 2U, 32'768U), L'\0');
    }
}

}  // namespace abdc
