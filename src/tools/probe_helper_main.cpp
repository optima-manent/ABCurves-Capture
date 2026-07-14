#include "acquisition/CertificationProbeClient.h"

#include "base/BuildInfo.h"
#include "base/Json.h"
#include "base/Sha256.h"
#include "windows_capture/NativeUsbPcap.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

class UniqueHandle final {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE value) : value_(value) {}
    ~UniqueHandle() {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    [[nodiscard]] HANDLE Get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE value_ = nullptr;
};

struct HelperArguments {
    std::filesystem::path config;
    std::filesystem::path ready;
    std::filesystem::path result;
    std::filesystem::path cancel;
    std::filesystem::path error;
    std::string config_sha256;
    std::uint32_t parent_pid = 0;
};

[[nodiscard]] std::string WideToUtf8(const std::wstring_view value) {
    if (value.empty()) return {};
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("argument text exceeds conversion limit");
    }
    const int count = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (count <= 0) throw std::runtime_error("argument is not valid UTF-16");
    std::string result(static_cast<std::size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                            static_cast<int>(value.size()), result.data(), count,
                            nullptr, nullptr) != count) {
        throw std::runtime_error("argument conversion failed");
    }
    return result;
}

[[nodiscard]] std::uint64_t ParseUnsigned(const std::wstring& text,
                                          const wchar_t* label) {
    if (text.empty() || text.front() == L'+' || text.front() == L'-') {
        throw std::invalid_argument(WideToUtf8(label) + " must be unsigned");
    }
    std::size_t used = 0;
    std::uint64_t result = 0;
    try {
        result = std::stoull(text, &used, 10);
    } catch (...) {
        throw std::invalid_argument(WideToUtf8(label) + " is not an integer");
    }
    if (used != text.size()) {
        throw std::invalid_argument(WideToUtf8(label) + " contains trailing text");
    }
    return result;
}

[[nodiscard]] HelperArguments ParseArguments(const int argc, wchar_t** argv) {
    if (argc < 2 || std::wstring_view(argv[1]) != L"--certification-probe" ||
        (argc - 2) % 2 != 0) {
        throw std::invalid_argument(
            "usage: abct_probe_helper --certification-probe --config ABS "
            "--config-sha256 HEX --parent-pid N --ready-file ABS --result-file ABS "
            "--cancel-file ABS --error-file ABS");
    }
    std::map<std::wstring, std::wstring, std::less<>> values;
    for (int index = 2; index < argc; index += 2) {
        const std::wstring name(argv[index]);
        if (!name.starts_with(L"--") ||
            !values.emplace(name, std::wstring(argv[index + 1])).second) {
            throw std::invalid_argument("invalid or duplicate probe helper option");
        }
    }
    constexpr std::array known{
        std::wstring_view(L"--config"),
        std::wstring_view(L"--config-sha256"),
        std::wstring_view(L"--parent-pid"),
        std::wstring_view(L"--ready-file"),
        std::wstring_view(L"--result-file"),
        std::wstring_view(L"--cancel-file"),
        std::wstring_view(L"--error-file"),
    };
    for (const auto& [name, unused] : values) {
        (void)unused;
        if (std::find(known.begin(), known.end(), name) == known.end()) {
            throw std::invalid_argument("unknown probe helper option");
        }
    }
    const auto require = [&](const wchar_t* name) -> const std::wstring& {
        const auto found = values.find(name);
        if (found == values.end()) throw std::invalid_argument("missing probe helper option");
        return found->second;
    };
    HelperArguments result;
    result.config = require(L"--config");
    result.ready = require(L"--ready-file");
    result.result = require(L"--result-file");
    result.cancel = require(L"--cancel-file");
    result.error = require(L"--error-file");
    result.config_sha256 = WideToUtf8(require(L"--config-sha256"));
    if (result.config_sha256.size() != 64U ||
        !std::all_of(result.config_sha256.begin(), result.config_sha256.end(),
                     [](const char character) {
                         return (character >= '0' && character <= '9') ||
                                (character >= 'a' && character <= 'f');
                     })) {
        throw std::invalid_argument("config SHA-256 is invalid");
    }
    const auto parent = ParseUnsigned(require(L"--parent-pid"), L"--parent-pid");
    if (parent == 0U || parent > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("parent PID is outside its range");
    }
    result.parent_pid = static_cast<std::uint32_t>(parent);
    return result;
}

[[nodiscard]] bool SafeAbsoluteFile(const std::filesystem::path& path) {
    if (path.empty() || !path.is_absolute() || path.filename().empty()) return false;
    const auto& text = path.native();
    return text.find(L'\0') == std::wstring::npos &&
           text.find(L'\r') == std::wstring::npos &&
           text.find(L'\n') == std::wstring::npos &&
           text.find(L'"') == std::wstring::npos;
}

[[nodiscard]] std::wstring PathKey(const std::filesystem::path& path) {
    std::wstring value = path.lexically_normal().native();
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t character) {
        if (character == L'/') return L'\\';
        return static_cast<wchar_t>(std::towlower(character));
    });
    return value;
}

void ValidatePaths(const HelperArguments& arguments) {
    const std::array<const std::filesystem::path*, 5> paths{
        &arguments.config, &arguments.ready, &arguments.result,
        &arguments.cancel, &arguments.error,
    };
    const auto parent = arguments.config.parent_path().lexically_normal();
    if (!SafeAbsoluteFile(arguments.config) || parent.empty()) {
        throw std::invalid_argument("probe config path is unsafe");
    }
    std::set<std::wstring, std::less<>> unique;
    for (const auto* path : paths) {
        if (!SafeAbsoluteFile(*path) ||
            PathKey(path->parent_path()) != PathKey(parent) ||
            !unique.insert(PathKey(*path)).second) {
            throw std::invalid_argument(
                "probe controls must be distinct absolute files in one directory");
        }
    }
    std::error_code error;
    if (!std::filesystem::is_directory(parent, error) || error ||
        !std::filesystem::is_regular_file(arguments.config, error) || error) {
        throw std::invalid_argument("probe control directory or config is unavailable");
    }
    for (const auto* path : {&arguments.ready, &arguments.result,
                             &arguments.cancel, &arguments.error}) {
        if (std::filesystem::exists(*path)) {
            throw std::invalid_argument("probe output control already exists");
        }
    }
}

[[nodiscard]] std::wstring ExtendedPath(const std::filesystem::path& path) {
    std::wstring value = std::filesystem::absolute(path).wstring();
    if (value.starts_with(L"\\\\?\\")) return value;
    if (value.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + value.substr(2);
    return L"\\\\?\\" + value;
}

void WriteNewFile(const std::filesystem::path& path,
                  const std::string_view contents) {
    const auto native = ExtendedPath(path);
    UniqueHandle output(CreateFileW(
        native.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (!output) throw std::runtime_error("refusing to overwrite probe status file");
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const DWORD count = static_cast<DWORD>(std::min<std::size_t>(
            contents.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(output.Get(), contents.data() + offset, count, &written,
                       nullptr) || written != count) {
            throw std::runtime_error("probe status write failed");
        }
        offset += written;
    }
    if (!FlushFileBuffers(output.Get())) {
        throw std::runtime_error("probe status durable flush failed");
    }
}

void WriteNewFileAtomically(const std::filesystem::path& path,
                            const std::string_view contents) {
    auto temporary = path;
    temporary += L".tmp." + std::to_wstring(GetCurrentProcessId());
    WriteNewFile(temporary, contents);
    const auto source = ExtendedPath(temporary);
    const auto destination = ExtendedPath(path);
    if (!MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError();
        static_cast<void>(DeleteFileW(source.c_str()));
        throw std::runtime_error(
            "atomic probe result publication failed with Win32 error " +
            std::to_string(error));
    }
}

[[nodiscard]] std::vector<std::byte> ReadConfig(
    const std::filesystem::path& path) {
    const auto size = std::filesystem::file_size(path);
    if (size == 0U || size > abdc::acquisition::kMaximumCertificationProbeConfigBytes ||
        size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw std::runtime_error("probe config has an unsafe size");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("probe config cannot be opened");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    if (input.gcount() != static_cast<std::streamsize>(bytes.size())) {
        throw std::runtime_error("probe config read was truncated");
    }
    return bytes;
}

[[nodiscard]] std::string RandomCapability() {
    std::array<unsigned char, 32> random{};
    if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("probe capability generation failed");
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(random.size() * 2U, '0');
    for (std::size_t index = 0; index < random.size(); ++index) {
        result[index * 2U] = digits[random[index] >> 4U];
        result[index * 2U + 1U] = digits[random[index] & 0x0fU];
    }
    return result;
}

[[nodiscard]] std::string JsonLine(const abdc::json::Value& value) {
    return abdc::json::DumpCanonical(value, false) + "\n";
}

[[nodiscard]] std::string ReadyJson(const HelperArguments& arguments,
                                    const std::string& capability) {
    abdc::json::Value value(abdc::json::Value::Object{});
    value["schema"] = "abcurves.certification.ready.v1";
    value["state"] = "ready";
    value["capability"] = capability;
    value["helper_pid"] = static_cast<std::int64_t>(GetCurrentProcessId());
    value["parent_pid"] = static_cast<std::int64_t>(arguments.parent_pid);
    value["cancel_schema"] = "abcurves.certification.cancel.v1";
    return JsonLine(value);
}

void WriteErrorIfPossible(const HelperArguments& arguments,
                          const std::string_view reason,
                          const std::string_view detail) noexcept {
    try {
        if (!SafeAbsoluteFile(arguments.error) ||
            std::filesystem::exists(arguments.error)) return;
        abdc::json::Value value(abdc::json::Value::Object{});
        value["schema"] = "abcurves.certification.error.v1";
        value["state"] = "error";
        value["helper_pid"] = static_cast<std::int64_t>(GetCurrentProcessId());
        value["parent_pid"] = static_cast<std::int64_t>(arguments.parent_pid);
        value["reason"] = std::string(reason).substr(0, 128U);
        value["detail"] = std::string(detail).substr(0, 4096U);
        WriteNewFile(arguments.error, JsonLine(value));
    } catch (...) {
    }
}

[[nodiscard]] bool ValidCancel(const std::filesystem::path& path,
                               const std::string& capability) {
    const auto size = std::filesystem::file_size(path);
    if (size == 0U || size > 4096U) return false;
    std::ifstream input(path, std::ios::binary);
    std::string text(static_cast<std::size_t>(size), '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (input.gcount() != static_cast<std::streamsize>(text.size())) return false;
    const auto value = abdc::json::Parse(text);
    return value.At("schema").AsString() ==
               "abcurves.certification.cancel.v1" &&
           value.At("capability").AsString() == capability;
}

[[nodiscard]] std::int64_t QpcNow() noexcept {
    LARGE_INTEGER value{};
    return QueryPerformanceCounter(&value) ? value.QuadPart : 0;
}

[[nodiscard]] std::int64_t QpcFrequency() {
    LARGE_INTEGER value{};
    if (!QueryPerformanceFrequency(&value) || value.QuadPart <= 0) {
        throw std::runtime_error("QueryPerformanceFrequency failed");
    }
    return value.QuadPart;
}

// Adds a readiness observation without changing CertificationProbeWorker's
// pure source interface or exposing native capture state to the parent.
class ObservedProbeSource final : public abdc::acquisition::IUsbPcapChunkSource {
public:
    explicit ObservedProbeSource(abdc::acquisition::IUsbPcapChunkSource& source)
        : source_(source) {}

    bool Start(const abdc::windows_capture::NativeUsbPcapOptions& options) override {
        const bool started = source_.Start(options);
        {
            std::scoped_lock lock(mutex_);
            start_attempted_ = true;
            start_succeeded_ = started;
        }
        condition_.notify_all();
        return started;
    }

    void RequestStop() override { source_.RequestStop(); }

    bool WaitTakeChunk(std::vector<std::byte>& chunk,
                       const std::chrono::milliseconds timeout) override {
        return source_.WaitTakeChunk(chunk, timeout);
    }

    [[nodiscard]] abdc::windows_capture::NativeUsbPcapStatus Status()
        const override { return source_.Status(); }

    abdc::windows_capture::NativeUsbPcapStopReport StopAndDrain(
        const std::chrono::milliseconds timeout,
        abdc::windows_capture::NativeUsbPcapSemanticGuard guard) override {
        return source_.StopAndDrain(timeout, std::move(guard));
    }

    void Abort() noexcept override { source_.Abort(); }

    [[nodiscard]] std::pair<bool, bool> WaitStart(
        const std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        static_cast<void>(condition_.wait_for(
            lock, timeout, [&] { return start_attempted_; }));
        return {start_attempted_, start_succeeded_};
    }

private:
    abdc::acquisition::IUsbPcapChunkSource& source_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool start_attempted_ = false;
    bool start_succeeded_ = false;
};

int ProbeMain(const HelperArguments& arguments) {
    ValidatePaths(arguments);
    if (arguments.parent_pid == GetCurrentProcessId()) {
        throw std::invalid_argument("probe helper cannot tether to itself");
    }
    UniqueHandle parent(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                    FALSE, arguments.parent_pid));
    if (!parent || WaitForSingleObject(parent.Get(), 0) != WAIT_TIMEOUT) {
        throw std::runtime_error("parent process is unavailable");
    }

    const auto config_bytes = ReadConfig(arguments.config);
    if (abdc::Sha256Hex(config_bytes) != arguments.config_sha256) {
        throw std::runtime_error("probe config integrity check failed");
    }
    auto plan = abdc::acquisition::ParseCertificationProbeHelperConfig(
        config_bytes);
    plan.options.qpc_frequency = QpcFrequency();
    const std::string capability = RandomCapability();

    abdc::windows_capture::Win32NativeUsbPcapApi native_api;
    abdc::acquisition::NativeUsbPcapChunkSource native_source(native_api);
    ObservedProbeSource source(native_source);
    abdc::acquisition::CertificationProbeWorker worker(
        source, std::move(plan.routes), plan.options, [] { return QpcNow(); });

    std::optional<abdc::acquisition::CertificationProbeResult> worker_result;
    std::string worker_exception;
    std::atomic<bool> worker_done{false};
    std::thread worker_thread([&] {
        try {
            worker_result = worker.Run();
        } catch (const std::exception& error) {
            worker_exception = error.what();
        } catch (...) {
            worker_exception = "probe worker threw an unknown exception";
        }
        worker_done.store(true, std::memory_order_release);
    });

    bool ready_written = false;
    bool cancelled = false;
    bool parent_exited = false;
    bool invalid_cancel = false;
    std::string control_error;
    std::optional<std::chrono::steady_clock::time_point> cancel_seen;
    while (!worker_done.load(std::memory_order_acquire)) {
        const auto [attempted, started] = source.WaitStart(
            std::chrono::milliseconds(25));
        try {
            if (attempted && started && !ready_written) {
                WriteNewFile(arguments.ready, ReadyJson(arguments, capability));
                ready_written = true;
            }
            if (WaitForSingleObject(parent.Get(), 0) == WAIT_OBJECT_0) {
                parent_exited = true;
                source.RequestStop();
            }
            if (!cancelled && std::filesystem::exists(arguments.cancel)) {
                if (!cancel_seen) cancel_seen = std::chrono::steady_clock::now();
                if (ValidCancel(arguments.cancel, capability)) {
                    cancelled = true;
                    source.RequestStop();
                } else if (std::chrono::steady_clock::now() - *cancel_seen >=
                           std::chrono::seconds(1)) {
                    invalid_cancel = true;
                    source.RequestStop();
                }
            }
        } catch (const std::exception& error) {
            control_error = error.what();
            source.RequestStop();
        }
    }
    worker_thread.join();

    if (parent_exited) return 0;
    if (!control_error.empty()) {
        WriteErrorIfPossible(arguments, "control_failure", control_error);
        return 6;
    }
    if (invalid_cancel) {
        WriteErrorIfPossible(arguments, "invalid_cancel",
                             "probe cancel capability did not match");
        return 6;
    }
    if (!worker_exception.empty()) {
        WriteErrorIfPossible(arguments, "worker_exception", worker_exception);
        std::cerr << worker_exception << '\n';
        return 5;
    }
    if (!worker_result) {
        WriteErrorIfPossible(arguments, "missing_result",
                             "probe worker returned no result");
        return 5;
    }
    if (!ready_written) {
        const std::string detail = worker_result->detail.empty()
            ? "USBPcap probe could not start" : worker_result->detail;
        WriteErrorIfPossible(arguments, "source_start_failed", detail);
        return 4;
    }

    abdc::acquisition::CertificationProbeTransportResult result;
    result.cancelled = cancelled;
    result.probe = std::move(*worker_result);
    const auto encoded = abdc::acquisition::SerializeCertificationProbeResultEnvelope(
        result, capability, GetCurrentProcessId(), arguments.parent_pid);
    WriteNewFileAtomically(arguments.result, encoded);
    return 0;
}

}  // namespace

int wmain(const int argc, wchar_t** argv) {
    std::optional<HelperArguments> arguments;
    try {
        if (abdc::IsVersionRequest(argc, argv)) {
            return abdc::PrintBuildVersion("abct_probe_helper");
        }
        arguments = ParseArguments(argc, argv);
        return ProbeMain(*arguments);
    } catch (const std::exception& error) {
        if (arguments) {
            WriteErrorIfPossible(*arguments, "invalid_configuration", error.what());
        }
        std::cerr << "certification probe helper: " << error.what() << '\n';
        return 2;
    }
}
