#include "acquisition/CaptureWorker.h"

#include "base/AtomicFile.h"
#include "base/BuildInfo.h"
#include "base/Json.h"
#include "base/Sha256.h"
#include "capture/HidDescriptor.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
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
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using abdc::acquisition::CaptureFatalReason;
using abdc::acquisition::CaptureWorkerState;

class UniqueHandle final {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE value) : value_(value) {}
    ~UniqueHandle() {
        Reset();
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : value_(other.Release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) Reset(other.Release());
        return *this;
    }
    [[nodiscard]] HANDLE Get() const { return value_; }
    [[nodiscard]] explicit operator bool() const {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }
    void Reset(HANDLE value = nullptr) noexcept {
        if (*this) CloseHandle(value_);
        value_ = value;
    }
    [[nodiscard]] HANDLE Release() noexcept {
        const HANDLE value = value_;
        value_ = nullptr;
        return value;
    }

private:
    HANDLE value_ = nullptr;
};

struct HelperArguments {
    std::uint16_t root = 0;
    std::uint8_t address = 0;
    std::uint16_t bus = 0;
    std::uint8_t endpoint = 0;
    std::uint32_t parent_pid = 0;
    std::uint32_t flush_ms = 2'000;
    std::filesystem::path descriptor;
    std::filesystem::path output_directory;
    std::filesystem::path lease_file;
    std::filesystem::path ready_file;
    std::filesystem::path health_file;
    std::filesystem::path stop_file;
    std::filesystem::path error_file;
};

[[nodiscard]] std::string WideToUtf8(const std::wstring_view value) {
    if (value.empty()) return {};
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("text exceeds UTF-8 conversion limit");
    }
    const int size = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) throw std::runtime_error("UTF-16 argument is not valid text");
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                            static_cast<int>(value.size()), result.data(), size,
                            nullptr, nullptr) != size) {
        throw std::runtime_error("UTF-8 argument conversion failed");
    }
    return result;
}

[[nodiscard]] std::string PathText(const std::filesystem::path& path) {
    return WideToUtf8(path.wstring());
}

[[nodiscard]] std::wstring ExtendedPath(const std::filesystem::path& path) {
    std::wstring value = std::filesystem::absolute(path).wstring();
    if (value.starts_with(L"\\\\?\\")) return value;
    if (value.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + value.substr(2);
    return L"\\\\?\\" + value;
}

[[nodiscard]] std::uint64_t ParseUnsigned(const std::wstring& value,
                                          const wchar_t* label) {
    if (value.empty() || value.front() == L'+' || value.front() == L'-') {
        throw std::invalid_argument(WideToUtf8(label) + " must be an unsigned integer");
    }
    std::size_t used = 0;
    std::uint64_t parsed = 0;
    try {
        parsed = std::stoull(value, &used, 0);
    } catch (...) {
        throw std::invalid_argument(WideToUtf8(label) + " is not a valid integer");
    }
    if (used != value.size()) {
        throw std::invalid_argument(WideToUtf8(label) + " contains trailing text");
    }
    return parsed;
}

[[nodiscard]] HelperArguments ParseArguments(const int argc, wchar_t** argv) {
    if (argc < 2 || std::wstring_view(argv[1]) != L"--capture") {
        throw std::invalid_argument(
            "usage: abct_capture_helper --capture --root N --address N --bus N "
            "--endpoint N --descriptor ABS --output-dir ABS --lease ABS "
            "--parent-pid N "
            "--ready-file ABS --health-file ABS --stop-file ABS --error-file ABS "
            "[--flush-ms N]");
    }
    if ((argc - 2) % 2 != 0) {
        throw std::invalid_argument("capture helper options require name/value pairs");
    }
    std::map<std::wstring, std::wstring, std::less<>> values;
    for (int index = 2; index < argc; index += 2) {
        const std::wstring name(argv[index]);
        if (!name.starts_with(L"--") || name.size() <= 2U) {
            throw std::invalid_argument("invalid capture helper option name");
        }
        if (!values.emplace(name, std::wstring(argv[index + 1])).second) {
            throw std::invalid_argument("duplicate capture helper option");
        }
    }
    const auto require = [&](const wchar_t* name) -> const std::wstring& {
        const auto found = values.find(name);
        if (found == values.end()) {
            throw std::invalid_argument("missing capture helper option " +
                                        WideToUtf8(name));
        }
        return found->second;
    };
    const std::array known{
        std::wstring_view(L"--root"), std::wstring_view(L"--address"),
        std::wstring_view(L"--bus"), std::wstring_view(L"--endpoint"),
        std::wstring_view(L"--descriptor"), std::wstring_view(L"--output-dir"),
        std::wstring_view(L"--lease"),
        std::wstring_view(L"--parent-pid"), std::wstring_view(L"--ready-file"),
        std::wstring_view(L"--health-file"), std::wstring_view(L"--stop-file"),
        std::wstring_view(L"--error-file"), std::wstring_view(L"--flush-ms"),
    };
    for (const auto& [name, unused] : values) {
        (void)unused;
        if (std::find(known.begin(), known.end(), name) == known.end()) {
            throw std::invalid_argument("unknown capture helper option " +
                                        WideToUtf8(name));
        }
    }

    HelperArguments result;
    const auto root = ParseUnsigned(require(L"--root"), L"--root");
    const auto address = ParseUnsigned(require(L"--address"), L"--address");
    const auto bus = ParseUnsigned(require(L"--bus"), L"--bus");
    const auto endpoint = ParseUnsigned(require(L"--endpoint"), L"--endpoint");
    const auto parent = ParseUnsigned(require(L"--parent-pid"), L"--parent-pid");
    if (root == 0 || root > 255 || address == 0 || address > 127 ||
        bus == 0 || bus > std::numeric_limits<std::uint16_t>::max() ||
        endpoint > std::numeric_limits<std::uint8_t>::max() ||
        (endpoint != 0U &&
         ((endpoint & 0x80U) == 0U || (endpoint & 0x0fU) == 0U)) ||
        parent == 0 || parent > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("USB identity or parent PID is out of range");
    }
    result.root = static_cast<std::uint16_t>(root);
    result.address = static_cast<std::uint8_t>(address);
    result.bus = static_cast<std::uint16_t>(bus);
    result.endpoint = static_cast<std::uint8_t>(endpoint);
    result.parent_pid = static_cast<std::uint32_t>(parent);
    if (const auto found = values.find(L"--flush-ms"); found != values.end()) {
        const auto flush = ParseUnsigned(found->second, L"--flush-ms");
        if (flush == 0 || flush > 60'000) {
            throw std::invalid_argument("--flush-ms must be in [1,60000]");
        }
        result.flush_ms = static_cast<std::uint32_t>(flush);
    }
    result.descriptor = require(L"--descriptor");
    result.output_directory = require(L"--output-dir");
    result.lease_file = require(L"--lease");
    result.ready_file = require(L"--ready-file");
    result.health_file = require(L"--health-file");
    result.stop_file = require(L"--stop-file");
    result.error_file = require(L"--error-file");
    return result;
}

[[nodiscard]] bool SafeAbsoluteFile(const std::filesystem::path& path) {
    if (path.empty() || !path.is_absolute() || path.filename().empty()) return false;
    const auto& value = path.native();
    return value.find(L'\0') == std::wstring::npos &&
           value.find(L'\r') == std::wstring::npos &&
           value.find(L'\n') == std::wstring::npos &&
           value.find(L'"') == std::wstring::npos;
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
    if (!SafeAbsoluteFile(arguments.descriptor) ||
        !SafeAbsoluteFile(arguments.lease_file) ||
        !arguments.output_directory.is_absolute() ||
        arguments.output_directory.filename().empty()) {
        throw std::invalid_argument("descriptor and output directory must be safe absolute paths");
    }
    std::error_code error;
    if (!std::filesystem::is_regular_file(arguments.descriptor, error) || error) {
        throw std::invalid_argument("descriptor path must name an existing regular file");
    }
    if (!std::filesystem::is_directory(arguments.output_directory, error) || error) {
        throw std::invalid_argument("output directory must already exist");
    }

    const std::array<const std::filesystem::path*, 4> controls{
        &arguments.ready_file, &arguments.health_file,
        &arguments.stop_file, &arguments.error_file,
    };
    const auto control_parent = controls.front()->parent_path().lexically_normal();
    const auto control_parent_key = PathKey(control_parent);
    for (const auto* path : controls) {
        if (!SafeAbsoluteFile(*path) ||
            PathKey(path->parent_path()) != control_parent_key) {
            throw std::invalid_argument(
                "control files must be distinct safe absolute paths in one directory");
        }
        if (std::filesystem::exists(*path)) {
            throw std::invalid_argument("control file already exists; refusing to overwrite it");
        }
    }
    for (std::size_t left = 0; left < controls.size(); ++left) {
        for (std::size_t right = left + 1; right < controls.size(); ++right) {
            if (PathKey(*controls[left]) == PathKey(*controls[right])) {
                throw std::invalid_argument("control file paths must be distinct");
            }
        }
    }
    if (!std::filesystem::is_directory(control_parent, error) || error) {
        throw std::invalid_argument("control-file directory must already exist");
    }
}

[[nodiscard]] UniqueHandle AcquireSharedSessionLease(
    const std::filesystem::path& path) {
    if (!SafeAbsoluteFile(path)) {
        throw std::invalid_argument(
            "session writer lease must be a safe absolute path");
    }
    const auto native = ExtendedPath(path);
    UniqueHandle lease(CreateFileW(
        native.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!lease) {
        throw std::runtime_error("session writer lease could not be acquired");
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (GetFileType(lease.Get()) != FILE_TYPE_DISK ||
        !GetFileInformationByHandleEx(lease.Get(), FileAttributeTagInfo,
                                      &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT |
          FILE_ATTRIBUTE_DEVICE)) != 0U) {
        throw std::invalid_argument(
            "session writer lease must name a regular file");
    }
    return lease;
}

[[nodiscard]] std::vector<std::byte> ReadDescriptor(
    const std::filesystem::path& path) {
    const auto size = std::filesystem::file_size(path);
    if (size > (1U << 20U) ||
        size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw std::runtime_error("HID descriptor evidence has an unsafe size");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open HID descriptor evidence");
    std::vector<std::byte> result(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(result.data()),
               static_cast<std::streamsize>(result.size()));
    if (input.gcount() != static_cast<std::streamsize>(result.size())) {
        throw std::runtime_error("HID descriptor evidence read was truncated");
    }
    return result;
}

[[nodiscard]] std::string RandomCapability() {
    std::array<unsigned char, 32> random{};
    const NTSTATUS status = BCryptGenRandom(
        nullptr, random.data(), static_cast<ULONG>(random.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) throw std::runtime_error("capability-token generation failed");
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(random.size() * 2U, '0');
    for (std::size_t index = 0; index < random.size(); ++index) {
        result[index * 2U] = digits[random[index] >> 4U];
        result[index * 2U + 1U] = digits[random[index] & 0x0fU];
    }
    return result;
}

void WriteNewFile(const std::filesystem::path& path,
                  const std::string_view contents) {
    const std::wstring native = ExtendedPath(path);
    UniqueHandle output(CreateFileW(
        native.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (!output) throw std::runtime_error("refusing to overwrite status file");
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const DWORD count = static_cast<DWORD>(std::min<std::size_t>(
            contents.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(output.Get(), contents.data() + offset, count, &written,
                       nullptr) || written != count) {
            throw std::runtime_error("status-file write failed");
        }
        offset += written;
    }
    if (!FlushFileBuffers(output.Get())) {
        throw std::runtime_error("status-file durable flush failed");
    }
}

[[nodiscard]] std::string JsonLine(const abdc::json::Value& value) {
    return abdc::json::DumpCanonical(value, false) + "\n";
}

[[nodiscard]] abdc::json::Value ReadyStatus(
    const HelperArguments& arguments, const std::string& capability) {
    abdc::json::Value result(abdc::json::Value::Object{});
    result["schema"] = "abcurves.capture.ready.v1";
    result["state"] = "ready";
    result["capability"] = capability;
    result["helper_pid"] = static_cast<std::int64_t>(GetCurrentProcessId());
    result["parent_pid"] = static_cast<std::int64_t>(arguments.parent_pid);
    result["output_directory"] = PathText(arguments.output_directory);
    result["stop_schema"] = "abcurves.capture.stop.v1";
    return result;
}

[[nodiscard]] abdc::json::Value HealthStatus(
    const abdc::acquisition::CaptureWorkerSnapshot& snapshot,
    const std::string& stop_origin) {
    abdc::json::Value result(abdc::json::Value::Object{});
    result["schema"] = "abcurves.capture.health.v1";
    result["state"] = abdc::acquisition::ToString(snapshot.state);
    result["fatal_reason"] = abdc::acquisition::ToString(snapshot.fatal_reason);
    result["detail"] = snapshot.detail;
    result["stop_origin"] = stop_origin;
    result["source_bytes"] = static_cast<std::int64_t>(
        std::min<std::uint64_t>(snapshot.pipeline.source_bytes,
                                std::numeric_limits<std::int64_t>::max()));
    result["source_records"] = static_cast<std::int64_t>(
        std::min<std::uint64_t>(snapshot.pipeline.source_records,
                                std::numeric_limits<std::int64_t>::max()));
    result["endpoint_records"] = static_cast<std::int64_t>(
        std::min<std::uint64_t>(snapshot.pipeline.raw_device_records,
                                std::numeric_limits<std::int64_t>::max()));
    result["decoded_reports"] = static_cast<std::int64_t>(
        std::min<std::uint64_t>(snapshot.pipeline.decoded_reports,
                                std::numeric_limits<std::int64_t>::max()));
    result["anomalies"] = static_cast<std::int64_t>(
        std::min<std::uint64_t>(snapshot.pipeline.anomalies,
                                std::numeric_limits<std::int64_t>::max()));
    result["native_bytes_read"] = static_cast<std::int64_t>(
        std::min<std::uint64_t>(snapshot.native.counters.bytes_read,
                                std::numeric_limits<std::int64_t>::max()));
    result["native_queued_bytes"] = static_cast<std::int64_t>(
        std::min<std::size_t>(snapshot.native.counters.queued_bytes,
                              static_cast<std::size_t>(
                                  std::numeric_limits<std::int64_t>::max())));
    return result;
}

void WriteErrorIfPossible(const std::filesystem::path& path,
                          const CaptureFatalReason reason,
                          const std::string& detail) noexcept {
    try {
        if (path.empty() || std::filesystem::exists(path)) return;
        abdc::json::Value value(abdc::json::Value::Object{});
        value["schema"] = "abcurves.capture.error.v1";
        value["state"] = "error";
        value["fatal_reason"] = abdc::acquisition::ToString(reason);
        value["detail"] = detail;
        WriteNewFile(path, JsonLine(value));
    } catch (...) {
    }
}

[[nodiscard]] bool ValidStopFile(const std::filesystem::path& path,
                                 const std::string& capability) {
    const auto text = abdc::ReadUtf8File(path, 4096);
    const auto value = abdc::json::Parse(text);
    return value.At("schema").AsString() == "abcurves.capture.stop.v1" &&
           value.At("capability").AsString() == capability;
}

[[nodiscard]] std::int64_t QpcNow() {
    LARGE_INTEGER value{};
    if (!QueryPerformanceCounter(&value)) return 0;
    return value.QuadPart;
}

[[nodiscard]] std::int64_t QpcFrequency() {
    LARGE_INTEGER value{};
    if (!QueryPerformanceFrequency(&value) || value.QuadPart <= 0) {
        throw std::runtime_error("QueryPerformanceFrequency failed");
    }
    return value.QuadPart;
}

int CaptureMain(const HelperArguments& arguments) {
    ValidatePaths(arguments);
    if (arguments.parent_pid == GetCurrentProcessId()) {
        throw std::invalid_argument("capture helper cannot tether to itself");
    }
    UniqueHandle parent(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                    FALSE, arguments.parent_pid));
    if (!parent || WaitForSingleObject(parent.Get(), 0) != WAIT_TIMEOUT) {
        throw std::runtime_error("parent process is unavailable");
    }

    const auto descriptor = ReadDescriptor(arguments.descriptor);
    if (!descriptor.empty()) {
        try {
            const std::string bytes(
                reinterpret_cast<const char*>(descriptor.data()),
                descriptor.size());
            WriteNewFile(
                arguments.output_directory / "hid_report_descriptor.bin",
                bytes);
        } catch (...) {
            // Independent decoding evidence is valuable, but the authoritative
            // exact-address PCAP must not depend on this optional copy.
        }
    }
    std::optional<abdc::acquisition::DecodedMouseEndpoint> decoded_endpoint;
    if (!descriptor.empty()) {
        try {
            const auto parsed_descriptor =
                abdc::capture::HidDescriptor::Parse(descriptor);
            auto layouts = parsed_descriptor.RelativeMouseLayouts();
            if (arguments.endpoint == 0U || layouts.empty()) {
                throw std::runtime_error(
                    "optional descriptor does not define a decoded endpoint");
            }
            abdc::capture::ReportStreamIdentity report_identity;
            report_identity.bus = arguments.bus;
            report_identity.device = arguments.address;
            report_identity.endpoint = arguments.endpoint;
            report_identity.descriptor_evidence = descriptor;
            report_identity.descriptor_sha256 = abdc::Sha256Hex(descriptor);
            report_identity.decoder_spec =
                parsed_descriptor.CanonicalDecoderSpec();
            report_identity.qpc_frequency = QpcFrequency();
            decoded_endpoint.emplace(abdc::acquisition::DecodedMouseEndpoint{
                arguments.endpoint,
                abdc::capture::HidMouseDecoder(std::move(layouts)),
                std::move(report_identity),
            });
        } catch (...) {
            // Descriptor-derived reports are a convenience derivative. Raw
            // exact-address USBPcap capture remains authoritative and must be
            // allowed to proceed when optional evidence is not decodable.
            decoded_endpoint.reset();
        }
    }

    const auto output_paths =
        abdc::acquisition::OutputPathsIn(arguments.output_directory);
    abdc::acquisition::CapturePipeline pipeline(
        output_paths, {arguments.bus, arguments.address},
        std::move(decoded_endpoint));

    abdc::windows_capture::Win32NativeUsbPcapApi native_api;
    abdc::acquisition::NativeUsbPcapChunkSource source(native_api);
    abdc::acquisition::CaptureWorkerOptions worker_options;
    worker_options.native.root_index = arguments.root;
    worker_options.native.device_address = arguments.address;
    worker_options.durable_flush_interval =
        std::chrono::milliseconds(arguments.flush_ms);
    abdc::acquisition::CaptureWorker worker(
        source, pipeline, worker_options, [] { return QpcNow(); });

    const std::string capability = RandomCapability();
    std::optional<abdc::acquisition::CaptureWorkerResult> worker_result;
    std::string worker_exception;
    std::atomic<bool> worker_done{false};
    std::thread worker_thread([&] {
        try {
            worker_result = worker.Run();
        } catch (const std::exception& error) {
            worker_exception = error.what();
        } catch (...) {
            worker_exception = "capture worker threw an unknown exception";
        }
        worker_done.store(true, std::memory_order_release);
    });

    bool ready_written = false;
    bool health_created = false;
    std::string stop_origin;
    std::string control_error;
    std::optional<std::chrono::steady_clock::time_point> stop_file_seen;
    auto next_health = std::chrono::steady_clock::now();

    while (!worker_done.load(std::memory_order_acquire)) {
        const auto snapshot = worker.Snapshot();
        try {
            if (!ready_written &&
                (snapshot.state == CaptureWorkerState::Running ||
                 snapshot.state == CaptureWorkerState::StopRequested ||
                 snapshot.state == CaptureWorkerState::Draining)) {
                WriteNewFile(arguments.ready_file,
                             JsonLine(ReadyStatus(arguments, capability)));
                ready_written = true;
            }

            if (std::chrono::steady_clock::now() >= next_health) {
                const auto health = JsonLine(HealthStatus(snapshot, stop_origin));
                if (!health_created) {
                    WriteNewFile(arguments.health_file, health);
                    health_created = true;
                } else {
                    abdc::AtomicWriteFile(arguments.health_file, health);
                }
                next_health = std::chrono::steady_clock::now() +
                              std::chrono::seconds(1);
            }
        } catch (const std::exception& error) {
            control_error = std::string("status publication failed: ") + error.what();
            stop_origin = "status_failure";
            worker.RequestStop();
        }

        if (stop_origin.empty() && WaitForSingleObject(parent.Get(), 0) == WAIT_OBJECT_0) {
            stop_origin = "parent_exit";
            worker.RequestStop();
        }

        if (stop_origin.empty() && std::filesystem::exists(arguments.stop_file)) {
            if (!stop_file_seen) stop_file_seen = std::chrono::steady_clock::now();
            try {
                if (ValidStopFile(arguments.stop_file, capability)) {
                    stop_origin = "authorized_stop_file";
                    worker.RequestStop();
                } else {
                    throw std::runtime_error("stop capability did not match");
                }
            } catch (const std::exception& error) {
                // Atomic publication is expected, but allow a short window for
                // a parent that uses a plain create/write sequence.
                if (std::chrono::steady_clock::now() - *stop_file_seen >=
                    std::chrono::seconds(2)) {
                    control_error = std::string("invalid stop request: ") + error.what();
                    stop_origin = "invalid_stop_file";
                    worker.RequestStop();
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    worker_thread.join();

    const auto final_snapshot = worker.Snapshot();
    try {
        const auto health = JsonLine(HealthStatus(final_snapshot, stop_origin));
        if (!health_created) WriteNewFile(arguments.health_file, health);
        else abdc::AtomicWriteFile(arguments.health_file, health);
    } catch (const std::exception& error) {
        if (control_error.empty()) {
            control_error = std::string("final health publication failed: ") + error.what();
        }
    }

    if (!worker_exception.empty()) {
        WriteErrorIfPossible(arguments.error_file,
                             CaptureFatalReason::NativeOrDeviceLoss,
                             worker_exception);
        std::cerr << worker_exception << '\n';
        return 5;
    }
    if (!worker_result) {
        const std::string detail = "capture worker returned no result";
        WriteErrorIfPossible(arguments.error_file,
                             CaptureFatalReason::NativeOrDeviceLoss, detail);
        std::cerr << detail << '\n';
        return 5;
    }
    if (!control_error.empty()) {
        WriteErrorIfPossible(arguments.error_file,
                             CaptureFatalReason::WriterFailure, control_error);
        std::cerr << control_error << '\n';
        return 6;
    }
    if (!worker_result->clean) {
        WriteErrorIfPossible(arguments.error_file, worker_result->fatal_reason,
                             worker_result->detail);
        std::cerr << worker_result->detail << '\n';
        return 4;
    }
    return 0;
}

}  // namespace

int wmain(const int argc, wchar_t** argv) {
    std::optional<HelperArguments> arguments;
    std::optional<UniqueHandle> session_lease;
    try {
        if (abdc::IsVersionRequest(argc, argv)) {
            return abdc::PrintBuildVersion("abct_capture_helper");
        }
        arguments = ParseArguments(argc, argv);
        // Keep this independent handle alive through CaptureMain and through
        // any final error publication in the catch below. Recovery requests
        // an incompatible share mode and therefore cannot inspect or mutate
        // this session while the elevated writer may still publish files.
        session_lease.emplace(
            AcquireSharedSessionLease(arguments->lease_file));
        return CaptureMain(*arguments);
    } catch (const std::exception& error) {
        if (arguments && SafeAbsoluteFile(arguments->error_file)) {
            WriteErrorIfPossible(arguments->error_file,
                                 CaptureFatalReason::InvalidConfiguration,
                                 error.what());
        }
        std::cerr << "capture helper: " << error.what() << '\n';
        return 2;
    }
}
