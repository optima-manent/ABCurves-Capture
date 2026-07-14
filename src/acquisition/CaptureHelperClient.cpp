#include "acquisition/CaptureHelperClient.h"

#include "base/AtomicFile.h"
#include "base/Json.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace abdc::acquisition {
namespace {

constexpr std::wstring_view kHelperFilename = L"abct_capture_helper.exe";
constexpr std::chrono::milliseconds kPollInterval{50};
constexpr std::chrono::milliseconds kForcedExitWait{30'000};
constexpr std::uint32_t kForcedExitCode = 0xabdc0001U;

struct NativeProcess final {
    HANDLE process = nullptr;
    HANDLE kill_job = nullptr;
};

class LocalHandle final {
public:
    LocalHandle() = default;
    explicit LocalHandle(HANDLE value) : value_(value) {}
    ~LocalHandle() { Reset(); }
    LocalHandle(const LocalHandle&) = delete;
    LocalHandle& operator=(const LocalHandle&) = delete;
    [[nodiscard]] HANDLE Get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }
    void Reset(HANDLE value = nullptr) noexcept {
        if (*this) CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_ = nullptr;
};

class LocalMemory final {
public:
    explicit LocalMemory(HLOCAL value) : value_(value) {}
    ~LocalMemory() {
        if (value_ != nullptr) LocalFree(value_);
    }
    LocalMemory(const LocalMemory&) = delete;
    LocalMemory& operator=(const LocalMemory&) = delete;
    [[nodiscard]] HLOCAL Get() const noexcept { return value_; }

private:
    HLOCAL value_ = nullptr;
};

[[nodiscard]] std::wstring ExtendedPath(const std::filesystem::path& path) {
    auto value = std::filesystem::absolute(path).wstring();
    if (value.starts_with(L"\\\\?\\")) return value;
    if (value.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + value.substr(2);
    return L"\\\\?\\" + value;
}

[[nodiscard]] bool SafeAbsolutePath(const std::filesystem::path& path,
                                    const bool require_filename) {
    if (path.empty() || !path.is_absolute() ||
        (require_filename && path.filename().empty())) {
        return false;
    }
    const auto& value = path.native();
    return value.find(L'\0') == std::wstring::npos &&
           value.find(L'\r') == std::wstring::npos &&
           value.find(L'\n') == std::wstring::npos &&
           value.find(L'"') == std::wstring::npos;
}

[[nodiscard]] std::string WideToUtf8(const std::wstring_view value) {
    if (value.empty()) return {};
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("path is too long");
    }
    const int size = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) throw std::runtime_error("path text is invalid");
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                           static_cast<int>(value.size()), result.data(), size,
                           nullptr, nullptr) != size) {
        throw std::runtime_error("path text conversion failed");
    }
    return result;
}

[[nodiscard]] std::wstring Utf8ToWide(const std::string_view value) {
    if (value.empty()) return {};
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("status text is too long");
    }
    const int size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0);
    if (size <= 0) throw std::runtime_error("status path is not UTF-8");
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                            static_cast<int>(value.size()), result.data(), size) != size) {
        throw std::runtime_error("status path conversion failed");
    }
    return result;
}

[[nodiscard]] std::wstring PathKey(const std::filesystem::path& path) {
    auto result = std::filesystem::absolute(path).lexically_normal().native();
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t value) {
        if (value == L'/') return L'\\';
        return static_cast<wchar_t>(std::towlower(value));
    });
    return result;
}

[[nodiscard]] std::uint32_t CheckedProcessId(const std::int64_t value) {
    if (value <= 0 || value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("invalid process id in helper status");
    }
    return static_cast<std::uint32_t>(value);
}

[[nodiscard]] std::uint64_t CheckedCounter(const abdc::json::Value& value,
                                           const std::string_view name) {
    const auto number = value.At(name).AsInt();
    if (number < 0) throw std::runtime_error("negative helper health counter");
    return static_cast<std::uint64_t>(number);
}

[[nodiscard]] bool IsCapability(const std::string_view value) {
    return value.size() == 64U &&
           std::all_of(value.begin(), value.end(), [](const char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

[[nodiscard]] CaptureHelperReadySnapshot ParseReady(
    const std::string_view text, const std::uint32_t expected_helper_pid,
    const std::uint32_t expected_parent_pid,
    const std::filesystem::path& expected_output) {
    const auto value = abdc::json::Parse(text);
    if (value.At("schema").AsString() != "abcurves.capture.ready.v1" ||
        value.At("state").AsString() != "ready" ||
        value.At("stop_schema").AsString() != "abcurves.capture.stop.v1") {
        throw std::runtime_error("unexpected helper ready schema");
    }
    CaptureHelperReadySnapshot result;
    result.capability = value.At("capability").AsString();
    result.helper_pid = CheckedProcessId(value.At("helper_pid").AsInt());
    result.parent_pid = CheckedProcessId(value.At("parent_pid").AsInt());
    result.output_directory =
        std::filesystem::path(Utf8ToWide(value.At("output_directory").AsString()));
    if (!IsCapability(result.capability) ||
        result.helper_pid != expected_helper_pid ||
        result.parent_pid != expected_parent_pid ||
        PathKey(result.output_directory) != PathKey(expected_output)) {
        throw std::runtime_error("helper ready identity did not match launch");
    }
    return result;
}

[[nodiscard]] CaptureHelperHealthSnapshot ParseHealth(
    const std::string_view text) {
    const auto value = abdc::json::Parse(text);
    if (value.At("schema").AsString() != "abcurves.capture.health.v1") {
        throw std::runtime_error("unexpected helper health schema");
    }
    CaptureHelperHealthSnapshot result;
    result.state = value.At("state").AsString();
    result.fatal_reason = value.At("fatal_reason").AsString();
    result.detail = value.At("detail").AsString();
    result.stop_origin = value.At("stop_origin").AsString();
    result.source_bytes = CheckedCounter(value, "source_bytes");
    result.source_records = CheckedCounter(value, "source_records");
    result.endpoint_records = CheckedCounter(value, "endpoint_records");
    result.decoded_reports = CheckedCounter(value, "decoded_reports");
    result.anomalies = CheckedCounter(value, "anomalies");
    result.native_bytes_read = CheckedCounter(value, "native_bytes_read");
    result.native_queued_bytes = CheckedCounter(value, "native_queued_bytes");
    return result;
}

[[nodiscard]] CaptureHelperErrorSnapshot ParseError(
    const std::string_view text) {
    const auto value = abdc::json::Parse(text);
    if (value.At("schema").AsString() != "abcurves.capture.error.v1" ||
        value.At("state").AsString() != "error") {
        throw std::runtime_error("unexpected helper error schema");
    }
    CaptureHelperErrorSnapshot result;
    result.fatal_reason = value.At("fatal_reason").AsString();
    result.detail = value.At("detail").AsString();
    return result;
}

[[nodiscard]] std::string ParticipantError(
    const std::optional<CaptureHelperErrorSnapshot>& error,
    const std::string_view fallback) {
    if (!error) return std::string(fallback);
    if (error->fatal_reason == "queue_or_byte_loss") {
        return "Mouse capture lost data and stopped.";
    }
    if (error->fatal_reason == "native_or_device_loss") {
        return "The USB capture connection was lost.";
    }
    if (error->fatal_reason == "device_identity_changed") {
        return "The selected mouse changed.";
    }
    if (error->fatal_reason == "pcap_framing") {
        return "Mouse capture data became incomplete.";
    }
    if (error->fatal_reason == "writer_failure") {
        return "Mouse capture could not save data.";
    }
    if (error->fatal_reason == "invalid_configuration") {
        return "The selected mouse could not be opened.";
    }
    return std::string(fallback);
}

[[nodiscard]] std::string StopJson(const std::string_view capability) {
    abdc::json::Value value(abdc::json::Value::Object{});
    value["schema"] = "abcurves.capture.stop.v1";
    value["capability"] = std::string(capability);
    return abdc::json::DumpCanonical(value, false) + "\n";
}

[[nodiscard]] std::string ValidateConfig(
    const CaptureHelperLaunchConfig& config,
    const std::filesystem::path& executable,
    const ICaptureHelperPlatform& platform) {
    if (config.usb.root == 0 || config.usb.root > 255 ||
        config.usb.address == 0 || config.usb.address > 127 ||
        config.usb.bus == 0 ||
        (config.usb.endpoint != 0U &&
         ((config.usb.endpoint & 0x80U) == 0U ||
          (config.usb.endpoint & 0x0fU) == 0U))) {
        return "The selected mouse identity is invalid.";
    }
    if (!SafeAbsolutePath(config.output_directory, true) ||
        !platform.IsDirectory(config.output_directory)) {
        return "The capture folder is unavailable.";
    }
    if (!SafeAbsolutePath(config.session_lease, true) ||
        !platform.IsRegularFile(config.session_lease)) {
        return "The session writer lease is unavailable.";
    }
    if (!SafeAbsolutePath(executable, true)) {
        return "The USB capture helper path is invalid.";
    }
    if (config.durable_flush_ms == 0 || config.durable_flush_ms > 60'000 ||
        config.readiness_timeout <= std::chrono::milliseconds::zero() ||
        config.readiness_timeout > std::chrono::minutes(5) ||
        config.graceful_shutdown_timeout <= std::chrono::milliseconds::zero() ||
        config.graceful_shutdown_timeout > std::chrono::minutes(5)) {
        return "Mouse capture timing settings are invalid.";
    }
    return {};
}

[[nodiscard]] std::chrono::milliseconds NextPoll(
    const std::chrono::milliseconds remaining) {
    return std::min(remaining, kPollInterval);
}

[[nodiscard]] std::string RandomHex(const std::size_t byte_count) {
    std::vector<unsigned char> random(byte_count);
    if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("secure random generation failed");
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(byte_count * 2U, '0');
    for (std::size_t index = 0; index < random.size(); ++index) {
        result[index * 2U] = digits[random[index] >> 4U];
        result[index * 2U + 1U] = digits[random[index] & 0x0fU];
    }
    return result;
}

[[nodiscard]] std::wstring CurrentUserSidText() {
    LocalHandle token;
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
        throw std::runtime_error("cannot secure capture controls");
    }
    token.Reset(raw_token);
    DWORD size = 0;
    static_cast<void>(GetTokenInformation(token.Get(), TokenUser, nullptr, 0, &size));
    if (size == 0) throw std::runtime_error("cannot secure capture controls");
    std::vector<std::byte> buffer(size);
    if (!GetTokenInformation(token.Get(), TokenUser, buffer.data(), size, &size)) {
        throw std::runtime_error("cannot secure capture controls");
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid)) {
        throw std::runtime_error("cannot secure capture controls");
    }
    LocalMemory memory(sid);
    return std::wstring(sid);
}

[[nodiscard]] PSECURITY_DESCRIPTOR PrivateDirectorySecurityDescriptor() {
    const auto sid = CurrentUserSidText();
    const std::wstring sddl =
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + L")";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        throw std::runtime_error("cannot secure capture controls");
    }
    return descriptor;
}

}  // namespace

class CaptureHelperClient::Mutex final {
public:
    std::mutex value;
};

std::wstring QuoteCaptureHelperArgument(const std::wstring_view value) {
    const bool needs_quotes = value.empty() ||
        value.find_first_of(L" \t\n\v\"") != std::wstring_view::npos;
    if (!needs_quotes) return std::wstring(value);

    std::wstring result(1, L'"');
    std::size_t backslashes = 0;
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++backslashes;
            continue;
        }
        if (character == L'"') {
            result.append(backslashes * 2U + 1U, L'\\');
            result.push_back(L'"');
        } else {
            result.append(backslashes, L'\\');
            result.push_back(character);
        }
        backslashes = 0;
    }
    result.append(backslashes * 2U, L'\\');
    result.push_back(L'"');
    return result;
}

std::wstring SerializeCaptureHelperArguments(
    const std::span<const std::wstring> arguments) {
    std::wstring result;
    for (const auto& argument : arguments) {
        if (!result.empty()) result.push_back(L' ');
        result.append(QuoteCaptureHelperArgument(argument));
    }
    return result;
}

CaptureHelperCommand BuildCaptureHelperCommand(
    const CaptureHelperLaunchConfig& config,
    const CaptureHelperControlPaths& controls,
    const std::filesystem::path& executable,
    const std::uint32_t parent_pid) {
    CaptureHelperCommand result;
    result.executable = executable;
    result.arguments = {
        L"--capture",
        L"--root", std::to_wstring(config.usb.root),
        L"--address", std::to_wstring(config.usb.address),
        L"--bus", std::to_wstring(config.usb.bus),
        L"--endpoint", std::to_wstring(config.usb.endpoint),
        L"--descriptor", controls.descriptor.wstring(),
        L"--output-dir", config.output_directory.wstring(),
        L"--lease", config.session_lease.wstring(),
        L"--parent-pid", std::to_wstring(parent_pid),
        L"--ready-file", controls.ready.wstring(),
        L"--health-file", controls.health.wstring(),
        L"--stop-file", controls.stop.wstring(),
        L"--error-file", controls.error.wstring(),
        L"--flush-ms", std::to_wstring(config.durable_flush_ms),
    };
    result.parameter_line = SerializeCaptureHelperArguments(result.arguments);
    return result;
}

std::uint32_t Win32CaptureHelperPlatform::CurrentProcessId() const {
    return GetCurrentProcessId();
}

std::filesystem::path Win32CaptureHelperPlatform::SiblingExecutable(
    const std::wstring_view filename) const {
    std::vector<wchar_t> buffer(512, L'\0');
    for (;;) {
        const DWORD count = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (count == 0) throw std::runtime_error("application location is unavailable");
        if (count < buffer.size() - 1U) {
            const std::filesystem::path module(
                std::wstring(buffer.data(), static_cast<std::size_t>(count)));
            return std::filesystem::absolute(module.parent_path() / filename);
        }
        if (buffer.size() >= 32'768U) {
            throw std::runtime_error("application path is too long");
        }
        buffer.resize(std::min<std::size_t>(buffer.size() * 2U, 32'768U), L'\0');
    }
}

std::filesystem::path Win32CaptureHelperPlatform::DefaultControlRoot() const {
    std::vector<wchar_t> buffer(MAX_PATH + 1U, L'\0');
    const DWORD required = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
    if (required == 0) throw std::runtime_error("temporary folder is unavailable");
    if (required >= buffer.size()) {
        buffer.resize(static_cast<std::size_t>(required) + 1U, L'\0');
        const DWORD second = GetTempPathW(
            static_cast<DWORD>(buffer.size()), buffer.data());
        if (second == 0 || second >= buffer.size()) {
            throw std::runtime_error("temporary folder is unavailable");
        }
    }
    return std::filesystem::absolute(
        std::filesystem::path(buffer.data()) / L"ABCurvesCaptureTrainer");
}

bool Win32CaptureHelperPlatform::IsDirectory(
    const std::filesystem::path& path) const {
    std::error_code error;
    return std::filesystem::is_directory(path, error) && !error;
}

bool Win32CaptureHelperPlatform::IsRegularFile(
    const std::filesystem::path& path) const {
    std::error_code error;
    return std::filesystem::is_regular_file(path, error) && !error;
}

std::filesystem::path Win32CaptureHelperPlatform::CreatePrivateControlDirectory(
    const std::filesystem::path& root) {
    if (!SafeAbsolutePath(root, false)) {
        throw std::runtime_error("control folder path is invalid");
    }
    std::error_code error;
    std::filesystem::create_directories(root, error);
    if (error || !std::filesystem::is_directory(root, error) || error) {
        throw std::runtime_error("control folder is unavailable");
    }

    LocalMemory descriptor(PrivateDirectorySecurityDescriptor());
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor.Get();
    attributes.bInheritHandle = FALSE;

    for (unsigned attempt = 0; attempt < 32U; ++attempt) {
        const auto path = root / (L"capture-" + Utf8ToWide(RandomHex(16)));
        const auto native = ExtendedPath(path);
        if (CreateDirectoryW(native.c_str(), &attributes)) return path;
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            throw std::runtime_error("private capture controls could not be created");
        }
    }
    throw std::runtime_error("fresh capture controls could not be created");
}

void Win32CaptureHelperPlatform::WriteNewPrivateFile(
    const std::filesystem::path& path, const std::span<const std::byte> bytes) {
    const auto native = ExtendedPath(path);
    LocalHandle output(CreateFileW(
        native.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (!output) throw std::runtime_error("capture evidence could not be created");
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD count = static_cast<DWORD>(std::min<std::size_t>(
            bytes.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(output.Get(), bytes.data() + offset, count, &written, nullptr) ||
            written != count) {
            throw std::runtime_error("capture evidence could not be saved");
        }
        offset += written;
    }
    if (!FlushFileBuffers(output.Get())) {
        throw std::runtime_error("capture evidence could not be saved");
    }
}

ElevatedLaunchResult Win32CaptureHelperPlatform::LaunchElevated(
    const std::filesystem::path& executable,
    const std::wstring_view parameter_line) {
    ElevatedLaunchResult result;
    const std::wstring file = executable.wstring();
    const std::wstring parameters(parameter_line);
    const std::wstring directory = executable.parent_path().wstring();
    SHELLEXECUTEINFOW execute{};
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC |
                    SEE_MASK_FLAG_NO_UI;
    execute.lpVerb = L"runas";
    execute.lpFile = file.c_str();
    execute.lpParameters = parameters.c_str();
    execute.lpDirectory = directory.empty() ? nullptr : directory.c_str();
    execute.nShow = SW_HIDE;
    if (!ShellExecuteExW(&execute)) {
        result.native_error = GetLastError();
        if (result.native_error == ERROR_CANCELLED) {
            result.disposition = ElevatedLaunchDisposition::UacDenied;
        } else if (result.native_error == ERROR_FILE_NOT_FOUND ||
                   result.native_error == ERROR_PATH_NOT_FOUND) {
            result.disposition = ElevatedLaunchDisposition::NotFound;
        } else {
            result.disposition = ElevatedLaunchDisposition::Failed;
        }
        return result;
    }
    if (execute.hProcess == nullptr) {
        result.disposition = ElevatedLaunchDisposition::Failed;
        return result;
    }

    auto process = std::make_unique<NativeProcess>();
    process->process = execute.hProcess;
    process->kill_job = CreateJobObjectW(nullptr, nullptr);
    if (process->kill_job != nullptr) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(process->kill_job,
                                     JobObjectExtendedLimitInformation,
                                     &limits, sizeof(limits)) ||
            !AssignProcessToJobObject(process->kill_job, process->process)) {
            CloseHandle(process->kill_job);
            process->kill_job = nullptr;
        }
    }
    result.disposition = ElevatedLaunchDisposition::Started;
    result.process_id = GetProcessId(process->process);
    result.process = reinterpret_cast<std::uintptr_t>(process.release());
    if (result.process_id == 0) {
        CloseProcess(result.process);
        result.process = 0;
        result.disposition = ElevatedLaunchDisposition::Failed;
    }
    return result;
}

CaptureHelperProcessPoll Win32CaptureHelperPlatform::WaitProcess(
    const std::uintptr_t process, const std::chrono::milliseconds timeout) {
    const auto* native = reinterpret_cast<const NativeProcess*>(process);
    if (native == nullptr || native->process == nullptr || timeout.count() < 0) {
        return {CaptureHelperProcessState::Failed, std::nullopt};
    }
    const auto bounded = std::min<std::int64_t>(
        timeout.count(), std::numeric_limits<DWORD>::max() - 1LL);
    const DWORD wait = WaitForSingleObject(
        native->process, static_cast<DWORD>(bounded));
    if (wait == WAIT_TIMEOUT) {
        return {CaptureHelperProcessState::Running, std::nullopt};
    }
    if (wait != WAIT_OBJECT_0) {
        return {CaptureHelperProcessState::Failed, std::nullopt};
    }
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(native->process, &exit_code)) {
        return {CaptureHelperProcessState::Failed, std::nullopt};
    }
    return {CaptureHelperProcessState::Exited, exit_code};
}

bool Win32CaptureHelperPlatform::TerminateProcess(
    const std::uintptr_t process, const std::uint32_t exit_code) {
    const auto* native = reinterpret_cast<const NativeProcess*>(process);
    if (native == nullptr || native->process == nullptr) return false;
    if (::TerminateProcess(native->process, exit_code)) return true;
    if (native->kill_job != nullptr && TerminateJobObject(native->kill_job, exit_code)) {
        return true;
    }
    return WaitForSingleObject(native->process, 0) == WAIT_OBJECT_0;
}

void Win32CaptureHelperPlatform::CloseProcess(const std::uintptr_t process) noexcept {
    auto* native = reinterpret_cast<NativeProcess*>(process);
    if (native == nullptr) return;
    if (native->process != nullptr) CloseHandle(native->process);
    if (native->kill_job != nullptr) CloseHandle(native->kill_job);
    delete native;
}

bool Win32CaptureHelperPlatform::FileExists(
    const std::filesystem::path& path) const {
    std::error_code error;
    return std::filesystem::is_regular_file(path, error) && !error;
}

std::string Win32CaptureHelperPlatform::ReadSmallFile(
    const std::filesystem::path& path, const std::uint64_t maximum_bytes) const {
    return abdc::ReadUtf8File(path, maximum_bytes);
}

void Win32CaptureHelperPlatform::AtomicWriteFile(
    const std::filesystem::path& path, const std::string_view contents) {
    abdc::AtomicWriteFile(path, contents);
}

void Win32CaptureHelperPlatform::RemoveOwnedFile(
    const std::filesystem::path& path) noexcept {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

void Win32CaptureHelperPlatform::RemoveOwnedDirectoryIfEmpty(
    const std::filesystem::path& path) noexcept {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

CaptureHelperClient::CaptureHelperClient()
    : CaptureHelperClient(std::make_shared<Win32CaptureHelperPlatform>()) {}

CaptureHelperClient::CaptureHelperClient(
    std::shared_ptr<ICaptureHelperPlatform> platform)
    : platform_(std::move(platform)), mutex_(std::make_unique<Mutex>()) {
    if (!platform_) throw std::invalid_argument("capture helper platform is required");
}

CaptureHelperClient::~CaptureHelperClient() {
    if (!mutex_) return;
    std::scoped_lock lock(mutex_->value);
    static_cast<void>(StopAndWaitWithoutLock());
}

CaptureHelperStartResult CaptureHelperClient::Start(
    const CaptureHelperLaunchConfig& config) {
    std::scoped_lock lock(mutex_->value);
    if (start_attempted_) {
        return {false, CaptureHelperStartFailure::InvalidConfiguration,
                "Mouse capture has already been started."};
    }
    start_attempted_ = true;
    state_ = CaptureHelperClientState::Starting;
    config_ = config;

    try {
        const auto executable = config.helper_executable.empty()
            ? platform_->SiblingExecutable(kHelperFilename)
            : std::filesystem::absolute(config.helper_executable);
        config_.output_directory = std::filesystem::absolute(config.output_directory);
        config_.session_lease = std::filesystem::absolute(config.session_lease);
        config_.helper_executable = executable;
        if (config_.descriptor_evidence.size() > (1U << 20U) ||
            config_.usb.endpoint == 0U) {
            // Optional decoder evidence may be absent or unusable without
            // weakening exact-address raw USB capture.
            config_.descriptor_evidence.clear();
        }
        const auto validation = ValidateConfig(config_, executable, *platform_);
        if (!validation.empty()) {
            state_ = CaptureHelperClientState::Failed;
            message_ = validation;
            return {false, CaptureHelperStartFailure::InvalidConfiguration, message_};
        }
        if (!platform_->IsRegularFile(executable)) {
            state_ = CaptureHelperClientState::Failed;
            message_ = "The USB capture helper is missing.";
            return {false, CaptureHelperStartFailure::HelperMissing, message_};
        }

        const auto control_root = config.control_root.empty()
            ? platform_->DefaultControlRoot()
            : std::filesystem::absolute(config.control_root);
        controls_.directory = platform_->CreatePrivateControlDirectory(control_root);
        controls_created_ = true;
        controls_.descriptor = controls_.directory / L"descriptor.bin";
        controls_.ready = controls_.directory / L"ready.json";
        controls_.health = controls_.directory / L"health.json";
        controls_.stop = controls_.directory / L"stop.json";
        controls_.error = controls_.directory / L"error.json";
        platform_->WriteNewPrivateFile(controls_.descriptor,
                                       config_.descriptor_evidence);

        parent_pid_ = platform_->CurrentProcessId();
        if (parent_pid_ == 0) throw std::runtime_error("parent process is unavailable");
        const auto command = BuildCaptureHelperCommand(
            config_, controls_, executable, parent_pid_);
        const auto launched = platform_->LaunchElevated(
            command.executable, command.parameter_line);
        if (launched.disposition != ElevatedLaunchDisposition::Started ||
            launched.process == 0 || launched.process_id == 0) {
            CleanupControls();
            state_ = CaptureHelperClientState::Failed;
            if (launched.disposition == ElevatedLaunchDisposition::UacDenied) {
                message_ = "Mouse capture needs administrator approval.";
                return {false, CaptureHelperStartFailure::UacDenied, message_};
            }
            if (launched.disposition == ElevatedLaunchDisposition::NotFound) {
                message_ = "The USB capture helper is missing.";
                return {false, CaptureHelperStartFailure::HelperMissing, message_};
            }
            message_ = "Mouse capture could not start.";
            return {false, CaptureHelperStartFailure::LaunchFailed, message_};
        }
        process_ = launched.process;
        launched_process_id_ = launched.process_id;

        auto remaining = config_.readiness_timeout;
        bool ready_file_seen = false;
        while (remaining > std::chrono::milliseconds::zero()) {
            if (platform_->FileExists(controls_.error)) {
                try {
                    error_ = ParseError(platform_->ReadSmallFile(controls_.error, 16U << 10U));
                } catch (...) {
                }
                if (error_) {
                    message_ = ParticipantError(
                        error_, "Mouse capture stopped before it was ready.");
                    const auto exit_wait = std::min(remaining,
                        std::chrono::milliseconds{2'000});
                    const auto poll = platform_->WaitProcess(process_, exit_wait);
                    if (poll.state == CaptureHelperProcessState::Exited) {
                        FinishExited(poll.exit_code);
                    } else {
                        TerminateFailedStart();
                    }
                    state_ = CaptureHelperClientState::Failed;
                    return {false, CaptureHelperStartFailure::EarlyExit, message_};
                }
            }
            if (platform_->FileExists(controls_.ready)) {
                ready_file_seen = true;
                try {
                    ready_ = ParseReady(
                        platform_->ReadSmallFile(controls_.ready, 4096),
                        launched_process_id_, parent_pid_, config_.output_directory);
                } catch (...) {
                    // The helper creates its one-shot status file before
                    // filling and flushing it. A single incomplete read is a
                    // publication race, not evidence of a forged status.
                }
                if (ready_) {
                    state_ = CaptureHelperClientState::Running;
                    message_.clear();
                    ObserveHealthAndError();
                    return {true, CaptureHelperStartFailure::None, {}};
                }
            }

            const auto slice = NextPoll(remaining);
            const auto poll = platform_->WaitProcess(process_, slice);
            remaining -= slice;
            if (poll.state == CaptureHelperProcessState::Exited) {
                ObserveHealthAndError();
                FinishExited(poll.exit_code);
                message_ = ParticipantError(
                    error_, "Mouse capture stopped before it was ready.");
                state_ = CaptureHelperClientState::Failed;
                return {false, CaptureHelperStartFailure::EarlyExit, message_};
            }
            if (poll.state == CaptureHelperProcessState::Failed) {
                message_ = "Mouse capture could not be monitored.";
                state_ = CaptureHelperClientState::Failed;
                TerminateFailedStart();
                return {false, CaptureHelperStartFailure::LaunchFailed, message_};
            }
        }

        message_ = ready_file_seen
            ? "Mouse capture returned invalid status."
            : "Mouse capture did not start in time.";
        state_ = CaptureHelperClientState::Failed;
        TerminateFailedStart();
        return {false, ready_file_seen
                           ? CaptureHelperStartFailure::InvalidStatus
                           : CaptureHelperStartFailure::ReadyTimeout,
                message_};
    } catch (...) {
        message_ = "Mouse capture could not start.";
        state_ = CaptureHelperClientState::Failed;
        TerminateFailedStart();
        CleanupControls();
        return {false, CaptureHelperStartFailure::LaunchFailed, message_};
    }
}

CaptureHelperClientSnapshot CaptureHelperClient::Snapshot() {
    std::scoped_lock lock(mutex_->value);
    return SnapshotWithoutLock();
}

CaptureHelperClientSnapshot CaptureHelperClient::SnapshotWithoutLock() {
    ObserveHealthAndError();
    if (process_ != 0) {
        const auto poll = platform_->WaitProcess(process_, std::chrono::milliseconds::zero());
        if (poll.state == CaptureHelperProcessState::Exited) {
            ObserveHealthAndError();
            FinishExited(poll.exit_code);
        } else if (poll.state == CaptureHelperProcessState::Failed) {
            message_ = "Mouse capture status is unavailable.";
        }
    }
    return {state_, exit_code_, ready_, health_, error_, message_,
            process_ != 0};
}

void CaptureHelperClient::ObserveHealthAndError() noexcept {
    try {
        if (!controls_created_) return;
        if (platform_->FileExists(controls_.health)) {
            health_ = ParseHealth(
                platform_->ReadSmallFile(controls_.health, 64U << 10U));
        }
        if (platform_->FileExists(controls_.error)) {
            error_ = ParseError(
                platform_->ReadSmallFile(controls_.error, 16U << 10U));
        }
    } catch (...) {
        // A health refresh is advisory. Keep the last complete snapshot; the
        // process handle and final error/exit status remain authoritative.
    }
}

bool CaptureHelperClient::RequestStop() {
    std::scoped_lock lock(mutex_->value);
    if (process_ == 0) return state_ == CaptureHelperClientState::Completed;
    if (state_ == CaptureHelperClientState::StopRequested) return true;
    if (!ready_ || !IsCapability(ready_->capability)) return false;
    try {
        platform_->AtomicWriteFile(controls_.stop,
                                   StopJson(ready_->capability));
        state_ = CaptureHelperClientState::StopRequested;
        return true;
    } catch (...) {
        message_ = "Mouse capture could not be stopped normally.";
        return false;
    }
}

CaptureHelperStopResult CaptureHelperClient::StopAndWait() {
    std::scoped_lock lock(mutex_->value);
    return StopAndWaitWithoutLock();
}

CaptureHelperStopResult CaptureHelperClient::StopAndWaitWithoutLock() noexcept {
    if (process_ == 0) {
        CleanupControls();
        return {state_ == CaptureHelperClientState::Completed,
                forced_termination_, exit_code_, message_};
    }

    if (ready_ && state_ != CaptureHelperClientState::StopRequested) {
        try {
            platform_->AtomicWriteFile(controls_.stop,
                                       StopJson(ready_->capability));
            state_ = CaptureHelperClientState::StopRequested;
        } catch (...) {
            message_ = "Mouse capture could not be stopped normally.";
        }
    }

    auto remaining = config_.graceful_shutdown_timeout;
    while (remaining > std::chrono::milliseconds::zero()) {
        const auto slice = NextPoll(remaining);
        CaptureHelperProcessPoll poll;
        try {
            poll = platform_->WaitProcess(process_, slice);
        } catch (...) {
            poll.state = CaptureHelperProcessState::Failed;
        }
        remaining -= slice;
        if (poll.state == CaptureHelperProcessState::Exited) {
            ObserveHealthAndError();
            FinishExited(poll.exit_code);
            return {true, forced_termination_, exit_code_, message_};
        }
        if (poll.state == CaptureHelperProcessState::Failed) break;
    }

    forced_termination_ = true;
    try {
        static_cast<void>(platform_->TerminateProcess(process_, kForcedExitCode));
        const auto poll = platform_->WaitProcess(process_, kForcedExitWait);
        if (poll.state == CaptureHelperProcessState::Exited) {
            ObserveHealthAndError();
            FinishExited(poll.exit_code);
            message_ = "Mouse capture was force-stopped.";
            state_ = CaptureHelperClientState::Failed;
            return {true, true, exit_code_, message_};
        }
    } catch (...) {
    }

    // Keep control files if the process did not signal: they are its only
    // authenticated stop channel. The helper is additionally tethered to our
    // PID and cannot outlive the participant application.
    message_ = "Mouse capture is still stopping.";
    state_ = CaptureHelperClientState::Failed;
    return {false, true, exit_code_, message_};
}

void CaptureHelperClient::FinishExited(
    const std::optional<std::uint32_t> exit_code) noexcept {
    exit_code_ = exit_code;
    if (process_ != 0) {
        platform_->CloseProcess(process_);
        process_ = 0;
    }
    if (exit_code && *exit_code == 0 && !forced_termination_) {
        state_ = CaptureHelperClientState::Completed;
        if (message_ == "Mouse capture is still stopping.") message_.clear();
    } else {
        state_ = CaptureHelperClientState::Failed;
        if (message_.empty()) {
            message_ = ParticipantError(error_, "Mouse capture stopped unexpectedly.");
        }
    }
    CleanupControls();
}

void CaptureHelperClient::TerminateFailedStart() noexcept {
    if (process_ == 0) return;
    forced_termination_ = true;
    try {
        static_cast<void>(platform_->TerminateProcess(process_, kForcedExitCode));
        const auto poll = platform_->WaitProcess(process_, kForcedExitWait);
        if (poll.state != CaptureHelperProcessState::Exited) return;
        exit_code_ = poll.exit_code;
        platform_->CloseProcess(process_);
        process_ = 0;
        CleanupControls();
    } catch (...) {
    }
}

void CaptureHelperClient::CleanupControls() noexcept {
    if (!controls_created_ || process_ != 0) return;
    platform_->RemoveOwnedFile(controls_.stop);
    platform_->RemoveOwnedFile(controls_.error);
    platform_->RemoveOwnedFile(controls_.health);
    platform_->RemoveOwnedFile(controls_.ready);
    platform_->RemoveOwnedFile(controls_.descriptor);
    platform_->RemoveOwnedDirectoryIfEmpty(controls_.directory);
    controls_created_ = false;
}

}  // namespace abdc::acquisition
