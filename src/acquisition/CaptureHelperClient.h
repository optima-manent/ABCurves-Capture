#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace abdc::acquisition {

struct CaptureHelperUsbIdentity {
    std::uint16_t root = 0;
    std::uint8_t address = 0;
    std::uint16_t bus = 0;
    std::uint8_t endpoint = 0;
};

struct CaptureHelperControlPaths {
    std::filesystem::path directory;
    std::filesystem::path descriptor;
    std::filesystem::path ready;
    std::filesystem::path health;
    std::filesystem::path stop;
    std::filesystem::path error;
};

struct CaptureHelperLaunchConfig {
    CaptureHelperUsbIdentity usb;
    std::vector<std::byte> descriptor_evidence;
    std::filesystem::path output_directory;
    std::filesystem::path session_lease;

    // Empty values select the sibling abct_capture_helper.exe and the
    // platform's per-user temporary control root, respectively.
    std::filesystem::path helper_executable;
    std::filesystem::path control_root;

    std::chrono::milliseconds readiness_timeout{15'000};
    std::chrono::milliseconds graceful_shutdown_timeout{10'000};
    std::uint32_t durable_flush_ms = 2'000;
};

struct CaptureHelperCommand {
    std::filesystem::path executable;
    std::vector<std::wstring> arguments;
    std::wstring parameter_line;
};

[[nodiscard]] std::wstring QuoteCaptureHelperArgument(std::wstring_view value);
[[nodiscard]] std::wstring SerializeCaptureHelperArguments(
    std::span<const std::wstring> arguments);
[[nodiscard]] CaptureHelperCommand BuildCaptureHelperCommand(
    const CaptureHelperLaunchConfig& config,
    const CaptureHelperControlPaths& controls,
    const std::filesystem::path& executable,
    std::uint32_t parent_pid);

enum class ElevatedLaunchDisposition {
    Started,
    UacDenied,
    NotFound,
    Failed,
};

struct ElevatedLaunchResult {
    ElevatedLaunchDisposition disposition = ElevatedLaunchDisposition::Failed;
    std::uintptr_t process = 0;
    std::uint32_t process_id = 0;
    std::uint32_t native_error = 0;
};

enum class CaptureHelperProcessState {
    Running,
    Exited,
    Failed,
};

struct CaptureHelperProcessPoll {
    CaptureHelperProcessState state = CaptureHelperProcessState::Failed;
    std::optional<std::uint32_t> exit_code;
};

// All effects needed by the client are behind this interface so contract
// tests never need USBPcap, UAC, real processes, sleeps, or the filesystem.
class ICaptureHelperPlatform {
public:
    virtual ~ICaptureHelperPlatform() = default;

    [[nodiscard]] virtual std::uint32_t CurrentProcessId() const = 0;
    [[nodiscard]] virtual std::filesystem::path SiblingExecutable(
        std::wstring_view filename) const = 0;
    [[nodiscard]] virtual std::filesystem::path DefaultControlRoot() const = 0;
    [[nodiscard]] virtual bool IsDirectory(
        const std::filesystem::path& path) const = 0;
    [[nodiscard]] virtual bool IsRegularFile(
        const std::filesystem::path& path) const = 0;

    // The returned directory must be newly created with a protected DACL.
    [[nodiscard]] virtual std::filesystem::path CreatePrivateControlDirectory(
        const std::filesystem::path& root) = 0;
    virtual void WriteNewPrivateFile(const std::filesystem::path& path,
                                     std::span<const std::byte> bytes) = 0;

    [[nodiscard]] virtual ElevatedLaunchResult LaunchElevated(
        const std::filesystem::path& executable,
        std::wstring_view parameter_line) = 0;
    [[nodiscard]] virtual CaptureHelperProcessPoll WaitProcess(
        std::uintptr_t process, std::chrono::milliseconds timeout) = 0;
    [[nodiscard]] virtual bool TerminateProcess(std::uintptr_t process,
                                                std::uint32_t exit_code) = 0;
    virtual void CloseProcess(std::uintptr_t process) noexcept = 0;

    [[nodiscard]] virtual bool FileExists(
        const std::filesystem::path& path) const = 0;
    [[nodiscard]] virtual std::string ReadSmallFile(
        const std::filesystem::path& path, std::uint64_t maximum_bytes) const = 0;
    virtual void AtomicWriteFile(const std::filesystem::path& path,
                                 std::string_view contents) = 0;
    virtual void RemoveOwnedFile(const std::filesystem::path& path) noexcept = 0;
    virtual void RemoveOwnedDirectoryIfEmpty(
        const std::filesystem::path& path) noexcept = 0;
};

class Win32CaptureHelperPlatform final : public ICaptureHelperPlatform {
public:
    [[nodiscard]] std::uint32_t CurrentProcessId() const override;
    [[nodiscard]] std::filesystem::path SiblingExecutable(
        std::wstring_view filename) const override;
    [[nodiscard]] std::filesystem::path DefaultControlRoot() const override;
    [[nodiscard]] bool IsDirectory(
        const std::filesystem::path& path) const override;
    [[nodiscard]] bool IsRegularFile(
        const std::filesystem::path& path) const override;
    [[nodiscard]] std::filesystem::path CreatePrivateControlDirectory(
        const std::filesystem::path& root) override;
    void WriteNewPrivateFile(const std::filesystem::path& path,
                             std::span<const std::byte> bytes) override;
    [[nodiscard]] ElevatedLaunchResult LaunchElevated(
        const std::filesystem::path& executable,
        std::wstring_view parameter_line) override;
    [[nodiscard]] CaptureHelperProcessPoll WaitProcess(
        std::uintptr_t process, std::chrono::milliseconds timeout) override;
    [[nodiscard]] bool TerminateProcess(std::uintptr_t process,
                                        std::uint32_t exit_code) override;
    void CloseProcess(std::uintptr_t process) noexcept override;
    [[nodiscard]] bool FileExists(
        const std::filesystem::path& path) const override;
    [[nodiscard]] std::string ReadSmallFile(
        const std::filesystem::path& path,
        std::uint64_t maximum_bytes) const override;
    void AtomicWriteFile(const std::filesystem::path& path,
                         std::string_view contents) override;
    void RemoveOwnedFile(const std::filesystem::path& path) noexcept override;
    void RemoveOwnedDirectoryIfEmpty(
        const std::filesystem::path& path) noexcept override;
};

enum class CaptureHelperClientState {
    Idle,
    Starting,
    Running,
    StopRequested,
    Completed,
    Failed,
};

enum class CaptureHelperStartFailure {
    None,
    InvalidConfiguration,
    UacDenied,
    HelperMissing,
    LaunchFailed,
    ReadyTimeout,
    EarlyExit,
    InvalidStatus,
};

struct CaptureHelperReadySnapshot {
    std::string capability;
    std::uint32_t helper_pid = 0;
    std::uint32_t parent_pid = 0;
    std::filesystem::path output_directory;
};

struct CaptureHelperHealthSnapshot {
    std::string state;
    std::string fatal_reason;
    std::string detail;
    std::string stop_origin;
    std::uint64_t source_bytes = 0;
    std::uint64_t source_records = 0;
    std::uint64_t endpoint_records = 0;
    std::uint64_t decoded_reports = 0;
    std::uint64_t anomalies = 0;
    std::uint64_t native_bytes_read = 0;
    std::uint64_t native_queued_bytes = 0;
};

struct CaptureHelperErrorSnapshot {
    std::string fatal_reason;
    std::string detail;
};

struct CaptureHelperStartResult {
    bool started = false;
    CaptureHelperStartFailure failure = CaptureHelperStartFailure::None;
    std::string message;
};

struct CaptureHelperClientSnapshot {
    CaptureHelperClientState state = CaptureHelperClientState::Idle;
    std::optional<std::uint32_t> exit_code;
    std::optional<CaptureHelperReadySnapshot> ready;
    std::optional<CaptureHelperHealthSnapshot> health;
    std::optional<CaptureHelperErrorSnapshot> error;
    std::string message;
    // True until the process handle has signalled and been closed. A failed
    // state alone is not proof that capture files have no live writer.
    bool process_alive = false;
};

struct CaptureHelperStopResult {
    bool stopped = false;
    bool forced = false;
    std::optional<std::uint32_t> exit_code;
    std::string message;
};

class CaptureHelperClient final {
public:
    CaptureHelperClient();
    explicit CaptureHelperClient(std::shared_ptr<ICaptureHelperPlatform> platform);
    ~CaptureHelperClient();

    CaptureHelperClient(const CaptureHelperClient&) = delete;
    CaptureHelperClient& operator=(const CaptureHelperClient&) = delete;

    // Start is deliberately single-shot. A denied or failed launch is returned
    // to the application; this class never repeats a UAC prompt automatically.
    [[nodiscard]] CaptureHelperStartResult Start(
        const CaptureHelperLaunchConfig& config);
    [[nodiscard]] CaptureHelperClientSnapshot Snapshot();
    [[nodiscard]] bool RequestStop();
    [[nodiscard]] CaptureHelperStopResult StopAndWait();

    [[nodiscard]] const CaptureHelperControlPaths& ControlPaths() const noexcept {
        return controls_;
    }

private:
    [[nodiscard]] CaptureHelperClientSnapshot SnapshotWithoutLock();
    [[nodiscard]] CaptureHelperStopResult StopAndWaitWithoutLock() noexcept;
    void ObserveHealthAndError() noexcept;
    void FinishExited(std::optional<std::uint32_t> exit_code) noexcept;
    void TerminateFailedStart() noexcept;
    void CleanupControls() noexcept;

    std::shared_ptr<ICaptureHelperPlatform> platform_;
    CaptureHelperLaunchConfig config_;
    CaptureHelperControlPaths controls_;
    std::uintptr_t process_ = 0;
    std::uint32_t launched_process_id_ = 0;
    std::uint32_t parent_pid_ = 0;
    CaptureHelperClientState state_ = CaptureHelperClientState::Idle;
    std::optional<std::uint32_t> exit_code_;
    std::optional<CaptureHelperReadySnapshot> ready_;
    std::optional<CaptureHelperHealthSnapshot> health_;
    std::optional<CaptureHelperErrorSnapshot> error_;
    std::string message_;
    bool controls_created_ = false;
    bool start_attempted_ = false;
    bool forced_termination_ = false;

    class Mutex;
    std::unique_ptr<Mutex> mutex_;
};

}  // namespace abdc::acquisition
