#pragma once

#include "acquisition/CaptureHelperClient.h"
#include "acquisition/CertificationProbe.h"

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

inline constexpr std::uint64_t kMaximumCertificationProbeConfigBytes =
    32ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t kMaximumCertificationProbeResultBytes =
    32ULL * 1024ULL * 1024ULL;

// One private helper route. Descriptor evidence, the derived canonical
// decoder specification, and the runtime join token live only in the private
// control directory and are removed after the elevated process exits.
struct CertificationProbeLaunchRoute {
    std::string probe_route_token;
    std::uint8_t endpoint_address = 0;
    std::vector<std::byte> descriptor_evidence;
    std::string canonical_decoder_spec;
};

struct CertificationProbeLaunchConfig {
    std::uint16_t usbpcap_root_index = 0;
    // Exact filter in legacy/exact mode; Windows-topology ranking hint when
    // discover_device_address is true.
    std::uint8_t filtered_device_address = 0;

    // Observe the root transiently and choose the changing interrupt stream.
    // Only bounded derivative evidence crosses the helper boundary; no broad
    // PCAP bytes or payloads are saved. The recording helper remains exact.
    bool discover_device_address = false;

    // Zero is the normal first-probe value. The helper learns packet.bus from
    // the first matching interrupt record and then requires it to stay fixed.
    std::uint16_t expected_packet_bus = 0;
    std::vector<CertificationProbeLaunchRoute> routes;

    std::int64_t maximum_duration_ns = 10'000'000'000LL;
    std::size_t maximum_samples_per_route = 131'072U;
    std::size_t maximum_intervals_per_route = 131'072U;
    std::size_t maximum_reports_per_transfer = 4'096U;
    std::size_t maximum_candidate_payload_bytes = 64U * 1024U;
    std::uint64_t maximum_source_bytes = 512ULL * 1024ULL * 1024ULL;
    std::uint64_t maximum_source_records = 2'000'000ULL;

    // Empty paths select the sibling abct_probe_helper.exe and the same
    // protected per-user control root used by the recording helper.
    std::filesystem::path helper_executable;
    std::filesystem::path control_root;
    std::chrono::milliseconds graceful_shutdown_timeout{5'000};
};

struct CertificationProbeControlPaths {
    std::filesystem::path directory;
    std::filesystem::path config;
    std::filesystem::path ready;
    std::filesystem::path result;
    std::filesystem::path cancel;
    std::filesystem::path error;
};

struct CertificationProbeCommand {
    std::filesystem::path executable;
    std::vector<std::wstring> arguments;
    std::wstring parameter_line;
};

// The parsed private plan used by the helper. qpc_frequency is deliberately
// left at zero; only the elevated helper may fill it from the local QPC.
struct CertificationProbeHelperPlan {
    CertificationProbeOptions options;
    std::vector<CertificationProbeRouteConfig> routes;
};

[[nodiscard]] std::vector<std::byte> SerializeCertificationProbeHelperConfig(
    const CertificationProbeLaunchConfig& config);
[[nodiscard]] CertificationProbeHelperPlan ParseCertificationProbeHelperConfig(
    std::span<const std::byte> bytes);
[[nodiscard]] CertificationProbeCommand BuildCertificationProbeCommand(
    const CertificationProbeControlPaths& controls,
    const std::filesystem::path& executable,
    std::uint32_t parent_pid,
    std::string_view config_sha256);

struct CertificationProbeReadySnapshot {
    std::string capability;
    std::uint32_t helper_pid = 0;
    std::uint32_t parent_pid = 0;
};

struct CertificationProbeTransportResult {
    bool cancelled = false;
    CertificationProbeResult probe;
};

// Public protocol functions keep the helper/client boundary independently
// testable. The result schema contains derivative motion/timing evidence only;
// HID report payloads and address-wide PCAP bytes have no representation.
[[nodiscard]] std::string SerializeCertificationProbeResultEnvelope(
    const CertificationProbeTransportResult& result,
    std::string_view capability,
    std::uint32_t helper_pid,
    std::uint32_t parent_pid);
[[nodiscard]] CertificationProbeTransportResult
ParseCertificationProbeResultEnvelope(
    std::string_view text,
    std::string_view expected_capability,
    std::uint32_t expected_helper_pid,
    std::uint32_t expected_parent_pid);

enum class CertificationProbeClientState {
    Idle,
    Starting,
    Running,
    CancelRequested,
    Completed,
    Cancelled,
    Failed,
};

enum class CertificationProbeStartFailure {
    None,
    InvalidConfiguration,
    UacDenied,
    HelperMissing,
    LaunchFailed,
};

struct CertificationProbeStartResult {
    bool started = false;
    CertificationProbeStartFailure failure =
        CertificationProbeStartFailure::None;
    std::string message;
};

struct CertificationProbeClientSnapshot {
    CertificationProbeClientState state = CertificationProbeClientState::Idle;
    std::optional<std::uint32_t> exit_code;
    std::optional<CertificationProbeReadySnapshot> ready;
    std::optional<CertificationProbeTransportResult> result;
    std::string message;
};

class CertificationProbeClient final {
public:
    CertificationProbeClient();
    explicit CertificationProbeClient(
        std::shared_ptr<ICaptureHelperPlatform> platform);
    ~CertificationProbeClient();

    CertificationProbeClient(const CertificationProbeClient&) = delete;
    CertificationProbeClient& operator=(const CertificationProbeClient&) = delete;

    // Start performs exactly one ShellExecute("runas") call and returns as
    // soon as that launch succeeds. Polling is nonblocking so the parent can
    // keep collecting selected-device Raw Input throughout the gesture.
    [[nodiscard]] CertificationProbeStartResult Start(
        const CertificationProbeLaunchConfig& config);
    [[nodiscard]] CertificationProbeClientSnapshot Snapshot();
    [[nodiscard]] bool RequestCancel();
    void CancelAndWait() noexcept;

    [[nodiscard]] const CertificationProbeControlPaths& ControlPaths()
        const noexcept { return controls_; }

private:
    [[nodiscard]] CertificationProbeClientSnapshot SnapshotWithoutLock();
    void ObserveFiles() noexcept;
    void FinishExited(std::optional<std::uint32_t> exit_code) noexcept;
    void CleanupControls() noexcept;
    void TerminateAndClose() noexcept;

    std::shared_ptr<ICaptureHelperPlatform> platform_;
    CertificationProbeLaunchConfig config_;
    CertificationProbeControlPaths controls_;
    std::uintptr_t process_ = 0;
    std::uint32_t helper_pid_ = 0;
    std::uint32_t parent_pid_ = 0;
    CertificationProbeClientState state_ = CertificationProbeClientState::Idle;
    std::optional<std::uint32_t> exit_code_;
    std::optional<CertificationProbeReadySnapshot> ready_;
    std::optional<CertificationProbeTransportResult> result_;
    std::string message_;
    bool controls_created_ = false;
    bool start_attempted_ = false;
    bool cancel_pending_ = false;
    bool cancel_written_ = false;

    class Mutex;
    std::unique_ptr<Mutex> mutex_;
};

}  // namespace abdc::acquisition
