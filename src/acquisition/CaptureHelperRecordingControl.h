#pragma once

#include "acquisition/CaptureHelperClient.h"
#include "session/RecordingSession.h"

#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace abdc::acquisition {

// Everything known before a SessionWorkspace exists. The certified packet bus
// and optional decoded endpoint are supplied by the locked identity;
// root/address and descriptor evidence remain private runtime material.
struct CaptureHelperRecordingConfig final {
    std::uint16_t usbpcap_root_index = 0;
    std::uint8_t filtered_device_address = 0;
    std::vector<std::byte> descriptor_evidence;
    std::filesystem::path helper_executable;
    std::filesystem::path control_root;
    std::chrono::milliseconds readiness_timeout{15'000};
    std::chrono::milliseconds graceful_shutdown_timeout{10'000};
    std::uint32_t durable_flush_ms = 2'000;
};

// Pure translation kept public so failure-policy behavior can be tested
// without UAC, processes, sleeps, or a USBPcap installation.
[[nodiscard]] session::RecordingCaptureSnapshot MapCaptureHelperSnapshot(
    const CaptureHelperClientSnapshot& snapshot);

// Production bridge between the elevated helper and RecordingSession. It is
// the only application-side component that understands both interfaces.
class CaptureHelperRecordingControl final
    : public session::IRecordingCaptureControl {
public:
    explicit CaptureHelperRecordingControl(CaptureHelperRecordingConfig config);
    CaptureHelperRecordingControl(
        CaptureHelperRecordingConfig config,
        std::shared_ptr<ICaptureHelperPlatform> platform);
    ~CaptureHelperRecordingControl() override;

    CaptureHelperRecordingControl(const CaptureHelperRecordingControl&) = delete;
    CaptureHelperRecordingControl& operator=(
        const CaptureHelperRecordingControl&) = delete;

    void BeginCapture(const session::CaptureStartRequest& request) override;
    void RequestStop() override;
    [[nodiscard]] session::RecordingCaptureSnapshot Snapshot() const override;

private:
    CaptureHelperRecordingConfig config_;
    mutable std::mutex mutex_;
    mutable CaptureHelperClient client_;
    bool begin_called_ = false;
    bool stop_called_ = false;
    std::optional<session::RecordingCaptureSnapshot> start_failure_;
    mutable std::optional<session::RecordingCaptureSnapshot>
        stop_in_progress_snapshot_;
    mutable std::future<CaptureHelperStopResult> stop_future_;
};

}  // namespace abdc::acquisition
