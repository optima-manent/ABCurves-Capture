#include "acquisition/CaptureHelperRecordingControl.h"

#include <chrono>
#include <stdexcept>
#include <utility>

namespace abdc::acquisition {
namespace {

session::RuntimeIssue FatalIssueFor(const std::string& reason) noexcept {
    if (reason == "queue_or_byte_loss") {
        return session::RuntimeIssue::NativeQueueOverflow;
    }
    if (reason == "device_identity_changed") {
        return session::RuntimeIssue::SelectedDeviceChanged;
    }
    if (reason == "pcap_framing") {
        return session::RuntimeIssue::PcapFramingLost;
    }
    if (reason == "writer_failure") {
        return session::RuntimeIssue::StorageWriteFailed;
    }
    if (reason == "invalid_configuration") {
        return session::RuntimeIssue::IntegrityFailed;
    }
    return session::RuntimeIssue::CaptureHelperLost;
}

bool IsNone(const std::string& reason) noexcept {
    return reason.empty() || reason == "none";
}

}  // namespace

session::RecordingCaptureSnapshot MapCaptureHelperSnapshot(
    const CaptureHelperClientSnapshot& snapshot) {
    session::RecordingCaptureSnapshot result;
    result.ready = snapshot.ready.has_value();
    result.running = snapshot.process_alive ||
                     snapshot.state == CaptureHelperClientState::Running ||
                     snapshot.state == CaptureHelperClientState::StopRequested;
    result.stop_requested =
        snapshot.state == CaptureHelperClientState::StopRequested;
    result.stop_complete =
        snapshot.state == CaptureHelperClientState::Completed ||
        (snapshot.state == CaptureHelperClientState::Failed &&
         !snapshot.process_alive);
    result.shutdown_failed =
        snapshot.state == CaptureHelperClientState::Failed &&
        snapshot.process_alive;
    result.detail = snapshot.message;
    if (snapshot.ready) result.helper_pid = snapshot.ready->helper_pid;

    if (snapshot.health) {
        const auto& health = *snapshot.health;
        result.counters.source_bytes = health.source_bytes;
        result.counters.raw_pcap_records = health.endpoint_records;
        result.counters.decoded_reports = health.decoded_reports;
        result.counters.anomaly_count = health.anomalies;
        if (!health.detail.empty()) result.detail = health.detail;
        if (!IsNone(health.fatal_reason)) {
            result.fatal_issue = FatalIssueFor(health.fatal_reason);
            if (health.fatal_reason == "queue_or_byte_loss") {
                result.counters.queue_overflow_events = 1;
            }
        }
        result.clean_stop = snapshot.state == CaptureHelperClientState::Completed &&
                            health.state == "completed" &&
                            IsNone(health.fatal_reason);
    }

    if (snapshot.error) {
        if (!IsNone(snapshot.error->fatal_reason)) {
            result.fatal_issue = FatalIssueFor(snapshot.error->fatal_reason);
        }
        if (!snapshot.error->detail.empty()) result.detail = snapshot.error->detail;
    }

    if (snapshot.state == CaptureHelperClientState::Failed &&
        !result.fatal_issue) {
        result.fatal_issue = session::RuntimeIssue::CaptureHelperLost;
    }
    return result;
}

CaptureHelperRecordingControl::CaptureHelperRecordingControl(
    CaptureHelperRecordingConfig config)
    : config_(std::move(config)), client_() {}

CaptureHelperRecordingControl::CaptureHelperRecordingControl(
    CaptureHelperRecordingConfig config,
    std::shared_ptr<ICaptureHelperPlatform> platform)
    : config_(std::move(config)), client_(std::move(platform)) {}

CaptureHelperRecordingControl::~CaptureHelperRecordingControl() {
    try {
        if (begin_called_ && !stop_called_) RequestStop();
    } catch (...) {
    }
    if (stop_future_.valid()) {
        stop_future_.wait();
    }
}

void CaptureHelperRecordingControl::BeginCapture(
    const session::CaptureStartRequest& request) {
    std::scoped_lock lock(mutex_);
    if (begin_called_) {
        throw std::logic_error("capture helper recording control is single-shot");
    }
    begin_called_ = true;

    CaptureHelperLaunchConfig launch;
    launch.usb.root = config_.usbpcap_root_index;
    launch.usb.address = config_.filtered_device_address;
    launch.usb.bus = request.locked_mouse.usb_bus;
    launch.usb.endpoint = request.locked_mouse.interrupt_in_endpoint;
    launch.descriptor_evidence = config_.descriptor_evidence;
    launch.output_directory = request.capture_directory;
    launch.session_lease = request.session_lease;
    launch.helper_executable = config_.helper_executable;
    launch.control_root = config_.control_root;
    launch.readiness_timeout = config_.readiness_timeout;
    launch.graceful_shutdown_timeout = config_.graceful_shutdown_timeout;
    launch.durable_flush_ms = config_.durable_flush_ms;

    const auto started = client_.Start(launch);
    if (!started.started) {
        session::RecordingCaptureSnapshot failed;
        failed.stop_complete = true;
        failed.fatal_issue = session::RuntimeIssue::CaptureHelperLost;
        failed.detail = started.message.empty()
            ? "capture helper did not start"
            : started.message;
        start_failure_ = failed;
        throw std::runtime_error(failed.detail);
    }
}

void CaptureHelperRecordingControl::RequestStop() {
    std::scoped_lock lock(mutex_);
    if (!begin_called_ || stop_called_) return;
    stop_called_ = true;
    (void)client_.RequestStop();
    stop_in_progress_snapshot_ = MapCaptureHelperSnapshot(client_.Snapshot());
    stop_in_progress_snapshot_->stop_requested = true;
    stop_future_ = std::async(std::launch::async, [this] {
        return client_.StopAndWait();
    });
}

session::RecordingCaptureSnapshot
CaptureHelperRecordingControl::Snapshot() const {
    std::scoped_lock lock(mutex_);
    if (start_failure_) return *start_failure_;
    if (!begin_called_) return {};
    if (stop_future_.valid()) {
        if (stop_future_.wait_for(std::chrono::milliseconds::zero()) !=
            std::future_status::ready) {
            return *stop_in_progress_snapshot_;
        }
        (void)stop_future_.get();
        stop_in_progress_snapshot_.reset();
    }
    return MapCaptureHelperSnapshot(client_.Snapshot());
}

}  // namespace abdc::acquisition
