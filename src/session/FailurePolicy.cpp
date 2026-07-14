#include "session/FailurePolicy.h"

namespace abdc::session {

std::string_view ToString(const RuntimeIssue issue) noexcept {
    switch (issue) {
    case RuntimeIssue::RawInputUsbDifference: return "raw_input_usb_difference";
    case RuntimeIssue::RawInputUnavailable: return "raw_input_unavailable";
    case RuntimeIssue::GameplayInputUnavailable:
        return "gameplay_input_unavailable";
    case RuntimeIssue::OtherMouseActivity: return "other_mouse_activity";
    case RuntimeIssue::DecodeFailure: return "decode_failure";
    case RuntimeIssue::FailedUsbTransfer: return "failed_usb_transfer";
    case RuntimeIssue::PcapTimestampRegression: return "pcap_timestamp_regression";
    case RuntimeIssue::ClockFitUncertain: return "clock_fit_uncertain";
    case RuntimeIssue::FrameStall: return "frame_stall";
    case RuntimeIssue::FocusLost: return "focus_lost";
    case RuntimeIssue::Minimized: return "minimized";
    case RuntimeIssue::DisplayChanged: return "display_changed";
    case RuntimeIssue::GraphicsDeviceLost: return "graphics_device_lost";
    case RuntimeIssue::SystemSuspend: return "system_suspend";
    case RuntimeIssue::CaptureHelperLost: return "capture_helper_lost";
    case RuntimeIssue::SelectedDeviceChanged: return "selected_device_changed";
    case RuntimeIssue::NativeQueueOverflow: return "native_queue_overflow";
    case RuntimeIssue::CaptureBytesDiscarded: return "capture_bytes_discarded";
    case RuntimeIssue::PcapFramingLost: return "pcap_framing_lost";
    case RuntimeIssue::StorageWriteFailed: return "storage_write_failed";
    case RuntimeIssue::IntegrityFailed: return "integrity_failed";
    }
    return "unknown";
}

std::string_view ToString(const RuntimeAction action) noexcept {
    switch (action) {
    case RuntimeAction::ContinueWithAnnotation: return "continue_with_annotation";
    case RuntimeAction::PauseGameplayAndDiscardActiveEvent:
        return "pause_gameplay_and_discard_active_event";
    case RuntimeAction::StopCaptureAndPreservePrefix:
        return "stop_capture_and_preserve_prefix";
    }
    return "unknown";
}

}  // namespace abdc::session
