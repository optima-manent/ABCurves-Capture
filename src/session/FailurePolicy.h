#pragma once

#include <string_view>

namespace abdc::session {

enum class RuntimeIssue {
    RawInputUsbDifference,
    RawInputUnavailable,
    GameplayInputUnavailable,
    OtherMouseActivity,
    DecodeFailure,
    FailedUsbTransfer,
    PcapTimestampRegression,
    ClockFitUncertain,
    FrameStall,
    FocusLost,
    Minimized,
    DisplayChanged,
    GraphicsDeviceLost,
    SystemSuspend,
    CaptureHelperLost,
    SelectedDeviceChanged,
    NativeQueueOverflow,
    CaptureBytesDiscarded,
    PcapFramingLost,
    StorageWriteFailed,
    IntegrityFailed,
};

enum class RuntimeAction {
    ContinueWithAnnotation,
    PauseGameplayAndDiscardActiveEvent,
    StopCaptureAndPreservePrefix,
};

[[nodiscard]] constexpr RuntimeAction ActionFor(const RuntimeIssue issue) noexcept {
    switch (issue) {
    case RuntimeIssue::FocusLost:
    case RuntimeIssue::Minimized:
    case RuntimeIssue::DisplayChanged:
    case RuntimeIssue::GraphicsDeviceLost:
    case RuntimeIssue::SystemSuspend:
    case RuntimeIssue::GameplayInputUnavailable:
        return RuntimeAction::PauseGameplayAndDiscardActiveEvent;

    case RuntimeIssue::CaptureHelperLost:
    case RuntimeIssue::SelectedDeviceChanged:
    case RuntimeIssue::NativeQueueOverflow:
    case RuntimeIssue::CaptureBytesDiscarded:
    case RuntimeIssue::PcapFramingLost:
    case RuntimeIssue::StorageWriteFailed:
    case RuntimeIssue::IntegrityFailed:
        return RuntimeAction::StopCaptureAndPreservePrefix;

    case RuntimeIssue::RawInputUsbDifference:
    case RuntimeIssue::RawInputUnavailable:
    case RuntimeIssue::OtherMouseActivity:
    case RuntimeIssue::DecodeFailure:
    case RuntimeIssue::FailedUsbTransfer:
    case RuntimeIssue::PcapTimestampRegression:
    case RuntimeIssue::ClockFitUncertain:
    case RuntimeIssue::FrameStall:
        return RuntimeAction::ContinueWithAnnotation;
    }
    return RuntimeAction::StopCaptureAndPreservePrefix;
}

[[nodiscard]] std::string_view ToString(RuntimeIssue issue) noexcept;
[[nodiscard]] std::string_view ToString(RuntimeAction action) noexcept;

}  // namespace abdc::session
