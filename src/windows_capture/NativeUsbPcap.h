/*
 * Copyright (c) 2013-2019 Tomasz Mon <desowin@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The public USBPcap ABI declarations and configuration order in this file
 * are derived from desowin/usbpcap tag 1.5.4.0 (commit
 * 1a8893cf4b704a9812a82440ef2e476e194cdd65), specifically
 * USBPcapDriver/include/USBPcap.h and USBPcapCMD/thread.c.
 */

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace abdc::windows_capture {

namespace usbpcap_abi {

// CTL_CODE(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, access), copied
// numerically so the native boundary does not depend on a bundled driver SDK.
inline constexpr std::uint32_t kIoctlSetupBuffer = 0x00226000U;
inline constexpr std::uint32_t kIoctlStartFiltering = 0x0022E004U;
inline constexpr std::uint32_t kIoctlStopFiltering = 0x0022E008U;
inline constexpr std::uint32_t kIoctlSetSnaplenSize = 0x00226010U;

struct IoctlSize {
    std::uint32_t size = 0;
};

#pragma pack(push, 1)
struct AddressFilter {
    std::array<std::uint32_t, 4> addresses{};
    std::uint8_t filter_all = 0;
};
#pragma pack(pop)

static_assert(sizeof(IoctlSize) == 4);
static_assert(sizeof(AddressFilter) == 17);

[[nodiscard]] bool IsExactlySelectedAddress(const AddressFilter& filter,
                                            std::uint8_t selected_address);

}  // namespace usbpcap_abi

using NativeUsbPcapHandle = std::uintptr_t;
inline constexpr NativeUsbPcapHandle kInvalidNativeUsbPcapHandle = 0;

// Opaque storage for one platform OVERLAPPED and its event. The Win32
// implementation verifies the size and alignment at compile time; fakes may
// ignore it or use it as test-local state.
struct NativeUsbPcapReadContext {
    alignas(void*) std::array<std::byte, 64> native{};
};

enum class NativeUsbPcapReadDisposition {
    Completed,
    Pending,
    TimedOut,
    Cancelled,
    Failed,
};

struct NativeUsbPcapReadResult {
    NativeUsbPcapReadDisposition disposition = NativeUsbPcapReadDisposition::Failed;
    std::uint32_t bytes = 0;
    std::uint32_t win32_error = 0;
};

class INativeUsbPcapApi {
public:
    virtual ~INativeUsbPcapApi() = default;

    virtual bool QueryProcessElevated(bool& elevated, std::uint32_t& win32_error) = 0;
    virtual bool OpenCaptureDevice(const std::wstring& device_path,
                                   NativeUsbPcapHandle& handle,
                                   std::uint32_t& win32_error) = 0;
    virtual bool DeviceControl(NativeUsbPcapHandle handle, std::uint32_t control_code,
                               std::span<const std::byte> input,
                               std::uint32_t& bytes_returned,
                               std::uint32_t& win32_error) = 0;
    virtual bool CreateReadContext(NativeUsbPcapReadContext& context,
                                   std::uint32_t& win32_error) = 0;
    virtual void DestroyReadContext(NativeUsbPcapReadContext& context) noexcept = 0;
    virtual NativeUsbPcapReadResult BeginRead(NativeUsbPcapHandle handle,
                                              std::span<std::byte> destination,
                                              NativeUsbPcapReadContext& context) = 0;
    virtual NativeUsbPcapReadResult WaitRead(NativeUsbPcapHandle handle,
                                             NativeUsbPcapReadContext& context,
                                             std::chrono::milliseconds timeout) = 0;
    virtual bool CancelRead(NativeUsbPcapHandle handle,
                            NativeUsbPcapReadContext& context,
                            std::uint32_t& win32_error) = 0;
    virtual bool CloseCaptureDevice(NativeUsbPcapHandle handle,
                                    std::uint32_t& win32_error) noexcept = 0;
};

class Win32NativeUsbPcapApi final : public INativeUsbPcapApi {
public:
    bool QueryProcessElevated(bool& elevated, std::uint32_t& win32_error) override;
    bool OpenCaptureDevice(const std::wstring& device_path,
                           NativeUsbPcapHandle& handle,
                           std::uint32_t& win32_error) override;
    bool DeviceControl(NativeUsbPcapHandle handle, std::uint32_t control_code,
                       std::span<const std::byte> input,
                       std::uint32_t& bytes_returned,
                       std::uint32_t& win32_error) override;
    bool CreateReadContext(NativeUsbPcapReadContext& context,
                           std::uint32_t& win32_error) override;
    void DestroyReadContext(NativeUsbPcapReadContext& context) noexcept override;
    NativeUsbPcapReadResult BeginRead(NativeUsbPcapHandle handle,
                                      std::span<std::byte> destination,
                                      NativeUsbPcapReadContext& context) override;
    NativeUsbPcapReadResult WaitRead(NativeUsbPcapHandle handle,
                                     NativeUsbPcapReadContext& context,
                                     std::chrono::milliseconds timeout) override;
    bool CancelRead(NativeUsbPcapHandle handle, NativeUsbPcapReadContext& context,
                    std::uint32_t& win32_error) override;
    bool CloseCaptureDevice(NativeUsbPcapHandle handle,
                            std::uint32_t& win32_error) noexcept override;
};

struct NativeUsbPcapOptions {
    std::uint16_t root_index = 0;
    std::uint8_t device_address = 0;
    // Explicit bounded diagnostic/certification broad capture. Session
    // recording leaves this false and uses one exact certified address.
    bool capture_all_devices = false;
    std::uint32_t snapshot_length = 65'535U;
    std::uint32_t kernel_buffer_bytes = 16U * 1024U * 1024U;
    std::size_t read_chunk_bytes = 64U * 1024U;
    std::size_t consumer_queue_bytes = 16U * 1024U * 1024U;
    std::chrono::milliseconds read_poll_interval{20};
    std::chrono::milliseconds cancellation_timeout{2'000};
};

[[nodiscard]] std::wstring BuildNativeUsbPcapPath(std::uint16_t root_index);
[[nodiscard]] std::string ValidateNativeUsbPcapOptions(const NativeUsbPcapOptions& options);

enum class NativeUsbPcapState {
    Idle,
    Opening,
    Configuring,
    Capturing,
    StopRequested,
    Draining,
    Stopped,
    AccessDenied,
    DeviceUnavailable,
    ConfigurationFailed,
    DeviceLost,
    QueueOverflow,
    StopFilteringFailed,
    CancellationFailed,
    DrainFailed,
    InternalError,
};

struct NativeUsbPcapCounters {
    std::uint64_t read_operations = 0;
    std::uint64_t read_completions = 0;
    std::uint64_t zero_byte_read_completions = 0;
    std::uint64_t partial_read_completions = 0;
    std::uint64_t bytes_read = 0;
    std::uint64_t chunks_enqueued = 0;
    std::uint64_t bytes_enqueued = 0;
    std::uint64_t chunks_delivered = 0;
    std::uint64_t bytes_delivered = 0;
    std::uint64_t queue_overflow_events = 0;
    std::uint64_t bytes_discarded = 0;
    std::uint64_t cancel_requests = 0;
    std::uint64_t cancel_completions = 0;
    std::size_t queued_bytes = 0;
    std::size_t peak_queued_bytes = 0;
};

struct NativeUsbPcapStatus {
    NativeUsbPcapState state = NativeUsbPcapState::Idle;
    std::wstring device_path;
    std::uint32_t win32_error = 0;
    std::string message;
    bool filter_started = false;
    bool filter_stop_attempted = false;
    bool filter_stop_succeeded = false;
    bool kernel_quiet_observed = false;
    bool quiet_completion_observed = false;
    bool reader_finished = false;
    bool handle_closed = false;
    NativeUsbPcapCounters counters;
};

struct NativeUsbPcapSemanticDrainEvidence {
    bool parser_at_record_boundary = false;
    bool authoritative_writer_clean = false;
    std::uint64_t accounted_bytes = 0;
    std::string diagnostic;
};

using NativeUsbPcapSemanticGuard =
    std::function<NativeUsbPcapSemanticDrainEvidence()>;

struct NativeUsbPcapStopReport {
    bool clean = false;
    bool filter_stop_attempted = false;
    bool filter_stop_succeeded = false;
    bool kernel_quiet_observed = false;
    bool cancellation_observed = false;
    bool quiet_completion_observed = false;
    bool consumer_queue_empty = false;
    bool semantic_guard_invoked = false;
    bool semantic_guard_passed = false;
    bool handle_closed = false;
    std::uint64_t bytes_read = 0;
    std::uint64_t bytes_delivered = 0;
    std::uint64_t bytes_accounted = 0;
    std::size_t bytes_left_in_queue = 0;
    std::uint32_t win32_error = 0;
    std::string diagnostic;
};

class NativeUsbPcapCapture final {
public:
    explicit NativeUsbPcapCapture(INativeUsbPcapApi& api);
    ~NativeUsbPcapCapture();

    NativeUsbPcapCapture(const NativeUsbPcapCapture&) = delete;
    NativeUsbPcapCapture& operator=(const NativeUsbPcapCapture&) = delete;

    [[nodiscard]] bool Start(const NativeUsbPcapOptions& options);
    void RequestStop();
    [[nodiscard]] NativeUsbPcapStopReport StopAndDrain(
        std::chrono::milliseconds consumer_drain_timeout,
        NativeUsbPcapSemanticGuard semantic_guard);
    void Abort() noexcept;

    [[nodiscard]] bool TryTakeChunk(std::vector<std::byte>& chunk);
    [[nodiscard]] bool WaitTakeChunk(std::vector<std::byte>& chunk,
                                    std::chrono::milliseconds timeout);
    [[nodiscard]] NativeUsbPcapStatus Status() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace abdc::windows_capture
