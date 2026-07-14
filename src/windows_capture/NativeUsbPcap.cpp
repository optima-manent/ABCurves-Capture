/*
 * Copyright (c) 2013-2019 Tomasz Mon <desowin@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * USBPcap ABI and setup sequencing are derived from desowin/usbpcap
 * 1.5.4.0 as identified in NativeUsbPcap.h. The capture lifecycle, bounded
 * queue, diagnostics, and semantic drain guard are original to this project.
 */

#include "windows_capture/NativeUsbPcap.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <bit>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <limits>
#include <mutex>
#include <new>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>

namespace abdc::windows_capture {
namespace {

constexpr std::uint32_t kErrorAccessDenied = ERROR_ACCESS_DENIED;
constexpr std::uint32_t kErrorNotFound = ERROR_NOT_FOUND;
constexpr std::uint32_t kErrorOperationAborted = ERROR_OPERATION_ABORTED;
constexpr std::uint32_t kMaximumSnaplen = 1024U * 1024U;
constexpr std::uint32_t kMinimumKernelBuffer = 4U * 1024U;
constexpr std::uint32_t kMaximumKernelBuffer = 128U * 1024U * 1024U;
constexpr std::size_t kMaximumReadChunk = 1024U * 1024U;
constexpr std::size_t kMaximumConsumerQueue = 256U * 1024U * 1024U;

struct Win32ReadStorage {
    OVERLAPPED overlapped{};
};

static_assert(sizeof(Win32ReadStorage) <= sizeof(NativeUsbPcapReadContext::native));
static_assert(alignof(Win32ReadStorage) <= alignof(NativeUsbPcapReadContext));

[[nodiscard]] Win32ReadStorage& ReadStorage(NativeUsbPcapReadContext& context) {
    return *std::launder(reinterpret_cast<Win32ReadStorage*>(context.native.data()));
}

[[nodiscard]] HANDLE ToWin32Handle(const NativeUsbPcapHandle handle) {
    return reinterpret_cast<HANDLE>(handle);
}

[[nodiscard]] bool IsDeviceLossError(const std::uint32_t error) {
    return error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_DEV_NOT_EXIST ||
           error == ERROR_GEN_FAILURE || error == ERROR_INVALID_HANDLE ||
           error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

[[nodiscard]] std::span<const std::byte> BytesOf(const usbpcap_abi::IoctlSize& value) {
    return std::as_bytes(std::span{&value, std::size_t{1}});
}

[[nodiscard]] std::span<const std::byte> BytesOf(const usbpcap_abi::AddressFilter& value) {
    return std::as_bytes(std::span{&value, std::size_t{1}});
}

[[nodiscard]] bool IsFailureState(const NativeUsbPcapState state) {
    switch (state) {
        case NativeUsbPcapState::AccessDenied:
        case NativeUsbPcapState::DeviceUnavailable:
        case NativeUsbPcapState::ConfigurationFailed:
        case NativeUsbPcapState::DeviceLost:
        case NativeUsbPcapState::QueueOverflow:
        case NativeUsbPcapState::StopFilteringFailed:
        case NativeUsbPcapState::CancellationFailed:
        case NativeUsbPcapState::DrainFailed:
        case NativeUsbPcapState::InternalError:
            return true;
        default:
            return false;
    }
}

}  // namespace

bool usbpcap_abi::IsExactlySelectedAddress(const AddressFilter& filter,
                                           const std::uint8_t selected_address) {
    if (selected_address == 0 || selected_address > 127 || filter.filter_all != 0) return false;

    std::uint32_t set_bits = 0;
    for (const std::uint32_t word : filter.addresses) {
        set_bits += static_cast<std::uint32_t>(std::popcount(word));
    }
    const std::size_t word = selected_address / 32U;
    const std::uint32_t bit = 1U << (selected_address % 32U);
    return set_bits == 1 && (filter.addresses[word] & bit) != 0 &&
           (filter.addresses[0] & 1U) == 0;
}

std::wstring BuildNativeUsbPcapPath(const std::uint16_t root_index) {
    if (root_index == 0 || root_index > 255) return {};
    return L"\\\\.\\USBPcap" + std::to_wstring(root_index);
}

std::string ValidateNativeUsbPcapOptions(const NativeUsbPcapOptions& options) {
    if (BuildNativeUsbPcapPath(options.root_index).empty()) {
        return "USBPcap root index must be in [1,255]";
    }
    if (!options.capture_all_devices &&
        (options.device_address == 0 || options.device_address > 127)) {
        return "selected USB device address must be in [1,127]; address 0 (new devices) is forbidden";
    }
    if (options.snapshot_length == 0 || options.snapshot_length > kMaximumSnaplen) {
        return "snapshot length must be in [1,1048576]";
    }
    if (options.kernel_buffer_bytes < kMinimumKernelBuffer ||
        options.kernel_buffer_bytes > kMaximumKernelBuffer) {
        return "kernel buffer must be within USBPcap's [4096,134217728] byte range";
    }
    if (options.read_chunk_bytes == 0 || options.read_chunk_bytes > kMaximumReadChunk ||
        options.read_chunk_bytes > std::numeric_limits<std::uint32_t>::max()) {
        return "read chunk must be in [1,1048576]";
    }
    if (options.consumer_queue_bytes == 0 ||
        options.consumer_queue_bytes > kMaximumConsumerQueue) {
        return "consumer queue must be in [1,268435456]";
    }
    if (options.read_poll_interval <= std::chrono::milliseconds::zero() ||
        options.read_poll_interval > std::chrono::seconds(1)) {
        return "read poll interval must be in (0,1000] ms";
    }
    if (options.cancellation_timeout <= std::chrono::milliseconds::zero() ||
        options.cancellation_timeout > std::chrono::seconds(30)) {
        return "cancellation timeout must be in (0,30000] ms";
    }
    return {};
}

bool Win32NativeUsbPcapApi::QueryProcessElevated(bool& elevated,
                                                 std::uint32_t& win32_error) {
    elevated = false;
    win32_error = 0;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        win32_error = GetLastError();
        return false;
    }
    TOKEN_ELEVATION information{};
    DWORD returned = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &information,
                                        sizeof(information), &returned);
    if (!ok) win32_error = GetLastError();
    if (!CloseHandle(token) && ok) {
        win32_error = GetLastError();
        return false;
    }
    if (!ok) return false;
    elevated = information.TokenIsElevated != 0;
    return true;
}

bool Win32NativeUsbPcapApi::OpenCaptureDevice(const std::wstring& device_path,
                                              NativeUsbPcapHandle& handle,
                                              std::uint32_t& win32_error) {
    handle = kInvalidNativeUsbPcapHandle;
    win32_error = 0;
    const HANDLE native = CreateFileW(device_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                      0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
                                      nullptr);
    if (native == INVALID_HANDLE_VALUE) {
        win32_error = GetLastError();
        return false;
    }
    handle = reinterpret_cast<NativeUsbPcapHandle>(native);
    return true;
}

bool Win32NativeUsbPcapApi::DeviceControl(const NativeUsbPcapHandle handle,
                                          const std::uint32_t control_code,
                                          const std::span<const std::byte> input,
                                          std::uint32_t& bytes_returned,
                                          std::uint32_t& win32_error) {
    bytes_returned = 0;
    win32_error = 0;
    DWORD native_returned = 0;
    void* input_pointer = input.empty() ? nullptr : const_cast<std::byte*>(input.data());
    const BOOL ok = DeviceIoControl(ToWin32Handle(handle), control_code, input_pointer,
                                    static_cast<DWORD>(input.size()), nullptr, 0,
                                    &native_returned, nullptr);
    bytes_returned = native_returned;
    if (!ok) {
        win32_error = GetLastError();
        return false;
    }
    return true;
}

bool Win32NativeUsbPcapApi::CreateReadContext(NativeUsbPcapReadContext& context,
                                              std::uint32_t& win32_error) {
    context.native.fill(std::byte{0});
    auto* storage = ::new (static_cast<void*>(context.native.data())) Win32ReadStorage{};
    storage->overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (storage->overlapped.hEvent == nullptr) {
        storage->~Win32ReadStorage();
        win32_error = GetLastError();
        return false;
    }
    win32_error = 0;
    return true;
}

void Win32NativeUsbPcapApi::DestroyReadContext(NativeUsbPcapReadContext& context) noexcept {
    auto& storage = ReadStorage(context);
    if (storage.overlapped.hEvent != nullptr) {
        CloseHandle(storage.overlapped.hEvent);
    }
    storage.~Win32ReadStorage();
    context.native.fill(std::byte{0});
}

NativeUsbPcapReadResult Win32NativeUsbPcapApi::BeginRead(
    const NativeUsbPcapHandle handle, const std::span<std::byte> destination,
    NativeUsbPcapReadContext& context) {
    auto& overlapped = ReadStorage(context).overlapped;
    const HANDLE event = overlapped.hEvent;
    std::memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = event;
    if (!ResetEvent(event)) {
        return {NativeUsbPcapReadDisposition::Failed, 0, GetLastError()};
    }

    DWORD bytes = 0;
    const BOOL ok = ReadFile(ToWin32Handle(handle), destination.data(),
                             static_cast<DWORD>(destination.size()), &bytes, &overlapped);
    if (ok) return {NativeUsbPcapReadDisposition::Completed, bytes, 0};
    const DWORD error = GetLastError();
    if (error == ERROR_IO_PENDING) {
        return {NativeUsbPcapReadDisposition::Pending, 0, 0};
    }
    return {NativeUsbPcapReadDisposition::Failed, 0, error};
}

NativeUsbPcapReadResult Win32NativeUsbPcapApi::WaitRead(
    const NativeUsbPcapHandle handle, NativeUsbPcapReadContext& context,
    const std::chrono::milliseconds timeout) {
    auto& overlapped = ReadStorage(context).overlapped;
    const auto bounded = std::clamp<std::int64_t>(timeout.count(), 0, MAXDWORD - 1LL);
    const DWORD wait = WaitForSingleObject(overlapped.hEvent, static_cast<DWORD>(bounded));
    if (wait == WAIT_TIMEOUT) return {NativeUsbPcapReadDisposition::TimedOut, 0, 0};
    if (wait != WAIT_OBJECT_0) {
        return {NativeUsbPcapReadDisposition::Failed, 0, GetLastError()};
    }

    DWORD bytes = 0;
    if (GetOverlappedResult(ToWin32Handle(handle), &overlapped, &bytes, FALSE)) {
        return {NativeUsbPcapReadDisposition::Completed, bytes, 0};
    }
    const DWORD error = GetLastError();
    if (error == ERROR_OPERATION_ABORTED) {
        return {NativeUsbPcapReadDisposition::Cancelled, 0, error};
    }
    if (error == ERROR_IO_INCOMPLETE) {
        return {NativeUsbPcapReadDisposition::TimedOut, 0, 0};
    }
    return {NativeUsbPcapReadDisposition::Failed, 0, error};
}

bool Win32NativeUsbPcapApi::CancelRead(const NativeUsbPcapHandle handle,
                                      NativeUsbPcapReadContext& context,
                                      std::uint32_t& win32_error) {
    if (CancelIoEx(ToWin32Handle(handle), &ReadStorage(context).overlapped)) {
        win32_error = 0;
        return true;
    }
    win32_error = GetLastError();
    return false;
}

bool Win32NativeUsbPcapApi::CloseCaptureDevice(const NativeUsbPcapHandle handle,
                                               std::uint32_t& win32_error) noexcept {
    if (handle == kInvalidNativeUsbPcapHandle) {
        win32_error = 0;
        return true;
    }
    if (CloseHandle(ToWin32Handle(handle))) {
        win32_error = 0;
        return true;
    }
    win32_error = GetLastError();
    return false;
}

struct NativeUsbPcapCapture::Impl {
    explicit Impl(INativeUsbPcapApi& supplied_api) : api(supplied_api) {}

    INativeUsbPcapApi& api;
    NativeUsbPcapOptions options;
    NativeUsbPcapHandle handle = kInvalidNativeUsbPcapHandle;
    NativeUsbPcapReadContext read_context{};
    bool read_context_ready = false;
    std::thread reader;
    std::atomic_bool stop_requested{false};

    mutable std::mutex mutex;
    std::condition_variable data_available;
    std::condition_variable queue_changed;
    std::deque<std::vector<std::byte>> queue;
    NativeUsbPcapStatus status;
    bool stop_completed = false;
    NativeUsbPcapStopReport last_stop;

    void SetFailure(const NativeUsbPcapState state, const std::uint32_t error,
                    std::string message) {
        std::lock_guard lock(mutex);
        if (!IsFailureState(status.state)) {
            status.state = state;
            status.win32_error = error;
            status.message = std::move(message);
        }
    }

    [[nodiscard]] bool Control(const std::uint32_t code,
                               const std::span<const std::byte> input,
                               std::uint32_t& error) {
        std::uint32_t returned = 0;
        return api.DeviceControl(handle, code, input, returned, error);
    }

    [[nodiscard]] bool StopFiltering() {
        {
            std::lock_guard lock(mutex);
            if (status.filter_stop_attempted) return status.filter_stop_succeeded;
            status.filter_stop_attempted = true;
        }
        std::uint32_t error = 0;
        const bool ok = Control(usbpcap_abi::kIoctlStopFiltering, {}, error);
        {
            std::lock_guard lock(mutex);
            status.filter_stop_succeeded = ok;
            if (!ok && !IsFailureState(status.state)) {
                status.state = NativeUsbPcapState::StopFilteringFailed;
                status.win32_error = error;
                status.message = "IOCTL_USBPCAP_STOP_FILTERING failed";
            }
        }
        return ok;
    }

    [[nodiscard]] bool EnqueueRead(const std::span<const std::byte> bytes) {
        std::vector<std::byte> chunk(bytes.begin(), bytes.end());
        {
            std::lock_guard lock(mutex);
            auto& counters = status.counters;
            ++counters.read_completions;
            counters.bytes_read += bytes.size();
            if (bytes.size() < options.read_chunk_bytes) ++counters.partial_read_completions;

            if (bytes.size() > options.consumer_queue_bytes -
                                   std::min(options.consumer_queue_bytes,
                                            counters.queued_bytes)) {
                ++counters.queue_overflow_events;
                counters.bytes_discarded += bytes.size();
                status.state = NativeUsbPcapState::QueueOverflow;
                status.win32_error = ERROR_NOT_ENOUGH_MEMORY;
                status.message = "bounded native PCAP consumer queue overflowed";
                stop_requested.store(true, std::memory_order_release);
                return false;
            }
            counters.queued_bytes += chunk.size();
            counters.peak_queued_bytes =
                std::max(counters.peak_queued_bytes, counters.queued_bytes);
            ++counters.chunks_enqueued;
            counters.bytes_enqueued += chunk.size();
            queue.push_back(std::move(chunk));
        }
        data_available.notify_one();
        queue_changed.notify_all();
        return true;
    }

    enum class CompletionOutcome {
        DataEnqueued,
        EmptyWhileCapturing,
        QuietEnd,
        Failed,
    };

    [[nodiscard]] CompletionOutcome HandleCompletion(
        const NativeUsbPcapReadResult& result,
        const std::span<const std::byte> buffer) {
        if (result.bytes > buffer.size()) {
            SetFailure(NativeUsbPcapState::InternalError, ERROR_INVALID_DATA,
                       "Win32 API returned more bytes than the read buffer");
            return CompletionOutcome::Failed;
        }
        if (result.bytes == 0U) {
            std::lock_guard lock(mutex);
            ++status.counters.read_completions;
            ++status.counters.zero_byte_read_completions;

            // USBPcap's reference reader accepts successful zero-byte reads.
            // While filtering is active they mean that no bytes are available
            // yet. Once STOP_FILTERING has succeeded, the same completion is
            // positive evidence that the kernel ring reached its quiet edge.
            if (stop_requested.load(std::memory_order_acquire) &&
                status.filter_stop_succeeded) {
                status.kernel_quiet_observed = true;
                status.quiet_completion_observed = true;
                return CompletionOutcome::QuietEnd;
            }
            return CompletionOutcome::EmptyWhileCapturing;
        }
        return EnqueueRead(buffer.first(result.bytes))
                   ? CompletionOutcome::DataEnqueued
                   : CompletionOutcome::Failed;
    }

    enum class CancelOutcome { Drained, CompletionRaced, Failed };

    [[nodiscard]] CancelOutcome CancelPendingRead(
        const std::span<const std::byte> buffer) {
        std::uint32_t cancel_error = 0;
        {
            std::lock_guard lock(mutex);
            ++status.counters.cancel_requests;
        }
        const bool cancel_requested = api.CancelRead(handle, read_context, cancel_error);
        if (!cancel_requested && cancel_error != kErrorNotFound) {
            SetFailure(NativeUsbPcapState::CancellationFailed, cancel_error,
                       "CancelIoEx failed for the final USBPcap read");
            return CancelOutcome::Failed;
        }

        const auto deadline = std::chrono::steady_clock::now() + options.cancellation_timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto result = api.WaitRead(handle, read_context, options.read_poll_interval);
            if (result.disposition == NativeUsbPcapReadDisposition::Cancelled) {
                std::lock_guard lock(mutex);
                ++status.counters.cancel_completions;
                status.kernel_quiet_observed = true;
                return CancelOutcome::Drained;
            }
            if (result.disposition == NativeUsbPcapReadDisposition::Completed) {
                const auto completion = HandleCompletion(result, buffer);
                if (completion == CompletionOutcome::QuietEnd) return CancelOutcome::Drained;
                return completion == CompletionOutcome::Failed
                           ? CancelOutcome::Failed
                           : CancelOutcome::CompletionRaced;
            }
            if (result.disposition == NativeUsbPcapReadDisposition::Failed) {
                SetFailure(IsDeviceLossError(result.win32_error)
                               ? NativeUsbPcapState::DeviceLost
                               : NativeUsbPcapState::CancellationFailed,
                           result.win32_error,
                           "final USBPcap read failed while awaiting cancellation");
                return CancelOutcome::Failed;
            }
        }
        SetFailure(NativeUsbPcapState::CancellationFailed, WAIT_TIMEOUT,
                   "final USBPcap read did not acknowledge cancellation before timeout");
        return CancelOutcome::Failed;
    }

    void ReaderLoop() noexcept {
        try {
            std::vector<std::byte> buffer(options.read_chunk_bytes);
            bool done = false;
            while (!done) {
                if (stop_requested.load(std::memory_order_acquire) && !StopFiltering()) break;

                {
                    std::lock_guard lock(mutex);
                    ++status.counters.read_operations;
                }
                auto result = api.BeginRead(handle, buffer, read_context);
                if (result.disposition == NativeUsbPcapReadDisposition::Completed) {
                    const auto completion = HandleCompletion(result, buffer);
                    if (completion == CompletionOutcome::Failed ||
                        completion == CompletionOutcome::QuietEnd) {
                        break;
                    }
                    if (completion == CompletionOutcome::EmptyWhileCapturing) {
                        std::this_thread::sleep_for(options.read_poll_interval);
                    }
                    continue;
                }
                if (result.disposition != NativeUsbPcapReadDisposition::Pending) {
                    const auto state = IsDeviceLossError(result.win32_error)
                                           ? NativeUsbPcapState::DeviceLost
                                           : NativeUsbPcapState::InternalError;
                    SetFailure(state, result.win32_error, "USBPcap overlapped ReadFile failed");
                    break;
                }

                for (;;) {
                    result = api.WaitRead(handle, read_context, options.read_poll_interval);
                    if (result.disposition == NativeUsbPcapReadDisposition::Completed) {
                        const auto completion = HandleCompletion(result, buffer);
                        if (completion == CompletionOutcome::Failed ||
                            completion == CompletionOutcome::QuietEnd) {
                            done = true;
                        } else if (completion == CompletionOutcome::EmptyWhileCapturing) {
                            std::this_thread::sleep_for(options.read_poll_interval);
                        }
                        break;
                    }
                    if (result.disposition == NativeUsbPcapReadDisposition::Cancelled) {
                        SetFailure(NativeUsbPcapState::DeviceLost, kErrorOperationAborted,
                                   "USBPcap read was cancelled without a stop request");
                        done = true;
                        break;
                    }
                    if (result.disposition == NativeUsbPcapReadDisposition::Failed) {
                        const auto state = IsDeviceLossError(result.win32_error)
                                               ? NativeUsbPcapState::DeviceLost
                                               : NativeUsbPcapState::InternalError;
                        SetFailure(state, result.win32_error,
                                   "USBPcap overlapped read completion failed");
                        done = true;
                        break;
                    }
                    if (!stop_requested.load(std::memory_order_acquire)) continue;

                    if (!StopFiltering()) {
                        done = true;
                        break;
                    }

                    // The filter is now closed to new packets. Give the already
                    // pending read one full quiet interval to receive buffered
                    // bytes before using cancellation as the end-of-ring probe.
                    result = api.WaitRead(handle, read_context, options.read_poll_interval);
                    if (result.disposition == NativeUsbPcapReadDisposition::Completed) {
                        const auto completion = HandleCompletion(result, buffer);
                        if (completion == CompletionOutcome::Failed ||
                            completion == CompletionOutcome::QuietEnd) {
                            done = true;
                        }
                        break;
                    }
                    if (result.disposition == NativeUsbPcapReadDisposition::Failed) {
                        const auto state = IsDeviceLossError(result.win32_error)
                                               ? NativeUsbPcapState::DeviceLost
                                               : NativeUsbPcapState::CancellationFailed;
                        SetFailure(state, result.win32_error,
                                   "USBPcap final drain read failed");
                        done = true;
                        break;
                    }
                    if (result.disposition == NativeUsbPcapReadDisposition::Cancelled) {
                        std::lock_guard lock(mutex);
                        ++status.counters.cancel_completions;
                        status.kernel_quiet_observed = true;
                        done = true;
                        break;
                    }

                    const CancelOutcome outcome = CancelPendingRead(buffer);
                    if (outcome == CancelOutcome::Drained) {
                        done = true;
                    } else if (outcome == CancelOutcome::Failed) {
                        done = true;
                    }
                    break;
                }
            }
        } catch (const std::exception& error) {
            SetFailure(NativeUsbPcapState::InternalError, 0,
                       std::string("native capture reader exception: ") + error.what());
        } catch (...) {
            SetFailure(NativeUsbPcapState::InternalError, 0,
                       "unknown native capture reader exception");
        }

        if (stop_requested.load(std::memory_order_acquire)) {
            (void)StopFiltering();
        }
        {
            std::lock_guard lock(mutex);
            status.reader_finished = true;
            if (!IsFailureState(status.state)) status.state = NativeUsbPcapState::Draining;
        }
        data_available.notify_all();
        queue_changed.notify_all();
    }

    void DestroyContextAndClose() noexcept {
        if (read_context_ready) {
            api.DestroyReadContext(read_context);
            read_context_ready = false;
        }
        if (handle != kInvalidNativeUsbPcapHandle) {
            std::uint32_t error = 0;
            const bool closed = api.CloseCaptureDevice(handle, error);
            handle = kInvalidNativeUsbPcapHandle;
            std::lock_guard lock(mutex);
            status.handle_closed = closed;
            if (!closed && !IsFailureState(status.state)) {
                status.state = NativeUsbPcapState::DrainFailed;
                status.win32_error = error;
                status.message = "CloseHandle failed for USBPcap capture handle";
            }
        }
    }
};

NativeUsbPcapCapture::NativeUsbPcapCapture(INativeUsbPcapApi& api)
    : impl_(std::make_unique<Impl>(api)) {}

NativeUsbPcapCapture::~NativeUsbPcapCapture() { Abort(); }

bool NativeUsbPcapCapture::Start(const NativeUsbPcapOptions& options) {
    const std::string validation = ValidateNativeUsbPcapOptions(options);
    {
        std::lock_guard lock(impl_->mutex);
        if (impl_->status.state != NativeUsbPcapState::Idle) return false;
        if (!validation.empty()) {
            impl_->status.state = NativeUsbPcapState::ConfigurationFailed;
            impl_->status.message = validation;
            return false;
        }
        impl_->options = options;
        impl_->status.state = NativeUsbPcapState::Opening;
        impl_->status.device_path = BuildNativeUsbPcapPath(options.root_index);
    }

    bool elevated = false;
    std::uint32_t error = 0;
    if (!impl_->api.QueryProcessElevated(elevated, error)) {
        impl_->SetFailure(NativeUsbPcapState::DeviceUnavailable, error,
                          "could not verify process elevation");
        return false;
    }
    if (!elevated) {
        impl_->SetFailure(NativeUsbPcapState::AccessDenied, kErrorAccessDenied,
                          "native USBPcap capture requires an elevated process");
        return false;
    }

    if (!impl_->api.OpenCaptureDevice(impl_->status.device_path, impl_->handle, error)) {
        impl_->SetFailure(error == kErrorAccessDenied ? NativeUsbPcapState::AccessDenied
                                                     : NativeUsbPcapState::DeviceUnavailable,
                          error, "could not exclusively open the selected USBPcap root");
        return false;
    }
    {
        std::lock_guard lock(impl_->mutex);
        impl_->status.state = NativeUsbPcapState::Configuring;
    }

    const usbpcap_abi::IoctlSize snaplen{options.snapshot_length};
    if (!impl_->Control(usbpcap_abi::kIoctlSetSnaplenSize, BytesOf(snaplen), error)) {
        impl_->SetFailure(NativeUsbPcapState::ConfigurationFailed, error,
                          "IOCTL_USBPCAP_SET_SNAPLEN_SIZE failed");
        impl_->DestroyContextAndClose();
        return false;
    }
    const usbpcap_abi::IoctlSize kernel_buffer{options.kernel_buffer_bytes};
    if (!impl_->Control(usbpcap_abi::kIoctlSetupBuffer, BytesOf(kernel_buffer), error)) {
        impl_->SetFailure(NativeUsbPcapState::ConfigurationFailed, error,
                          "IOCTL_USBPCAP_SETUP_BUFFER failed");
        impl_->DestroyContextAndClose();
        return false;
    }

    usbpcap_abi::AddressFilter filter{};
    if (options.capture_all_devices) {
        filter.filter_all = 1U;
    } else {
        filter.addresses[options.device_address / 32U] =
            1U << (options.device_address % 32U);
    }
    const bool valid_filter = options.capture_all_devices
        ? filter.filter_all == 1U &&
            std::all_of(filter.addresses.begin(), filter.addresses.end(),
                        [](const std::uint32_t word) { return word == 0U; })
        : usbpcap_abi::IsExactlySelectedAddress(filter,
                                                options.device_address);
    if (!valid_filter) {
        impl_->SetFailure(NativeUsbPcapState::InternalError, ERROR_INVALID_DATA,
                          "constructed USBPcap address filter was invalid");
        impl_->DestroyContextAndClose();
        return false;
    }
    if (!impl_->Control(usbpcap_abi::kIoctlStartFiltering, BytesOf(filter), error)) {
        impl_->SetFailure(NativeUsbPcapState::ConfigurationFailed, error,
                          "IOCTL_USBPCAP_START_FILTERING failed");
        impl_->DestroyContextAndClose();
        return false;
    }
    {
        std::lock_guard lock(impl_->mutex);
        impl_->status.filter_started = true;
    }

    if (!impl_->api.CreateReadContext(impl_->read_context, error)) {
        impl_->SetFailure(NativeUsbPcapState::ConfigurationFailed, error,
                          "could not create the overlapped read event");
        (void)impl_->StopFiltering();
        impl_->DestroyContextAndClose();
        return false;
    }
    impl_->read_context_ready = true;
    {
        std::lock_guard lock(impl_->mutex);
        impl_->status.state = NativeUsbPcapState::Capturing;
        impl_->status.message = options.capture_all_devices
            ? "capturing bounded whole-root USBPcap PCAP bytes"
            : "capturing exact selected-device USBPcap PCAP bytes";
    }
    try {
        impl_->reader = std::thread([implementation = impl_.get()] {
            implementation->ReaderLoop();
        });
    } catch (const std::exception& exception) {
        impl_->SetFailure(NativeUsbPcapState::InternalError, 0,
                          std::string("could not start reader thread: ") + exception.what());
        (void)impl_->StopFiltering();
        impl_->DestroyContextAndClose();
        return false;
    }
    return true;
}

void NativeUsbPcapCapture::RequestStop() {
    impl_->stop_requested.store(true, std::memory_order_release);
    std::lock_guard lock(impl_->mutex);
    if (impl_->status.state == NativeUsbPcapState::Capturing) {
        impl_->status.state = NativeUsbPcapState::StopRequested;
        impl_->status.message = "selected-device capture stop requested";
    }
}

NativeUsbPcapStopReport NativeUsbPcapCapture::StopAndDrain(
    const std::chrono::milliseconds consumer_drain_timeout,
    NativeUsbPcapSemanticGuard semantic_guard) {
    {
        std::lock_guard lock(impl_->mutex);
        if (impl_->stop_completed) return impl_->last_stop;
    }
    RequestStop();
    if (impl_->reader.joinable()) impl_->reader.join();

    NativeUsbPcapStopReport report;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::max(consumer_drain_timeout, std::chrono::milliseconds::zero());
    {
        std::unique_lock lock(impl_->mutex);
        impl_->queue_changed.wait_until(lock, deadline, [&] {
            return impl_->status.counters.queued_bytes == 0;
        });
        report.consumer_queue_empty = impl_->status.counters.queued_bytes == 0;
        report.bytes_left_in_queue = impl_->status.counters.queued_bytes;
        report.bytes_read = impl_->status.counters.bytes_read;
        report.bytes_delivered = impl_->status.counters.bytes_delivered;
        report.filter_stop_attempted = impl_->status.filter_stop_attempted;
        report.filter_stop_succeeded = impl_->status.filter_stop_succeeded;
        report.kernel_quiet_observed = impl_->status.kernel_quiet_observed;
        report.cancellation_observed = impl_->status.counters.cancel_completions != 0;
        report.quiet_completion_observed = impl_->status.quiet_completion_observed;
    }

    NativeUsbPcapSemanticDrainEvidence evidence;
    if (report.consumer_queue_empty && semantic_guard) {
        report.semantic_guard_invoked = true;
        try {
            evidence = semantic_guard();
            report.bytes_accounted = evidence.accounted_bytes;
            report.semantic_guard_passed =
                evidence.parser_at_record_boundary && evidence.authoritative_writer_clean &&
                evidence.accounted_bytes == report.bytes_read &&
                report.bytes_delivered == report.bytes_read;
        } catch (const std::exception& exception) {
            evidence.diagnostic = std::string("semantic drain guard threw: ") + exception.what();
        } catch (...) {
            evidence.diagnostic = "semantic drain guard threw an unknown exception";
        }
    }

    impl_->DestroyContextAndClose();
    {
        std::lock_guard lock(impl_->mutex);
        report.handle_closed = impl_->status.handle_closed;
        report.win32_error = impl_->status.win32_error;
        const bool prior_failure = IsFailureState(impl_->status.state);
        report.clean = !prior_failure && report.filter_stop_attempted &&
                       report.filter_stop_succeeded && report.kernel_quiet_observed &&
                       (report.cancellation_observed || report.quiet_completion_observed) &&
                       report.consumer_queue_empty &&
                       report.semantic_guard_passed && report.handle_closed &&
                       impl_->status.counters.queue_overflow_events == 0 &&
                       impl_->status.counters.bytes_discarded == 0;

        std::ostringstream diagnostic;
        if (!evidence.diagnostic.empty()) diagnostic << evidence.diagnostic;
        if (!report.consumer_queue_empty) {
            if (diagnostic.tellp() > 0) diagnostic << "; ";
            diagnostic << report.bytes_left_in_queue << " PCAP byte(s) remained in consumer queue";
        }
        if (!report.semantic_guard_invoked) {
            if (diagnostic.tellp() > 0) diagnostic << "; ";
            diagnostic << "semantic parser/writer drain guard was not invoked";
        } else if (!report.semantic_guard_passed) {
            if (diagnostic.tellp() > 0) diagnostic << "; ";
            diagnostic << "semantic parser/writer drain evidence did not account for every byte";
        }
        if (!impl_->status.message.empty() && !report.clean) {
            if (diagnostic.tellp() > 0) diagnostic << "; ";
            diagnostic << impl_->status.message;
        }
        if (report.clean) diagnostic << "native filter, kernel read, queue, parser, and writer drained cleanly";
        report.diagnostic = diagnostic.str();

        if (report.clean) {
            impl_->status.state = NativeUsbPcapState::Stopped;
            impl_->status.message = report.diagnostic;
        } else if (!IsFailureState(impl_->status.state)) {
            impl_->status.state = NativeUsbPcapState::DrainFailed;
            impl_->status.message = report.diagnostic;
        }
        impl_->stop_completed = true;
        impl_->last_stop = report;
    }
    return report;
}

void NativeUsbPcapCapture::Abort() noexcept {
    if (!impl_) return;
    {
        std::lock_guard lock(impl_->mutex);
        if (impl_->stop_completed && impl_->handle == kInvalidNativeUsbPcapHandle &&
            !impl_->reader.joinable()) {
            return;
        }
    }
    RequestStop();
    if (impl_->reader.joinable()) impl_->reader.join();
    {
        std::lock_guard lock(impl_->mutex);
        impl_->status.counters.bytes_discarded += impl_->status.counters.queued_bytes;
        impl_->queue.clear();
        impl_->status.counters.queued_bytes = 0;
        if (!IsFailureState(impl_->status.state)) {
            impl_->status.state = NativeUsbPcapState::DrainFailed;
            impl_->status.message = "capture aborted without semantic drain evidence";
        }
    }
    impl_->DestroyContextAndClose();
    impl_->data_available.notify_all();
    impl_->queue_changed.notify_all();
}

bool NativeUsbPcapCapture::TryTakeChunk(std::vector<std::byte>& chunk) {
    std::lock_guard lock(impl_->mutex);
    if (impl_->queue.empty()) return false;
    chunk = std::move(impl_->queue.front());
    impl_->queue.pop_front();
    impl_->status.counters.queued_bytes -= chunk.size();
    ++impl_->status.counters.chunks_delivered;
    impl_->status.counters.bytes_delivered += chunk.size();
    impl_->queue_changed.notify_all();
    return true;
}

bool NativeUsbPcapCapture::WaitTakeChunk(std::vector<std::byte>& chunk,
                                        const std::chrono::milliseconds timeout) {
    std::unique_lock lock(impl_->mutex);
    impl_->data_available.wait_for(lock, timeout, [&] {
        return !impl_->queue.empty() || impl_->status.reader_finished;
    });
    if (impl_->queue.empty()) return false;
    chunk = std::move(impl_->queue.front());
    impl_->queue.pop_front();
    impl_->status.counters.queued_bytes -= chunk.size();
    ++impl_->status.counters.chunks_delivered;
    impl_->status.counters.bytes_delivered += chunk.size();
    lock.unlock();
    impl_->queue_changed.notify_all();
    return true;
}

NativeUsbPcapStatus NativeUsbPcapCapture::Status() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->status;
}

}  // namespace abdc::windows_capture
