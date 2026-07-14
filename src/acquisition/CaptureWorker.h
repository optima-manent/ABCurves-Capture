#pragma once

#include "capture/HidDescriptor.h"
#include "capture/MouseReportExtractor.h"
#include "capture/PcapReader.h"
#include "capture/ReportStream.h"
#include "windows_capture/NativeUsbPcap.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace abdc::acquisition {

struct CertifiedUsbDevice {
    std::uint16_t bus = 0;
    std::uint16_t device = 0;
};

struct DecodedMouseEndpoint {
    std::uint8_t endpoint = 0;
    capture::HidMouseDecoder decoder;
    capture::ReportStreamIdentity report_identity;
};

struct CaptureOutputPaths {
    std::filesystem::path device_pcap_partial;
    std::filesystem::path device_pcap_final;
    std::filesystem::path reports_partial;
    std::filesystem::path reports_final;
    std::filesystem::path anomalies_partial;
    std::filesystem::path anomalies_final;
};

[[nodiscard]] CaptureOutputPaths OutputPathsIn(
    const std::filesystem::path& absolute_output_directory);
[[nodiscard]] std::string ValidateOutputPaths(const CaptureOutputPaths& paths);

enum class CapturePipelineFailureKind {
    PcapFraming,
    DeviceIdentity,
    Writer,
};

class CapturePipelineError final : public std::runtime_error {
public:
    CapturePipelineError(CapturePipelineFailureKind kind, std::string message);
    [[nodiscard]] CapturePipelineFailureKind Kind() const noexcept { return kind_; }

private:
    CapturePipelineFailureKind kind_;
};

struct CapturePipelineSnapshot {
    std::uint64_t source_bytes = 0;
    std::uint64_t source_records = 0;
    std::uint64_t raw_device_records = 0;
    std::uint64_t decoded_endpoint_records = 0;
    std::uint64_t decoded_reports = 0;
    std::uint64_t anomalies = 0;
    std::uint64_t derivative_failures = 0;
    bool decoder_available = false;
    bool report_stream_available = false;
    bool anomaly_journal_available = false;
    bool pcap_header_ready = false;
    bool parser_at_record_boundary = false;
    bool sealed = false;
    bool published = false;
};

class ICapturePipeline {
public:
    virtual ~ICapturePipeline() = default;

    // observed_qpc is sampled after the chunk reaches the consumer. Native PCAP
    // time remains authoritative and is never replaced by this observation.
    virtual void ProcessChunk(std::span<const std::byte> chunk,
                              std::int64_t observed_qpc) = 0;
    virtual void Checkpoint() = 0;
    virtual void Seal() = 0;
    virtual void Publish() = 0;
    [[nodiscard]] virtual windows_capture::NativeUsbPcapSemanticDrainEvidence
    DrainEvidence() const = 0;
    [[nodiscard]] virtual CapturePipelineSnapshot Snapshot() const = 0;
};

// The authoritative product is a device-wide exact-address PCAP. Every source
// record is appended before optional HID decoding is attempted. ABCRPT2 and
// the anomaly journal are degradable derivatives.
class CapturePipeline final : public ICapturePipeline {
public:
    CapturePipeline(CaptureOutputPaths paths,
                    CertifiedUsbDevice device,
                    std::optional<DecodedMouseEndpoint> decoded_endpoint);

    ~CapturePipeline() override;

    CapturePipeline(const CapturePipeline&) = delete;
    CapturePipeline& operator=(const CapturePipeline&) = delete;

    void ProcessChunk(std::span<const std::byte> chunk,
                      std::int64_t observed_qpc) override;
    void Checkpoint() override;
    void Seal() override;
    void Publish() override;
    [[nodiscard]] windows_capture::NativeUsbPcapSemanticDrainEvidence
    DrainEvidence() const override;
    [[nodiscard]] CapturePipelineSnapshot Snapshot() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// This narrow interface is deliberately shaped like NativeUsbPcapCapture. A
// fake can provide deterministic chunks, while production delegates every read
// and stop/drain decision to the unchanged native implementation.
class IUsbPcapChunkSource {
public:
    virtual ~IUsbPcapChunkSource() = default;
    virtual bool Start(const windows_capture::NativeUsbPcapOptions& options) = 0;
    virtual void RequestStop() = 0;
    virtual bool WaitTakeChunk(std::vector<std::byte>& chunk,
                               std::chrono::milliseconds timeout) = 0;
    [[nodiscard]] virtual windows_capture::NativeUsbPcapStatus Status() const = 0;
    virtual windows_capture::NativeUsbPcapStopReport StopAndDrain(
        std::chrono::milliseconds consumer_drain_timeout,
        windows_capture::NativeUsbPcapSemanticGuard semantic_guard) = 0;
    virtual void Abort() noexcept = 0;
};

class NativeUsbPcapChunkSource final : public IUsbPcapChunkSource {
public:
    explicit NativeUsbPcapChunkSource(windows_capture::INativeUsbPcapApi& api);

    bool Start(const windows_capture::NativeUsbPcapOptions& options) override;
    void RequestStop() override;
    bool WaitTakeChunk(std::vector<std::byte>& chunk,
                       std::chrono::milliseconds timeout) override;
    [[nodiscard]] windows_capture::NativeUsbPcapStatus Status() const override;
    windows_capture::NativeUsbPcapStopReport StopAndDrain(
        std::chrono::milliseconds consumer_drain_timeout,
        windows_capture::NativeUsbPcapSemanticGuard semantic_guard) override;
    void Abort() noexcept override;

private:
    windows_capture::NativeUsbPcapCapture capture_;
};

enum class CaptureWorkerState {
    Idle,
    Starting,
    Running,
    StopRequested,
    Draining,
    Publishing,
    Completed,
    Failed,
};

[[nodiscard]] const char* ToString(CaptureWorkerState state) noexcept;

enum class CaptureFatalReason {
    None,
    InvalidConfiguration,
    QueueOrByteLoss,
    NativeOrDeviceLoss,
    DeviceIdentityChanged,
    PcapFraming,
    WriterFailure,
};

[[nodiscard]] const char* ToString(CaptureFatalReason reason) noexcept;

struct CaptureWorkerOptions {
    windows_capture::NativeUsbPcapOptions native;
    std::chrono::milliseconds consumer_poll_interval{20};
    std::chrono::milliseconds durable_flush_interval{2'000};
    std::chrono::milliseconds consumer_drain_timeout{5'000};
};

[[nodiscard]] std::string ValidateCaptureWorkerOptions(
    const CaptureWorkerOptions& options);

struct CaptureWorkerSnapshot {
    CaptureWorkerState state = CaptureWorkerState::Idle;
    CaptureFatalReason fatal_reason = CaptureFatalReason::None;
    std::string detail;
    CapturePipelineSnapshot pipeline;
    windows_capture::NativeUsbPcapStatus native;
};

struct CaptureWorkerResult {
    bool clean = false;
    CaptureFatalReason fatal_reason = CaptureFatalReason::None;
    std::string detail;
    CapturePipelineSnapshot pipeline;
    windows_capture::NativeUsbPcapStopReport native_stop;
};

class CaptureWorker final {
public:
    using QpcNow = std::function<std::int64_t()>;

    CaptureWorker(IUsbPcapChunkSource& source,
                  ICapturePipeline& pipeline,
                  CaptureWorkerOptions options,
                  QpcNow qpc_now);
    ~CaptureWorker();

    CaptureWorker(const CaptureWorker&) = delete;
    CaptureWorker& operator=(const CaptureWorker&) = delete;

    // Run blocks until RequestStop, source failure, or a fatal processing
    // failure. It is intended to run on the helper's worker thread.
    [[nodiscard]] CaptureWorkerResult Run();
    void RequestStop();
    [[nodiscard]] CaptureWorkerSnapshot Snapshot() const;

private:
    void UpdateSnapshot(CaptureWorkerState state,
                        CaptureFatalReason reason,
                        std::string detail);

    IUsbPcapChunkSource& source_;
    ICapturePipeline& pipeline_;
    CaptureWorkerOptions options_;
    QpcNow qpc_now_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> source_started_{false};
    std::atomic<bool> run_entered_{false};
    mutable std::mutex snapshot_mutex_;
    CaptureWorkerSnapshot snapshot_{};
};

}  // namespace abdc::acquisition
