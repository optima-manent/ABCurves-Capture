#include "acquisition/CaptureWorker.h"

#include "base/Json.h"
#include "capture/DevicePcapWriter.h"
#include "capture/StreamingPcapParser.h"
#include "capture/UsbPcapPacket.h"
#include "session/AppendOnlyJsonl.h"

#include <algorithm>
#include <array>
#include <cwctype>
#include <limits>
#include <optional>
#include <sstream>
#include <utility>

namespace abdc::acquisition {
namespace {

constexpr std::string_view kAnomalySchema = "abcurves.capture.anomaly.v1";

[[nodiscard]] bool SamePath(const std::filesystem::path& left,
                            const std::filesystem::path& right) {
    auto key = [](const std::filesystem::path& path) {
        std::wstring value = path.lexically_normal().native();
        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t character) {
            if (character == L'/') return L'\\';
            return static_cast<wchar_t>(std::towlower(character));
        });
        return value;
    };
    return key(left) == key(right);
}

[[nodiscard]] json::Value JsonUnsigned(const std::uint64_t value) {
    if (value <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return json::Value(static_cast<std::int64_t>(value));
    }
    return json::Value(std::to_string(value));
}

[[nodiscard]] CaptureFatalReason FailureForNativeState(
    const windows_capture::NativeUsbPcapStatus& status) {
    if (status.counters.queue_overflow_events != 0U ||
        status.counters.bytes_discarded != 0U ||
        status.state == windows_capture::NativeUsbPcapState::QueueOverflow) {
        return CaptureFatalReason::QueueOrByteLoss;
    }
    switch (status.state) {
    case windows_capture::NativeUsbPcapState::AccessDenied:
    case windows_capture::NativeUsbPcapState::DeviceUnavailable:
    case windows_capture::NativeUsbPcapState::ConfigurationFailed:
    case windows_capture::NativeUsbPcapState::DeviceLost:
    case windows_capture::NativeUsbPcapState::StopFilteringFailed:
    case windows_capture::NativeUsbPcapState::CancellationFailed:
    case windows_capture::NativeUsbPcapState::DrainFailed:
    case windows_capture::NativeUsbPcapState::InternalError:
        return CaptureFatalReason::NativeOrDeviceLoss;
    default:
        return CaptureFatalReason::None;
    }
}

[[nodiscard]] CaptureFatalReason FailureForStopReport(
    const windows_capture::NativeUsbPcapStopReport& report,
    const windows_capture::NativeUsbPcapStatus& status) {
    if (status.counters.queue_overflow_events != 0U ||
        status.counters.bytes_discarded != 0U ||
        report.bytes_delivered != report.bytes_read ||
        report.bytes_accounted != report.bytes_read ||
        !report.consumer_queue_empty) {
        return CaptureFatalReason::QueueOrByteLoss;
    }
    return CaptureFatalReason::NativeOrDeviceLoss;
}

[[nodiscard]] std::chrono::milliseconds TimeUntil(
    const std::chrono::steady_clock::time_point deadline,
    const std::chrono::milliseconds maximum) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return std::chrono::milliseconds::zero();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    return std::min(maximum, std::max(remaining, std::chrono::milliseconds{1}));
}

}  // namespace

CaptureOutputPaths OutputPathsIn(
    const std::filesystem::path& absolute_output_directory) {
    return {
        absolute_output_directory / L"mouse_usb.pcap.partial",
        absolute_output_directory / L"mouse_usb.pcap",
        absolute_output_directory / L"mouse_reports.abcr2.partial",
        absolute_output_directory / L"mouse_reports.abcr2",
        absolute_output_directory / L"capture_anomalies.jsonl.partial",
        absolute_output_directory / L"capture_anomalies.jsonl",
    };
}

std::string ValidateOutputPaths(const CaptureOutputPaths& paths) {
    const std::array<const std::filesystem::path*, 6> values{
        &paths.device_pcap_partial, &paths.device_pcap_final,
        &paths.reports_partial, &paths.reports_final,
        &paths.anomalies_partial, &paths.anomalies_final,
    };
    for (const auto* value : values) {
        if (value->empty() || !value->is_absolute() || value->filename().empty()) {
            return "capture output paths must be absolute file paths";
        }
        if (std::filesystem::exists(*value)) {
            return "capture output already exists; refusing to overwrite it";
        }
    }
    for (std::size_t left = 0; left < values.size(); ++left) {
        for (std::size_t right = left + 1; right < values.size(); ++right) {
            if (SamePath(*values[left], *values[right])) {
                return "capture output paths must be distinct";
            }
        }
    }
    return {};
}

CapturePipelineError::CapturePipelineError(const CapturePipelineFailureKind kind,
                                           std::string message)
    : std::runtime_error(std::move(message)), kind_(kind) {}

struct CapturePipeline::Impl {
    Impl(CaptureOutputPaths output_paths,
         const CertifiedUsbDevice certified_device,
         std::optional<DecodedMouseEndpoint> decoded_endpoint)
        : paths(std::move(output_paths)),
          device(certified_device) {
        const std::string path_error = ValidateOutputPaths(paths);
        if (!path_error.empty()) {
            throw CapturePipelineError(CapturePipelineFailureKind::Writer, path_error);
        }
        if (device.bus == 0U || device.device == 0U) {
            throw std::invalid_argument("invalid certified USB device");
        }
        if (decoded_endpoint) {
            auto& decoded = *decoded_endpoint;
            if ((decoded.endpoint & 0x80U) == 0U ||
                (decoded.endpoint & 0x0fU) == 0U ||
                decoded.report_identity.bus != device.bus ||
                decoded.report_identity.device != device.device ||
                decoded.report_identity.endpoint != decoded.endpoint) {
                throw std::invalid_argument(
                    "optional report identity does not match the certified USB device");
            }
            decoded_endpoint_address = decoded.endpoint;
            extractor.emplace(device.bus, device.device, decoded.endpoint,
                              std::move(decoded.decoder));
            snapshot.decoder_available = true;
            try {
                reports = std::make_unique<capture::ReportStreamWriter>(
                    paths.reports_partial,
                    std::move(decoded.report_identity));
                snapshot.report_stream_available = true;
            } catch (const std::exception&) {
                ++snapshot.derivative_failures;
            }
        }
        try {
            anomalies = std::make_unique<session::AppendOnlyJsonlWriter>(
                paths.anomalies_partial, std::string(kAnomalySchema));
            snapshot.anomaly_journal_available = true;
        } catch (const std::exception&) {
            ++snapshot.derivative_failures;
        }
    }

    void EnsureDeviceWriter() {
        if (device_pcap || !parser.HeaderReady()) return;
        try {
            device_pcap = std::make_unique<capture::DevicePcapWriter>(
                paths.device_pcap_partial, parser.Header(), device.bus,
                device.device);
        } catch (const std::exception& error) {
            authoritative_writer_failed = true;
            throw CapturePipelineError(
                CapturePipelineFailureKind::Writer,
                std::string("could not create device PCAP: ") + error.what());
        }
    }

    void DisableAnomalyJournal() noexcept {
        if (!anomalies) return;
        anomalies.reset();
        snapshot.anomaly_journal_available = false;
        ++snapshot.derivative_failures;
    }

    void DisableReportStream() noexcept {
        if (!reports) return;
        reports.reset();
        snapshot.report_stream_available = false;
        ++snapshot.derivative_failures;
    }

    void AppendAnomaly(const std::string& code,
                       const capture::PcapRecord& record,
                       const std::uint64_t irp_id,
                       const std::string& detail) {
        json::Value object(json::Value::Object{});
        object["code"] = code;
        object["pcap_sequence"] = JsonUnsigned(record.sequence);
        object["capture_unix_ns"] = [&]() -> json::Value {
            try {
                return json::Value(record.UnixNanoseconds());
            } catch (...) {
                return json::Value(nullptr);
            }
        }();
        object["observed_qpc"] = record.observed_qpc;
        object["irp_id"] = JsonUnsigned(irp_id);
        object["detail"] = detail;
        if (!anomalies) return;
        try {
            (void)anomalies->Append(std::move(object));
            ++snapshot.anomalies;
        } catch (const std::exception&) {
            DisableAnomalyJournal();
        }
    }

    void AppendAnomaly(const capture::CaptureAnomaly& anomaly,
                       const capture::PcapRecord& record) {
        AppendAnomaly(capture::ToString(anomaly.code), record, anomaly.irp_id,
                      anomaly.detail);
    }

    void ProcessRecord(capture::PcapRecord& record,
                       const std::int64_t chunk_observed_qpc) {
        const std::int64_t supplied_qpc = chunk_observed_qpc;
        const std::int64_t minimum_qpc = last_observed_qpc.value_or(1);
        record.observed_qpc = supplied_qpc > 0
            ? std::max(supplied_qpc, minimum_qpc)
            : minimum_qpc;
        const bool qpc_adjusted = supplied_qpc <= 0 ||
            (last_observed_qpc && supplied_qpc < *last_observed_qpc);
        last_observed_qpc = record.observed_qpc;

        capture::UsbPcapPacket packet;
        try {
            packet = capture::UsbPcapPacket::Parse(record.data,
                                                   record.original_length);
        } catch (const std::exception& error) {
            throw CapturePipelineError(
                CapturePipelineFailureKind::PcapFraming,
                std::string("invalid LINKTYPE_USBPCAP record: ") + error.what());
        }

        if (packet.bus != device.bus || packet.device != device.device) {
            std::ostringstream message;
            message << "exact-address capture yielded unexpected USB identity "
                    << packet.bus << ':' << packet.device << " instead of "
                    << device.bus << ':' << device.device;
            throw CapturePipelineError(CapturePipelineFailureKind::DeviceIdentity,
                                       message.str());
        }

        // This ordering is the core durability contract. Every exact-address
        // record is retained before optional endpoint interpretation.
        try {
            device_pcap->Append(record, packet);
            ++snapshot.raw_device_records;
        } catch (const std::exception& error) {
            authoritative_writer_failed = true;
            throw CapturePipelineError(
                CapturePipelineFailureKind::Writer,
                std::string("device PCAP append failed: ") + error.what());
        }

        if (packet.payload_truncated) {
            std::ostringstream detail;
            detail << "PCAP snapshot retained " << packet.payload.size()
                   << " of " << packet.declared_data_length
                   << " USB transfer payload bytes; the raw record was preserved and optional decoding was skipped";
            AppendAnomaly("snaplen_truncated", record, packet.irp_id,
                          detail.str());
            return;
        }

        if (!extractor || packet.endpoint != decoded_endpoint_address ||
            packet.transfer != capture::UsbTransfer::Interrupt) {
            return;
        }
        ++snapshot.decoded_endpoint_records;

        if (qpc_adjusted) {
            AppendAnomaly(
                "observation_qpc_adjusted", record, packet.irp_id,
                "consumer QPC was unavailable or regressed; a monotonic observation bound was retained");
        }

        capture::MouseExtractionResult extracted;
        try {
            extracted = extractor->Process(record, packet);
        } catch (const std::exception& error) {
            // Raw bytes are already durable in the device stream. Timestamp
            // or decoder-side interpretation failures remain metadata only.
            AppendAnomaly("extraction_failed", record, packet.irp_id, error.what());
            return;
        }

        for (const auto& anomaly : extracted.anomalies) {
            AppendAnomaly(anomaly, record);
        }
        for (const auto& report : extracted.reports) {
            if (!reports) break;
            try {
                reports->Append(report);
                ++snapshot.decoded_reports;
            } catch (const std::exception&) {
                DisableReportStream();
            }
        }
    }

    CaptureOutputPaths paths;
    CertifiedUsbDevice device;
    std::uint8_t decoded_endpoint_address = 0U;
    capture::StreamingPcapParser parser;
    std::optional<capture::MouseReportExtractor> extractor;
    std::unique_ptr<capture::DevicePcapWriter> device_pcap;
    std::unique_ptr<capture::ReportStreamWriter> reports;
    std::unique_ptr<session::AppendOnlyJsonlWriter> anomalies;
    CapturePipelineSnapshot snapshot{};
    std::optional<std::int64_t> last_observed_qpc;
    bool authoritative_writer_failed = false;
};

CapturePipeline::CapturePipeline(
    CaptureOutputPaths paths, const CertifiedUsbDevice device,
    std::optional<DecodedMouseEndpoint> decoded_endpoint)
    : impl_(std::make_unique<Impl>(std::move(paths), device,
                                  std::move(decoded_endpoint))) {}

CapturePipeline::~CapturePipeline() = default;

void CapturePipeline::ProcessChunk(const std::span<const std::byte> chunk,
                                   const std::int64_t observed_qpc) {
    if (impl_->snapshot.sealed || impl_->snapshot.published) {
        throw std::logic_error("cannot append to a sealed capture pipeline");
    }
    if (chunk.empty()) return;
    if (chunk.size() >
        std::numeric_limits<std::uint64_t>::max() - impl_->snapshot.source_bytes) {
        throw CapturePipelineError(CapturePipelineFailureKind::PcapFraming,
                                   "source-byte accounting overflow");
    }
    impl_->snapshot.source_bytes += chunk.size();

    std::vector<capture::PcapRecord> records;
    try {
        impl_->parser.Append(chunk);
        records = impl_->parser.TakeRecords();
    } catch (const CapturePipelineError&) {
        throw;
    } catch (const std::exception& error) {
        throw CapturePipelineError(
            CapturePipelineFailureKind::PcapFraming,
            std::string("streaming PCAP framing failed: ") + error.what());
    }
    impl_->snapshot.pcap_header_ready = impl_->parser.HeaderReady();
    impl_->snapshot.parser_at_record_boundary = impl_->parser.AtRecordBoundary();
    impl_->EnsureDeviceWriter();

    for (auto& record : records) {
        ++impl_->snapshot.source_records;
        impl_->ProcessRecord(record, observed_qpc);
    }
    impl_->snapshot.parser_at_record_boundary = impl_->parser.AtRecordBoundary();
}

void CapturePipeline::Checkpoint() {
    if (impl_->snapshot.published) {
        throw std::logic_error("cannot checkpoint a published capture pipeline");
    }
    try {
        if (impl_->device_pcap) impl_->device_pcap->Checkpoint();
    } catch (const std::exception& error) {
        impl_->authoritative_writer_failed = true;
        throw CapturePipelineError(
            CapturePipelineFailureKind::Writer,
            std::string("device PCAP durable flush failed: ") + error.what());
    }
    if (impl_->reports) {
        try {
            impl_->reports->Checkpoint();
        } catch (const std::exception&) {
            impl_->DisableReportStream();
        }
    }
    if (impl_->anomalies) {
        try {
            impl_->anomalies->Checkpoint();
        } catch (const std::exception&) {
            impl_->DisableAnomalyJournal();
        }
    }
}

void CapturePipeline::Seal() {
    if (impl_->snapshot.sealed) return;
    if (impl_->snapshot.published) {
        throw std::logic_error("published capture pipeline was not sealed");
    }
    try {
        impl_->parser.Finalize();
    } catch (const std::exception& error) {
        throw CapturePipelineError(
            CapturePipelineFailureKind::PcapFraming,
            std::string("capture ended off a PCAP record boundary: ") + error.what());
    }
    impl_->EnsureDeviceWriter();
    Checkpoint();
    impl_->snapshot.pcap_header_ready = impl_->parser.HeaderReady();
    impl_->snapshot.parser_at_record_boundary = impl_->parser.AtRecordBoundary();
    impl_->snapshot.sealed = true;
}

void CapturePipeline::Publish() {
    if (!impl_->snapshot.sealed) {
        throw std::logic_error("capture pipeline must be sealed before publication");
    }
    if (impl_->snapshot.published) {
        throw std::logic_error("capture pipeline was already published");
    }
    try {
        impl_->device_pcap->Finalize(impl_->paths.device_pcap_final);
    } catch (const std::exception& error) {
        impl_->authoritative_writer_failed = true;
        throw CapturePipelineError(
            CapturePipelineFailureKind::Writer,
            std::string("device PCAP publication failed: ") + error.what());
    }
    if (impl_->reports) {
        try {
            impl_->reports->Finalize(impl_->paths.reports_final);
        } catch (const std::exception&) {
            impl_->DisableReportStream();
        }
    }
    if (impl_->anomalies) {
        try {
            impl_->anomalies->Finalize(impl_->paths.anomalies_final);
        } catch (const std::exception&) {
            impl_->DisableAnomalyJournal();
        }
    }
    impl_->snapshot.published = true;
}

windows_capture::NativeUsbPcapSemanticDrainEvidence
CapturePipeline::DrainEvidence() const {
    windows_capture::NativeUsbPcapSemanticDrainEvidence result;
    result.parser_at_record_boundary = impl_->parser.AtRecordBoundary();
    result.authoritative_writer_clean =
        impl_->snapshot.sealed && !impl_->authoritative_writer_failed;
    result.accounted_bytes = impl_->snapshot.source_bytes;
    if (!result.parser_at_record_boundary) {
        result.diagnostic = "streaming parser is not at a complete PCAP record boundary";
    } else if (!result.authoritative_writer_clean) {
        result.diagnostic = "device PCAP writer has not reached a clean durable seal";
    }
    return result;
}

CapturePipelineSnapshot CapturePipeline::Snapshot() const {
    CapturePipelineSnapshot result = impl_->snapshot;
    result.pcap_header_ready = impl_->parser.HeaderReady();
    result.parser_at_record_boundary = impl_->parser.AtRecordBoundary();
    return result;
}

NativeUsbPcapChunkSource::NativeUsbPcapChunkSource(
    windows_capture::INativeUsbPcapApi& api)
    : capture_(api) {}

bool NativeUsbPcapChunkSource::Start(
    const windows_capture::NativeUsbPcapOptions& options) {
    return capture_.Start(options);
}

void NativeUsbPcapChunkSource::RequestStop() { capture_.RequestStop(); }

bool NativeUsbPcapChunkSource::WaitTakeChunk(
    std::vector<std::byte>& chunk, const std::chrono::milliseconds timeout) {
    return capture_.WaitTakeChunk(chunk, timeout);
}

windows_capture::NativeUsbPcapStatus NativeUsbPcapChunkSource::Status() const {
    return capture_.Status();
}

windows_capture::NativeUsbPcapStopReport NativeUsbPcapChunkSource::StopAndDrain(
    const std::chrono::milliseconds consumer_drain_timeout,
    windows_capture::NativeUsbPcapSemanticGuard semantic_guard) {
    return capture_.StopAndDrain(consumer_drain_timeout, std::move(semantic_guard));
}

void NativeUsbPcapChunkSource::Abort() noexcept { capture_.Abort(); }

const char* ToString(const CaptureWorkerState state) noexcept {
    switch (state) {
    case CaptureWorkerState::Idle: return "idle";
    case CaptureWorkerState::Starting: return "starting";
    case CaptureWorkerState::Running: return "running";
    case CaptureWorkerState::StopRequested: return "stop_requested";
    case CaptureWorkerState::Draining: return "draining";
    case CaptureWorkerState::Publishing: return "publishing";
    case CaptureWorkerState::Completed: return "completed";
    case CaptureWorkerState::Failed: return "failed";
    }
    return "unknown";
}

const char* ToString(const CaptureFatalReason reason) noexcept {
    switch (reason) {
    case CaptureFatalReason::None: return "none";
    case CaptureFatalReason::InvalidConfiguration: return "invalid_configuration";
    case CaptureFatalReason::QueueOrByteLoss: return "queue_or_byte_loss";
    case CaptureFatalReason::NativeOrDeviceLoss: return "native_or_device_loss";
    case CaptureFatalReason::DeviceIdentityChanged: return "device_identity_changed";
    case CaptureFatalReason::PcapFraming: return "pcap_framing";
    case CaptureFatalReason::WriterFailure: return "writer_failure";
    }
    return "unknown";
}

std::string ValidateCaptureWorkerOptions(const CaptureWorkerOptions& options) {
    if (const auto native_error =
            windows_capture::ValidateNativeUsbPcapOptions(options.native);
        !native_error.empty()) {
        return native_error;
    }
    if (options.consumer_poll_interval <= std::chrono::milliseconds::zero() ||
        options.consumer_poll_interval > std::chrono::seconds(1)) {
        return "consumer poll interval must be in (0,1000] ms";
    }
    if (options.durable_flush_interval <= std::chrono::milliseconds::zero() ||
        options.durable_flush_interval > std::chrono::minutes(1)) {
        return "durable flush interval must be in (0,60000] ms";
    }
    if (options.consumer_drain_timeout < std::chrono::milliseconds::zero() ||
        options.consumer_drain_timeout > std::chrono::minutes(1)) {
        return "consumer drain timeout must be in [0,60000] ms";
    }
    return {};
}

CaptureWorker::CaptureWorker(IUsbPcapChunkSource& source,
                             ICapturePipeline& pipeline,
                             CaptureWorkerOptions options,
                             QpcNow qpc_now)
    : source_(source), pipeline_(pipeline), options_(std::move(options)),
      qpc_now_(std::move(qpc_now)) {
    if (!qpc_now_) throw std::invalid_argument("capture worker requires a QPC source");
}

CaptureWorker::~CaptureWorker() {
    if (source_started_.load(std::memory_order_acquire)) {
        source_.Abort();
    }
}

void CaptureWorker::UpdateSnapshot(const CaptureWorkerState state,
                                   const CaptureFatalReason reason,
                                   std::string detail) {
    CaptureWorkerSnapshot next;
    next.state = state;
    next.fatal_reason = reason;
    next.detail = std::move(detail);
    next.pipeline = pipeline_.Snapshot();
    next.native = source_.Status();
    std::lock_guard lock(snapshot_mutex_);
    snapshot_ = std::move(next);
}

CaptureWorkerSnapshot CaptureWorker::Snapshot() const {
    std::lock_guard lock(snapshot_mutex_);
    return snapshot_;
}

void CaptureWorker::RequestStop() {
    stop_requested_.store(true, std::memory_order_release);
    if (source_started_.load(std::memory_order_acquire)) source_.RequestStop();
}

CaptureWorkerResult CaptureWorker::Run() {
    if (run_entered_.exchange(true, std::memory_order_acq_rel)) {
        throw std::logic_error("capture worker can only run once");
    }

    CaptureWorkerResult result;
    const auto fail_without_source = [&](const CaptureFatalReason reason,
                                         std::string detail) {
        result.fatal_reason = reason;
        result.detail = std::move(detail);
        result.pipeline = pipeline_.Snapshot();
        UpdateSnapshot(CaptureWorkerState::Failed, reason, result.detail);
        return result;
    };

    const std::string validation = ValidateCaptureWorkerOptions(options_);
    if (!validation.empty()) {
        return fail_without_source(CaptureFatalReason::InvalidConfiguration,
                                   validation);
    }

    UpdateSnapshot(CaptureWorkerState::Starting, CaptureFatalReason::None,
                   "opening exact-address USBPcap capture");
    if (!source_.Start(options_.native)) {
        const auto status = source_.Status();
        const auto reason = FailureForNativeState(status) == CaptureFatalReason::None
            ? CaptureFatalReason::NativeOrDeviceLoss
            : FailureForNativeState(status);
        source_.Abort();
        return fail_without_source(reason,
            status.message.empty() ? "native USBPcap capture did not start"
                                   : status.message);
    }
    source_started_.store(true, std::memory_order_release);
    UpdateSnapshot(CaptureWorkerState::Running, CaptureFatalReason::None,
                   "capturing selected mouse in the background");

    CaptureFatalReason pending_reason = CaptureFatalReason::None;
    std::string pending_detail;
    bool stop_forwarded = false;
    auto next_flush = std::chrono::steady_clock::now() +
                      options_.durable_flush_interval;

    for (;;) {
        if (stop_requested_.load(std::memory_order_acquire) && !stop_forwarded) {
            source_.RequestStop();
            stop_forwarded = true;
            UpdateSnapshot(CaptureWorkerState::StopRequested,
                           CaptureFatalReason::None,
                           "stop requested; draining native capture");
        }

        std::vector<std::byte> chunk;
        const auto wait = TimeUntil(next_flush, options_.consumer_poll_interval);
        const bool received = source_.WaitTakeChunk(chunk, wait);
        if (received) {
            try {
                std::int64_t observed_qpc = 0;
                try {
                    observed_qpc = qpc_now_();
                } catch (...) {
                    // The pipeline records and normalizes an unavailable QPC;
                    // native timestamps and source bytes remain authoritative.
                }
                pipeline_.ProcessChunk(chunk, observed_qpc);
            } catch (const CapturePipelineError& error) {
                switch (error.Kind()) {
                case CapturePipelineFailureKind::PcapFraming:
                    pending_reason = CaptureFatalReason::PcapFraming;
                    break;
                case CapturePipelineFailureKind::DeviceIdentity:
                    pending_reason = CaptureFatalReason::DeviceIdentityChanged;
                    break;
                case CapturePipelineFailureKind::Writer:
                    pending_reason = CaptureFatalReason::WriterFailure;
                    break;
                }
                pending_detail = error.what();
                if (error.Kind() != CapturePipelineFailureKind::Writer) {
                    try {
                        // Preserve every complete exact-device record that preceded
                        // the destructive framing/identity boundary.
                        pipeline_.Checkpoint();
                    } catch (...) {
                    }
                }
                source_.Abort();
                source_started_.store(false, std::memory_order_release);
                result.fatal_reason = pending_reason;
                result.detail = pending_detail;
                result.pipeline = pipeline_.Snapshot();
                UpdateSnapshot(CaptureWorkerState::Failed, pending_reason,
                               pending_detail);
                return result;
            } catch (const std::exception& error) {
                source_.Abort();
                source_started_.store(false, std::memory_order_release);
                return fail_without_source(
                    CaptureFatalReason::WriterFailure,
                    std::string("capture pipeline failed: ") + error.what());
            }
        }

        if (std::chrono::steady_clock::now() >= next_flush) {
            try {
                pipeline_.Checkpoint();
            } catch (const std::exception& error) {
                source_.Abort();
                source_started_.store(false, std::memory_order_release);
                return fail_without_source(
                    CaptureFatalReason::WriterFailure, error.what());
            }
            next_flush = std::chrono::steady_clock::now() +
                         options_.durable_flush_interval;
        }

        const auto native_status = source_.Status();
        const auto native_failure = FailureForNativeState(native_status);
        if (native_failure != CaptureFatalReason::None &&
            pending_reason == CaptureFatalReason::None) {
            pending_reason = native_failure;
            pending_detail = native_status.message.empty()
                ? "native capture entered a fatal state"
                : native_status.message;
            source_.RequestStop();
            stop_forwarded = true;
        }

        if (!received && native_status.reader_finished) {
            if (!stop_forwarded && pending_reason == CaptureFatalReason::None) {
                pending_reason = CaptureFatalReason::NativeOrDeviceLoss;
                pending_detail = "native reader ended without a stop request";
            }
            break;
        }

        UpdateSnapshot(stop_forwarded ? CaptureWorkerState::Draining
                                      : CaptureWorkerState::Running,
                       pending_reason, pending_detail);
    }

    UpdateSnapshot(CaptureWorkerState::Draining, pending_reason,
                   pending_detail.empty() ? "sealing captured PCAP records"
                                          : pending_detail);
    try {
        pipeline_.Seal();
    } catch (const CapturePipelineError& error) {
        if (pending_reason == CaptureFatalReason::None) {
            pending_reason = error.Kind() == CapturePipelineFailureKind::Writer
                ? CaptureFatalReason::WriterFailure
                : CaptureFatalReason::PcapFraming;
            pending_detail = error.what();
        } else {
            pending_detail += "; ";
            pending_detail += error.what();
        }
    } catch (const std::exception& error) {
        if (pending_reason == CaptureFatalReason::None) {
            pending_reason = CaptureFatalReason::WriterFailure;
            pending_detail = error.what();
        }
    }

    result.native_stop = source_.StopAndDrain(
        options_.consumer_drain_timeout,
        [this] { return pipeline_.DrainEvidence(); });
    source_started_.store(false, std::memory_order_release);
    const auto final_native_status = source_.Status();
    if (!result.native_stop.clean && pending_reason == CaptureFatalReason::None) {
        pending_reason = FailureForStopReport(result.native_stop,
                                              final_native_status);
        pending_detail = result.native_stop.diagnostic.empty()
            ? "native capture did not drain cleanly"
            : result.native_stop.diagnostic;
    }

    if (pending_reason == CaptureFatalReason::None) {
        UpdateSnapshot(CaptureWorkerState::Publishing, CaptureFatalReason::None,
                       "publishing durable capture products");
        try {
            pipeline_.Publish();
        } catch (const std::exception& error) {
            pending_reason = CaptureFatalReason::WriterFailure;
            pending_detail = error.what();
        }
    }

    result.clean = pending_reason == CaptureFatalReason::None;
    result.fatal_reason = pending_reason;
    result.detail = result.clean
        ? "capture stopped, drained, and published cleanly"
        : pending_detail;
    result.pipeline = pipeline_.Snapshot();
    UpdateSnapshot(result.clean ? CaptureWorkerState::Completed
                                : CaptureWorkerState::Failed,
                   result.fatal_reason, result.detail);
    return result;
}

}  // namespace abdc::acquisition
