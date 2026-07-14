#include "TestHarness.h"

#include "acquisition/CertificationProbeClient.h"
#include "base/Json.h"
#include "capture/HidDescriptor.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace std::chrono_literals;
constexpr std::uintptr_t kProcess = 71U;
constexpr std::uint32_t kParentPid = 101U;
constexpr std::uint32_t kHelperPid = 202U;
constexpr std::string_view kCapability =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

std::vector<std::byte> Bytes(std::initializer_list<unsigned> values) {
    std::vector<std::byte> result;
    for (const auto value : values) {
        result.push_back(static_cast<std::byte>(value));
    }
    return result;
}

std::vector<std::byte> MouseDescriptor() {
    return Bytes({
        0x05,0x01,0x09,0x02,0xA1,0x01,0x09,0x01,0xA1,0x00,
        0x05,0x09,0x19,0x01,0x29,0x03,0x15,0x00,0x25,0x01,
        0x95,0x03,0x75,0x01,0x81,0x02,0x95,0x01,0x75,0x05,0x81,0x01,
        0x05,0x01,0x09,0x30,0x09,0x31,0x09,0x38,0x15,0x81,0x25,0x7F,
        0x75,0x08,0x95,0x03,0x81,0x06,0xC0,0xC0
    });
}

abdc::acquisition::CertificationProbeLaunchConfig ValidConfig() {
    abdc::acquisition::CertificationProbeLaunchConfig result;
    result.usbpcap_root_index = 1U;
    result.filtered_device_address = 7U;
    result.expected_packet_bus = 0U;
    auto descriptor = MouseDescriptor();
    const auto parsed = abdc::capture::HidDescriptor::Parse(descriptor);
    result.routes.push_back({"route-1", 0x81U, std::move(descriptor),
                             parsed.CanonicalDecoderSpec()});
    result.maximum_duration_ns = 8'000'000'000LL;
    result.graceful_shutdown_timeout = 100ms;
    return result;
}

abdc::acquisition::CertificationProbeTransportResult WireResult(
    const bool cancelled = false) {
    abdc::acquisition::CertificationProbeTransportResult result;
    result.cancelled = cancelled;
    result.probe.clean = true;
    result.probe.fatal_reason =
        abdc::acquisition::CertificationProbeFatalReason::None;
    result.probe.source_bytes = 1234U;
    result.probe.source_records = 4U;
    result.probe.candidate_records = 3U;
    result.probe.ignored_records = 1U;
    result.probe.native_stop.clean = true;
    result.probe.native_stop.filter_stop_attempted = true;
    result.probe.native_stop.filter_stop_succeeded = true;
    result.probe.native_stop.kernel_quiet_observed = true;
    result.probe.native_stop.quiet_completion_observed = true;
    result.probe.native_stop.consumer_queue_empty = true;
    result.probe.native_stop.semantic_guard_invoked = true;
    result.probe.native_stop.semantic_guard_passed = true;
    result.probe.native_stop.handle_closed = true;
    result.probe.native_stop.bytes_read = 1234U;
    result.probe.native_stop.bytes_delivered = 1234U;
    result.probe.native_stop.bytes_accounted = 1234U;
    result.probe.validated_identity =
        abdc::acquisition::ValidatedCertificationUsbIdentity{
            1U, 7U, 7U, 9U, 7U, false};
    abdc::device::CertificationProbeEvidence evidence;
    evidence.probe_route_token = "route-1";
    evidence.probe_duration_ns = 2'000'000'000LL;
    evidence.source_capture_intact = true;
    evidence.usb_totals.canonical_dx = 12;
    evidence.usb_totals.canonical_dy = -5;
    evidence.usb_totals.packet_count = 1U;
    evidence.usb_totals.absolute_motion_counts = 17U;
    evidence.usb_samples.push_back({10, 12, -5, true, false});
    evidence.positive_usb_transfer_intervals_ns.push_back(1'000'000LL);
    result.probe.evidence.push_back(std::move(evidence));
    result.probe.route_counters.emplace_back();
    result.probe.route_counters.front().decoded_reports = 1U;
    return result;
}

[[nodiscard]] std::string JsonLine(const abdc::json::Value& value) {
    return abdc::json::DumpCanonical(value, false) + "\n";
}

class FakePlatform final : public abdc::acquisition::ICaptureHelperPlatform {
public:
    std::uint32_t CurrentProcessId() const override { return kParentPid; }
    std::filesystem::path SiblingExecutable(std::wstring_view filename)
        const override {
        sibling_name = std::wstring(filename);
        return helper;
    }
    std::filesystem::path DefaultControlRoot() const override { return root; }
    bool IsDirectory(const std::filesystem::path& path) const override {
        return directories.contains(path);
    }
    bool IsRegularFile(const std::filesystem::path& path) const override {
        return path == helper;
    }
    std::filesystem::path CreatePrivateControlDirectory(
        const std::filesystem::path& requested) override {
        EXPECT_EQ(requested, root);
        directories.insert(directory);
        return directory;
    }
    void WriteNewPrivateFile(const std::filesystem::path& path,
                             std::span<const std::byte> bytes) override {
        config_bytes.assign(bytes.begin(), bytes.end());
        files[path] = std::string(reinterpret_cast<const char*>(bytes.data()),
                                  bytes.size());
    }
    abdc::acquisition::ElevatedLaunchResult LaunchElevated(
        const std::filesystem::path& executable,
        std::wstring_view parameters) override {
        ++launches;
        launched_executable = executable;
        launched_parameters = parameters;
        return launch_result;
    }
    abdc::acquisition::CaptureHelperProcessPoll WaitProcess(
        std::uintptr_t process, std::chrono::milliseconds timeout) override {
        EXPECT_EQ(process, kProcess);
        waits.push_back(timeout);
        return running
            ? abdc::acquisition::CaptureHelperProcessPoll{
                  abdc::acquisition::CaptureHelperProcessState::Running,
                  std::nullopt}
            : abdc::acquisition::CaptureHelperProcessPoll{
                  abdc::acquisition::CaptureHelperProcessState::Exited,
                  exit_code};
    }
    bool TerminateProcess(std::uintptr_t process, std::uint32_t code) override {
        EXPECT_EQ(process, kProcess);
        ++terminations;
        running = false;
        exit_code = code;
        return true;
    }
    void CloseProcess(std::uintptr_t process) noexcept override {
        if (process == kProcess) ++closes;
    }
    bool FileExists(const std::filesystem::path& path) const override {
        return files.contains(path);
    }
    std::string ReadSmallFile(const std::filesystem::path& path,
                              std::uint64_t maximum_bytes) const override {
        const auto found = files.find(path);
        if (found == files.end() || found->second.size() > maximum_bytes) {
            throw std::runtime_error("fake file unavailable");
        }
        return found->second;
    }
    void AtomicWriteFile(const std::filesystem::path& path,
                         std::string_view contents) override {
        ++atomic_writes;
        files[path] = std::string(contents);
    }
    void RemoveOwnedFile(const std::filesystem::path& path) noexcept override {
        removed.insert(path);
        files.erase(path);
    }
    void RemoveOwnedDirectoryIfEmpty(
        const std::filesystem::path& path) noexcept override {
        directories.erase(path);
        removed_directories.insert(path);
    }

    void PublishReady() {
        abdc::json::Value value(abdc::json::Value::Object{});
        value["schema"] = "abcurves.certification.ready.v1";
        value["state"] = "ready";
        value["capability"] = std::string(kCapability);
        value["helper_pid"] = static_cast<std::int64_t>(kHelperPid);
        value["parent_pid"] = static_cast<std::int64_t>(kParentPid);
        value["cancel_schema"] = "abcurves.certification.cancel.v1";
        files[directory / L"ready.json"] = JsonLine(value);
    }

    void PublishResult(const bool cancelled = false) {
        files[directory / L"result.json"] =
            abdc::acquisition::SerializeCertificationProbeResultEnvelope(
                WireResult(cancelled), kCapability, kHelperPid, kParentPid);
    }

    std::filesystem::path helper = LR"(C:\ABCT\abct_probe_helper.exe)";
    std::filesystem::path root = LR"(C:\private)";
    std::filesystem::path directory = LR"(C:\private\probe-fixed)";
    mutable std::wstring sibling_name;
    mutable std::set<std::filesystem::path> directories{root};
    std::map<std::filesystem::path, std::string> files;
    std::vector<std::byte> config_bytes;
    abdc::acquisition::ElevatedLaunchResult launch_result{
        abdc::acquisition::ElevatedLaunchDisposition::Started,
        kProcess, kHelperPid, 0U};
    bool running = true;
    std::uint32_t exit_code = 0U;
    int launches = 0;
    int atomic_writes = 0;
    int terminations = 0;
    int closes = 0;
    std::filesystem::path launched_executable;
    std::wstring launched_parameters;
    std::vector<std::chrono::milliseconds> waits;
    std::set<std::filesystem::path> removed;
    std::set<std::filesystem::path> removed_directories;
};

}  // namespace

TEST_CASE("certification probe private config reconstructs exact decoders") {
    const auto config = ValidConfig();
    const auto bytes =
        abdc::acquisition::SerializeCertificationProbeHelperConfig(config);
    const auto parsed =
        abdc::acquisition::ParseCertificationProbeHelperConfig(bytes);
    EXPECT_EQ(parsed.options.native.root_index, 1U);
    EXPECT_EQ(parsed.options.native.device_address, 7U);
    EXPECT_EQ(parsed.options.selected_bus, 0U);
    EXPECT_EQ(parsed.options.selected_device, 7U);
    EXPECT_EQ(parsed.options.qpc_frequency, 0LL);
    EXPECT_EQ(parsed.routes.size(), std::size_t{1});
    EXPECT_EQ(parsed.routes.front().probe_route_token, std::string("route-1"));
    EXPECT_EQ(parsed.routes.front().endpoint_address, 0x81U);
    EXPECT_TRUE(parsed.routes.front().decoder.has_value());
    EXPECT_TRUE(!parsed.routes.front().decoder->Layouts().empty());
}

TEST_CASE("certification result protocol retains observed packet bus without payload") {
    const auto encoded =
        abdc::acquisition::SerializeCertificationProbeResultEnvelope(
            WireResult(), kCapability, kHelperPid, kParentPid);
    EXPECT_TRUE(encoded.find("packet_bus") != std::string::npos);
    EXPECT_TRUE(encoded.find("descriptor_hex") == std::string::npos);
    EXPECT_TRUE(encoded.find("payload_hex") == std::string::npos);
    const auto decoded =
        abdc::acquisition::ParseCertificationProbeResultEnvelope(
            encoded, kCapability, kHelperPid, kParentPid);
    EXPECT_TRUE(decoded.probe.clean);
    EXPECT_TRUE(decoded.probe.validated_identity.has_value());
    EXPECT_EQ(decoded.probe.validated_identity->usbpcap_root_index, 1U);
    EXPECT_EQ(decoded.probe.validated_identity->packet_bus, 9U);
    EXPECT_EQ(decoded.probe.evidence.front().usb_samples.front().canonical_dx, 12);
}

TEST_CASE("certification result protocol distinguishes a topology hint from a discovered address") {
    auto result = WireResult();
    result.probe.validated_identity =
        abdc::acquisition::ValidatedCertificationUsbIdentity{
            1U, 7U, 0U, 9U, 8U, true};
    result.probe.evidence.front().observed_packet_bus = 9U;
    result.probe.evidence.front().observed_device_address = 8U;
    result.probe.evidence.front().device_address_discovered_from_root = true;
    result.probe.evidence.front().device_wide_activity = true;
    const auto encoded =
        abdc::acquisition::SerializeCertificationProbeResultEnvelope(
            result, kCapability, kHelperPid, kParentPid);
    const auto decoded =
        abdc::acquisition::ParseCertificationProbeResultEnvelope(
            encoded, kCapability, kHelperPid, kParentPid);
    EXPECT_TRUE(decoded.probe.validated_identity->whole_root_capture);
    EXPECT_EQ(decoded.probe.validated_identity->topology_device_address, 7U);
    EXPECT_EQ(decoded.probe.validated_identity->filtered_device_address, 0U);
    EXPECT_EQ(decoded.probe.validated_identity->packet_device, 8U);
    EXPECT_TRUE(decoded.probe.evidence.front().device_wide_activity);
}

TEST_CASE("certification private config supports a device-wide raw-only route") {
    abdc::acquisition::CertificationProbeLaunchConfig config;
    config.usbpcap_root_index = 1U;
    config.filtered_device_address = 7U;
    abdc::acquisition::CertificationProbeLaunchRoute route;
    route.probe_route_token = "raw-only-route";
    route.endpoint_address = 0U;
    config.routes.push_back(std::move(route));
    const auto bytes =
        abdc::acquisition::SerializeCertificationProbeHelperConfig(config);
    const auto parsed =
        abdc::acquisition::ParseCertificationProbeHelperConfig(bytes);
    EXPECT_EQ(parsed.routes.size(), 1U);
    EXPECT_EQ(parsed.routes.front().endpoint_address, 0U);
    EXPECT_TRUE(!parsed.routes.front().decoder.has_value());
}

TEST_CASE("certification private config keeps topology address as a whole-root ranking hint") {
    auto config = ValidConfig();
    config.discover_device_address = true;
    const auto bytes =
        abdc::acquisition::SerializeCertificationProbeHelperConfig(config);
    const auto parsed =
        abdc::acquisition::ParseCertificationProbeHelperConfig(bytes);
    EXPECT_TRUE(parsed.options.native.capture_all_devices);
    EXPECT_EQ(parsed.options.native.device_address, 0U);
    EXPECT_EQ(parsed.options.native.snapshot_length, 4U * 1024U);
    EXPECT_EQ(parsed.options.selected_device, 7U);
}

TEST_CASE("certification helper command exposes only private controls and parent tether") {
    abdc::acquisition::CertificationProbeControlPaths controls;
    controls.directory = LR"(C:\private controls\probe)";
    controls.config = controls.directory / L"probe config.json";
    controls.ready = controls.directory / L"ready.json";
    controls.result = controls.directory / L"result.json";
    controls.cancel = controls.directory / L"cancel.json";
    controls.error = controls.directory / L"error.json";
    const auto command = abdc::acquisition::BuildCertificationProbeCommand(
        controls, LR"(C:\ABCT\abct_probe_helper.exe)", kParentPid,
        kCapability);
    EXPECT_EQ(command.arguments.front(),
              std::wstring(L"--certification-probe"));
    EXPECT_TRUE(command.parameter_line.find(L"--config") != std::wstring::npos);
    EXPECT_TRUE(command.parameter_line.find(L"--parent-pid 101") !=
                std::wstring::npos);
    EXPECT_TRUE(command.parameter_line.find(L"--root") == std::wstring::npos);
    EXPECT_TRUE(command.parameter_line.find(L"route-1") == std::wstring::npos);
}

TEST_CASE("certification client starts asynchronously and accepts authenticated result") {
    auto platform = std::make_shared<FakePlatform>();
    abdc::acquisition::CertificationProbeClient client(platform);
    const auto started = client.Start(ValidConfig());
    EXPECT_TRUE(started.started);
    EXPECT_EQ(platform->launches, 1);
    EXPECT_TRUE(platform->waits.empty());
    EXPECT_EQ(platform->sibling_name, std::wstring(L"abct_probe_helper.exe"));
    EXPECT_TRUE(!platform->config_bytes.empty());

    auto snapshot = client.Snapshot();
    EXPECT_EQ(snapshot.state,
              abdc::acquisition::CertificationProbeClientState::Starting);
    EXPECT_EQ(platform->waits.back(), 0ms);
    platform->PublishReady();
    snapshot = client.Snapshot();
    EXPECT_EQ(snapshot.state,
              abdc::acquisition::CertificationProbeClientState::Running);
    EXPECT_TRUE(snapshot.ready.has_value());

    platform->PublishResult();
    platform->running = false;
    snapshot = client.Snapshot();
    EXPECT_EQ(snapshot.state,
              abdc::acquisition::CertificationProbeClientState::Completed);
    EXPECT_TRUE(snapshot.result.has_value());
    EXPECT_EQ(snapshot.result->probe.validated_identity->packet_bus, 9U);
    EXPECT_EQ(platform->closes, 1);
    EXPECT_TRUE(platform->removed_directories.contains(platform->directory));
}

TEST_CASE("certification client queues cancel before ready and never relaunches UAC") {
    auto platform = std::make_shared<FakePlatform>();
    abdc::acquisition::CertificationProbeClient client(platform);
    EXPECT_TRUE(client.Start(ValidConfig()).started);
    EXPECT_TRUE(client.RequestCancel());
    EXPECT_EQ(platform->atomic_writes, 0);
    platform->PublishReady();
    auto snapshot = client.Snapshot();
    EXPECT_EQ(snapshot.state,
              abdc::acquisition::CertificationProbeClientState::CancelRequested);
    EXPECT_EQ(platform->atomic_writes, 1);
    const auto cancel = abdc::json::Parse(
        platform->files[platform->directory / L"cancel.json"]);
    EXPECT_EQ(cancel.At("capability").AsString(), std::string(kCapability));
    platform->PublishResult(true);
    platform->running = false;
    snapshot = client.Snapshot();
    EXPECT_EQ(snapshot.state,
              abdc::acquisition::CertificationProbeClientState::Cancelled);
    EXPECT_TRUE(!client.Start(ValidConfig()).started);
    EXPECT_EQ(platform->launches, 1);
}

TEST_CASE("certification client reports UAC denial once") {
    auto platform = std::make_shared<FakePlatform>();
    platform->launch_result = {
        abdc::acquisition::ElevatedLaunchDisposition::UacDenied, 0U, 0U, 1223U};
    abdc::acquisition::CertificationProbeClient client(platform);
    const auto first = client.Start(ValidConfig());
    EXPECT_TRUE(!first.started);
    EXPECT_EQ(first.failure,
              abdc::acquisition::CertificationProbeStartFailure::UacDenied);
    EXPECT_TRUE(!client.Start(ValidConfig()).started);
    EXPECT_EQ(platform->launches, 1);
}
