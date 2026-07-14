#include "TestHarness.h"

#include "acquisition/CaptureHelperClient.h"
#include "base/Json.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace {

using namespace std::chrono_literals;
using abdc::acquisition::CaptureHelperProcessPoll;
using abdc::acquisition::CaptureHelperProcessState;
using abdc::acquisition::ElevatedLaunchDisposition;
using abdc::acquisition::ElevatedLaunchResult;

constexpr std::uintptr_t kProcess = 77;
constexpr std::uint32_t kHelperPid = 222;
constexpr std::uint32_t kParentPid = 111;
constexpr std::string_view kCapability =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

[[nodiscard]] std::string JsonLine(const abdc::json::Value& value) {
    return abdc::json::DumpCanonical(value, false) + "\n";
}

class FakePlatform final : public abdc::acquisition::ICaptureHelperPlatform {
public:
    std::uint32_t CurrentProcessId() const override { return kParentPid; }

    std::filesystem::path SiblingExecutable(
        std::wstring_view filename) const override {
        sibling_lookups.emplace_back(filename);
        return helper;
    }

    std::filesystem::path DefaultControlRoot() const override {
        return control_root;
    }

    bool IsDirectory(const std::filesystem::path& path) const override {
        return directories.contains(path);
    }

    bool IsRegularFile(const std::filesystem::path& path) const override {
        return path == helper || path == session_lease;
    }

    std::filesystem::path CreatePrivateControlDirectory(
        const std::filesystem::path& root) override {
        ++private_directory_creates;
        EXPECT_EQ(root, control_root);
        directories.insert(control_directory);
        return control_directory;
    }

    void WriteNewPrivateFile(const std::filesystem::path& path,
                             std::span<const std::byte> bytes) override {
        EXPECT_TRUE(!files.contains(path));
        descriptor_size = bytes.size();
        files[path] = std::string(bytes.size(), 'd');
    }

    ElevatedLaunchResult LaunchElevated(
        const std::filesystem::path& executable,
        std::wstring_view parameter_line) override {
        ++launches;
        launched_executable = executable;
        launched_parameters = parameter_line;
        if (on_launch) on_launch();
        return launch_result;
    }

    CaptureHelperProcessPoll WaitProcess(
        std::uintptr_t process, std::chrono::milliseconds timeout) override {
        EXPECT_EQ(process, kProcess);
        ++waits;
        wait_durations.push_back(timeout);
        if (on_wait) on_wait(timeout);
        if (!running) {
            return {CaptureHelperProcessState::Exited, process_exit_code};
        }
        return {CaptureHelperProcessState::Running, std::nullopt};
    }

    bool TerminateProcess(std::uintptr_t process,
                          std::uint32_t exit_code) override {
        EXPECT_EQ(process, kProcess);
        ++terminations;
        terminated_with = exit_code;
        running = false;
        process_exit_code = exit_code;
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
        last_atomic_path = path;
        last_atomic_contents = std::string(contents);
        files[path] = std::string(contents);
    }

    void RemoveOwnedFile(const std::filesystem::path& path) noexcept override {
        removed_files.insert(path);
        files.erase(path);
    }

    void RemoveOwnedDirectoryIfEmpty(
        const std::filesystem::path& path) noexcept override {
        removed_directories.insert(path);
        directories.erase(path);
    }

    void PublishReady() {
        abdc::json::Value value(abdc::json::Value::Object{});
        value["schema"] = "abcurves.capture.ready.v1";
        value["state"] = "ready";
        value["capability"] = std::string(kCapability);
        value["helper_pid"] = static_cast<std::int64_t>(kHelperPid);
        value["parent_pid"] = static_cast<std::int64_t>(kParentPid);
        value["output_directory"] = "C:\\session output\\capture";
        value["stop_schema"] = "abcurves.capture.stop.v1";
        files[control_directory / L"ready.json"] = JsonLine(value);
    }

    void PublishHealth() {
        abdc::json::Value value(abdc::json::Value::Object{});
        value["schema"] = "abcurves.capture.health.v1";
        value["state"] = "running";
        value["fatal_reason"] = "none";
        value["detail"] = "capturing";
        value["stop_origin"] = "";
        value["source_bytes"] = 1200;
        value["source_records"] = 42;
        value["endpoint_records"] = 40;
        value["decoded_reports"] = 39;
        value["anomalies"] = 1;
        value["native_bytes_read"] = 1300;
        value["native_queued_bytes"] = 0;
        files[control_directory / L"health.json"] = JsonLine(value);
    }

    void PublishError(std::string reason, std::string detail) {
        abdc::json::Value value(abdc::json::Value::Object{});
        value["schema"] = "abcurves.capture.error.v1";
        value["state"] = "error";
        value["fatal_reason"] = std::move(reason);
        value["detail"] = std::move(detail);
        files[control_directory / L"error.json"] = JsonLine(value);
    }

    std::filesystem::path helper =
        LR"(C:\Program Files\ABCT\abct_capture_helper.exe)";
    std::filesystem::path control_root = LR"(C:\private root)";
    std::filesystem::path control_directory =
        LR"(C:\private root\capture-fixed)";
    std::filesystem::path session_lease =
        LR"(C:\session output\.leases\session_test.lock)";
    std::set<std::filesystem::path> directories{
        std::filesystem::path(LR"(C:\session output\capture)"), control_root};
    std::map<std::filesystem::path, std::string> files;
    mutable std::vector<std::wstring> sibling_lookups;
    ElevatedLaunchResult launch_result{
        ElevatedLaunchDisposition::Started, kProcess, kHelperPid, 0};
    bool running = true;
    std::uint32_t process_exit_code = 0;
    std::function<void()> on_launch;
    std::function<void(std::chrono::milliseconds)> on_wait;
    std::filesystem::path launched_executable;
    std::wstring launched_parameters;
    std::filesystem::path last_atomic_path;
    std::string last_atomic_contents;
    std::vector<std::chrono::milliseconds> wait_durations;
    std::set<std::filesystem::path> removed_files;
    std::set<std::filesystem::path> removed_directories;
    std::size_t descriptor_size = 0;
    std::uint32_t terminated_with = 0;
    int private_directory_creates = 0;
    int launches = 0;
    int waits = 0;
    int terminations = 0;
    int closes = 0;
    int atomic_writes = 0;
};

[[nodiscard]] abdc::acquisition::CaptureHelperLaunchConfig ValidConfig() {
    abdc::acquisition::CaptureHelperLaunchConfig config;
    config.usb = {3, 7, 2, 0x81};
    config.descriptor_evidence = {
        std::byte{0x05}, std::byte{0x01}, std::byte{0x09}, std::byte{0x02}};
    config.output_directory = LR"(C:\session output\capture)";
    config.session_lease = LR"(C:\session output\.leases\session_test.lock)";
    config.readiness_timeout = 200ms;
    config.graceful_shutdown_timeout = 150ms;
    return config;
}

[[nodiscard]] std::shared_ptr<FakePlatform> ReadyPlatform() {
    auto platform = std::make_shared<FakePlatform>();
    bool published = false;
    platform->on_wait = [platform, published](std::chrono::milliseconds timeout) mutable {
        if (timeout > 0ms && !published) {
            platform->PublishReady();
            published = true;
        }
    };
    return platform;
}

}  // namespace

TEST_CASE("capture helper command exactly carries certified endpoint and controls") {
    auto config = ValidConfig();
    config.helper_executable =
        LR"(C:\Program Files\ABCT\abct_capture_helper.exe)";
    abdc::acquisition::CaptureHelperControlPaths controls;
    controls.directory = LR"(C:\private controls\fresh)";
    controls.descriptor = controls.directory / L"descriptor evidence.bin";
    controls.ready = controls.directory / L"ready.json";
    controls.health = controls.directory / L"health.json";
    controls.stop = controls.directory / L"stop.json";
    controls.error = controls.directory / L"error.json";

    const auto command = abdc::acquisition::BuildCaptureHelperCommand(
        config, controls, config.helper_executable, kParentPid);
    EXPECT_EQ(command.arguments.size(), std::size_t{27});
    EXPECT_EQ(command.arguments[0], std::wstring(L"--capture"));
    EXPECT_EQ(command.arguments[2], std::wstring(L"3"));
    EXPECT_EQ(command.arguments[4], std::wstring(L"7"));
    EXPECT_EQ(command.arguments[6], std::wstring(L"2"));
    EXPECT_EQ(command.arguments[8], std::wstring(L"129"));
    EXPECT_EQ(command.arguments[10], controls.descriptor.wstring());
    EXPECT_EQ(command.arguments[12], config.output_directory.wstring());
    EXPECT_EQ(command.arguments[14], config.session_lease.wstring());
    EXPECT_EQ(command.arguments[16], std::wstring(L"111"));
    EXPECT_EQ(command.arguments[18], controls.ready.wstring());
    EXPECT_EQ(command.arguments[20], controls.health.wstring());
    EXPECT_EQ(command.arguments[22], controls.stop.wstring());
    EXPECT_EQ(command.arguments[24], controls.error.wstring());
    EXPECT_EQ(command.arguments[26], std::wstring(L"2000"));
    EXPECT_TRUE(command.parameter_line.find(
        L"--descriptor \"C:\\private controls\\fresh\\descriptor evidence.bin\"") !=
        std::wstring::npos);
    EXPECT_TRUE(command.parameter_line.find(
        L"--lease \"C:\\session output\\.leases\\session_test.lock\"") !=
        std::wstring::npos);
}

TEST_CASE("capture helper client requires an existing session writer lease") {
    auto platform = std::make_shared<FakePlatform>();
    auto config = ValidConfig();
    config.session_lease = LR"(C:\missing\session.lock)";
    abdc::acquisition::CaptureHelperClient client(platform);
    const auto result = client.Start(config);
    EXPECT_TRUE(!result.started);
    EXPECT_EQ(result.failure,
              abdc::acquisition::CaptureHelperStartFailure::InvalidConfiguration);
    EXPECT_EQ(result.message,
              std::string("The session writer lease is unavailable."));
    EXPECT_EQ(platform->launches, 0);
}

TEST_CASE("capture helper argument quoting preserves trailing slashes and quotes") {
    EXPECT_EQ(abdc::acquisition::QuoteCaptureHelperArgument(
                  LR"(C:\path with space\)"),
              std::wstring(L"\"C:\\path with space\\\\\""));
    EXPECT_EQ(abdc::acquisition::QuoteCaptureHelperArgument(L"a\"b"),
              std::wstring(L"\"a\\\"b\""));
}

TEST_CASE("capture helper client reads ready and nonblocking health then stops cleanly") {
    auto platform = ReadyPlatform();
    abdc::acquisition::CaptureHelperClient client(platform);
    const auto started = client.Start(ValidConfig());
    EXPECT_TRUE(started.started);
    EXPECT_EQ(platform->launches, 1);
    EXPECT_EQ(platform->descriptor_size, std::size_t{4});
    EXPECT_EQ(platform->launched_executable, platform->helper);
    EXPECT_EQ(platform->sibling_lookups.size(), std::size_t{1});
    EXPECT_EQ(platform->sibling_lookups.front(),
              std::wstring(L"abct_capture_helper.exe"));

    platform->PublishHealth();
    const auto snapshot = client.Snapshot();
    EXPECT_EQ(snapshot.state,
              abdc::acquisition::CaptureHelperClientState::Running);
    EXPECT_TRUE(snapshot.ready.has_value());
    EXPECT_EQ(snapshot.ready->capability, std::string(kCapability));
    EXPECT_TRUE(snapshot.health.has_value());
    EXPECT_EQ(snapshot.health->source_records, std::uint64_t{42});
    EXPECT_EQ(snapshot.health->decoded_reports, std::uint64_t{39});

    EXPECT_TRUE(client.RequestStop());
    EXPECT_EQ(platform->atomic_writes, 1);
    EXPECT_EQ(platform->last_atomic_path,
              platform->control_directory / L"stop.json");
    const auto stop = abdc::json::Parse(platform->last_atomic_contents);
    EXPECT_EQ(stop.At("schema").AsString(),
              std::string("abcurves.capture.stop.v1"));
    EXPECT_EQ(stop.At("capability").AsString(), std::string(kCapability));

    platform->running = false;
    platform->process_exit_code = 0;
    const auto stopped = client.StopAndWait();
    EXPECT_TRUE(stopped.stopped);
    EXPECT_TRUE(!stopped.forced);
    EXPECT_EQ(platform->terminations, 0);
    EXPECT_EQ(platform->closes, 1);
    EXPECT_TRUE(platform->removed_directories.contains(
        platform->control_directory));
}

TEST_CASE("capture helper drops unusable optional decoder evidence") {
    auto platform = ReadyPlatform();
    auto config = ValidConfig();
    config.usb.endpoint = 0U;
    abdc::acquisition::CaptureHelperClient client(platform);
    const auto started = client.Start(config);
    EXPECT_TRUE(started.started);
    EXPECT_EQ(platform->descriptor_size, std::size_t{0});

    platform->running = false;
    platform->process_exit_code = 0;
    EXPECT_TRUE(client.StopAndWait().stopped);
}

TEST_CASE("capture helper UAC denial is concise and never retried") {
    auto platform = std::make_shared<FakePlatform>();
    platform->launch_result = {
        ElevatedLaunchDisposition::UacDenied, 0, 0, 1223};
    abdc::acquisition::CaptureHelperClient client(platform);
    const auto first = client.Start(ValidConfig());
    EXPECT_TRUE(!first.started);
    EXPECT_EQ(first.failure,
              abdc::acquisition::CaptureHelperStartFailure::UacDenied);
    EXPECT_EQ(first.message,
              std::string("Mouse capture needs administrator approval."));
    const auto second = client.Start(ValidConfig());
    EXPECT_TRUE(!second.started);
    EXPECT_EQ(platform->launches, 1);
    EXPECT_TRUE(platform->removed_directories.contains(
        platform->control_directory));
}

TEST_CASE("capture helper early fatal exit preserves parsed error meaning") {
    auto platform = std::make_shared<FakePlatform>();
    platform->on_launch = [platform] {
        platform->PublishError("native_or_device_loss", "pipe closed");
    };
    platform->on_wait = [platform](std::chrono::milliseconds timeout) {
        if (timeout > 0ms) {
            platform->running = false;
            platform->process_exit_code = 4;
        }
    };
    abdc::acquisition::CaptureHelperClient client(platform);
    const auto result = client.Start(ValidConfig());
    EXPECT_TRUE(!result.started);
    EXPECT_EQ(result.failure,
              abdc::acquisition::CaptureHelperStartFailure::EarlyExit);
    EXPECT_EQ(result.message,
              std::string("The USB capture connection was lost."));
    const auto snapshot = client.Snapshot();
    EXPECT_TRUE(snapshot.error.has_value());
    EXPECT_EQ(snapshot.error->detail, std::string("pipe closed"));
    EXPECT_EQ(platform->terminations, 0);
}

TEST_CASE("capture helper readiness timeout terminates once without relaunch") {
    auto platform = std::make_shared<FakePlatform>();
    auto config = ValidConfig();
    config.readiness_timeout = 120ms;
    abdc::acquisition::CaptureHelperClient client(platform);
    const auto result = client.Start(config);
    EXPECT_TRUE(!result.started);
    EXPECT_EQ(result.failure,
              abdc::acquisition::CaptureHelperStartFailure::ReadyTimeout);
    EXPECT_EQ(platform->launches, 1);
    EXPECT_EQ(platform->terminations, 1);
    EXPECT_EQ(platform->closes, 1);
    EXPECT_TRUE(platform->removed_directories.contains(
        platform->control_directory));
}

TEST_CASE("capture helper graceful timeout uses one destructive fallback") {
    auto platform = ReadyPlatform();
    auto config = ValidConfig();
    config.graceful_shutdown_timeout = 100ms;
    abdc::acquisition::CaptureHelperClient client(platform);
    EXPECT_TRUE(client.Start(config).started);
    const auto result = client.StopAndWait();
    EXPECT_TRUE(result.stopped);
    EXPECT_TRUE(result.forced);
    EXPECT_EQ(platform->atomic_writes, 1);
    EXPECT_EQ(platform->terminations, 1);
    EXPECT_EQ(platform->closes, 1);
}

TEST_CASE("capture helper rejects a forged ready capability") {
    auto platform = std::make_shared<FakePlatform>();
    platform->on_wait = [platform](std::chrono::milliseconds timeout) {
        if (timeout <= 0ms) return;
        platform->PublishReady();
        auto& ready = platform->files[platform->control_directory / L"ready.json"];
        const auto offset = ready.find(std::string(kCapability));
        ready.replace(offset, kCapability.size(), "not-a-capability");
    };
    abdc::acquisition::CaptureHelperClient client(platform);
    const auto result = client.Start(ValidConfig());
    EXPECT_TRUE(!result.started);
    EXPECT_EQ(result.failure,
              abdc::acquisition::CaptureHelperStartFailure::InvalidStatus);
    EXPECT_EQ(platform->terminations, 1);
    EXPECT_EQ(platform->launches, 1);
}

TEST_CASE("capture helper tolerates an in-progress one-shot ready publication") {
    auto platform = std::make_shared<FakePlatform>();
    int positive_waits = 0;
    platform->on_wait = [platform, positive_waits](
                            std::chrono::milliseconds timeout) mutable {
        if (timeout <= 0ms) return;
        ++positive_waits;
        if (positive_waits == 1) {
            platform->files[platform->control_directory / L"ready.json"] = "{";
        } else {
            platform->PublishReady();
        }
    };
    abdc::acquisition::CaptureHelperClient client(platform);
    const auto result = client.Start(ValidConfig());
    EXPECT_TRUE(result.started);
    EXPECT_EQ(platform->terminations, 0);
    platform->running = false;
    platform->process_exit_code = 0;
    EXPECT_TRUE(client.StopAndWait().stopped);
}
