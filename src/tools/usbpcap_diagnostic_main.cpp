#include "app/ParticipantInventory.h"
#include "base/BuildInfo.h"
#include "capture/StreamingPcapParser.h"
#include "capture/UsbPcapPacket.h"
#include "windows_capture/NativeUsbPcap.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace {

using namespace std::chrono_literals;

constexpr auto kCaptureDuration = 8s;

struct EndpointKey {
    std::uint16_t bus = 0;
    std::uint16_t device = 0;
    std::uint8_t endpoint = 0;

    [[nodiscard]] bool operator<(const EndpointKey& other) const noexcept {
        return std::tie(bus, device, endpoint) <
               std::tie(other.bus, other.device, other.endpoint);
    }
};

struct EndpointStats {
    std::uint64_t interrupt_in_records = 0;
    std::uint64_t completions = 0;
    std::uint64_t successful_nonempty_completions = 0;
    std::uint64_t payload_change_events = 0;
    std::uint64_t failed_completions = 0;
    std::uint64_t payload_bytes = 0;
    std::uint64_t truncated_payloads = 0;
    std::vector<std::byte> last_successful_payload;
};

struct CaptureSummary {
    bool started = false;
    bool parser_clean = false;
    std::uint64_t source_bytes = 0;
    std::uint64_t source_records = 0;
    std::uint64_t packet_parse_errors = 0;
    std::map<EndpointKey, EndpointStats> endpoints;
    abdc::windows_capture::NativeUsbPcapStatus native_status;
    abdc::windows_capture::NativeUsbPcapStopReport stop;
};

class Report final {
public:
    explicit Report(std::filesystem::path path)
        : path_(std::move(path)) {
        file_.open(path_, std::ios::binary | std::ios::trunc);
        if (!file_) {
            file_.clear();
            path_ = std::filesystem::temp_directory_path() /
                "ABCurves USBPcap Diagnostic Report.txt";
            file_.open(path_, std::ios::binary | std::ios::trunc);
        }
    }

    [[nodiscard]] bool Ready() const { return file_.is_open(); }
    [[nodiscard]] const std::filesystem::path& Path() const { return path_; }

    void Line(const std::string_view text = {}) {
        std::cout << text << '\n';
        if (file_) {
            file_ << text << '\n';
            file_.flush();
        }
    }

private:
    std::filesystem::path path_;
    std::ofstream file_;
};

[[nodiscard]] std::array<std::byte, 32> FreshSalt() {
    std::array<std::byte, 32> salt{};
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(salt.data()),
                        static_cast<ULONG>(salt.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("Windows random generation failed");
    }
    return salt;
}

[[nodiscard]] std::filesystem::path ExecutableDirectory() {
    std::wstring buffer(32'768U, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0U || length >= buffer.size()) {
        return std::filesystem::temp_directory_path();
    }
    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path();
}

[[nodiscard]] std::string Hex4(const std::uint16_t value) {
    std::ostringstream stream;
    stream << std::uppercase << std::hex << std::setfill('0')
           << std::setw(4) << value;
    return stream.str();
}

[[nodiscard]] std::string EndpointText(const std::uint8_t endpoint) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << std::setfill('0')
           << std::setw(2) << static_cast<unsigned>(endpoint);
    return stream.str();
}

void Countdown(Report& report) {
    report.Line("Get ready to move the selected mouse continuously and click several times.");
    for (int second = 3; second > 0; --second) {
        report.Line("Starting in " + std::to_string(second) + "...");
        std::this_thread::sleep_for(1s);
    }
    report.Line("MOVE AND CLICK NOW.");
}

void ProcessChunk(CaptureSummary& summary,
                  abdc::capture::StreamingPcapParser& parser,
                  const std::span<const std::byte> chunk) {
    summary.source_bytes += chunk.size();
    parser.Append(chunk);
    auto records = parser.TakeRecords();
    summary.source_records += records.size();
    for (const auto& record : records) {
        abdc::capture::UsbPcapPacket packet;
        try {
            packet = abdc::capture::UsbPcapPacket::Parse(
                record.data, record.original_length);
        } catch (const std::exception&) {
            ++summary.packet_parse_errors;
            continue;
        }
        if (packet.transfer != abdc::capture::UsbTransfer::Interrupt ||
            !packet.IsInEndpoint()) {
            continue;
        }
        auto& stats = summary.endpoints[
            {packet.bus, packet.device, packet.endpoint}];
        ++stats.interrupt_in_records;
        if (!packet.IsCompletion()) continue;
        ++stats.completions;
        if (packet.status != 0U) {
            ++stats.failed_completions;
            continue;
        }
        if (packet.payload.empty()) continue;
        ++stats.successful_nonempty_completions;
        stats.payload_bytes += packet.payload.size();
        if (packet.payload_truncated) ++stats.truncated_payloads;
        if (!stats.last_successful_payload.empty() &&
            (stats.last_successful_payload.size() != packet.payload.size() ||
             !std::equal(stats.last_successful_payload.begin(),
                         stats.last_successful_payload.end(),
                         packet.payload.begin()))) {
            ++stats.payload_change_events;
        }
        stats.last_successful_payload.assign(packet.payload.begin(),
                                             packet.payload.end());
    }
}

[[nodiscard]] CaptureSummary RunCapture(const std::uint16_t root,
                                        const std::uint8_t address,
                                        const bool whole_root,
                                        Report& report) {
    CaptureSummary summary;
    abdc::windows_capture::Win32NativeUsbPcapApi api;
    abdc::windows_capture::NativeUsbPcapCapture capture(api);
    abdc::windows_capture::NativeUsbPcapOptions options;
    options.root_index = root;
    options.device_address = whole_root ? 0U : address;
    options.capture_all_devices = whole_root;

    if (!capture.Start(options)) {
        summary.native_status = capture.Status();
        capture.Abort();
        return summary;
    }
    summary.started = true;
    abdc::capture::StreamingPcapParser parser;
    const auto capture_started = std::chrono::steady_clock::now();
    const auto deadline = capture_started + kCaptureDuration;
    int reported_second = 0;
    try {
        while (std::chrono::steady_clock::now() < deadline) {
            std::vector<std::byte> chunk;
            if (capture.WaitTakeChunk(chunk, 50ms)) {
                ProcessChunk(summary, parser, chunk);
            }
            const int elapsed = static_cast<int>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - capture_started).count());
            if (elapsed > reported_second && elapsed <= kCaptureDuration.count()) {
                reported_second = elapsed;
                std::cout << '.' << std::flush;
            }
            const auto status = capture.Status();
            if (status.reader_finished) break;
        }
        std::cout << '\n';
        capture.RequestStop();
        for (;;) {
            std::vector<std::byte> chunk;
            const bool received = capture.WaitTakeChunk(chunk, 50ms);
            if (received) ProcessChunk(summary, parser, chunk);
            const auto status = capture.Status();
            if (!received && status.reader_finished) break;
        }
        parser.Finalize();
        summary.parser_clean = true;
    } catch (const std::exception& error) {
        report.Line(std::string("Parser error: ") + error.what());
    }

    summary.stop = capture.StopAndDrain(5s, [&] {
        abdc::windows_capture::NativeUsbPcapSemanticDrainEvidence evidence;
        evidence.parser_at_record_boundary =
            summary.parser_clean && parser.AtRecordBoundary();
        evidence.authoritative_writer_clean = summary.parser_clean;
        evidence.accounted_bytes = summary.source_bytes;
        evidence.diagnostic = summary.parser_clean
            ? "diagnostic parser consumed every delivered byte; "
            : "diagnostic parser did not end cleanly; ";
        return evidence;
    });
    summary.native_status = capture.Status();
    return summary;
}

[[nodiscard]] std::uint64_t SuccessfulForAddress(
    const CaptureSummary& summary, const std::uint16_t device,
    const std::optional<std::set<std::uint8_t>>& endpoints = std::nullopt) {
    std::uint64_t result = 0;
    for (const auto& [key, stats] : summary.endpoints) {
        if (key.device != device ||
            (endpoints && !endpoints->contains(key.endpoint))) {
            continue;
        }
        result += stats.successful_nonempty_completions;
    }
    return result;
}

[[nodiscard]] std::uint64_t ChangesForAddress(
    const CaptureSummary& summary, const std::uint16_t device) {
    std::uint64_t result = 0;
    for (const auto& [key, stats] : summary.endpoints) {
        if (key.device == device) result += stats.payload_change_events;
    }
    return result;
}

void PrintSummary(const std::string_view label, const CaptureSummary& summary,
                  Report& report) {
    report.Line();
    report.Line(std::string("=== ") + std::string(label) + " ===");
    report.Line("started=" + std::string(summary.started ? "yes" : "no") +
                " parser_clean=" +
                std::string(summary.parser_clean ? "yes" : "no") +
                " clean_stop=" +
                std::string(summary.stop.clean ? "yes" : "no"));
    report.Line("source_bytes=" + std::to_string(summary.source_bytes) +
                " source_records=" + std::to_string(summary.source_records) +
                " packet_parse_errors=" +
                std::to_string(summary.packet_parse_errors));
    report.Line("native_win32_error=" +
                std::to_string(summary.native_status.win32_error) +
                " native_message=" + summary.native_status.message);
    report.Line("interrupt-IN endpoint observations:");
    if (summary.endpoints.empty()) report.Line("  <none>");
    for (const auto& [key, stats] : summary.endpoints) {
        report.Line(
            "  bus=" + std::to_string(key.bus) +
            " address=" + std::to_string(key.device) +
            " endpoint=" + EndpointText(key.endpoint) +
            " records=" + std::to_string(stats.interrupt_in_records) +
            " successful_nonempty=" +
                std::to_string(stats.successful_nonempty_completions) +
            " changes=" + std::to_string(stats.payload_change_events) +
            " failed=" + std::to_string(stats.failed_completions) +
            " truncated=" + std::to_string(stats.truncated_payloads) +
            " payload_bytes=" + std::to_string(stats.payload_bytes));
    }
}

void PrintConclusion(const CaptureSummary& exact,
                     const CaptureSummary& whole_root,
                     const std::uint8_t expected_address,
                     const std::set<std::uint8_t>& configured_endpoints,
                     Report& report) {
    const auto exact_expected = SuccessfulForAddress(exact, expected_address);
    const auto broad_expected = SuccessfulForAddress(whole_root, expected_address);
    const auto exact_configured = configured_endpoints.empty()
        ? exact_expected
        : SuccessfulForAddress(exact, expected_address,
                               configured_endpoints);
    const auto expected_changes = std::max(
        ChangesForAddress(exact, expected_address),
        ChangesForAddress(whole_root, expected_address));

    std::uint16_t best_device = 0U;
    std::uint64_t best_changes = 0U;
    std::uint64_t best_completions = 0U;
    for (const auto& [key, stats] : whole_root.endpoints) {
        if (key.device == expected_address) continue;
        const auto changes = ChangesForAddress(whole_root, key.device);
        const auto completions = SuccessfulForAddress(whole_root, key.device);
        if (std::tie(changes, completions) >
            std::tie(best_changes, best_completions)) {
            best_device = key.device;
            best_changes = changes;
            best_completions = completions;
        }
    }

    report.Line();
    report.Line("=== CONCLUSION ===");
    if (!exact.started || !whole_root.started) {
        report.Line("USBPcap could not start one or both diagnostic captures. "
                    "The Win32 error and native message above are decisive.");
        return;
    }
    const bool other_stream_dominates =
        best_device != 0U && best_changes >= 16U &&
        (expected_changes == 0U ||
         best_changes / 8U > expected_changes);
    if (other_stream_dominates) {
        report.Line("LIKELY ADDRESS-MAPPING MISMATCH: expected address " +
                    std::to_string(expected_address) + " produced " +
                    std::to_string(expected_changes) +
                    " changing payloads, while address " +
                    std::to_string(best_device) + " produced " +
                    std::to_string(best_changes) +
                    ". The sparse expected-address traffic is not enough to "
                    "declare the mouse mapping healthy. Keep other USB devices "
                    "idle when interpreting this result.");
        return;
    }
    if (exact_expected > 0U && exact_configured == 0U) {
        report.Line("LIKELY ENDPOINT-SELECTION MISMATCH: the mapped USB address "
                    "was active, but none of the endpoints supplied to the "
                    "collector's certification route carried usable traffic.");
        return;
    }
    if (exact_expected > 0U) {
        report.Line("EXACT CAPTURE WORKED: the mapped address produced usable "
                    "interrupt traffic in this diagnostic. Re-test collector "
                    ABDC_VERSION "; if it still fails, compare probe timing and route "
                    "selection rather than the USBPcap driver.");
        return;
    }
    if (broad_expected > 0U) {
        report.Line("EXACT FILTER FAILURE: whole-root capture saw the expected "
                    "address, but USBPcap's exact-address filter returned no "
                    "usable interrupt traffic. A broad-capture/user-space-filter "
                    "fallback is justified on this machine.");
        return;
    }

    if (best_device != 0U && best_changes > 0U) {
        report.Line("LIKELY ADDRESS-MAPPING MISMATCH: expected address " +
                    std::to_string(expected_address) +
                    " was quiet, while address " +
                    std::to_string(best_device) + " produced " +
                    std::to_string(best_changes) +
                    " changing interrupt payloads. Keep other USB devices idle "
                    "when interpreting this result.");
        return;
    }
    if (whole_root.source_records == 0U) {
        report.Line("NO ROOT TRAFFIC: USBPcap started but returned no records. "
                    "This points to the installed USBPcap filter/driver or the "
                    "selected root rather than mouse descriptor decoding.");
        return;
    }
    report.Line("ROOT TRAFFIC BUT NO MOVING INTERRUPT ENDPOINT: repeat once while "
                "moving continuously. If unchanged, investigate the USBPcap "
                "driver stack or a device on a different mapped root.");
}

[[nodiscard]] std::optional<std::size_t> SelectMouse(
    const abdc::app::ParticipantInventory& inventory, Report& report) {
    report.Line();
    report.Line("Detected physical mouse choices:");
    for (std::size_t index = 0; index < inventory.choices.size(); ++index) {
        const auto& choice = inventory.choices[index];
        report.Line("  " + std::to_string(index + 1U) + ") " +
                    choice.product_name +
                    (choice.ready ? " [ready]" : " [not probeable]"));
    }
    if (inventory.choices.empty()) return std::nullopt;

    for (;;) {
        std::cout << "Enter the number of the mouse to diagnose: " << std::flush;
        std::string input;
        if (!std::getline(std::cin, input)) return std::nullopt;
        try {
            const auto value = std::stoul(input);
            if (value >= 1U && value <= inventory.choices.size() &&
                inventory.choices[value - 1U].ready) {
                return value - 1U;
            }
        } catch (const std::exception&) {
        }
        report.Line("Please choose a [ready] mouse number.");
    }
}

void PauseBeforeExit() {
    std::cout << "\nPress Enter to close..." << std::flush;
    std::string ignored;
    std::getline(std::cin, ignored);
}

int DiagnosticMain() {
    SetConsoleOutputCP(CP_UTF8);
    const auto report_path =
        ExecutableDirectory() / "ABCurves USBPcap Diagnostic Report.txt";
    Report report(report_path);
    if (!report.Ready()) {
        throw std::runtime_error("could not create the diagnostic report beside the executable");
    }

    report.Line("ABCurves USBPcap Diagnostic " ABDC_VERSION);
    report.Line("This tool stores counters only. It does not save USB payloads or PCAP data.");
    report.Line("Report: " + report.Path().string());
    abdc::windows_capture::Win32NativeUsbPcapApi elevation_api;
    bool elevated = false;
    std::uint32_t elevation_error = 0;
    if (!elevation_api.QueryProcessElevated(elevated, elevation_error) ||
        !elevated) {
        throw std::runtime_error(
            "administrator elevation is required before USBPcap testing");
    }
    report.Line();
    report.Line("Scanning Windows mouse and USB topology...");
    const auto salt = FreshSalt();
    const auto inventory = abdc::app::DiscoverParticipantInventory(salt);
    const auto selected = SelectMouse(inventory, report);
    if (!selected) {
        report.Line("No probeable mouse was selected.");
        return 2;
    }
    const auto routes =
        abdc::app::CertificationTopologiesForChoice(inventory, *selected);
    const auto root = routes.front().transport.usbpcap_root_index;
    const auto address = routes.front().transport.device_address;
    std::set<std::uint8_t> configured_endpoints;
    for (const auto& route : routes) {
        if (route.transport.usbpcap_root_index != root ||
            route.transport.device_address != address) {
            throw std::runtime_error("selected mouse routes disagree on USB root/address");
        }
        if (route.transport.endpoint_address != 0U) {
            configured_endpoints.insert(route.transport.endpoint_address);
        }
    }

    const auto& choice = inventory.choices[*selected];
    report.Line();
    report.Line("Selected: " + choice.product_name + " VID=" +
                Hex4(choice.vendor_id) + " PID=" + Hex4(choice.product_id));
    report.Line("Collector mapping: USBPcap" + std::to_string(root) +
                " device_address=" + std::to_string(address));
    std::string endpoint_line = "Configured route endpoints:";
    if (configured_endpoints.empty()) endpoint_line += " <device-wide>";
    for (const auto endpoint : configured_endpoints) {
        endpoint_line += " " + EndpointText(endpoint);
    }
    report.Line(endpoint_line);

    report.Line();
    report.Line("TEST 1 OF 2: collector-style exact-address capture");
    report.Line("Press Enter when ready.");
    std::string ignored;
    std::getline(std::cin, ignored);
    Countdown(report);
    const auto exact = RunCapture(root, address, false, report);

    report.Line();
    report.Line("TEST 2 OF 2: diagnostic whole-root capture");
    report.Line("Press Enter when ready. Keep other USB devices as idle as practical.");
    std::getline(std::cin, ignored);
    Countdown(report);
    const auto whole_root = RunCapture(root, address, true, report);

    PrintSummary("EXACT ADDRESS", exact, report);
    PrintSummary("WHOLE ROOT", whole_root, report);
    PrintConclusion(exact, whole_root, address, configured_endpoints, report);
    report.Line();
    report.Line("Send this report back to the ABCurves researcher:");
    report.Line(report.Path().string());
    return 0;
}

}  // namespace

int wmain() {
    int result = 1;
    try {
        result = DiagnosticMain();
    } catch (const std::exception& error) {
        std::cerr << "Diagnostic failed: " << error.what() << '\n';
    } catch (...) {
        std::cerr << "Diagnostic failed with an unknown error.\n";
    }
    PauseBeforeExit();
    return result;
}
