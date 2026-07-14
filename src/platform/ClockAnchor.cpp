#include "platform/ClockAnchor.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <limits>
#include <stdexcept>

namespace abdc::platform {
namespace {

std::int64_t FileTimeToUnixNanoseconds(const FILETIME& file_time) {
    ULARGE_INTEGER value{};
    value.LowPart = file_time.dwLowDateTime;
    value.HighPart = file_time.dwHighDateTime;
    constexpr std::uint64_t windows_to_unix_100ns = 116'444'736'000'000'000ULL;
    if (value.QuadPart < windows_to_unix_100ns) {
        throw std::runtime_error("precise UTC precedes the Unix epoch");
    }
    const auto unix_100ns = value.QuadPart - windows_to_unix_100ns;
    if (unix_100ns > static_cast<std::uint64_t>(
            std::numeric_limits<std::int64_t>::max() / 100LL)) {
        throw std::overflow_error("precise UTC exceeds Unix-nanosecond range");
    }
    return static_cast<std::int64_t>(unix_100ns * 100ULL);
}

}  // namespace

ClockAnchor SamplePreciseClockAnchor(std::string source) {
    if (source.empty() || source.size() > 64U) {
        throw std::invalid_argument("clock anchor source is invalid");
    }
    LARGE_INTEGER before{};
    LARGE_INTEGER after{};
    FILETIME utc{};
    if (!QueryPerformanceCounter(&before)) {
        throw std::runtime_error("clock anchor QPC-before query failed");
    }
    GetSystemTimePreciseAsFileTime(&utc);
    if (!QueryPerformanceCounter(&after)) {
        throw std::runtime_error("clock anchor QPC-after query failed");
    }
    if (after.QuadPart < before.QuadPart) {
        throw std::runtime_error("QPC regressed inside a clock anchor");
    }
    ClockAnchor anchor;
    anchor.qpc_before = before.QuadPart;
    anchor.utc_unix_ns = FileTimeToUnixNanoseconds(utc);
    anchor.qpc_after = after.QuadPart;
    anchor.bracket_ticks = after.QuadPart - before.QuadPart;
    anchor.qpc_midpoint = before.QuadPart + anchor.bracket_ticks / 2LL;
    anchor.source = std::move(source);
    return anchor;
}

json::Value ClockAnchorToJson(const ClockAnchor& anchor) {
    if (anchor.qpc_before <= 0 || anchor.qpc_after < anchor.qpc_before ||
        anchor.qpc_midpoint < anchor.qpc_before ||
        anchor.qpc_midpoint > anchor.qpc_after || anchor.utc_unix_ns <= 0 ||
        anchor.source.empty()) {
        throw std::invalid_argument("clock anchor is structurally invalid");
    }
    json::Value value = json::Value::Object{};
    value["qpc_before"] = anchor.qpc_before;
    value["qpc_midpoint"] = anchor.qpc_midpoint;
    value["qpc_after"] = anchor.qpc_after;
    value["bracket_ticks"] = anchor.bracket_ticks;
    value["utc_unix_ns"] = std::to_string(anchor.utc_unix_ns);
    value["source"] = anchor.source;
    return value;
}

ClockAnchor ClockAnchorFromJson(const json::Value& value) {
    ClockAnchor anchor;
    anchor.qpc_before = value.At("qpc_before").AsInt();
    anchor.qpc_midpoint = value.At("qpc_midpoint").AsInt();
    anchor.qpc_after = value.At("qpc_after").AsInt();
    anchor.bracket_ticks = value.At("bracket_ticks").AsInt();
    anchor.utc_unix_ns = std::stoll(value.At("utc_unix_ns").AsString());
    anchor.source = value.At("source").AsString();
    (void)ClockAnchorToJson(anchor);
    return anchor;
}

}  // namespace abdc::platform

