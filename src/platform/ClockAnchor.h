#pragma once

#include "base/Json.h"

#include <cstdint>
#include <string>

namespace abdc::platform {

struct ClockAnchor {
    std::int64_t qpc_before = 0;
    std::int64_t utc_unix_ns = 0;
    std::int64_t qpc_after = 0;
    std::int64_t qpc_midpoint = 0;
    std::int64_t bracket_ticks = 0;
    std::string source;
};

[[nodiscard]] ClockAnchor SamplePreciseClockAnchor(std::string source);
[[nodiscard]] json::Value ClockAnchorToJson(const ClockAnchor& anchor);
[[nodiscard]] ClockAnchor ClockAnchorFromJson(const json::Value& value);

}  // namespace abdc::platform

