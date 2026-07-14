#pragma once

#include <cstdint>
#include <string_view>

namespace abdc::derive {

// Persist the numeric value and stable name with every derived artifact.  The
// device fields are never transformed; this version controls only the adapter
// fields consumed by a downstream model or legacy exporter.
enum class AxisConventionVersion : std::uint32_t {
    LegacyDeviceNativeYV1 = 1,
    PhalmM16CountSpaceXRightYUpV2 = 2,
};

inline constexpr AxisConventionVersion kCurrentResearchAxisConvention =
    AxisConventionVersion::PhalmM16CountSpaceXRightYUpV2;

struct AxisConventionInfo {
    AxisConventionVersion version{};
    std::string_view stable_name;
    std::string_view derived_x_positive;
    std::string_view derived_y_positive;
};

struct DeviceAndDerivedDelta {
    std::int64_t device_dx{};
    std::int64_t device_dy{};
    std::int64_t derived_dx{};
    std::int64_t derived_dy{};

    bool operator==(const DeviceAndDerivedDelta&) const = default;
};

[[nodiscard]] AxisConventionInfo DescribeAxisConvention(
    AxisConventionVersion convention);

// Preserves device_dx/device_dy verbatim.  PHALM-M16 count space is X-right,
// Y-up, so its adapter negates the usual HID/Windows native Y.  The legacy
// adapter exposes native Y unchanged.
[[nodiscard]] DeviceAndDerivedDelta DeriveAxes(
    std::int64_t device_dx,
    std::int64_t device_dy,
    AxisConventionVersion convention);

}  // namespace abdc::derive
