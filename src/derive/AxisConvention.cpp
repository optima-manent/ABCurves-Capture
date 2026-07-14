#include "derive/AxisConvention.h"

#include <limits>
#include <stdexcept>

namespace abdc::derive {

AxisConventionInfo DescribeAxisConvention(
    const AxisConventionVersion convention) {
    switch (convention) {
        case AxisConventionVersion::LegacyDeviceNativeYV1:
            return {
                convention,
                "legacy_device_native_y_v1",
                "device-positive-x",
                "device-positive-y",
            };
        case AxisConventionVersion::PhalmM16CountSpaceXRightYUpV2:
            return {
                convention,
                "phalm_m16_count_space_x_right_y_up_v2",
                "right",
                "up",
            };
    }
    throw std::invalid_argument("unknown axis convention version");
}

DeviceAndDerivedDelta DeriveAxes(
    const std::int64_t device_dx,
    const std::int64_t device_dy,
    const AxisConventionVersion convention) {
    static_cast<void>(DescribeAxisConvention(convention));

    auto derived_dy = device_dy;
    if (convention == AxisConventionVersion::PhalmM16CountSpaceXRightYUpV2) {
        if (device_dy == std::numeric_limits<std::int64_t>::min()) {
            throw std::overflow_error(
                "PHALM-M16 Y-up conversion cannot negate INT64_MIN");
        }
        derived_dy = -device_dy;
    }
    return {device_dx, device_dy, device_dx, derived_dy};
}

}  // namespace abdc::derive
