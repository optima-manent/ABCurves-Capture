#pragma once

namespace abdc::device {

// Raw Input is a gameplay/witness channel. This classification never grants
// it authority over the USB capture lane.
enum class RawDeviceOrigin {
    SelectedActive,
    SelectedPhysicalSibling,
    OtherPhysical,
    Unknown,
};

}  // namespace abdc::device

