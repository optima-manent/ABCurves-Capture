#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <optional>

namespace abdc::platform {

struct RawMousePacket final {
    std::int64_t receipt_qpc = 0;
    std::uintptr_t device_handle = 0;
    std::int64_t dx = 0;
    std::int64_t dy = 0;
    std::int32_t wheel = 0;
    std::int32_t horizontal_wheel = 0;
    std::uint16_t native_button_flags = 0;
    bool relative = true;
    bool no_coalesce = false;
    bool left_down = false;
    bool left_up = false;
    bool right_down = false;
    bool right_up = false;
    bool middle_down = false;
    bool middle_up = false;
};

// Normal-user, low-latency gameplay input and an optional witness only. The
// authoritative research stream remains the selected USBPcap device address.
class RawInputSource final {
public:
    [[nodiscard]] bool Register(HWND target_window) const noexcept;
    [[nodiscard]] std::optional<RawMousePacket> ReadMouse(
        HRAWINPUT raw_input,
        std::int64_t receipt_qpc) const;
};

}  // namespace abdc::platform
