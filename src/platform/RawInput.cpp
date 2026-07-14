#include "platform/RawInput.h"

#include <cstddef>
#include <limits>
#include <stdexcept>
#include <vector>

namespace abdc::platform {

bool RawInputSource::Register(HWND target_window) const noexcept {
    if (target_window == nullptr) return false;
    RAWINPUTDEVICE device{};
    device.usUsagePage = 0x01U;
    device.usUsage = 0x02U;
    device.dwFlags = RIDEV_INPUTSINK | RIDEV_DEVNOTIFY;
    device.hwndTarget = target_window;
    return RegisterRawInputDevices(&device, 1U, sizeof(device)) == TRUE;
}

std::optional<RawMousePacket> RawInputSource::ReadMouse(
    HRAWINPUT raw_input,
    const std::int64_t receipt_qpc) const {
    if (raw_input == nullptr || receipt_qpc <= 0) {
        throw std::invalid_argument("Raw Input packet arguments are invalid");
    }
    UINT bytes = 0U;
    const auto size_result =
        GetRawInputData(raw_input, RID_INPUT, nullptr, &bytes, sizeof(RAWINPUTHEADER));
    if (size_result != 0U || bytes < sizeof(RAWINPUTHEADER) ||
        bytes > 16U * 1024U * 1024U) {
        return std::nullopt;
    }
    std::vector<std::byte> buffer(bytes);
    UINT available = bytes;
    const auto read = GetRawInputData(raw_input, RID_INPUT, buffer.data(),
                                      &available, sizeof(RAWINPUTHEADER));
    if (read == static_cast<UINT>(-1) || read != bytes || available != bytes) {
        return std::nullopt;
    }
    const auto* input = reinterpret_cast<const RAWINPUT*>(buffer.data());
    if (input->header.dwType != RIM_TYPEMOUSE ||
        input->header.dwSize < sizeof(RAWINPUTHEADER) + sizeof(RAWMOUSE)) {
        return std::nullopt;
    }

    const auto& mouse = input->data.mouse;
    RawMousePacket packet;
    packet.receipt_qpc = receipt_qpc;
    packet.device_handle = reinterpret_cast<std::uintptr_t>(input->header.hDevice);
    packet.dx = mouse.lLastX;
    packet.dy = mouse.lLastY;
    packet.native_button_flags = mouse.usButtonFlags;
    packet.relative = (mouse.usFlags & MOUSE_MOVE_ABSOLUTE) == 0U;
#ifdef MOUSE_MOVE_NOCOALESCE
    packet.no_coalesce = (mouse.usFlags & MOUSE_MOVE_NOCOALESCE) != 0U;
#endif
    packet.left_down = (mouse.usButtonFlags & RI_MOUSE_LEFT_BUTTON_DOWN) != 0U;
    packet.left_up = (mouse.usButtonFlags & RI_MOUSE_LEFT_BUTTON_UP) != 0U;
    packet.right_down = (mouse.usButtonFlags & RI_MOUSE_RIGHT_BUTTON_DOWN) != 0U;
    packet.right_up = (mouse.usButtonFlags & RI_MOUSE_RIGHT_BUTTON_UP) != 0U;
    packet.middle_down = (mouse.usButtonFlags & RI_MOUSE_MIDDLE_BUTTON_DOWN) != 0U;
    packet.middle_up = (mouse.usButtonFlags & RI_MOUSE_MIDDLE_BUTTON_UP) != 0U;
    if ((mouse.usButtonFlags & RI_MOUSE_WHEEL) != 0U) {
        packet.wheel = static_cast<SHORT>(mouse.usButtonData);
    }
    if ((mouse.usButtonFlags & RI_MOUSE_HWHEEL) != 0U) {
        packet.horizontal_wheel = static_cast<SHORT>(mouse.usButtonData);
    }
    return packet;
}

}  // namespace abdc::platform
