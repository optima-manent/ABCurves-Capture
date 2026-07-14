// Adapted from the user-owned AIM TRAINER reference for this project.
#pragma once

#include <functional>
#include <cstdint>
#include <string>
#include <windows.h>

class Win32Window {
public:
    using RawInputCallback = std::function<void(HRAWINPUT, std::int64_t)>;
    using KeyCallback = std::function<void(UINT, bool)>;
    using MouseMoveCallback = std::function<void(int, int)>;
    using MouseButtonCallback = std::function<void(int, int, bool)>;
    using FocusCallback = std::function<void(bool)>;
    using CaptureCallback = std::function<void(bool)>;
    using ResizeCallback = std::function<void(UINT, UINT)>;
    // Return false to defer destruction while an active session is being
    // stopped and sealed. The owner can post WM_CLOSE again once safe.
    using CloseCallback = std::function<bool()>;
    using SystemEventCallback = std::function<void(UINT, WPARAM, LPARAM)>;

    bool Create(HINSTANCE instance, int show_command, const wchar_t* title, int width, int height);
    bool PumpMessages();
    void SetTitle(const std::wstring& title) const;
    void ToggleFullscreen();
    void CaptureMouse();
    void ReleaseMouse();
    void UseArrowCursor();

    [[nodiscard]] HWND Handle() const { return hwnd_; }
    [[nodiscard]] bool HasFocus() const { return has_focus_; }
    [[nodiscard]] bool HasMouseCapture() const;
    [[nodiscard]] bool IsRunning() const { return running_; }
    [[nodiscard]] bool IsFullscreen() const { return fullscreen_; }
    [[nodiscard]] UINT ClientWidth() const;
    [[nodiscard]] UINT ClientHeight() const;
    [[nodiscard]] int LastPumpMessageCount() const { return last_pump_message_count_; }
    [[nodiscard]] int LastPumpRawInputCount() const { return last_pump_raw_input_count_; }

    RawInputCallback on_raw_input;
    KeyCallback on_key;
    MouseMoveCallback on_mouse_move;
    MouseButtonCallback on_mouse_button;
    FocusCallback on_focus;
    CaptureCallback on_capture;
    ResizeCallback on_resize;
    CloseCallback on_close;
    SystemEventCallback on_system_event;

private:
    static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
    LRESULT WndProc(UINT message, WPARAM wparam, LPARAM lparam);
    void UpdateCursorClip() const;
    void HideCursor();
    void ShowCursorAgain();

    HWND hwnd_ = nullptr;
    HINSTANCE instance_ = nullptr;
    bool running_ = true;
    bool has_focus_ = true;
    bool fullscreen_ = false;
    bool mouse_capture_mode_ = false;
    bool cursor_hidden_ = false;
    int last_pump_message_count_ = 0;
    int last_pump_raw_input_count_ = 0;
    RECT windowed_rect_{};
    DWORD windowed_style_ = 0;
};
