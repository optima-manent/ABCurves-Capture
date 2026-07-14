// Adapted from the user-owned AIM TRAINER reference for this project.
#include "platform/Win32Window.h"

#include <algorithm>
#include <string>
#include <windowsx.h>

namespace {
constexpr wchar_t kWindowClassName[] = L"ABCT_PARTICIPANT_WINDOW_V1";
constexpr int kMessageServiceBudget = 512;
}

bool Win32Window::Create(HINSTANCE instance, int show_command, const wchar_t* title, int width, int height) {
    instance_ = instance;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = &Win32Window::StaticWndProc;
    wc.hInstance = instance_;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kWindowClassName;
    wc.style = CS_HREDRAW | CS_VREDRAW;

    RegisterClassExW(&wc);

    RECT rect{0, 0, width, height};
    AdjustWindowRect(&rect, WS_OVERLAPPEDWINDOW, FALSE);

    hwnd_ = CreateWindowExW(0,
                            kWindowClassName,
                            title,
                            WS_OVERLAPPEDWINDOW,
                            CW_USEDEFAULT,
                            CW_USEDEFAULT,
                            rect.right - rect.left,
                            rect.bottom - rect.top,
                            nullptr,
                            nullptr,
                            instance_,
                            this);
    if (!hwnd_) {
        return false;
    }

    ShowWindow(hwnd_, show_command);
    UpdateWindow(hwnd_);
    UseArrowCursor();
    return true;
}

bool Win32Window::PumpMessages() {
    last_pump_message_count_ = 0;
    last_pump_raw_input_count_ = 0;

    MSG message{};
    while (last_pump_message_count_ < kMessageServiceBudget &&
           PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
        ++last_pump_message_count_;
        if (message.message == WM_INPUT) {
            ++last_pump_raw_input_count_;
        }
        if (message.message == WM_QUIT) {
            running_ = false;
            return false;
        }
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return running_;
}

void Win32Window::SetTitle(const std::wstring& title) const {
    if (hwnd_) {
        SetWindowTextW(hwnd_, title.c_str());
    }
}

void Win32Window::ToggleFullscreen() {
    if (!hwnd_) {
        return;
    }

    if (!fullscreen_) {
        windowed_style_ = GetWindowLongW(hwnd_, GWL_STYLE);
        GetWindowRect(hwnd_, &windowed_rect_);

        MONITORINFO monitor_info{};
        monitor_info.cbSize = sizeof(monitor_info);
        GetMonitorInfoW(MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST), &monitor_info);

        SetWindowLongW(hwnd_, GWL_STYLE, windowed_style_ & ~WS_OVERLAPPEDWINDOW);
        SetWindowPos(hwnd_,
                     HWND_TOP,
                     monitor_info.rcMonitor.left,
                     monitor_info.rcMonitor.top,
                     monitor_info.rcMonitor.right - monitor_info.rcMonitor.left,
                     monitor_info.rcMonitor.bottom - monitor_info.rcMonitor.top,
                     SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        fullscreen_ = true;
    } else {
        SetWindowLongW(hwnd_, GWL_STYLE, windowed_style_);
        SetWindowPos(hwnd_,
                     nullptr,
                     windowed_rect_.left,
                     windowed_rect_.top,
                     windowed_rect_.right - windowed_rect_.left,
                     windowed_rect_.bottom - windowed_rect_.top,
                     SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        fullscreen_ = false;
    }
}

void Win32Window::CaptureMouse() {
    if (!hwnd_) return;
    if (!has_focus_ || GetForegroundWindow() != hwnd_ || IsIconic(hwnd_) != FALSE) {
        mouse_capture_mode_ = false;
        ClipCursor(nullptr);
        ShowCursorAgain();
        UseArrowCursor();
        if (on_capture) on_capture(false);
        return;
    }

    SetCapture(hwnd_);
    if (GetCapture() != hwnd_) {
        mouse_capture_mode_ = false;
        ClipCursor(nullptr);
        ShowCursorAgain();
        UseArrowCursor();
        if (on_capture) on_capture(false);
        return;
    }
    mouse_capture_mode_ = true;
    UpdateCursorClip();
    HideCursor();
    if (on_capture) on_capture(true);
}

void Win32Window::ReleaseMouse() {
    mouse_capture_mode_ = false;
    ClipCursor(nullptr);
    ShowCursorAgain();
    UseArrowCursor();
    if (GetCapture() == hwnd_) {
        ReleaseCapture();
    }
    if (on_capture) {
        on_capture(false);
    }
}

bool Win32Window::HasMouseCapture() const {
    return hwnd_ != nullptr && mouse_capture_mode_ && GetCapture() == hwnd_;
}

void Win32Window::UseArrowCursor() {
    if (!hwnd_) {
        return;
    }
    HCURSOR arrow = LoadCursor(nullptr, IDC_ARROW);
    SetClassLongPtrW(hwnd_, GCLP_HCURSOR, reinterpret_cast<LONG_PTR>(arrow));
    ShowCursorAgain();
    SetCursor(arrow);
}

UINT Win32Window::ClientWidth() const {
    if (!hwnd_) {
        return 1;
    }
    RECT client{};
    GetClientRect(hwnd_, &client);
    return static_cast<UINT>(std::max<LONG>(1, client.right - client.left));
}

UINT Win32Window::ClientHeight() const {
    if (!hwnd_) {
        return 1;
    }
    RECT client{};
    GetClientRect(hwnd_, &client);
    return static_cast<UINT>(std::max<LONG>(1, client.bottom - client.top));
}

void Win32Window::UpdateCursorClip() const {
    if (!hwnd_ || !mouse_capture_mode_ || !has_focus_) {
        ClipCursor(nullptr);
        return;
    }

    RECT client{};
    GetClientRect(hwnd_, &client);
    POINT top_left{client.left, client.top};
    POINT bottom_right{client.right, client.bottom};
    ClientToScreen(hwnd_, &top_left);
    ClientToScreen(hwnd_, &bottom_right);

    RECT clip{top_left.x, top_left.y, bottom_right.x, bottom_right.y};
    ClipCursor(&clip);
}

void Win32Window::HideCursor() {
    if (cursor_hidden_) {
        return;
    }

    while (ShowCursor(FALSE) >= 0) {
    }
    cursor_hidden_ = true;
}

void Win32Window::ShowCursorAgain() {
    if (!cursor_hidden_) {
        return;
    }

    while (ShowCursor(TRUE) < 0) {
    }
    cursor_hidden_ = false;
}

LRESULT CALLBACK Win32Window::StaticWndProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    Win32Window* window = nullptr;
    if (message == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
        window = static_cast<Win32Window*>(create->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
        window->hwnd_ = hwnd;
    } else {
        window = reinterpret_cast<Win32Window*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }

    if (window) {
        return window->WndProc(message, wparam, lparam);
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

LRESULT Win32Window::WndProc(UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_INPUT:
        if (on_raw_input) {
            LARGE_INTEGER receipt_qpc{};
            QueryPerformanceCounter(&receipt_qpc);
            on_raw_input(reinterpret_cast<HRAWINPUT>(lparam), receipt_qpc.QuadPart);
        }
        // Foreground WM_INPUT requires DefWindowProc cleanup after the packet
        // has been consumed. Background RIM_INPUTSINK packets return directly.
        return GET_RAWINPUT_CODE_WPARAM(wparam) == RIM_INPUT
            ? DefWindowProcW(hwnd_, message, wparam, lparam)
            : 0;
    case WM_INPUT_DEVICE_CHANGE:
        if (on_system_event) on_system_event(message, wparam, lparam);
        return 0;
    case WM_DISPLAYCHANGE:
    case WM_DPICHANGED:
        if (on_system_event) on_system_event(message, wparam, lparam);
        break;
    case WM_POWERBROADCAST:
        if (on_system_event) on_system_event(message, wparam, lparam);
        return TRUE;
    case WM_SETCURSOR:
        if (LOWORD(lparam) == HTCLIENT) {
            if (has_focus_ && mouse_capture_mode_ && GetCapture() == hwnd_) {
                SetCursor(nullptr);
            } else {
                UseArrowCursor();
            }
            return TRUE;
        }
        break;
    case WM_KEYDOWN:
        if (on_key) {
            on_key(static_cast<UINT>(wparam), true);
        }
        return 0;
    case WM_KEYUP:
        if (on_key) {
            on_key(static_cast<UINT>(wparam), false);
        }
        return 0;
    case WM_MOUSEMOVE:
        if (!mouse_capture_mode_) {
            UseArrowCursor();
        }
        if (on_mouse_move) {
            on_mouse_move(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam));
        }
        return 0;
    case WM_LBUTTONDOWN:
        SetFocus(hwnd_);
        if (!mouse_capture_mode_) {
            UseArrowCursor();
        }
        if (on_mouse_button) {
            on_mouse_button(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam), true);
        }
        return 0;
    case WM_LBUTTONUP:
        if (on_mouse_button) {
            on_mouse_button(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam), false);
        }
        return 0;
    case WM_ACTIVATEAPP:
        has_focus_ = (wparam != FALSE);
        if (!has_focus_ && mouse_capture_mode_) {
            ClipCursor(nullptr);
            ShowCursorAgain();
            UseArrowCursor();
            if (GetCapture() == hwnd_) {
                ReleaseCapture();
            }
        } else if (has_focus_ && mouse_capture_mode_) {
            SetCapture(hwnd_);
            UpdateCursorClip();
            HideCursor();
        }
        if (on_focus) {
            on_focus(has_focus_);
        }
        return 0;
    case WM_CAPTURECHANGED:
        if (reinterpret_cast<HWND>(lparam) != hwnd_) {
            mouse_capture_mode_ = false;
            ClipCursor(nullptr);
            ShowCursorAgain();
            if (on_capture) {
                on_capture(false);
            }
        }
        return 0;
    case WM_SIZE:
        UpdateCursorClip();
        if (on_system_event) on_system_event(message, wparam, lparam);
        if (on_resize && wparam != SIZE_MINIMIZED) {
            on_resize(LOWORD(lparam), HIWORD(lparam));
        }
        return 0;
    case WM_CLOSE:
        if (on_close && !on_close()) return 0;
        running_ = false;
        ReleaseMouse();
        DestroyWindow(hwnd_);
        return 0;
    case WM_DESTROY:
        running_ = false;
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd_, message, wparam, lparam);
    }

    return DefWindowProcW(hwnd_, message, wparam, lparam);
}
