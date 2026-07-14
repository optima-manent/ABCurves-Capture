// Adapted from the user-owned AIM TRAINER reference for this project.
#pragma once

#include <string>
#include <vector>

struct RenderVertex {
    float x = 0.0f;
    float y = 0.0f;
    float r = 1.0f;
    float g = 1.0f;
    float b = 1.0f;
    float a = 1.0f;
};

struct RenderColor {
    float r = 1.0f;
    float g = 1.0f;
    float b = 1.0f;
    float a = 1.0f;
};

enum class RenderTextAlign {
    Left,
    Center,
    Right
};

struct RenderRect {
    float left = 0.0f;
    float top = 0.0f;
    float right = 0.0f;
    float bottom = 0.0f;
    RenderColor color{};
};

struct RenderText {
    std::string text;
    float x = 0.0f;
    float y = 0.0f;
    double scale = 1.0;
    RenderColor color{};
    RenderTextAlign align = RenderTextAlign::Left;
};

struct RenderCrosshairPreview {
    float x = 0.0f;
    float y = 0.0f;
    double scale = 1.0;
};

struct RenderUiLayer {
    std::vector<RenderRect> rects;
    std::vector<RenderCrosshairPreview> crosshair_previews;
    std::vector<RenderText> texts;
};

