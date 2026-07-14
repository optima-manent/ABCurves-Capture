// Adapted from the user-owned AIM TRAINER reference for this project.
#include "render/CrosshairRenderer.h"

#include <algorithm>

namespace {
float PixelToNdcX(float pixels, unsigned int viewport_width) {
    return viewport_width == 0 ? 0.0f : (pixels * 2.0f) / static_cast<float>(viewport_width);
}

float PixelToNdcY(float pixels, unsigned int viewport_height) {
    return viewport_height == 0 ? 0.0f : (pixels * 2.0f) / static_cast<float>(viewport_height);
}

void AddRect(std::vector<RenderVertex>& vertices,
             float left,
             float top,
             float right,
             float bottom,
             float r,
             float g,
             float b,
             float a) {
    vertices.push_back({left, top, r, g, b, a});
    vertices.push_back({right, top, r, g, b, a});
    vertices.push_back({right, bottom, r, g, b, a});
    vertices.push_back({left, top, r, g, b, a});
    vertices.push_back({right, bottom, r, g, b, a});
    vertices.push_back({left, bottom, r, g, b, a});
}
}

namespace CrosshairRenderer {

void AppendCrosshairAt(std::vector<RenderVertex>& vertices,
                       unsigned int viewport_width,
                       unsigned int viewport_height,
                       double scale,
                       float center_x,
                       float center_y) {
    const float s = static_cast<float>(std::clamp(scale, 0.25, 2.0));
    const float length_x = PixelToNdcX(28.0f * s, viewport_width);
    const float length_y = PixelToNdcY(28.0f * s, viewport_height);
    const float gap_x = PixelToNdcX(5.0f * s, viewport_width);
    const float gap_y = PixelToNdcY(5.0f * s, viewport_height);
    const float width_x = PixelToNdcX(2.0f, viewport_width);
    const float width_y = PixelToNdcY(2.0f, viewport_height);
    const float dot_x = PixelToNdcX(2.0f * s, viewport_width);
    const float dot_y = PixelToNdcY(2.0f * s, viewport_height);

    AddRect(vertices,
            center_x - length_x,
            center_y - width_y,
            center_x - gap_x,
            center_y + width_y,
            0.95f,
            0.95f,
            0.90f,
            1.0f);
    AddRect(vertices,
            center_x + gap_x,
            center_y - width_y,
            center_x + length_x,
            center_y + width_y,
            0.95f,
            0.95f,
            0.90f,
            1.0f);
    AddRect(vertices,
            center_x - width_x,
            center_y - length_y,
            center_x + width_x,
            center_y - gap_y,
            0.95f,
            0.95f,
            0.90f,
            1.0f);
    AddRect(vertices,
            center_x - width_x,
            center_y + gap_y,
            center_x + width_x,
            center_y + length_y,
            0.95f,
            0.95f,
            0.90f,
            1.0f);
    AddRect(vertices,
            center_x - dot_x,
            center_y + dot_y,
            center_x + dot_x,
            center_y - dot_y,
            1.0f,
            1.0f,
            1.0f,
            1.0f);
}

void AppendCrosshair(std::vector<RenderVertex>& vertices,
                     unsigned int viewport_width,
                     unsigned int viewport_height,
                     double scale) {
    AppendCrosshairAt(vertices, viewport_width, viewport_height, scale, 0.0f, 0.0f);
}

}

