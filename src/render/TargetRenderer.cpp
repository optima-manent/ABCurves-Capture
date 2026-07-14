// Adapted from the user-owned AIM TRAINER reference for this project.
#include "render/TargetRenderer.h"

#include <algorithm>
#include <cmath>

namespace {
constexpr double kPi = 3.14159265358979323846;
constexpr double kHalfAngularViewRadians = kPi * 0.5;

float ViewportScaleX(unsigned int width, unsigned int height) {
    if (width == 0 || height == 0) {
        return 1.0f;
    }
    return static_cast<float>(std::min(width, height)) / static_cast<float>(width);
}

float ViewportScaleY(unsigned int width, unsigned int height) {
    if (width == 0 || height == 0) {
        return 1.0f;
    }
    return static_cast<float>(std::min(width, height)) / static_cast<float>(height);
}

void AddVertex(std::vector<RenderVertex>& vertices,
               float x,
               float y,
               float r,
               float g,
               float b,
               float a) {
    vertices.push_back(RenderVertex{x, y, r, g, b, a});
}
}

namespace TargetRenderer {

GeometryStatus AppendTarget(std::vector<RenderVertex>& vertices,
                  double rel_x_counts,
                  double rel_y_counts,
                  double radius_counts,
                  double radians_per_count,
                  unsigned int viewport_width,
                  unsigned int viewport_height,
                  bool inside_target,
                  float visual_strength) {
    if (!std::isfinite(rel_x_counts) || !std::isfinite(rel_y_counts) ||
        !std::isfinite(radius_counts) || !std::isfinite(radians_per_count) ||
        !std::isfinite(visual_strength) || radius_counts <= 0.0 ||
        radians_per_count <= 0.0 || visual_strength < 0.0F ||
        viewport_width == 0U || viewport_height == 0U) {
        return GeometryStatus::Invalid;
    }
    if (visual_strength == 0.0F) return GeometryStatus::Hidden;
    const float scale_x = ViewportScaleX(viewport_width, viewport_height);
    const float scale_y = ViewportScaleY(viewport_width, viewport_height);
    const float count_to_ndc = static_cast<float>(radians_per_count / kHalfAngularViewRadians);
    const float center_x = static_cast<float>(rel_x_counts) * count_to_ndc * scale_x;
    const float center_y = static_cast<float>(rel_y_counts) * count_to_ndc * scale_y;
    const float radius = std::max(0.0f, static_cast<float>(radius_counts) * count_to_ndc);
    const float radius_x = radius * scale_x;
    const float radius_y = radius * scale_y;
    if (!std::isfinite(center_x) || !std::isfinite(center_y) ||
        !std::isfinite(radius_x) || !std::isfinite(radius_y)) {
        return GeometryStatus::Invalid;
    }
    if (center_x + radius_x < -1.0F || center_x - radius_x > 1.0F ||
        center_y + radius_y < -1.0F || center_y - radius_y > 1.0F) {
        return GeometryStatus::Offscreen;
    }

    const float strength = std::clamp(visual_strength, 0.0f, 1.0f);
    const bool green = inside_target;
    const float r = green ? 0.1f : 0.95f;
    const float g = green ? 0.9f : 0.12f;
    const float b = green ? 0.28f : 0.10f;

    constexpr int kSegments = 72;
    for (int i = 0; i < kSegments; ++i) {
        const double a0 = (static_cast<double>(i) / static_cast<double>(kSegments)) * kPi * 2.0;
        const double a1 = (static_cast<double>(i + 1) / static_cast<double>(kSegments)) * kPi * 2.0;
        const float x0 = center_x + static_cast<float>(std::cos(a0)) * radius_x;
        const float y0 = center_y + static_cast<float>(std::sin(a0)) * radius_y;
        const float x1 = center_x + static_cast<float>(std::cos(a1)) * radius_x;
        const float y1 = center_y + static_cast<float>(std::sin(a1)) * radius_y;
        AddVertex(vertices, center_x, center_y, r, g, b, strength);
        AddVertex(vertices, x0, y0, r, g, b, strength);
        AddVertex(vertices, x1, y1, r, g, b, strength);
    }
    return GeometryStatus::Drawable;
}

}
