#include "render/GridRenderer.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace {

constexpr long double kPi = 3.141592653589793238462643383279502884L;
constexpr std::int64_t kMinorSpacingCounts = 160;
constexpr std::int64_t kMajorEvery = 5;

void AddQuad(std::vector<RenderVertex>& vertices,
             const float left, const float top, const float right, const float bottom,
             const float red, const float green, const float blue) {
    vertices.push_back({left, top, red, green, blue, 1.0F});
    vertices.push_back({right, top, red, green, blue, 1.0F});
    vertices.push_back({right, bottom, red, green, blue, 1.0F});
    vertices.push_back({left, top, red, green, blue, 1.0F});
    vertices.push_back({right, bottom, red, green, blue, 1.0F});
    vertices.push_back({left, bottom, red, green, blue, 1.0F});
}

bool IsMajor(const std::int64_t index) {
    return index % kMajorEvery == 0;
}

}  // namespace

namespace GridRenderer {

bool AppendWorldGrid(std::vector<RenderVertex>& vertices,
                     const std::int64_t camera_x_counts,
                     const std::int64_t camera_y_counts,
                     const double radians_per_count,
                     const unsigned int viewport_width,
                     const unsigned int viewport_height) {
    if (!std::isfinite(radians_per_count) || radians_per_count <= 0.0 ||
        viewport_width == 0U || viewport_height == 0U) {
        return false;
    }
    const long double shortest = static_cast<long double>(std::min(viewport_width, viewport_height));
    const long double scale_x = shortest / static_cast<long double>(viewport_width);
    const long double scale_y = shortest / static_cast<long double>(viewport_height);
    const long double count_to_ndc = static_cast<long double>(radians_per_count) / (kPi * 0.5L);
    const long double x_per_count = count_to_ndc * scale_x;
    const long double y_per_count = count_to_ndc * scale_y;
    if (!(x_per_count > 0.0L) || !(y_per_count > 0.0L)) return false;

    const long double half_x_counts = 1.0L / x_per_count;
    const long double half_y_counts = 1.0L / y_per_count;
    const long double camera_x = static_cast<long double>(camera_x_counts);
    const long double camera_y = static_cast<long double>(camera_y_counts);
    // Only emit lattice lines whose centres are inside the viewport. D3D clips
    // the sub-pixel line thickness at an edge, but keeping the generated
    // geometry itself bounded makes this renderer safe for other backends too.
    const long double first_x_value =
        std::ceil((camera_x - half_x_counts) / kMinorSpacingCounts);
    const long double last_x_value =
        std::floor((camera_x + half_x_counts) / kMinorSpacingCounts);
    const long double first_y_value =
        std::ceil((camera_y - half_y_counts) / kMinorSpacingCounts);
    const long double last_y_value =
        std::floor((camera_y + half_y_counts) / kMinorSpacingCounts);
    constexpr long double minimum_index =
        static_cast<long double>(std::numeric_limits<std::int64_t>::min());
    constexpr long double maximum_index =
        static_cast<long double>(std::numeric_limits<std::int64_t>::max());
    if (!std::isfinite(first_x_value) || !std::isfinite(last_x_value) ||
        !std::isfinite(first_y_value) || !std::isfinite(last_y_value) ||
        first_x_value < minimum_index || first_x_value > maximum_index ||
        last_x_value < minimum_index || last_x_value > maximum_index ||
        first_y_value < minimum_index || first_y_value > maximum_index ||
        last_y_value < minimum_index || last_y_value > maximum_index ||
        last_x_value < first_x_value || last_y_value < first_y_value ||
        last_x_value - first_x_value > 256.0L ||
        last_y_value - first_y_value > 256.0L) {
        return false;
    }
    const auto first_x = static_cast<std::int64_t>(first_x_value);
    const auto last_x = static_cast<std::int64_t>(last_x_value);
    const auto first_y = static_cast<std::int64_t>(first_y_value);
    const auto last_y = static_cast<std::int64_t>(last_y_value);

    const float vertical_pixel = 2.0F / static_cast<float>(viewport_width);
    const float horizontal_pixel = 2.0F / static_cast<float>(viewport_height);
    for (std::int64_t index = first_x; index <= last_x; ++index) {
        const auto relative = static_cast<long double>(index) * kMinorSpacingCounts - camera_x;
        const float x = static_cast<float>(relative * x_per_count);
        const bool major = IsMajor(index);
        const float thickness = vertical_pixel * (major ? 1.45F : 0.75F);
        AddQuad(vertices, x - thickness, 1.0F, x + thickness, -1.0F,
                major ? 0.075F : 0.043F,
                major ? 0.155F : 0.085F,
                major ? 0.165F : 0.095F);
    }
    for (std::int64_t index = first_y; index <= last_y; ++index) {
        const auto relative = static_cast<long double>(index) * kMinorSpacingCounts - camera_y;
        const float y = static_cast<float>(relative * y_per_count);
        const bool major = IsMajor(index);
        const float thickness = horizontal_pixel * (major ? 1.45F : 0.75F);
        AddQuad(vertices, -1.0F, y + thickness, 1.0F, y - thickness,
                major ? 0.075F : 0.043F,
                major ? 0.155F : 0.085F,
                major ? 0.165F : 0.095F);
    }
    return true;
}

}  // namespace GridRenderer
