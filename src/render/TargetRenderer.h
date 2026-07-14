// Adapted from the user-owned AIM TRAINER reference for this project.
#pragma once

#include "render/RenderTypes.h"

#include <vector>

namespace TargetRenderer {
enum class GeometryStatus { Drawable, Hidden, Offscreen, Invalid };

[[nodiscard]] GeometryStatus AppendTarget(std::vector<RenderVertex>& vertices,
                                double rel_x_counts,
                                double rel_y_counts,
                                double radius_counts,
                                double radians_per_count,
                                unsigned int viewport_width,
                                unsigned int viewport_height,
                                bool inside_target,
                                float visual_strength);
}
