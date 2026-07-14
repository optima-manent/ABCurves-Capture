#pragma once

#include "render/RenderTypes.h"

#include <cstdint>
#include <vector>

namespace GridRenderer {

// Appends a subtle, world-anchored count-space wall. Grid intersections are
// fixed in canonical coordinates; camera movement scrolls the wall opposite
// the mouse motion just like a stationary environment behind the target.
[[nodiscard]] bool AppendWorldGrid(std::vector<RenderVertex>& vertices,
                                   std::int64_t camera_x_counts,
                                   std::int64_t camera_y_counts,
                                   double radians_per_count,
                                   unsigned int viewport_width,
                                   unsigned int viewport_height);

}  // namespace GridRenderer
