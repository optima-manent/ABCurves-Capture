// Adapted from the user-owned AIM TRAINER reference for this project.
#pragma once

#include "render/RenderTypes.h"

#include <vector>

namespace CrosshairRenderer {
void AppendCrosshairAt(std::vector<RenderVertex>& vertices,
                       unsigned int viewport_width,
                       unsigned int viewport_height,
                       double scale,
                       float center_x,
                       float center_y);
void AppendCrosshair(std::vector<RenderVertex>& vertices,
                     unsigned int viewport_width,
                     unsigned int viewport_height,
                     double scale);
}

