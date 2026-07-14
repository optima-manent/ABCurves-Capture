// Adapted from the user-owned AIM TRAINER reference for this project.
#pragma once

#include "render/RenderTypes.h"

#include <string>
#include <vector>

namespace HudRenderer {

float TextWidth(const std::string& text, double scale);
float TextHeight(double scale);
void AppendRect(std::vector<RenderVertex>& vertices, const RenderRect& rect);
void AppendOutline(std::vector<RenderVertex>& vertices,
                   float left,
                   float top,
                   float right,
                   float bottom,
                   float thickness,
                   RenderColor color);
void AppendText(std::vector<RenderVertex>& vertices, const RenderText& text);
void AppendUiLayer(std::vector<RenderVertex>& vertices, const RenderUiLayer& layer);

}

