#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace UiTextLayout {

[[nodiscard]] std::vector<std::string> Wrap(
    std::string_view text, float maximum_width, double scale,
    std::size_t maximum_lines = 3U);

}  // namespace UiTextLayout
