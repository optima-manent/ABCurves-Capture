#include "render/UiTextLayout.h"

#include "render/HudRenderer.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace UiTextLayout {
namespace {

std::string Trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    return value;
}

}  // namespace

std::vector<std::string> Wrap(const std::string_view text, const float maximum_width,
                              const double scale, const std::size_t maximum_lines) {
    if (maximum_width <= 0.0F || maximum_lines == 0U) {
        throw std::invalid_argument("text layout bounds must be positive");
    }
    const float character_width = HudRenderer::TextWidth("M", scale);
    const auto capacity = std::max<std::size_t>(1U,
        static_cast<std::size_t>(maximum_width / character_width));
    std::vector<std::string> lines;
    std::string remaining = Trim(std::string(text));
    while (!remaining.empty() && lines.size() < maximum_lines) {
        if (remaining.size() <= capacity) {
            lines.push_back(std::move(remaining));
            break;
        }
        std::size_t split = remaining.rfind(' ', capacity);
        if (split == std::string::npos || split == 0U) split = capacity;
        lines.push_back(Trim(remaining.substr(0, split)));
        remaining = Trim(remaining.substr(split));
    }
    if (!remaining.empty() && !lines.empty()) {
        auto& last = lines.back();
        if (capacity <= 3U) last.assign(capacity, '.');
        else {
            if (last.size() > capacity - 3U) last.resize(capacity - 3U);
            last = Trim(std::move(last)) + "...";
        }
    }
    return lines;
}

}  // namespace UiTextLayout
