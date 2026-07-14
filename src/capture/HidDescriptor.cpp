#include "capture/HidDescriptor.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace abdc::capture {
namespace {

struct Globals {
    std::uint32_t usage_page = 0;
    std::int64_t logical_minimum = 0;
    std::int64_t logical_maximum = 0;
    std::uint32_t report_size = 0;
    std::uint32_t report_count = 0;
    std::uint8_t report_id = 0;
};

struct Locals {
    std::vector<std::uint32_t> usages;
    std::uint32_t usage_minimum = 0;
    std::uint32_t usage_maximum = 0;
    bool has_usage_range = false;
    void Reset() { usages.clear(); usage_minimum = usage_maximum = 0; has_usage_range = false; }
};

std::uint32_t ReadUnsigned(const std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[i])) << (8U * i);
    }
    return value;
}

std::int64_t ReadSigned(const std::span<const std::byte> bytes) {
    if (bytes.empty()) return 0;
    std::uint64_t value = ReadUnsigned(bytes);
    const unsigned bits = static_cast<unsigned>(bytes.size() * 8U);
    if ((value & (std::uint64_t{1} << (bits - 1U))) != 0) {
        value |= (~std::uint64_t{0}) << bits;
    }
    return static_cast<std::int64_t>(value);
}

std::uint32_t UsageForIndex(const Locals& locals, const std::uint32_t index) {
    if (index < locals.usages.size()) return locals.usages[index];
    if (locals.has_usage_range && locals.usage_minimum + index <= locals.usage_maximum) {
        return locals.usage_minimum + index;
    }
    if (!locals.usages.empty()) return locals.usages.back();
    return 0;
}

std::uint64_t ExtractBits(const std::span<const std::byte> bytes, const std::uint32_t bit_offset,
                          const std::uint8_t bit_size) {
    if (bit_size == 0 || bit_size > 32) throw std::runtime_error("unsupported HID field width");
    if (static_cast<std::uint64_t>(bit_offset) + bit_size > static_cast<std::uint64_t>(bytes.size()) * 8U) {
        throw std::runtime_error("partial HID input report");
    }
    std::uint64_t value = 0;
    for (std::uint8_t bit = 0; bit < bit_size; ++bit) {
        const std::uint32_t source = bit_offset + bit;
        const auto byte = std::to_integer<std::uint8_t>(bytes[source / 8U]);
        if ((byte & (1U << (source % 8U))) != 0) value |= std::uint64_t{1} << bit;
    }
    return value;
}

std::int32_t DecodeValue(const HidField& field, const std::span<const std::byte> report) {
    std::uint64_t raw = ExtractBits(report, field.bit_offset, field.bit_size);
    std::int64_t value = static_cast<std::int64_t>(raw);
    if (field.logical_minimum < 0 && field.bit_size < 64 &&
        (raw & (std::uint64_t{1} << (field.bit_size - 1U))) != 0) {
        raw |= (~std::uint64_t{0}) << field.bit_size;
        value = static_cast<std::int64_t>(raw);
    }
    if (value < field.logical_minimum || value > field.logical_maximum) {
        throw std::runtime_error("HID logical value outside descriptor range");
    }
    if (value < std::numeric_limits<std::int32_t>::min() || value > std::numeric_limits<std::int32_t>::max()) {
        throw std::runtime_error("HID logical value exceeds int32");
    }
    return static_cast<std::int32_t>(value);
}

}  // namespace

HidDescriptor HidDescriptor::Parse(const std::span<const std::byte> descriptor) {
    if (descriptor.empty() || descriptor.size() > 64U * 1024U) {
        throw std::runtime_error("invalid HID report descriptor length");
    }
    HidDescriptor parsed;
    Globals globals;
    Locals locals;
    std::vector<Globals> stack;
    std::size_t collection_depth = 0;
    parsed.report_bits_[0] = 0;

    std::size_t offset = 0;
    while (offset < descriptor.size()) {
        const auto prefix = std::to_integer<std::uint8_t>(descriptor[offset++]);
        if (prefix == 0xfeU) throw std::runtime_error("HID long items are unsupported");
        const std::size_t size_code = prefix & 0x03U;
        const std::size_t item_size = size_code == 3 ? 4 : size_code;
        if (offset + item_size > descriptor.size()) throw std::runtime_error("truncated HID item");
        const auto data = descriptor.subspan(offset, item_size);
        offset += item_size;
        const std::uint8_t type = (prefix >> 2U) & 0x03U;
        const std::uint8_t tag = (prefix >> 4U) & 0x0fU;
        const std::uint32_t uvalue = ReadUnsigned(data);

        if (type == 1) {
            switch (tag) {
            case 0: globals.usage_page = uvalue; break;
            case 1: globals.logical_minimum = ReadSigned(data); break;
            case 2:
                globals.logical_maximum = globals.logical_minimum < 0 ? ReadSigned(data)
                                                                        : static_cast<std::int64_t>(uvalue);
                break;
            case 7: globals.report_size = uvalue; break;
            case 8:
                if (uvalue == 0 || uvalue > 255) throw std::runtime_error("invalid HID report ID");
                globals.report_id = static_cast<std::uint8_t>(uvalue);
                parsed.uses_report_ids_ = true;
                if (!parsed.report_bits_.contains(globals.report_id)) parsed.report_bits_[globals.report_id] = 8;
                break;
            case 9: globals.report_count = uvalue; break;
            case 10: stack.push_back(globals); break;
            case 11:
                if (stack.empty()) throw std::runtime_error("HID global pop underflow");
                globals = stack.back(); stack.pop_back(); break;
            default: break;
            }
        } else if (type == 2) {
            switch (tag) {
            case 0: locals.usages.push_back(uvalue); break;
            case 1: locals.usage_minimum = uvalue; locals.has_usage_range = true; break;
            case 2: locals.usage_maximum = uvalue; locals.has_usage_range = true; break;
            default: break;
            }
        } else if (type == 0) {
            if (tag == 10) {
                if (item_size == 0U) {
                    throw std::runtime_error("HID collection item has no collection type");
                }
                if (collection_depth == 0U && (uvalue & 0xffU) == 1U) {
                    const auto combined_usage = UsageForIndex(locals, 0U);
                    HidApplicationCollection collection;
                    collection.usage_page = static_cast<std::uint16_t>(
                        combined_usage > 0xffffU ? combined_usage >> 16U
                                                 : globals.usage_page);
                    collection.usage =
                        static_cast<std::uint16_t>(combined_usage & 0xffffU);
                    parsed.application_collections_.push_back(collection);
                }
                ++collection_depth;
            } else if (tag == 12) {
                if (collection_depth == 0U) {
                    throw std::runtime_error("HID collection stack underflow");
                }
                --collection_depth;
            } else if (tag == 8) {
                if (globals.report_size == 0 || globals.report_size > 32 || globals.report_count == 0 ||
                    globals.report_count > 1024) {
                    throw std::runtime_error("unsafe HID input field dimensions");
                }
                const bool constant = (uvalue & 0x01U) != 0;
                const bool variable = (uvalue & 0x02U) != 0;
                const bool relative = (uvalue & 0x04U) != 0;
                auto& report_offset = parsed.report_bits_[globals.report_id];
                if (parsed.uses_report_ids_ && globals.report_id == 0) {
                    throw std::runtime_error("mixed zero and nonzero HID report IDs");
                }
                for (std::uint32_t i = 0; i < globals.report_count; ++i) {
                    if (!constant && variable) {
                        const auto combined_usage = UsageForIndex(locals, i);
                        HidField field;
                        field.report_id = globals.report_id;
                        field.usage_page = static_cast<std::uint16_t>(
                            combined_usage > 0xffffU ? combined_usage >> 16U : globals.usage_page);
                        field.usage = static_cast<std::uint16_t>(combined_usage & 0xffffU);
                        field.bit_offset = report_offset;
                        field.bit_size = static_cast<std::uint8_t>(globals.report_size);
                        field.logical_minimum = globals.logical_minimum;
                        field.logical_maximum = globals.logical_maximum;
                        field.relative = relative;
                        parsed.fields_.push_back(field);
                    }
                    if (report_offset > std::numeric_limits<std::uint32_t>::max() - globals.report_size) {
                        throw std::runtime_error("HID report bit length overflow");
                    }
                    report_offset += globals.report_size;
                }
            }
            locals.Reset();
        }
    }
    if (!stack.empty()) throw std::runtime_error("unterminated HID global push");
    if (collection_depth != 0U) throw std::runtime_error("unterminated HID collection");
    if (parsed.fields_.empty()) throw std::runtime_error("HID descriptor contains no variable input fields");
    return parsed;
}

std::vector<MouseReportLayout> HidDescriptor::RelativeMouseLayouts() const {
    std::vector<MouseReportLayout> layouts;
    for (const auto& [report_id, bits] : report_bits_) {
        std::vector<HidField> x_fields;
        std::vector<HidField> y_fields;
        std::vector<HidField> wheel_fields;
        std::vector<HidField> horizontal_wheel_fields;
        std::vector<HidField> buttons;
        for (const auto& field : fields_) {
            if (field.report_id != report_id) continue;
            if (field.usage_page == 0x01 && field.usage == 0x30) x_fields.push_back(field);
            if (field.usage_page == 0x01 && field.usage == 0x31) y_fields.push_back(field);
            if (field.usage_page == 0x01 && field.usage == 0x38) wheel_fields.push_back(field);
            // Consumer-page AC Pan is the conventional horizontal wheel.
            if (field.usage_page == 0x0c && field.usage == 0x0238) {
                horizontal_wheel_fields.push_back(field);
            }
            if (field.usage_page == 0x09 && field.usage >= 1 && field.usage <= 32) buttons.push_back(field);
        }
        if (x_fields.empty() && y_fields.empty()) continue;
        if (x_fields.size() != 1 || y_fields.size() != 1) {
            throw std::runtime_error("ambiguous HID X/Y fields in report ID");
        }
        if (!x_fields.front().relative || !y_fields.front().relative) {
            throw std::runtime_error("absolute-coordinate HID report is unsupported");
        }
        if (wheel_fields.size() > 1U || horizontal_wheel_fields.size() > 1U) {
            throw std::runtime_error("ambiguous HID wheel fields in report ID");
        }
        if (buttons.empty() || std::none_of(buttons.begin(), buttons.end(),
                                           [](const HidField& field) { return field.usage == 1; })) {
            throw std::runtime_error("mouse report lacks descriptor-derived left button");
        }
        MouseReportLayout layout;
        layout.report_id = report_id;
        layout.byte_length = (static_cast<std::size_t>(bits) + 7U) / 8U;
        layout.x = x_fields.front();
        layout.y = y_fields.front();
        if (!wheel_fields.empty()) layout.wheel = wheel_fields.front();
        if (!horizontal_wheel_fields.empty()) {
            layout.horizontal_wheel = horizontal_wheel_fields.front();
        }
        layout.buttons = std::move(buttons);
        layouts.push_back(std::move(layout));
    }
    if (layouts.empty()) throw std::runtime_error("no supported relative mouse input report layout");
    std::sort(layouts.begin(), layouts.end(), [](const auto& a, const auto& b) { return a.report_id < b.report_id; });
    return layouts;
}

std::string HidDescriptor::CanonicalDecoderSpec() const {
    std::ostringstream out;
    out << "abdc.hid.decoder.v1\nreport_ids=" << (uses_report_ids_ ? 1 : 0) << '\n';
    auto fields = fields_;
    std::sort(fields.begin(), fields.end(), [](const HidField& a, const HidField& b) {
        return std::tie(a.report_id, a.bit_offset, a.usage_page, a.usage) <
               std::tie(b.report_id, b.bit_offset, b.usage_page, b.usage);
    });
    for (const auto& field : fields) {
        out << "id=" << static_cast<unsigned>(field.report_id)
            << ",off=" << field.bit_offset
            << ",bits=" << static_cast<unsigned>(field.bit_size)
            << ",page=" << field.usage_page
            << ",usage=" << field.usage
            << ",min=" << field.logical_minimum
            << ",max=" << field.logical_maximum
            << ",rel=" << (field.relative ? 1 : 0) << '\n';
    }
    return out.str();
}

std::size_t HidDescriptor::MaximumInputReportByteLength() const {
    std::size_t maximum = 0;
    for (const auto& [report_id, bits] : report_bits_) {
        (void)report_id;
        maximum = std::max(maximum, (static_cast<std::size_t>(bits) + 7U) / 8U);
    }
    return maximum;
}

HidMouseDecoder::HidMouseDecoder(std::vector<MouseReportLayout> layouts) : layouts_(std::move(layouts)) {
    if (layouts_.empty()) throw std::invalid_argument("HID mouse decoder needs at least one layout");
    std::sort(layouts_.begin(), layouts_.end(), [](const auto& a, const auto& b) { return a.report_id < b.report_id; });
    for (std::size_t i = 0; i < layouts_.size(); ++i) {
        if (layouts_[i].byte_length == 0 || layouts_[i].byte_length > 4096) {
            throw std::invalid_argument("invalid HID input report byte length");
        }
        if (i != 0 && layouts_[i - 1].report_id == layouts_[i].report_id) {
            throw std::invalid_argument("duplicate HID report layout");
        }
    }
    uses_report_ids_ = layouts_.front().report_id != 0;
    if (std::any_of(layouts_.begin(), layouts_.end(), [this](const auto& layout) {
            return (layout.report_id != 0) != uses_report_ids_;
        })) {
        throw std::invalid_argument("mixed HID report-ID convention");
    }
}

const MouseReportLayout& HidMouseDecoder::LayoutFor(const std::uint8_t report_id) const {
    const auto it = std::lower_bound(layouts_.begin(), layouts_.end(), report_id,
                                     [](const MouseReportLayout& layout, const std::uint8_t id) {
                                         return layout.report_id < id;
                                     });
    if (it == layouts_.end() || it->report_id != report_id) throw std::runtime_error("unknown HID report ID");
    return *it;
}

std::vector<DecodedMouseReport> HidMouseDecoder::DecodeBatch(const std::span<const std::byte> payload) const {
    if (payload.empty()) throw std::runtime_error("empty HID transfer payload");
    std::vector<DecodedMouseReport> decoded;
    std::size_t offset = 0;
    while (offset < payload.size()) {
        const std::uint8_t id = uses_report_ids_ ? std::to_integer<std::uint8_t>(payload[offset]) : 0;
        const auto& layout = LayoutFor(id);
        if (layout.byte_length > payload.size() - offset) throw std::runtime_error("partial HID report in transfer");
        const auto report = payload.subspan(offset, layout.byte_length);
        DecodedMouseReport item;
        item.report_id = id;
        item.dx = DecodeValue(layout.x, report);
        item.dy = DecodeValue(layout.y, report);
        if (layout.wheel) item.wheel = DecodeValue(*layout.wheel, report);
        if (layout.horizontal_wheel) {
            item.horizontal_wheel = DecodeValue(*layout.horizontal_wheel, report);
        }
        for (const auto& button : layout.buttons) {
            const auto state = ExtractBits(report, button.bit_offset, button.bit_size);
            if (state != 0) item.buttons |= 1U << (button.usage - 1U);
        }
        item.payload.assign(report.begin(), report.end());
        decoded.push_back(std::move(item));
        offset += layout.byte_length;
    }
    return decoded;
}

}  // namespace abdc::capture
