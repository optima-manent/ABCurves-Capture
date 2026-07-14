#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace abdc::capture {

struct HidField {
    std::uint8_t report_id = 0;
    std::uint16_t usage_page = 0;
    std::uint16_t usage = 0;
    std::uint32_t bit_offset = 0;
    std::uint8_t bit_size = 0;
    std::int64_t logical_minimum = 0;
    std::int64_t logical_maximum = 0;
    bool relative = false;
};

struct MouseReportLayout {
    std::uint8_t report_id = 0;
    std::size_t byte_length = 0;
    HidField x;
    HidField y;
    std::optional<HidField> wheel;
    std::optional<HidField> horizontal_wheel;
    std::vector<HidField> buttons;
};

struct DecodedMouseReport {
    std::uint8_t report_id = 0;
    std::int32_t dx = 0;
    std::int32_t dy = 0;
    std::int32_t wheel = 0;
    std::int32_t horizontal_wheel = 0;
    std::uint32_t buttons = 0;
    std::vector<std::byte> payload;
};

struct HidApplicationCollection {
    std::uint16_t usage_page = 0;
    std::uint16_t usage = 0;
};

class HidDescriptor final {
public:
    static HidDescriptor Parse(std::span<const std::byte> descriptor);

    [[nodiscard]] const std::vector<HidField>& InputFields() const { return fields_; }
    [[nodiscard]] std::vector<MouseReportLayout> RelativeMouseLayouts() const;
    [[nodiscard]] std::string CanonicalDecoderSpec() const;
    [[nodiscard]] bool UsesReportIds() const { return uses_report_ids_; }
    [[nodiscard]] std::size_t MaximumInputReportByteLength() const;
    [[nodiscard]] const std::vector<HidApplicationCollection>&
    TopLevelApplicationCollections() const { return application_collections_; }

private:
    std::vector<HidField> fields_;
    std::vector<HidApplicationCollection> application_collections_;
    std::map<std::uint8_t, std::uint32_t> report_bits_;
    bool uses_report_ids_ = false;
};

class HidMouseDecoder final {
public:
    explicit HidMouseDecoder(std::vector<MouseReportLayout> layouts);

    [[nodiscard]] const std::vector<MouseReportLayout>& Layouts() const { return layouts_; }
    [[nodiscard]] std::vector<DecodedMouseReport> DecodeBatch(std::span<const std::byte> payload) const;

private:
    const MouseReportLayout& LayoutFor(std::uint8_t report_id) const;
    std::vector<MouseReportLayout> layouts_;
    bool uses_report_ids_ = false;
};

}  // namespace abdc::capture
