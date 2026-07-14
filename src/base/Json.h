#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace abdc::json {

class Value final {
public:
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value, std::less<>>;
    using Storage = std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object>;

    Value() : data_(nullptr) {}
    Value(std::nullptr_t) : data_(nullptr) {}
    Value(bool value) : data_(value) {}
    Value(std::int64_t value) : data_(value) {}
    Value(int value) : data_(static_cast<std::int64_t>(value)) {}
    Value(double value) : data_(value) {}
    Value(std::string value) : data_(std::move(value)) {}
    Value(const char* value) : data_(std::string(value)) {}
    Value(Array value) : data_(std::move(value)) {}
    Value(Object value) : data_(std::move(value)) {}

    [[nodiscard]] const Storage& Data() const { return data_; }
    [[nodiscard]] bool IsNull() const;
    [[nodiscard]] bool AsBool() const;
    [[nodiscard]] std::int64_t AsInt() const;
    [[nodiscard]] double AsDouble() const;
    [[nodiscard]] const std::string& AsString() const;
    [[nodiscard]] const Array& AsArray() const;
    [[nodiscard]] const Object& AsObject() const;
    Array& AsArray();
    Object& AsObject();
    const Value& At(std::string_view key) const;
    Value& operator[](std::string key);

private:
    Storage data_;
};

Value Parse(std::string_view text);
std::string DumpCanonical(const Value& value, bool pretty = true);

}  // namespace abdc::json

