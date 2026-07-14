#include "base/Json.h"

#include <charconv>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace abdc::json {
namespace {

class Parser final {
public:
    explicit Parser(const std::string_view text) : text_(text) {}

    Value ParseRoot() {
        SkipWhitespace();
        auto value = ParseValue();
        SkipWhitespace();
        if (position_ != text_.size()) Fail("trailing content");
        return value;
    }

private:
    [[noreturn]] void Fail(const char* message) const {
        throw std::runtime_error(std::string("JSON ") + message + " at byte " + std::to_string(position_));
    }

    void SkipWhitespace() {
        while (position_ < text_.size()) {
            const char c = text_[position_];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            ++position_;
        }
    }

    bool Consume(const char c) {
        if (position_ < text_.size() && text_[position_] == c) { ++position_; return true; }
        return false;
    }

    Value ParseValue() {
        if (position_ >= text_.size()) Fail("unexpected end");
        switch (text_[position_]) {
        case 'n': Expect("null"); return nullptr;
        case 't': Expect("true"); return true;
        case 'f': Expect("false"); return false;
        case '"': return ParseString();
        case '[': return ParseArray();
        case '{': return ParseObject();
        default:
            if (text_[position_] == '-' || (text_[position_] >= '0' && text_[position_] <= '9')) return ParseNumber();
            Fail("unexpected token");
        }
    }

    void Expect(const std::string_view token) {
        if (text_.substr(position_, token.size()) != token) Fail("invalid literal");
        position_ += token.size();
    }

    static int Hex(const char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    std::uint32_t ParseHex4() {
        if (position_ + 4 > text_.size()) Fail("truncated unicode escape");
        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            const int digit = Hex(text_[position_++]);
            if (digit < 0) Fail("invalid unicode escape");
            value = (value << 4U) | static_cast<unsigned>(digit);
        }
        return value;
    }

    static void AppendUtf8(std::string& out, const std::uint32_t codepoint) {
        if (codepoint > 0x10ffffU || (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            throw std::runtime_error("JSON invalid Unicode scalar");
        }
        if (codepoint <= 0x7fU) out.push_back(static_cast<char>(codepoint));
        else if (codepoint <= 0x7ffU) {
            out.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else if (codepoint <= 0xffffU) {
            out.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else {
            out.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        }
    }

    std::string ParseString() {
        if (!Consume('"')) Fail("expected string");
        std::string out;
        while (position_ < text_.size()) {
            const unsigned char c = static_cast<unsigned char>(text_[position_++]);
            if (c == '"') return out;
            if (c < 0x20U) Fail("control byte in string");
            if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
            if (position_ >= text_.size()) Fail("truncated string escape");
            const char escaped = text_[position_++];
            switch (escaped) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                std::uint32_t codepoint = ParseHex4();
                if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
                    if (position_ + 2 > text_.size() || text_[position_] != '\\' || text_[position_ + 1] != 'u') {
                        Fail("missing low surrogate");
                    }
                    position_ += 2;
                    const auto low = ParseHex4();
                    if (low < 0xdc00U || low > 0xdfffU) Fail("invalid low surrogate");
                    codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U) + (low - 0xdc00U);
                } else if (codepoint >= 0xdc00U && codepoint <= 0xdfffU) {
                    Fail("orphan low surrogate");
                }
                AppendUtf8(out, codepoint);
                break;
            }
            default: Fail("invalid string escape");
            }
        }
        Fail("unterminated string");
    }

    Value ParseArray() {
        Consume('[');
        Value::Array array;
        SkipWhitespace();
        if (Consume(']')) return array;
        for (;;) {
            SkipWhitespace();
            array.push_back(ParseValue());
            SkipWhitespace();
            if (Consume(']')) return array;
            if (!Consume(',')) Fail("expected array comma");
        }
    }

    Value ParseObject() {
        Consume('{');
        Value::Object object;
        SkipWhitespace();
        if (Consume('}')) return object;
        for (;;) {
            SkipWhitespace();
            if (position_ >= text_.size() || text_[position_] != '"') Fail("expected object key");
            auto key = ParseString();
            SkipWhitespace();
            if (!Consume(':')) Fail("expected object colon");
            SkipWhitespace();
            auto [it, inserted] = object.emplace(std::move(key), ParseValue());
            if (!inserted) Fail("duplicate object key");
            SkipWhitespace();
            if (Consume('}')) return object;
            if (!Consume(',')) Fail("expected object comma");
        }
    }

    Value ParseNumber() {
        const std::size_t start = position_;
        Consume('-');
        if (position_ >= text_.size()) Fail("truncated number");
        if (text_[position_] == '0') ++position_;
        else {
            if (text_[position_] < '1' || text_[position_] > '9') Fail("invalid number integer");
            while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') ++position_;
        }
        bool integer = true;
        if (Consume('.')) {
            integer = false;
            const auto fraction_start = position_;
            while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') ++position_;
            if (position_ == fraction_start) Fail("empty number fraction");
        }
        if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E')) {
            integer = false; ++position_;
            if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-')) ++position_;
            const auto exponent_start = position_;
            while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') ++position_;
            if (position_ == exponent_start) Fail("empty exponent");
        }
        const auto token = text_.substr(start, position_ - start);
        if (integer) {
            std::int64_t value = 0;
            const auto result = std::from_chars(token.data(), token.data() + token.size(), value);
            if (result.ec == std::errc{} && result.ptr == token.data() + token.size()) return value;
        }
        std::string owned(token);
        char* end = nullptr;
        const double value = std::strtod(owned.c_str(), &end);
        if (end != owned.c_str() + owned.size() || !std::isfinite(value)) Fail("invalid finite number");
        return value;
    }

    std::string_view text_;
    std::size_t position_ = 0;
};

void Escape(std::ostringstream& out, const std::string& value) {
    out << '"';
    static constexpr char kHex[] = "0123456789abcdef";
    for (const unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20U) out << "\\u00" << kHex[c >> 4U] << kHex[c & 0x0fU];
            else out << static_cast<char>(c);
        }
    }
    out << '"';
}

void Dump(std::ostringstream& out, const Value& value, const bool pretty, const int depth) {
    const auto indent = [&](const int extra = 0) {
        if (pretty) out << std::string(static_cast<std::size_t>((depth + extra) * 2), ' ');
    };
    std::visit([&](const auto& item) {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) out << "null";
        else if constexpr (std::is_same_v<T, bool>) out << (item ? "true" : "false");
        else if constexpr (std::is_same_v<T, std::int64_t>) out << item;
        else if constexpr (std::is_same_v<T, double>) {
            if (!std::isfinite(item)) throw std::runtime_error("cannot serialize non-finite JSON number");
            out << std::setprecision(17) << item;
        } else if constexpr (std::is_same_v<T, std::string>) Escape(out, item);
        else if constexpr (std::is_same_v<T, Value::Array>) {
            out << '[';
            if (!item.empty()) {
                for (std::size_t i = 0; i < item.size(); ++i) {
                    if (i != 0) out << ',';
                    if (pretty) { out << '\n'; indent(1); }
                    Dump(out, item[i], pretty, depth + 1);
                }
                if (pretty) { out << '\n'; indent(); }
            }
            out << ']';
        } else if constexpr (std::is_same_v<T, Value::Object>) {
            out << '{';
            std::size_t i = 0;
            for (const auto& [key, child] : item) {
                if (i++ != 0) out << ',';
                if (pretty) { out << '\n'; indent(1); }
                Escape(out, key); out << (pretty ? ": " : ":");
                Dump(out, child, pretty, depth + 1);
            }
            if (!item.empty() && pretty) { out << '\n'; indent(); }
            out << '}';
        }
    }, value.Data());
}

}  // namespace

bool Value::IsNull() const { return std::holds_alternative<std::nullptr_t>(data_); }
bool Value::AsBool() const { return std::get<bool>(data_); }
std::int64_t Value::AsInt() const { return std::get<std::int64_t>(data_); }
double Value::AsDouble() const {
    if (const auto* value = std::get_if<double>(&data_)) return *value;
    return static_cast<double>(std::get<std::int64_t>(data_));
}
const std::string& Value::AsString() const { return std::get<std::string>(data_); }
const Value::Array& Value::AsArray() const { return std::get<Array>(data_); }
const Value::Object& Value::AsObject() const { return std::get<Object>(data_); }
Value::Array& Value::AsArray() { return std::get<Array>(data_); }
Value::Object& Value::AsObject() { return std::get<Object>(data_); }

const Value& Value::At(const std::string_view key) const {
    const auto& object = AsObject();
    const auto it = object.find(key);
    if (it == object.end()) throw std::out_of_range("missing JSON key: " + std::string(key));
    return it->second;
}

Value& Value::operator[](std::string key) {
    if (IsNull()) data_ = Object{};
    return AsObject()[std::move(key)];
}

Value Parse(const std::string_view text) { return Parser(text).ParseRoot(); }

std::string DumpCanonical(const Value& value, const bool pretty) {
    std::ostringstream out;
    Dump(out, value, pretty, 0);
    if (pretty) out << '\n';
    return out.str();
}

}  // namespace abdc::json

