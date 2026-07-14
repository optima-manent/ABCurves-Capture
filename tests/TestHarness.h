#pragma once

#include <exception>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace abdc::test {

struct Case { std::string name; std::function<void()> run; };
std::vector<Case>& Registry();

class Register final {
public:
    Register(std::string name, std::function<void()> run) {
        Registry().push_back({std::move(name), std::move(run)});
    }
};

template <typename A, typename B>
void Equal(const A& actual, const B& expected, const char* actual_text,
           const char* expected_text, const char* file, int line) {
    if (!(actual == expected)) {
        std::ostringstream out;
        out << file << ':' << line << ": expected " << actual_text
            << " == " << expected_text;
        throw std::runtime_error(out.str());
    }
}

inline void True(bool value, const char* text, const char* file, int line) {
    if (!value) {
        throw std::runtime_error(std::string(file) + ':' + std::to_string(line) +
                                 ": expected " + text);
    }
}

template <typename Callable>
void Throws(Callable&& callable, const char* text, const char* file, int line) {
    try {
        std::forward<Callable>(callable)();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error(std::string(file) + ':' + std::to_string(line) +
                             ": expected exception: " + text);
}

}  // namespace abdc::test

#define ABDC_TEST_JOIN_INNER(a, b) a##b
#define ABDC_TEST_JOIN(a, b) ABDC_TEST_JOIN_INNER(a, b)
#define TEST_CASE(name) \
    static void ABDC_TEST_JOIN(Test_, __LINE__)(); \
    static ::abdc::test::Register ABDC_TEST_JOIN(Register_, __LINE__)( \
        name, ABDC_TEST_JOIN(Test_, __LINE__)); \
    static void ABDC_TEST_JOIN(Test_, __LINE__)()
#define EXPECT_TRUE(value) \
    ::abdc::test::True(static_cast<bool>(value), #value, __FILE__, __LINE__)
#define EXPECT_EQ(actual, expected) \
    ::abdc::test::Equal((actual), (expected), #actual, #expected, __FILE__, __LINE__)
#define EXPECT_THROW(expression) \
    ::abdc::test::Throws([&] { (void)(expression); }, #expression, __FILE__, __LINE__)

