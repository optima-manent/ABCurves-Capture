#include "TestHarness.h"

#include <algorithm>
#include <iostream>

namespace abdc::test {

std::vector<Case>& Registry() {
    static std::vector<Case> tests;
    return tests;
}

}  // namespace abdc::test

int main() {
    auto& tests = abdc::test::Registry();
    std::sort(tests.begin(), tests.end(),
              [](const auto& left, const auto& right) {
                  return left.name < right.name;
              });
    std::size_t failures = 0;
    for (const auto& test : tests) {
        try {
            test.run();
            std::cout << "PASS " << test.name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "FAIL " << test.name << ": " << error.what() << '\n';
        }
    }
    std::cout << "RESULT " << (tests.size() - failures) << '/' << tests.size()
              << " passed\n";
    return failures == 0U ? 0 : 1;
}

