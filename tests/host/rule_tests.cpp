#include <Rule.hpp>

#include <gtest/gtest.h>

#include <regex>
#include <string>

namespace {

std::regex compileRuleRegex(const Rule &rule) {
    return std::regex(rule.regex(), std::regex::extended);
}

TEST(RuleTest, WildcardRuleTreatsOnlyStarAndQuestionAsSpecial) {
    const Rule rule(Rule::WILDCARD, 1, "api+*.example?.com");

    ASSERT_TRUE(rule.valid());
    EXPECT_TRUE(std::regex_match("api+edge.example1.com", compileRuleRegex(rule)));
    EXPECT_FALSE(std::regex_match("apiedge.example1.com", compileRuleRegex(rule)));
    EXPECT_FALSE(std::regex_match("api+edge.example12.com", compileRuleRegex(rule)));
}

TEST(RuleTest, DomainTypeCurrentlyPassesPatternThroughAsRegex) {
    const Rule rule(Rule::DOMAIN, 2, "example.com");

    ASSERT_TRUE(rule.valid());
    EXPECT_TRUE(std::regex_match("example.com", compileRuleRegex(rule)));
    EXPECT_TRUE(std::regex_match("exampleXcom", compileRuleRegex(rule)));
    EXPECT_FALSE(std::regex_match("sub.example.com", compileRuleRegex(rule)));
}

TEST(RuleTest, InvalidRegexIsRejected) {
    const Rule rule(Rule::REGEX, 3, "(");

    EXPECT_FALSE(rule.valid());
}

} // namespace
