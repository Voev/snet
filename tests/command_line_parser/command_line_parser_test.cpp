#include <gtest/gtest.h>
#include <snet/utils/options_parser.hpp>

using namespace snet;

class CommandLineParserTest : public testing::Test {
public:
    CommandLineParserTest() = default;
    ~CommandLineParserTest() = default;

    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(CommandLineParserTest, ExpectSuccess) {
    utils::ArgumentParser parser;

    parser.add("help, h", "Print help message", utils::OptionType::NoValue);
    parser.add("foo, f", "Valued option", utils::OptionType::SingleValue);

    std::cout << parser.help() << std::endl;
    std::vector<std::string> input{"--help", "--foo", "value"};
    parser.parse(input);

    ASSERT_TRUE(parser.is_used("h"));
    ASSERT_TRUE(parser.is_used("help"));
    

    auto value = parser.get("foo");
    ASSERT_EQ(value, "value");
}

//ssINSTANTIATE_TEST_SUITE_P(RsaTests, CommandLineParserTest, testing::Values(1024, 2048, 4096));