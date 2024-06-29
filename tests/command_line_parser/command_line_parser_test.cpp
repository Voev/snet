#include <gtest/gtest.h>
#include <snet/utils/options_parser.hpp>
#include <filesystem>

using namespace snet;

class CommandLineParserTest : public testing::Test {
public:
    CommandLineParserTest() = default;
    ~CommandLineParserTest() = default;

    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(CommandLineParserTest, ExpectSuccess) {
    utils::OptionsParser parser;
    std::filesystem::path path;

    parser.add("help, h", "Print help message");
    parser.add("foo, f", utils::Value(&path), "Valued option");

    parser.help(std::cout);
    std::vector<std::string> input{"--help", "--foo", "/etc/"};
    
    parser.parse(input);

    ASSERT_TRUE(parser.isUsed("h"));
    ASSERT_TRUE(parser.isUsed("help"));
    

    ASSERT_EQ(path, "/etc/");
}
//ssINSTANTIATE_TEST_SUITE_P(RsaTests, CommandLineParserTest, testing::Values(1024, 2048, 4096));