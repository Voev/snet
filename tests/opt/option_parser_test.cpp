#include <gtest/gtest.h>
#include <snet/opt/option_parser.hpp>
#include <filesystem>

using namespace snet;

TEST(CommandLineParserTest, ExpectSuccess) {
    opt::OptionParser parser;
    std::filesystem::path path;

    parser.add("help, h", "Print help message");
    parser.add("foo, f", opt::Value(&path), "Valued option");

    parser.help(std::cout);
    std::vector<std::string> input{"--help", "--foo", "/etc/"};
    
    parser.parse(input);

    ASSERT_TRUE(parser.isUsed("h"));
    ASSERT_TRUE(parser.isUsed("help"));

    ASSERT_EQ(path, "/etc/");
}
