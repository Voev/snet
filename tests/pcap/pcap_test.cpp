#include <iomanip>
#include <cctype>
#include <string>

#include <gtest/gtest.h>
#include <casket/utils/string.hpp>

#include <snet/io.hpp>
#include <snet/config_parser/config_parser.hpp>

#include "pcap_test.hpp"
#include "decrypt_by_keylog_test.hpp"
#include "controller_manager.hpp"

using namespace snet;

inline void NameGeneratorFiltering(std::string& name)
{
    for (auto& i : name)
    {
        if (!isalpha(i) && !isdigit(i) && i != '_')
        {
            i = '_';
        }
    }
}

static std::string NameGenerator(const testing::TestParamInfo<TestParam>& info)
{
    std::string name = info.param.first;
    NameGeneratorFiltering(name);
    return name;
}

void PcapTestImpl::setUp(const TestParam& param)
{
    io::Controller controller;

    auto option = param.second.find("pcap");
    ASSERT_NE(option, param.second.end());

    auto skipped = param.second.find("skip");
    if (skipped != param.second.end())
    {
        skipped_ = casket::iequals(skipped->second, "yes");
    }

    io::Config config;
    config.setInput(option->second);
    config.setMsgPoolSize(128);
    config.setTimeout(0);
    config.setSnaplen(2048);
    config.setMode(Mode::ReadFile);

    driver_ = ControllerManager::Instance().getDriver("pcap");
    ASSERT_NE(driver_, nullptr) << "driver was not found";

    ASSERT_EQ(Status::Success, driver_->configure(config));
    ASSERT_EQ(Status::Success, driver_->start());
}

void PcapTestImpl::tearDown()
{
    if (driver_)
    {
        driver_->stop();
    }
}

std::unique_ptr<PcapTestImpl> PcapTest::makeTest(const TestParam& param)
{
    if (param.first.find("decrypt_by_keylog") != std::string::npos)
    {
        return std::make_unique<DecryptByKeylog>(param.second);
    }

    return nullptr;
}

TEST_P(PcapTest, CheckPcapFile)
{
    try
    {
        ASSERT_NE(test_, nullptr) << "test wasn't created";

        if (test_->skipped())
        {
            GTEST_SKIP();
        }

        ASSERT_NO_THROW(test_->execute());
        GTEST_SUCCEED();
    }
    catch (std::exception& exc)
    {
        GTEST_FAIL() << exc.what();
    }
}

INSTANTIATE_TEST_CASE_P(PcapTests, PcapTest, testing::ValuesIn(ConfigParser::Instance().getSections()), NameGenerator);