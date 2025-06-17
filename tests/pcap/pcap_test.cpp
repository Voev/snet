#include <iomanip>
#include <gtest/gtest.h>
#include "pcap_test.hpp"
#include "config_parser.hpp"
#include "decrypt_by_keylog_test.hpp"
#include "controller_manager.hpp"

#include <snet/io.hpp>

using namespace snet;

static std::string NameGenerator(const testing::TestParamInfo<TestParam>& info)
{
    std::string name = info.param.first;
    return name;
}

void PcapTestImpl::setUp(const TestParam& param)
{
    io::Controller controller;

    auto option = param.second.find("pcap_file");
    ASSERT_NE(option, param.second.end());

    io::Config config;
    config.setInput(option->second);
    config.setMsgPoolSize(128);
    config.setTimeout(0);
    config.setSnaplen(2048);

    driver_ = ControllerManager::Instance().getDriver("pcap");
    ASSERT_NE(driver_, nullptr) << "driver was not found";

    driver_->configure(config);
    driver_->start();
}

void PcapTestImpl::tearDown()
{
    driver_->stop();
}


std::unique_ptr<PcapTestImpl> PcapTest::makeTest(const TestParam& param)
{
    if (param.first.find("decrypt_by_keylog") != std::string::npos)
        return std::make_unique<DecryptByKeylog>(param.second);

    return nullptr;
}

TEST_P(PcapTest, CheckPcapFile)
{
    try
    {
        auto executor = makeTest(GetParam());
        ASSERT_NE(executor, nullptr);
        
        if (executor->getExecutable())
        {
            GTEST_SKIP();
        }

        ASSERT_NO_THROW(executor->execute());
        GTEST_SUCCEED();
    }
    catch (std::exception& exc)
    {
        GTEST_FAIL() << exc.what();
    }
}

INSTANTIATE_TEST_CASE_P(PcapTests, PcapTest, testing::ValuesIn(ConfigParser::Instance().getSections()), NameGenerator);