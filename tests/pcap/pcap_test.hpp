#pragma once
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <snet/io.hpp>

#include <snet/config_parser/config_parser.hpp>

using TestParam = std::pair<const std::string, ConfigParser::Section>;

class PcapTestImpl
{
public:
    PcapTestImpl() = default;

    virtual ~PcapTestImpl() = default;

    virtual void execute() = 0;

    void setUp(const TestParam& param);

    void tearDown();

    bool skipped() const
    {
        return skipped_;
    }

private:
    PcapTestImpl(const PcapTestImpl&) = delete;
    PcapTestImpl(PcapTestImpl&&) = delete;

    PcapTestImpl& operator=(const PcapTestImpl&) = delete;
    PcapTestImpl& operator=(PcapTestImpl&&) = delete;

protected:
    std::shared_ptr<snet::io::Driver> driver_;

private:
    bool skipped_ = false;
};


class PcapTest : public testing::TestWithParam<TestParam>
{
public:
    PcapTest() = default;
    ~PcapTest() = default;

    void SetUp() override
    {
        ASSERT_NO_THROW(test_ = makeTest(GetParam()));
        ASSERT_NO_THROW(test_->setUp(GetParam()));
    }

    void TearDown() override
    {
        if (test_)
        {
            ASSERT_NO_THROW(test_->tearDown());
        }
    }

    static std::unique_ptr<PcapTestImpl> makeTest(const TestParam&);

protected:
    std::unique_ptr<PcapTestImpl> test_;
};