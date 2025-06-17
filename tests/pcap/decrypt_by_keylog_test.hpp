#pragma once
#include <string>
#include <vector>

#include "config_parser.hpp"
#include "pcap_test.hpp"

class DecryptByKeylog final : public PcapTestImpl
{
public:
    explicit DecryptByKeylog(const ConfigParser::Section& section);
    void execute() override;

private:
    std::vector<std::string> params_;
};