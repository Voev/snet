#pragma once
#include <snet/tls/record.hpp>

namespace snet::tls
{

class IRecordHandler
{
public:
    IRecordHandler() = default;

    virtual ~IRecordHandler() = default;

    virtual void handleRecord(const std::int8_t sideIndex, const Record& record) = 0;
};

} // namespace snet::tls