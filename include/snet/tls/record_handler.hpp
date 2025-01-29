#pragma once
#include <snet/tls/record.hpp>

namespace snet::tls
{

class RecordHandler
{
public:
    virtual ~RecordHandler() = default;

    virtual void handleRecord(const std::int8_t sideIndex, const Record& record) = 0;
};

} // namespace snet::tls