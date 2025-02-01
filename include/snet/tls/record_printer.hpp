#pragma once
#include <iosfwd>
#include <snet/tls/i_record_handler.hpp>

namespace snet::tls
{

class RecordPrinter final : public tls::IRecordHandler
{
public:
    RecordPrinter();

    ~RecordPrinter() noexcept;

    void handleRecord(const std::int8_t sideIndex, const tls::Record& record) override;
};

} // namespace snet::tls