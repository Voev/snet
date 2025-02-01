#include <snet/tls/record_processor.hpp>
#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

void RecordProcessor::process(const std::int8_t sideIndex, std::span<const uint8_t> inputBytes)
{
    std::size_t consumedBytes{0U};
    ThrowIfTrue(reader_ == nullptr, "Record reader is not setted");
    while (inputBytes.size_bytes() > 0)
    {
        auto record = reader_->readRecord(sideIndex, inputBytes, consumedBytes);
        for (const auto& handler : handlers_)
        {
            handler->handleRecord(sideIndex, record);
        }
        inputBytes = inputBytes.subspan(consumedBytes);
    }
}

} // namespace snet::tls