#include <snet/tls/record_processor.hpp>

#include <casket/utils/exception.hpp>
#include <casket/log/log_manager.hpp>

#include <iostream>

using namespace casket::utils;
using namespace casket::log;

namespace snet::tls
{

size_t RecordProcessor::process(const int8_t sideIndex, Session* session, uint8_t* inputBytes, size_t inputLength)
{
    ThrowIfTrue(!inputBytes || !inputLength, "invalid input parameters");
    ThrowIfTrue(!session, "invalid session");

    size_t processedLength{0};
    Record* currentRecord = session->currentRecord;

    while (processedLength < inputLength)
    {
        if (!currentRecord)
        {
            if (inputLength < processedLength + TLS_HEADER_SIZE)
            {
                break;
            }

            currentRecord = session->currentRecord = recordPool_.acquire();
            if (!currentRecord)
            {
                return processedLength;
            }

            currentRecord->deserializeHeader({inputBytes + processedLength, TLS_HEADER_SIZE});
        }

        processedLength += currentRecord->initPayload({inputBytes + processedLength, inputLength - processedLength});

        if (currentRecord->isFullyAssembled())
        {
            for (const auto& handler : handlers_)
            {
                handler->handleRecord(sideIndex, session, currentRecord);
            }
            currentRecord = nullptr;
        }
    }

    if (currentRecord != nullptr)
    {
        return 0;
    }

    return processedLength;
}

} // namespace snet::tls