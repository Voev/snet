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
    Record* readingRecord = session->readingRecord;

    while (processedLength < inputLength)
    {
        if (!readingRecord)
        {
            if (inputLength < processedLength + TLS_HEADER_SIZE)
            {
                break;
            }

            readingRecord = session->readingRecord = recordPool_.acquire();
            if (!readingRecord)
            {
                return processedLength;
            }

            readingRecord->deserializeHeader({inputBytes + processedLength, TLS_HEADER_SIZE});
        }

        processedLength += readingRecord->initPayload({inputBytes + processedLength, inputLength - processedLength});

        if (readingRecord->isFullyAssembled())
        {
            for (const auto& handler : handlers_)
            {
                handler->handleRecord(sideIndex, session, readingRecord);
            }
            readingRecord = nullptr;
        }
    }

    if (readingRecord != nullptr)
    {
        return 0;
    }

    return processedLength;
}

} // namespace snet::tls