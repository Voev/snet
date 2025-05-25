#include <snet/tls/record_processor.hpp>

#include <casket/utils/exception.hpp>
#include <casket/log/log_manager.hpp>

#include <iostream>

using namespace casket::utils;
using namespace casket::log;

namespace snet::tls
{

static inline void init_record(Record* record, const uint64_t seq, const int is_received_)
{
    (void)(is_received_);
    record->data = record->ciphertextBuffer;
    record->decrypted = record->plaintextBuffer;
    record->next_iv = NULL;
    record->current_len = 0;
    record->length = 0;
    record->seqnum = seq;
    record->is_decrypted = 0;

    record->is_reset = false;
}

// process_new_record
size_t RecordProcessor::process(const int8_t sideIndex, Session* session, uint8_t* inputBytes, size_t inputLength)
{
    size_t processedLength{0};
    Record* currentRecord{nullptr};

    while (processedLength < inputLength)
    {
        if (!currentRecord)
        {
            uint8_t* offset{nullptr};

            if (inputLength < processedLength + TLS_HEADER_SIZE)
                break;

            currentRecord = recordPool_.acquire();
            init_record(currentRecord, 0, true);

            if (!currentRecord)
                return processedLength;

            offset = inputBytes + processedLength;

            ThrowIfTrue(offset[0] < 20 || offset[0] > 23, "TLS record type had unexpected value");
            ThrowIfTrue(offset[1] != 3 || offset[2] >= 4, "TLS record version had unexpected value");

            currentRecord->type = static_cast<RecordType>(offset[0]);
            currentRecord->version = ProtocolVersion(offset[1], offset[2]);

            const size_t recordLength = utils::make_uint16(offset[TLS_HEADER_SIZE - 2], offset[TLS_HEADER_SIZE - 1]);
            ThrowIfTrue(recordLength > MAX_CIPHERTEXT_SIZE, "Received a record that exceeds maximum size");
            ThrowIfTrue(recordLength == 0, "Received a empty record");

            currentRecord->length = recordLength + TLS_HEADER_SIZE;

            const auto direction = (sideIndex == 0 ? "C->S" : "C<-S");
            std::cout << format("{}: {} {} [{}]", direction, currentRecord->version.toString(), toString(currentRecord->type),
                  currentRecord->length) << std::endl;
        }

        if (currentRecord->current_len > 0 || currentRecord->length + processedLength > inputLength)
        {
            auto copy_len = std::min(currentRecord->length - currentRecord->current_len, inputLength - processedLength);
            std::memcpy(currentRecord->data + currentRecord->current_len, inputBytes + processedLength, copy_len);
            currentRecord->current_len += copy_len;
            processedLength += copy_len;
        }
        else
        {
            currentRecord->data = inputBytes + processedLength;
            currentRecord->current_len += currentRecord->length;
            processedLength += currentRecord->length;
        }

        if (currentRecord->current_len == currentRecord->length)
        {
            for (const auto& handler : handlers_)
            {
                handler->handleRecord(sideIndex, session, currentRecord);
            }
            currentRecord = nullptr;
        }
    }

    if (currentRecord != NULL)
    {
        return 0;
    }

    return processedLength;
}

} // namespace snet::tls