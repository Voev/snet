#include <snet/tls/record_reader.hpp>
#include <snet/tls/types.hpp>
#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

RecordReader::RecordReader()
    : decryptedData_(MAX_PLAINTEXT_SIZE)
{
}

RecordReader::~RecordReader() noexcept
{
}

Record RecordReader::readRecord(const std::int8_t sideIndex, std::span<const std::uint8_t> inputBytes,
                                std::size_t& consumedBytes, Session* session)
{
    ThrowIfTrue(inputBytes.size() < TLS_HEADER_SIZE, "Inappropriate header size");
    ThrowIfTrue(inputBytes[0] < 20 || inputBytes[0] > 23, "TLS record type had unexpected value");
    ThrowIfTrue(inputBytes[1] != 3 || inputBytes[2] >= 4, "TLS record version had unexpected value");

    RecordType recordType = static_cast<RecordType>(inputBytes[0]);
    const ProtocolVersion recordVersion(inputBytes[1], inputBytes[2]);
    const size_t recordSize = utils::make_uint16(inputBytes[TLS_HEADER_SIZE - 2], inputBytes[TLS_HEADER_SIZE - 1]);

    ThrowIfTrue(recordSize > MAX_CIPHERTEXT_SIZE, "Received a record that exceeds maximum size");
    ThrowIfTrue(recordSize > inputBytes.size(), "Incorrect record length");
    ThrowIfTrue(recordSize == 0, "Received a empty record");

    consumedBytes = TLS_HEADER_SIZE + recordSize;

    if (session && session->canDecrypt((sideIndex == 0)) && recordType != RecordType::ChangeCipherSpec)
    {
        decryptedData_.clear();
        session->decrypt(sideIndex, recordType, recordVersion, inputBytes.subspan(TLS_HEADER_SIZE, recordSize),
                         decryptedData_);

        if (session->getVersion() == ProtocolVersion::TLSv1_3)
        {
            uint8_t lastByte = *(decryptedData_.end() - 1);
            ThrowIfTrue(lastByte < 20 || lastByte > 23, "TLS record type had unexpected value");
            recordType = static_cast<RecordType>(lastByte);
            return Record(recordType, recordVersion, std::span(decryptedData_.begin(), decryptedData_.end() - 1));
        }

        return Record(recordType, recordVersion, decryptedData_);
    }

    return Record(recordType, recordVersion, inputBytes.subspan(TLS_HEADER_SIZE, recordSize));
}

} // namespace snet::tls