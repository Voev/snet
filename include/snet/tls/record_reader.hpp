#pragma once
#include <vector>
#include <snet/tls/session.hpp>
#include <snet/tls/i_record_reader.hpp>

namespace snet::tls
{

class RecordReader final : public IRecordReader
{
public:
    RecordReader();
    ~RecordReader() noexcept;

    RecordReader(const RecordReader& other) = delete;
    RecordReader& operator=(const RecordReader& other) = delete;

    RecordReader(RecordReader&& other) noexcept = delete;
    RecordReader& operator=(RecordReader&& other) noexcept = delete;

    Record readRecord(const std::int8_t sideIndex, std::span<const std::uint8_t> inputBytes,
                      std::size_t& consumedBytes) override;

    void setSession(std::shared_ptr<Session> session);

private:
    std::shared_ptr<Session> session_;
    std::vector<std::uint8_t> decryptedData_;
};

} // namespace snet::tls