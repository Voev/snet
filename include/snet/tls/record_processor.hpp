#pragma once
#include <vector>
#include <memory>
#include <snet/tls/i_record_reader.hpp>
#include <snet/tls/i_record_handler.hpp>
#include <snet/tls/exception.hpp>

namespace snet::tls
{

class RecordProcessor final
{
public:
    RecordProcessor() = default;
    ~RecordProcessor() = default;

    RecordProcessor(const RecordProcessor& other) = delete;
    RecordProcessor& operator=(const RecordProcessor& other) = delete;

    RecordProcessor(RecordProcessor&& other) noexcept = default;
    RecordProcessor& operator=(RecordProcessor&& other) noexcept = default;

    void process(const std::int8_t sideIndex, std::span<const uint8_t> inputBytes);

    template <typename Reader>
    void addReader()
    {
        static_assert(std::is_base_of<tls::IRecordReader, Reader>::value,
                      "Reader type must derive from IRecordReader");

        reader_ = std::make_shared<Reader>();
    }

    template <typename Reader>
    std::shared_ptr<Reader> getReader() const
    {
        static_assert(std::is_base_of<tls::IRecordReader, Reader>::value,
                      "Reader type must derive from IRecordReader");

        if (auto castedReader = std::dynamic_pointer_cast<Reader>(reader_))
        {
            return castedReader;
        }
        return nullptr;
    }

    template <typename Handler>
    void addHandler()
    {
        static_assert(std::is_base_of<tls::IRecordHandler, Handler>::value,
                      "Handler type must derive from IRecordHandler");

        handlers_.emplace_back(std::make_shared<Handler>());
    }

    template <typename Handler>
    std::shared_ptr<Handler> getHandler() const
    {
        static_assert(std::is_base_of<tls::IRecordHandler, Handler>::value,
                      "Handler type must derive from IRecordHandler");

        for (const auto& handler : handlers_)
        {
            if (auto castedHandler = std::dynamic_pointer_cast<Handler>(handler))
            {
                return castedHandler;
            }
        }
        return nullptr;
    }

private:
    std::shared_ptr<IRecordReader> reader_;
    std::vector<std::shared_ptr<IRecordHandler>> handlers_;
};

} // namespace snet::tls