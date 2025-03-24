#pragma once
#include <vector>
#include <memory>
#include <snet/tls/i_record_reader.hpp>
#include <snet/tls/i_record_handler.hpp>

namespace snet::tls
{

/// @brief Class for processing TLS records.
class RecordProcessor final
{
public:
    /// @brief Default constructor.
    RecordProcessor() = default;

    /// @brief Destructor.
    ~RecordProcessor() = default;

    /// @brief Copy constructor.
    /// @param other constant reference to the record processor.
    RecordProcessor(const RecordProcessor& other) = delete;

    /// @brief Move constructor and move assignment operator.
    /// @param other rvalue reference to the record processor.
    RecordProcessor& operator=(const RecordProcessor& other) = delete;

    /// @brief Move constructor.
    /// @param other rvalue reference to the record processor.
    RecordProcessor(RecordProcessor&& other) noexcept = default;

    /// @brief Move assignment operator.
    /// @param other rvalue reference to the record processor.
    RecordProcessor& operator=(RecordProcessor&& other) noexcept = default;

    /// @brief Processes input bytes as TLS records.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param inputBytes The input bytes to process.
    void process(const std::int8_t sideIndex, std::span<const uint8_t> inputBytes);

    /// @brief Adds a record reader.
    /// @tparam Reader The type of the reader.
    template <typename Reader>
    void addReader()
    {
        static_assert(std::is_base_of<tls::IRecordReader, Reader>::value,
                      "Reader type must derive from IRecordReader");

        reader_ = std::make_shared<Reader>();
    }

    /// @brief Gets the record reader.
    /// @tparam Reader The type of the reader.
    /// @return A shared pointer to the reader if found, otherwise nullptr.
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

    /// @brief Adds a record handler.
    /// @tparam Handler The type of the handler.
    template <typename Handler>
    void addHandler()
    {
        static_assert(std::is_base_of<tls::IRecordHandler, Handler>::value,
                      "Handler type must derive from IRecordHandler");

        handlers_.emplace_back(std::make_shared<Handler>());
    }

    /// @brief Gets a record handler.
    /// @tparam Handler The type of the handler.
    /// @return A shared pointer to the handler if found, otherwise nullptr.
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