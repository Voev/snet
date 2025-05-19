#pragma once
#include <vector>
#include <memory>
#include <snet/tls/record.hpp>
#include <snet/tls/i_record_handler.hpp>

namespace snet::tls
{

/// @brief Class for processing TLS records.
class RecordProcessor final
{
public:
    /// @brief Default constructor.
    RecordProcessor()
        : recordPool_(1024)
    {}

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
    /// @param inputBytes The input bytes pointer.
    /// @param inputLength The input bytes length.
    size_t process(const int8_t sideIndex, uint8_t* inputBytes, size_t inputLength);

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
    std::vector<std::shared_ptr<IRecordHandler>> handlers_;
    RecordPool recordPool_;
};

} // namespace snet::tls