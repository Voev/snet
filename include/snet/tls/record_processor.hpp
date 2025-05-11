#pragma once
#include <vector>
#include <memory>
#include <snet/tls/i_record_handler.hpp>
#include <snet/tls/record_queue.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::tls
{


/// @brief Class for processing TLS records.
class RecordProcessor final : public utils::NonCopyable
{
public:
    /// @brief Default constructor.
    ///
    /// @param[in] recordPoolSize The size of record pool.
    RecordProcessor(const size_t recordPoolSize = 1024)
        : recordPool_(recordPoolSize)
    {
    }

    /// @brief Destructor.
    ~RecordProcessor() = default;

    /// @brief Move constructor.
    /// @param other rvalue reference to the record processor.
    RecordProcessor(RecordProcessor&& other) noexcept = default;

    /// @brief Move assignment operator.
    /// @param other rvalue reference to the record processor.
    RecordProcessor& operator=(RecordProcessor&& other) noexcept = default;

    /// @brief Processes input bytes as TLS records.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session The TLS session to process records.
    /// @param inputBytes The input bytes pointer.
    /// @param inputLength The input bytes length.
    size_t process(const int8_t sideIndex, Session* session, uint8_t* inputBytes, size_t inputLength);

    /// @brief Adds a record handler.
    /// @tparam Handler The type of the handler.
    /// @tparam Args
    /// @param[in] args
    template <typename Handler, typename... Args>
    void addHandler(Args&&... args) {
        static_assert(std::is_base_of_v<IRecordHandler, Handler>,
                     "Handler must inherit from IRecordHandler");
        
        handlers_.emplace_back(
            std::make_shared<Handler>(std::forward<Args>(args)...)
        );
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

    RecordPool& getRecordPool()
    {
        return recordPool_;
    }

private:
    std::vector<std::shared_ptr<IRecordHandler>> handlers_;
    RecordPool recordPool_;
};

} // namespace snet::tls