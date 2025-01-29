#pragma once
#include <vector>
#include <memory>
#include <snet/tls/record_handler.hpp>

namespace snet::tls
{

class RecordProcessor final
{
public:
    RecordProcessor() = default;

    ~RecordProcessor() = default;

    void process(const std::int8_t sideIndex, std::span<const uint8_t> inputBytes)
    {
        while (inputBytes.size_bytes() > 0)
        {
            auto record = tls::readRecord(sideIndex, inputBytes);
            for (const auto& handler : handlers_)
            {
                handler->handleRecord(sideIndex, record);
            }
            inputBytes = inputBytes.subspan(inputBytes.size_bytes());
        }
    }

    template <typename Handler>
    void addHandler()
    {
        static_assert(std::is_base_of<tls::RecordHandler, Handler>::value,
                      "Handler type must derive from RecordHandler");

        handlers_.emplace_back(std::make_shared<Handler>());
    }

    template <typename Handler>
    std::shared_ptr<Handler> getHandler() const
    {
        static_assert(std::is_base_of<tls::RecordHandler, Handler>::value,
                      "Handler type must derive from RecordHandler");

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
    std::vector<std::shared_ptr<RecordHandler>> handlers_;
};

} // namespace snet::tls