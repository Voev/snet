#pragma once
#include <snet/log/logger.hpp>

namespace snet::log
{

class Console final : public Logger
{
public:
    Console() = default;

    ~Console() = default;

    void emergency(std::string_view msg) override;

    void alert(std::string_view msg) override;

    void critical(std::string_view msg) override;

    void error(std::string_view msg) override;

    void warning(std::string_view msg) override;

    void notice(std::string_view msg) override;

    void info(std::string_view msg) override;

    void debug(std::string_view msg) override;
};

} // namespace snet::log