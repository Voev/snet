#pragma once
#include <cstdint>
#include <system_error>
#include <functional>
#include <snet/crypto/pointers.hpp>
#include <snet/tls/alert.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/connection.hpp>

namespace snet::tls
{

class Settings;

enum class Want
{
    Nothing = 0,
    Input,
    Output,
    Certificate,
};

class StateMachine final : public Connection
{
public:
    explicit StateMachine(const Settings& connection);

    ~StateMachine() noexcept;

    StateMachine(const StateMachine& other) = delete;
    StateMachine& operator=(const StateMachine& other) = delete;

    StateMachine(StateMachine&& other) noexcept;
    StateMachine& operator=(StateMachine&& other) noexcept;

    Want handshake(const std::uint8_t* bufferIn, const std::size_t bufferInSize,
                   std::uint8_t* bufferOut, std::size_t* bufferOutSize,
                   std::error_code& ec) noexcept;

    Want decrypt(std::uint8_t* bufferIn, std::size_t bufferInSize, std::uint8_t* bufferOut,
                 std::size_t* bufferOutSize, std::error_code& ec) noexcept;

    Want encrypt(std::uint8_t* bufferIn, std::size_t bufferInSize, std::uint8_t* bufferOut,
                 std::size_t* bufferOutSize, std::error_code& ec) noexcept;

    Want closeNotify(std::uint8_t* buffer, std::size_t* bufferSize, std::error_code& ec) noexcept;

    bool isClosed() const noexcept;

    void shutdown();

    const Alert& getAlert() const noexcept;

    bool isServer() const noexcept;

    void clear() noexcept;

    std::size_t lowerLayerRead(std::uint8_t* buffer, std::size_t length,
                               std::error_code& ec) noexcept;

    std::size_t lowerLayerWrite(const std::uint8_t* buffer, std::size_t length,
                                std::error_code& ec) noexcept;

    std::size_t lowerLayerPending() const noexcept;

private:
    Want handleResult(int result, std::size_t before, std::size_t after,
                      std::error_code& ec) noexcept;

private:
    Bio* lowerLayer_;
    Alert alert_;
};

} // namespace snet::tls
