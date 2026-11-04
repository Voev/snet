/// @file
/// @brief Bridges a TcpTransmitHandler to tls::IByteWriter.

#pragma once

#include <cstddef>
#include <cstdint>

#include <snet/tls/i_byte_writer.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>

namespace snet::probe
{

/// @brief Bridges a TcpTransmitHandler<SessionManagerType> to tls::IByteWriter.
///
/// @tparam SessionManagerType Session manager type used to instantiate
///         the TcpTransmitHandler (same as in the owner of `tx_`).
template <typename SessionManagerType>
class TcpByteWriter final : public snet::tls::IByteWriter
{
public:
    using TransmitHandler = snet::tcp::TcpTransmitHandler<SessionManagerType>;
    using Session = typename SessionManagerType::Session;

    TcpByteWriter(TransmitHandler& tx, Session* session) noexcept
        : tx_(tx)
        , session_(session)
    {
    }

    std::size_t available() const noexcept override
    {
        return tx_.freeSpace(session_);
    }

    bool write(nonstd::span<const std::uint8_t> data) noexcept override
    {
        return tx_.sendData(session_, data.data(), data.size()) == data.size();
    }

private:
    TransmitHandler& tx_;
    Session* session_;
};

} // namespace probe