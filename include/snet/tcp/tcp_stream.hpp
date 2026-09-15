#pragma once
#include <cstdint>
#include <cstddef>
#include <utility>
#include <snet/tcp/tcp_types.hpp>

namespace snet::tcp
{

/// @brief Zero-copy reader over a stream buffer.
///
/// Valid only within the callback that provides it.
/// Do NOT store past callback return.
class IStreamReader
{
public:
    virtual ~IStreamReader() = default;

    /// Zero-copy view of contiguous data.
    virtual std::pair<const uint8_t*, size_t> peek() = 0;

    /// Copy into user buffer.
    virtual size_t read(uint8_t* out, size_t maxLen) = 0;

    /// Consume n bytes after peek.
    virtual void consume(size_t n) = 0;

    /// Bytes available (contiguous).
    virtual size_t available() const = 0;
};

/// @brief Base for type-erased storage.
class IStreamConsumerBase
{
public:
    virtual ~IStreamConsumerBase() = default;
};

/// @brief Stream consumer with typed Session access.
template <typename SessionManagerType>
class IStreamConsumer : public IStreamConsumerBase
{
public:
    using Session = typename SessionManagerType::Session;
    using Key = typename SessionManagerType::Key;

    /// @brief Called when new contiguous data is available.
    ///
    /// Consumer has full access to session contexts via SessionManager:
    ///   auto* ctx = mgr->getContext<MyContext>(session);
    ///
    /// `reader` is valid only during this call — process data synchronously
    /// or copy what you need.
    virtual void onStreamData(Session* session, int8_t side, IStreamReader& reader) = 0;

    /// @brief Called when the stream is fully closed.
    virtual void onStreamClose(Session* session, int8_t side, int reason) = 0;

    /// @brief Called when a gap (missing bytes) is finalized.
    virtual void onStreamGap(Session* session, int8_t side, uint32_t missingBytes) = 0;
};

/// @brief Base for type-erased acceptor.
class IConnectionAcceptorBase
{
public:
    virtual ~IConnectionAcceptorBase() = default;
};

template <typename SessionManagerType>
class IConnectionAcceptor : public IConnectionAcceptorBase
{
public:
    using Session = typename SessionManagerType::Session;

    virtual void onAccept(Session* session, TcpConnection& conn) = 0;
    virtual void onReject(Session* session, TcpConnection& conn) = 0;
};

} // namespace snet::tcp