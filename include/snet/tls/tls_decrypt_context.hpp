#pragma once
#include <memory>
#include <snet/tls/session.hpp>

namespace snet::tls
{

struct TlsDecryptContext
{
    static constexpr size_t MAX_INSTANCES = 1;

    std::unique_ptr<Session> session;

    uint64_t decryptedRecords{0};

    void reset() noexcept
    {
        session->reset();
        decryptedRecords = 0;
    }
};

} // namespace snet::tls