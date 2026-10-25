#include <snet/probe/probe_acceptor.hpp>

#include <snet/tls/record_printer.hpp>

namespace snet::probe
{

std::vector<uint8_t> buildExtensionsBlob(std::string_view sni)
{
    std::vector<uint8_t> blob;
    auto put16 = [&](uint16_t v)
    {
        blob.push_back(static_cast<uint8_t>(v >> 8));
        blob.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    auto putExt = [&](uint16_t type, const std::vector<uint8_t>& data)
    {
        put16(type);
        put16(static_cast<uint16_t>(data.size()));
        blob.insert(blob.end(), data.begin(), data.end());
    };

    // SNI (0x0000) — только если sni не пустой
    if (!sni.empty())
    {
        std::vector<uint8_t> data;
        const uint16_t listLen = static_cast<uint16_t>(1 + 2 + sni.size());
        data.push_back(static_cast<uint8_t>(listLen >> 8));
        data.push_back(static_cast<uint8_t>(listLen & 0xFF));
        data.push_back(0); // host_name
        data.push_back(static_cast<uint8_t>(sni.size() >> 8));
        data.push_back(static_cast<uint8_t>(sni.size() & 0xFF));
        data.insert(data.end(), sni.begin(), sni.end());
        putExt(0x0000, data);
    }

    //  supported_groups (0x000a) 
    {
        std::vector<uint8_t> data;
        data.push_back(0x00);
        data.push_back(0x04); // list_len
        data.push_back(0x00);
        data.push_back(0x1D); // x25519
        data.push_back(0x00);
        data.push_back(0x17); // secp256r1
        putExt(0x000a, data);
    }

    //  signature_algorithms (0x000d) 
    {
        std::vector<uint8_t> data;
        data.push_back(0x00);
        data.push_back(0x06); // list_len
        data.push_back(0x04);
        data.push_back(0x03); // ecdsa_secp256r1_sha256
        data.push_back(0x08);
        data.push_back(0x04); // rsa_pss_rsae_sha256
        data.push_back(0x04);
        data.push_back(0x01); // rsa_pkcs1_sha256
        putExt(0x000d, data);
    }

    //  supported_versions (0x002b) 
    {
        std::vector<uint8_t> data;
        data.push_back(4); // list_len
        data.push_back(0x03);
        data.push_back(0x04); // TLS 1.3
        data.push_back(0x03);
        data.push_back(0x03); // TLS 1.2
        putExt(0x002b, data);
    }

    {
        std::vector<uint8_t> data;
        data.push_back(0x00);
        data.push_back(0x04); // client_shares_len = 4
        data.push_back(0x00);
        data.push_back(0x1D); // x25519
        data.push_back(0x00);
        data.push_back(0x00); // key_exchange_len = 0
        putExt(0x0033, data);
    }

    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(blob.size() >> 8));
    out.push_back(static_cast<uint8_t>(blob.size() & 0xFF));
    out.insert(out.end(), blob.begin(), blob.end());
    return out;
}


std::vector<uint8_t> buildClientHelloRecord(std::string_view sni, tls::ProtocolVersion preferred, tls::RecordPool& pool,
                                            tls::Session& session)
{
    auto extensionsBlob = buildExtensionsBlob(sni);
    if (extensionsBlob.empty())
        return {};

    static const std::array<uint8_t, 14> suites = {
        0x13,
        0x01, // TLS_AES_128_GCM_SHA256
        0x13,
        0x02, // TLS_AES_256_GCM_SHA384
        0x13,
        0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xC0,
        0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC0,
        0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0x00,
        0x9E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x00,
        0x9F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    };
    static const std::array<uint8_t, 1> compMethods = {0x00};

    tls::ClientHello ch{};
    ch.version = preferred;
    ch.random = {};
    ch.sessionID = {};
    ch.suites = {suites.data(), suites.size()};
    ch.compMethods = {compMethods.data(), compMethods.size()};
    ch.extensions = {extensionsBlob.data(), extensionsBlob.size()};

    session.setVersion(preferred);
    session.constructClientHello(ch);

    auto* rec = pool.acquire();
    if (!rec)
        return {};

    if (!rec->serializeHandshake(tls::HandshakeMessage(std::move(ch), tls::HandshakeType::ClientHelloCode), 0, session))
    {
        pool.release(rec);
        return {};
    }

    tls::PrintRecord(0, &session, rec);

    session.addOutgoingRecord(0, rec);

    std::vector<uint8_t> out(4096);
    const size_t n = session.writeRecords({out.data(), out.size()});
    if (n == 0)
        return {};
    out.resize(n);
    return out;
}

} // namespace snet::probe