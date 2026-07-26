#pragma once
#include <snet/crypto/typedefs.hpp>
#include <snet/crypto/pointers.hpp>

namespace snet::pki_fetch
{

crypto::X509CertPtr LoadCertByHttp(const char* url, int timeout);

crypto::X509CrlPtr LoadCrlByHttp(const char* url, int timeout);

crypto::CrlOwningStackPtr LocalSearchForCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx, OSSL_CONST_COMPAT X509Name* name);

crypto::CrlOwningStackPtr DownloadCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx);

} // namespace snet::pki_fetch