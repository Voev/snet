#pragma once
#include <snet/crypto/typedefs.hpp>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto
{

X509CertPtr LoadCertByHttp(const char* url, int timeout);

X509CrlPtr LoadCrlByHttp(const char* url, int timeout);

CrlOwningStackPtr LocalSearchForCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx, OSSL_CONST_COMPAT X509Name* name);

CrlOwningStackPtr DownloadCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx);

} // namespace snet::crypto