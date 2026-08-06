#pragma once
#include <snet/crypto/typedefs.hpp>
#include <snet/crypto/pointers.hpp>

#include <casket/nonstd/string_view.hpp>

namespace snet::pki_fetch
{

crypto::X509CertPtr LoadCertByHttp(nonstd::string_view url, int timeout);

crypto::X509CrlPtr LoadCrlByHttp(nonstd::string_view url, int timeout);

crypto::CrlOwningStackPtr LocalSearchForCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx, OSSL_CONST_COMPAT X509Name* name);

crypto::CrlOwningStackPtr DownloadCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx, int timeout);

} // namespace snet::pki_fetch