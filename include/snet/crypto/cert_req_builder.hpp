#pragma once

#include <casket/nonstd/string_view.hpp>
#include <casket/nonstd/chrono.hpp>
#include <casket/utils/noncopyable.hpp>

#include <snet/crypto/pointers.hpp>

namespace snet::crypto
{

class CertReqBuilder
{
public:
    CertReqBuilder();
    ~CertReqBuilder() noexcept;

    void reset();

    CertReqBuilder& setVersion(CertReqVersion version);
    CertReqBuilder& setSubjectName(OSSL_CONST_COMPAT X509Name* name);
    CertReqBuilder& setSubjectName(const std::string& name);
    CertReqBuilder& setPublicKey(Key* subjectPublicKey);

    CertReqBuilder& addExtension(X509Ext* extension);
    CertReqBuilder& addExtension(int extNid, nonstd::string_view value);
    CertReqBuilder& addExtension(nonstd::string_view name, nonstd::string_view value);

    CertReqBuilder& signWith(Key* privateKey);

    X509ReqPtr build();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::crypto