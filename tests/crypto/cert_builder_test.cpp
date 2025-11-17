#include <string_view>
#include <gtest/gtest.h>

#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/rsa_asymm_key.hpp>
#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_name.hpp>
#include <snet/crypto/cert_builder.hpp>
#include <snet/crypto/cert_name_builder.hpp>
#include <snet/crypto/cert_verifier.hpp>

using namespace snet;
using namespace snet::crypto;
using namespace std::chrono_literals;

class CertBuilderTest : public testing::Test
{
public:
    void SetUp() override
    {
        ASSERT_NO_THROW(key_ = RsaAsymmKey::generate(2048));
    }

    void TearDown() override
    {
        key_.reset();
    }

protected:
    KeyPtr key_;
};

TEST_F(CertBuilderTest, CreateSelfSignedCert)
{
    X509NamePtr name;
    ASSERT_NO_THROW(name = CertNameBuilder::fromString("CN=Test Root CA"));

    CertBuilder builder;
    // clang-format off
    ASSERT_NO_THROW(
        builder
            .selfSigned(key_)
            .setPublicKey(key_)
            .setSubjectName(name)
            .setIssuerName(name)
            .setNotBefore(nonstd::chrono_years(-10))
            .setNotAfter(nonstd::chrono_years(10))
            .setVersion(CertVersion::V3)
            .addExtension(NID_subject_key_identifier, "hash")
            .addExtension(NID_basic_constraints, "critical,CA:TRUE")
            .addExtension(NID_key_usage, "critical,cRLSign,keyCertSign")
    );
    // clang-format on
    X509CertPtr cert;
    ASSERT_NO_THROW(cert = builder.build());

    ASSERT_EQ(Cert::version(cert), CertVersion::V3);
    ASSERT_TRUE(CertName::isEqual(Cert::subjectName(cert), name));
    ASSERT_TRUE(CertName::isEqual(Cert::issuerName(cert), name));
    ASSERT_TRUE(AsymmKey::isEqual(key_, Cert::publicKey(cert)));
    //ASSERT_TRUE(Cert::isSelfSigned(cert, true));
}

TEST_F(CertBuilderTest, CreateChildCert)
{
    X509NamePtr name;
    ASSERT_NO_THROW(name = CertNameBuilder::fromString("CN=Test Root CA"));

    CertBuilder caBuilder;
    // clang-format off
    ASSERT_NO_THROW(
        caBuilder
            .selfSigned(key_)
            .setPublicKey(key_)
            .setSubjectName(name)
            .setIssuerName(name)
            .setNotBefore(0s)
            .setNotAfter(1h)
            .setVersion(CertVersion::V3)
            .addExtension(NID_subject_key_identifier, "hash")
            .addExtension(NID_basic_constraints, "critical,CA:TRUE")
            .addExtension(NID_key_usage, "critical,cRLSign,keyCertSign")
    );
    // clang-format on

    X509CertPtr ca;
    ASSERT_NO_THROW(ca = caBuilder.build());
    //ASSERT_TRUE(Cert::isSelfSigned(ca, true));

    auto childKey = RsaAsymmKey::generate(2048);

    CertBuilder childBuilder;
    // clang-format off
    ASSERT_NO_THROW(
        childBuilder
            .signedBy(key_, ca)
            .setPublicKey(childKey)
            .setSubjectName(name)
            .setIssuerName(name)
            .setNotBefore(0s)
            .setNotAfter(1h)
            .setVersion(CertVersion::V3)
            .addExtension(NID_authority_key_identifier, "keyid")
            .addExtension(NID_subject_key_identifier, "hash");
    );
    // clang-format on

    X509CertPtr child;
    ASSERT_NO_THROW(child = childBuilder.build());

    CertManager manager;
    ASSERT_NO_THROW(manager.addCA(ca));

    auto ec = CertVerifier(manager).verify(child);
    ASSERT_FALSE(ec) << ec.message();
}