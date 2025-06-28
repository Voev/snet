#include <string_view>
#include <gtest/gtest.h>

#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/asymm_keygen.hpp>
#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_name.hpp>
#include <snet/crypto/cert_builder.hpp>
#include <snet/crypto/cert_name_builder.hpp>
#include <snet/crypto/cert_verifier.hpp>

using namespace snet;
using namespace snet::crypto;
using namespace std::chrono_literals;

class CertBuilderTest : public testing::Test {
public:
    void SetUp() override {
        ASSERT_NO_THROW(key_ = akey::rsa::generate(2048));
    }

    void TearDown() override {
        key_.reset();
    }

protected:
    KeyPtr key_;
};

TEST_F(CertBuilderTest, CreateSelfSignedCert) {
    CertNamePtr name;
    ASSERT_NO_THROW(name = CertNameBuilder::fromString("CN=Test Root CA"));

    CertBuilder builder;
    // clang-format off
    ASSERT_NO_THROW(
        builder
            .selfSigned(key_)
            .setPublicKey(key_)
            .setSubjectName(name)
            .setIssuerName(name)
            .setNotBefore(cpp::chrono_years(-10))
            .setNotAfter(cpp::chrono_years(10))
            .setVersion(CertVersion::V3)
            .addExtension(NID_subject_key_identifier, "hash")
            .addExtension(NID_basic_constraints, "critical,CA:TRUE")
            .addExtension(NID_key_usage, "critical,cRLSign,keyCertSign")
    );
    // clang-format on
    CertPtr cert;
    ASSERT_NO_THROW(cert = builder.build());

    ASSERT_EQ(cert::version(cert), CertVersion::V3);
    ASSERT_TRUE(name::isEqual(cert::subjectName(cert), name));
    ASSERT_TRUE(name::isEqual(cert::issuerName(cert), name));
    ASSERT_TRUE(akey::isEqual(key_, cert::publicKey(cert)));
    ASSERT_TRUE(X509_self_signed(cert, true));
}

TEST_F(CertBuilderTest, CreateChildCert) {
    CertNamePtr name;
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

    CertPtr ca;
    ASSERT_NO_THROW(ca = caBuilder.build());
    ASSERT_TRUE(X509_self_signed(ca, true));

    auto childKey = akey::rsa::generate(2048);

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

    CertPtr child;
    ASSERT_NO_THROW(child = childBuilder.build());

    CertManager manager;
    ASSERT_NO_THROW(manager.addCA(ca));

    auto ec = CertVerifier(manager).verify(child);
    ASSERT_FALSE(ec) << ec.message();
}