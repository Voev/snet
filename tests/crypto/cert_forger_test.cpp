#include <gtest/gtest.h>
#include <snet/crypto/rsa_asymm_key.hpp>
#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_forger.hpp>
#include <snet/crypto/cert_name.hpp>
#include <snet/crypto/cert_authority.hpp>
#include <snet/crypto/cert_verifier.hpp>

using namespace snet::crypto;

class CertForgerTest : public ::testing::Test
{
protected:
    CertForgerTest()
        : ca_(RsaAsymmKey::generate(2048), "CN=Test Root CA")
    {
    }

    ~CertForgerTest() = default;

    void SetUp() override
    {
        auto originalKey = RsaAsymmKey::generate(2048);
        originalCert_ = ca_.sign("CN=Test Server", originalKey);
    }

    void TearDown() override
    {
    }

protected:
    CertAuthority ca_;
    X509CertPtr originalCert_;
};

TEST_F(CertForgerTest, ResignCertificate)
{
    X509CertPtr resignedCert;
    CertForger certForger(ca_.getKey(), ca_.getCert());

    KeyPtr forgedKey;

    ASSERT_NO_THROW(forgedKey = RsaAsymmKey::generate(2048));
    ASSERT_NO_THROW(resignedCert = certForger.resign(forgedKey, originalCert_));
    ASSERT_NE(resignedCert, nullptr);

    ASSERT_TRUE(CertName::isEqual(Cert::subjectName(resignedCert), Cert::subjectName(originalCert_)));
    ASSERT_TRUE(CertName::isEqual(Cert::issuerName(resignedCert), Cert::issuerName(originalCert_)));

    CertManager store;
    ASSERT_NO_THROW(store.addCA(ca_.getCert()));

    CertVerifier verifier(store);
    std::error_code ec = verifier.verify(resignedCert);
    ASSERT_FALSE(ec) << ec.message();
}
