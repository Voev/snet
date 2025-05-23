#include <gtest/gtest.h>
#include <snet/crypto/asymm_keygen.hpp>
#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_forger.hpp>
#include <snet/crypto/cert_name.hpp>
#include <snet/crypto/cert_authority.hpp>
#include <snet/crypto/cert_verifier.hpp>

using namespace snet::crypto;

class CertForgerTest : public ::testing::Test {
protected:
    CertForgerTest()
        : ca_("CN=Test Root CA") {
    }

    ~CertForgerTest() = default;

    void SetUp() override {
        auto originalKey = akey::rsa::generate(2048);
        originalCert_ = ca_.sign("CN=Test Server", originalKey);
    }

    void TearDown() override {
    }

protected:
    CertAuthority ca_;
    CertPtr originalCert_;
};

TEST_F(CertForgerTest, ResignCertificate) {
    CertPtr resignedCert;
    CertForger certForger(ca_.getKey(), ca_.getCert());

    ASSERT_NO_THROW(resignedCert = certForger.resign(originalCert_));
    ASSERT_NE(resignedCert, nullptr);

    ASSERT_TRUE(name::isEqual(cert::subjectName(resignedCert), cert::subjectName(originalCert_)));
    ASSERT_TRUE(name::isEqual(cert::issuerName(resignedCert), cert::issuerName(originalCert_)));

    CertManager store;
    ASSERT_NO_THROW(store.addCA(ca_.getCert()));

    CertVerifier verifier(store);
    std::error_code ec = verifier.verify(resignedCert);
    ASSERT_FALSE(ec) << ec.message();
}
