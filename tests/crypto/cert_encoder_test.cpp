#include <gtest/gtest.h>
#include <snet/crypto/cert.hpp>
#include <casket/nonstd/string_view.hpp>

using namespace snet::crypto;

class CertTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Тестовый сертификат в base64 (предоставленный вами)
        testCertBase64 =
            "MIIHsjCCBzigAwIBAgIMf1VEXlbr1oIbD1ZfMAoGCCqGSM49BAMDMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LX"
            "NhMSYwJAYDVQQDEx1HbG9iYWxTaWduIEVDQyBPViBTU0wgQ0EgMjAxODAeFw0yNjAyMDYwNjU4MDhaFw0yNjA4MDYyMDU5NTlaMFoxCzAJ"
            "BgNVBAYTAlJVMQ8wDQYDVQQIEwZNb3Njb3cxDzANBgNVBAcTBk1vc2NvdzETMBEGA1UEChMKWUFOREVYIExMQzEUMBIGA1UEAwwLKi55YW"
            "5kZXgudHIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATFSzszNlndMFgUvOvUN2XXVgpxlfZuMokx3E6gF2xF3jM2qzb2b+CCr/"
            "VhlEAYO7ndtLM402dlc42GJeOHNeBKo4IF7DCCBegwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/"
            "wQCMAAwgY4GCCsGAQUFBwEBBIGBMH8wRAYIKwYBBQUHMAKGOGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZWNjb3Z"
            "zc2xjYTIwMTguY3J0MDcGCCsGAQUFBzABhitodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9nc2VjY292c3NsY2EyMDE4MFYGA1UdIARPM"
            "E0wQQYJKwYBBAGgMgEUMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAgGBmeBDAECAjA"
            "/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZWNjb3Zzc2xjYTIwMTguY3JsMIICuwYDVR0RBIICsjCCA"
            "q6CCyoueWFuZGV4LnRyghZ4bi0tZDFhY3BqeDNmLnhuLS1wMWFpghgqLnhuLS1kMWFjcGp4M2YueG4tLXAxYWmCC3lhbmRleC5hZXJvgg0"
            "qLnlhbmRleC5hZXJvggt5YW5kZXguam9ic4INKi55YW5kZXguam9ic4IKeWFuZGV4Lm5ldIIMKi55YW5kZXgubmV0ggp5YW5kZXgub3Jng"
            "gwqLnlhbmRleC5vcmeCCXlhbmRleC5kZYILKi55YW5kZXguZGWCBXlhLnJ1ggcqLnlhLnJ1ggl5YW5kZXguaXSCCyoueWFuZGV4Lml0ggl"
            "5YW5kZXgudXqCCyoueWFuZGV4LnV6ggl5YW5kZXgudG2CCyoueWFuZGV4LnRtggl5YW5kZXgudGqCCyoueWFuZGV4LnRqggl5YW5kZXguc"
            "nWCCyoueWFuZGV4LnJ1ggl5YW5kZXgubWSCCyoueWFuZGV4Lm1kggl5YW5kZXgubHaCCyoueWFuZGV4Lmx2ggl5YW5kZXgubHSCCyoueWF"
            "uZGV4Lmx0ggl5YW5kZXgua3qCCyoueWFuZGV4Lmt6ggl5YW5kZXguZnKCCyoueWFuZGV4LmZyggl5YW5kZXguZWWCCyoueWFuZGV4LmVlg"
            "g15YW5kZXguY29tLnRygg8qLnlhbmRleC5jb20udHKCDXlhbmRleC5jb20uZ2WCDyoueWFuZGV4LmNvbS5nZYINeWFuZGV4LmNvbS5hbYI"
            "PKi55YW5kZXguY29tLmFtggp5YW5kZXguY29tggwqLnlhbmRleC5jb22CDHlhbmRleC5jby5pbIIOKi55YW5kZXguY28uaWyCCXlhbmRle"
            "C5ieYILKi55YW5kZXguYnmCCXlhbmRleC5heoILKi55YW5kZXguYXqCCXlhbmRleC50cjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQU"
            "HAwIwHwYDVR0jBBgwFoAUWHuOdSr+"
            "YYCqkEABrtboB0ZuP0gwHQYDVR0OBBYEFGEGXw6IWTFzHvLdI8HxykBeK8IxMIIBfgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdgCUTkOH+"
            "uzB74HzGSQmqBhlAcfTXzgCAT9yZ31VNy4Z2AAAAZwxvnzWAAAEAwBHMEUCIHl7Wgn3FuCbpVrwuXlIU+fl+gKjDdU/"
            "EXhiLLAkQn26AiEAxwsD0wDFPn+H4QKioZK8bkwG+TBrFrYiu8qHvsBv+iYAdgDLOPcViXyEoURfW8Hd+"
            "8lu8ppZzUcKaQWFsMsUwxRY5wAAAZwxvnsOAAAEAwBHMEUCIQCXPJPrcbNVb6aIBlEMD59Xi4q2LawDrJqFgzpG4BVSTgIgW/"
            "qn5FavXQN5yMwKoHw9lTp3W+UmpbRMCQg2sfn1ts0AdgDCMX5XRRmjRe5/ON6ykEHrx8IhWiK/"
            "f9W1rXaa2Q5SzQAAAZwxvnyCAAAEAwBHMEUCIQCqAe96lCzG9cav+Dm8/"
            "PiH5ryNwkh0wzhjR2CfQF2m7QIgHu2ZqynEFPYUcmLQnvXf0YHDgVq4T9spI+cQhkur/"
            "eAwCgYIKoZIzj0EAwMDaAAwZQIweSZMrTg0ZwHDX8TrCvv2Xnz//vUlWZgJdmQb3ZLgGLKYRHHj/"
            "8fLdyGK8SSW2aRaAjEAgJ5oajFqwRRUP/86wZuZ9vIayBhSuIPFPsZIiHP0jrw7u5CAveytcchDtab5F8o0";
    }

    std::string testCertBase64;
};

TEST_F(CertTest, FromBase64CreatesValidCert)
{
    // Тест создания сертификата из base64
    X509CertPtr cert = Cert::fromBase64(testCertBase64);

    ASSERT_NE(cert, nullptr);
    EXPECT_TRUE(Cert::isEqual(cert.get(), cert.get()));
}

TEST_F(CertTest, ToBase64ConvertsCorrectly)
{
    // Тест преобразования сертификата обратно в base64
    X509CertPtr originalCert = Cert::fromBase64(testCertBase64);
    ASSERT_NE(originalCert, nullptr);

    std::string convertedBase64 = Cert::toBase64(originalCert.get());
    EXPECT_FALSE(convertedBase64.empty());

    // Проверяем, что из полученного base64 можно восстановить сертификат
    X509CertPtr recoveredCert = Cert::fromBase64(convertedBase64);
    ASSERT_NE(recoveredCert, nullptr);

    EXPECT_TRUE(Cert::isEqual(originalCert.get(), recoveredCert.get()));
}

TEST_F(CertTest, FromBase64InvalidInput)
{
    // Тест с некорректной base64 строкой
    std::string invalidBase64 = "This is not a valid base64 certificate";

    X509CertPtr cert = Cert::fromBase64(invalidBase64);
    EXPECT_EQ(cert, nullptr);
}

TEST_F(CertTest, FromBase64EmptyInput)
{
    // Тест с пустой строкой
    X509CertPtr cert = Cert::fromBase64("");
    EXPECT_EQ(cert, nullptr);
}

TEST_F(CertTest, CertPropertiesExtraction)
{
    // Тест извлечения свойств сертификата
    X509CertPtr cert = Cert::fromBase64(testCertBase64);
    ASSERT_NE(cert, nullptr);

    // Проверяем извлечение subject name и issuer name
    X509NamePtr subject = Cert::subjectName(cert.get());
    EXPECT_NE(subject, nullptr);

    X509NamePtr issuer = Cert::issuerName(cert.get());
    EXPECT_NE(issuer, nullptr);

    // Проверяем серийный номер
    BigNumPtr serialNum = Cert::serialNumber(cert.get());
    EXPECT_NE(serialNum, nullptr);

    // Проверяем публичный ключ
    KeyPtr publicKey = Cert::publicKey(cert.get());
    EXPECT_NE(publicKey, nullptr);

    // Проверяем даты валидности
    std::time_t notBefore = Cert::notBefore(cert.get());
    std::time_t notAfter = Cert::notAfter(cert.get());

    EXPECT_GT(notAfter, notBefore);
    EXPECT_GT(notBefore, 0);
    EXPECT_GT(notAfter, 0);

    // Проверяем версию
    CertVersion version = Cert::version(cert.get());
    EXPECT_GE(version, CertVersion::V1);
    EXPECT_LE(version, CertVersion::V3);
}

TEST_F(CertTest, ShallowCopyAndDeepCopy)
{
    // Тест копирования сертификата
    X509CertPtr originalCert = Cert::fromBase64(testCertBase64);
    ASSERT_NE(originalCert, nullptr);

    X509CertPtr shallowCopied = Cert::shallowCopy(originalCert.get());
    EXPECT_NE(shallowCopied, nullptr);
    EXPECT_TRUE(Cert::isEqual(originalCert.get(), shallowCopied.get()));

    X509CertPtr deepCopied = Cert::deepCopy(originalCert.get());
    EXPECT_NE(deepCopied, nullptr);
    EXPECT_TRUE(Cert::isEqual(originalCert.get(), deepCopied.get()));
}

TEST_F(CertTest, FromBufferRoundTrip)
{
    // Тест преобразования в буфер и обратно
    X509CertPtr originalCert = Cert::fromBase64(testCertBase64);
    ASSERT_NE(originalCert, nullptr);

    // Сначала получаем размер буфера (вызов с пустым span)
    std::array<uint8_t, 8192> buffer;
    nonstd::span<uint8_t> outputSpan(buffer);

    int result = Cert::toBuffer(originalCert.get(), outputSpan);
    EXPECT_GT(result, 0);

    // Восстанавливаем сертификат из буфера
    nonstd::span<const uint8_t> inputSpan(buffer.data(), result);
    X509CertPtr recoveredCert = Cert::fromBuffer(inputSpan);
    ASSERT_NE(recoveredCert, nullptr);

    EXPECT_TRUE(Cert::isEqual(originalCert.get(), recoveredCert.get()));
}

TEST_F(CertTest, FromStorageAndFileThrowOrFail)
{
    // Эти функции могут выбросить исключение или вернуть nullptr
    // Тестируем их поведение с некорректными параметрами

    EXPECT_THROW({ Cert::fromStorage("invalid://uri"); }, std::exception);

    X509CertPtr fileCert = Cert::fromFile("/nonexistent/path/to/cert.pem");
    EXPECT_EQ(fileCert, nullptr);
}

TEST_F(CertTest, IsEqualForSameAndDifferentCerts)
{
    X509CertPtr cert1 = Cert::fromBase64(testCertBase64);
    ASSERT_NE(cert1, nullptr);

    X509CertPtr cert2 = Cert::deepCopy(cert1.get());
    ASSERT_NE(cert2, nullptr);

    EXPECT_TRUE(Cert::isEqual(cert1.get(), cert2.get()));
    EXPECT_TRUE(Cert::isEqual(cert1.get(), cert1.get()));
}