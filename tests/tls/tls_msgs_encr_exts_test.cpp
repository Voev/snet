#include <gtest/gtest.h>
#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/session.hpp>

using namespace testing;
using namespace snet::tls;

using SerializeTestParam = std::vector<uint8_t>;

class EncryptedExtensionsTest : public TestWithParam<SerializeTestParam>
{
protected:
    EncryptedExtensionsTest() = default;
    ~EncryptedExtensionsTest() = default;

protected:
    RecordPool recordPool_{8};
};

TEST_P(EncryptedExtensionsTest, DeserializeSerialize)
{
    SerializeTestParam param = GetParam();
    SerializeTestParam serialized(param.size());
    size_t serializedLength = 0;

    EncryptedExtensions encryptedExtensions;
    ASSERT_NO_THROW(encryptedExtensions.parse(param));

    Session session(recordPool_);
    ASSERT_NO_THROW(session.processEncryptedExtensions(encryptedExtensions));

    ASSERT_NO_THROW(serializedLength = encryptedExtensions.serialize(serialized, session));
    serialized.resize(serializedLength);

    ASSERT_EQ(serialized, param);
}

std::vector<std::vector<uint8_t>> gEncryptedExtensionsParams = {
    {0x00, 0x00},
    {0x00, 0x04, 0xFF, 0xFF, 0x00, 0x00},
};

INSTANTIATE_TEST_SUITE_P(EncryptedExtensionsTests, EncryptedExtensionsTest, ValuesIn(gEncryptedExtensionsParams));
