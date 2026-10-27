#include <gtest/gtest.h>
#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/session.hpp>
#include <snet/utils/compare_vectors.hpp>

using namespace testing;
using namespace snet::tls;
using namespace snet::utils;

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
    ASSERT_EQ(encryptedExtensions.deserialize(param), make_error_code(DecodeError::None));

    Session session(recordPool_);
    ASSERT_NO_THROW(session.processEncryptedExtensions(encryptedExtensions));

    serializedLength = encryptedExtensions.serialize(serialized, session);
    ASSERT_GT(serializedLength, 0U);
    serialized.resize(serializedLength);

    ASSERT_EQ(serialized, param) << CompareVectors(serialized, param);
}

std::vector<std::vector<uint8_t>> gEncryptedExtensionsParams = {
    {0x00, 0x00},
    {0x00, 0x04, 0xFF, 0xFF, 0x00, 0x00},
};

INSTANTIATE_TEST_SUITE_P(EncryptedExtensionsTests, EncryptedExtensionsTest, ValuesIn(gEncryptedExtensionsParams));
