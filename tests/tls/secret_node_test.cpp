#include <gtest/gtest.h>
#include <snet/tls/secret_node.hpp>

using namespace snet::tls;

class SecretNodeTest : public ::testing::Test
{
protected:
    SecretNode secretNode;

    Secret createTestSecret()
    {
        return Secret{1, 2, 3, 4, 5};
    }
};

TEST_F(SecretNodeTest, DefaultConstructor)
{
    for (int i = 0; i < SecretNode::SecretTypesCount; ++i)
    {
        EXPECT_TRUE(secretNode.getSecret(static_cast<SecretNode::Type>(i)).empty());
    }
}

TEST_F(SecretNodeTest, SetAndGetSecret)
{
    Secret testSecret = createTestSecret();

    secretNode.setSecret(SecretNode::ClientHandshakeTrafficSecret, testSecret);

    const Secret& retrievedSecret = secretNode.getSecret(SecretNode::ClientHandshakeTrafficSecret);
    EXPECT_EQ(retrievedSecret, testSecret);
}

TEST_F(SecretNodeTest, GetNonExistentSecret)
{
    const Secret& retrievedSecret = secretNode.getSecret(SecretNode::ServerApplicationTrafficSecret);
    EXPECT_TRUE(retrievedSecret.empty());
}

TEST_F(SecretNodeTest, IsValidSecretForVersion)
{
    Secret testSecret = createTestSecret();
    secretNode.setSecret(SecretNode::MasterSecret, testSecret);

    ProtocolVersion version(VersionCode::TLSv1_2);
    EXPECT_TRUE(secretNode.isValid(version));
}
