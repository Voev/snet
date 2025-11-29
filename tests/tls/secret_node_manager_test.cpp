#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <snet/tls/secret_node_manager.hpp>

using namespace snet::crypto;
using namespace snet::tls;

namespace
{

void createLogFile(const std::filesystem::path& filename, std::string_view content)
{
    std::ofstream of(filename);
    ASSERT_TRUE(of.is_open());

    of << content << std::endl;
    ASSERT_TRUE(of);

    of.close();
}

} // namespace

class SecretNodeManagerTest : public ::testing::Test
{
public:
    SecretNodeManagerTest() = default;
    ~SecretNodeManagerTest() = default;

protected:
    SecretNodeManager manager;
    ClientRandom clientRandom1;
    ClientRandom clientRandom2;

    SecretNode createTestSecretNode()
    {
        SecretNode secretNode;
        Secret testSecret = {10, 20, 30, 40};
        secretNode.setSecret(SecretNode::ClientTrafficSecret, testSecret);
        return secretNode;
    }
};

TEST_F(SecretNodeManagerTest, AddAndFindSecret)
{
    SecretNode secretNode = createTestSecretNode();
    manager.addSecrets(clientRandom1, std::move(secretNode));

    auto foundSecret = manager.findSecret(clientRandom1, SecretNode::ClientTrafficSecret);
    ASSERT_TRUE(foundSecret.has_value());
    EXPECT_EQ(foundSecret.value(), Secret({10, 20, 30, 40}));
}

TEST_F(SecretNodeManagerTest, FindSecretNotAdded)
{
    auto foundSecret = manager.findSecret(clientRandom2, SecretNode::ClientTrafficSecret);
    EXPECT_FALSE(foundSecret.has_value());
}

TEST_F(SecretNodeManagerTest, GetSecretNode)
{
    SecretNode secretNode = createTestSecretNode();
    manager.addSecrets(clientRandom1, std::move(secretNode));

    auto optSecretNode = manager.getSecretNode(clientRandom1);
    ASSERT_TRUE(optSecretNode.has_value());

    const SecretNode& retrievedNode = optSecretNode.value();
    const Secret& secret = retrievedNode.getSecret(SecretNode::ClientTrafficSecret);
    EXPECT_EQ(secret, Secret({10, 20, 30, 40}));
}

TEST_F(SecretNodeManagerTest, GetSecretNodeNotAdded)
{
    auto optSecretNode = manager.getSecretNode(clientRandom2);
    EXPECT_FALSE(optSecretNode.has_value());
}

class SecretNodeManagerFileTest : public ::testing::TestWithParam<std::string_view>
{
public:
    SecretNodeManagerFileTest()
        : testfile_(std::filesystem::temp_directory_path() / "test.keylog")
    {}

    ~SecretNodeManagerFileTest() noexcept = default;

    void SetUp() override
    {
        createLogFile(testfile_, GetParam());
    }

    void TearDown() override
    {
        std::filesystem::remove(testfile_);
    }

protected:
    std::filesystem::path testfile_;
};

TEST_P(SecretNodeManagerFileTest, ParseKeyLogFile)
{
    SecretNodeManager manager;
    ASSERT_NO_THROW(manager.parseKeyLogFile(testfile_));
}

INSTANTIATE_TEST_SUITE_P(
    KeyLogFileTests, SecretNodeManagerFileTest,
    ::testing::Values(
        "CLIENT_RANDOM 49a7f3596b92b6de40ca89c3faddbc0a38ec861d0fb93908b0d60094aaecbc15 "
        "917f6a06cdeba47275c4a0118f34b21d116b35d80a42c5f5f86c9d40876d025a78d2b32b5dedca6e13cc08f41c"
        "3210fd"));