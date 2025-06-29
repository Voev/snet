#include <casket/nonstd/span.hpp>
#include <gtest/gtest.h>
#include <snet/tls/alert.hpp>

using namespace snet::tls;

TEST(AlertTest, DefaultConstructor) {
    Alert alert;
    ASSERT_FALSE(alert.isFatal());
    ASSERT_EQ(alert.description(), Alert::None);
    ASSERT_FALSE(alert.isValid());
}

TEST(AlertTest, ParameterizedConstructor) {
    Alert alert(Alert::HandshakeFailure, true);
    ASSERT_TRUE(alert.isFatal());
    ASSERT_EQ(alert.description(), Alert::HandshakeFailure);
    ASSERT_TRUE(alert.isValid());
}

TEST(AlertTest, CopyConstructor) {
    Alert original(Alert::BadCertificate, false);
    Alert copy(original);
    ASSERT_EQ(copy.isFatal(), original.isFatal());
    ASSERT_EQ(copy.description(), original.description());
}

TEST(AlertTest, MoveConstructor) {
    Alert original(Alert::UnsupportedCertificate, true);
    Alert moved(std::move(original));
    ASSERT_TRUE(moved.isFatal());
    ASSERT_EQ(moved.description(), Alert::UnsupportedCertificate);
}

TEST(AlertTest, CopyAssignmentOperator) {
    Alert original(Alert::CertificateExpired, true);
    Alert copy;
    copy = original;
    ASSERT_EQ(copy.isFatal(), original.isFatal());
    ASSERT_EQ(copy.description(), original.description());
}

TEST(AlertTest, MoveAssignmentOperator) {
    Alert original(Alert::CertificateRevoked, false);
    Alert moved;
    moved = std::move(original);
    ASSERT_FALSE(moved.isFatal());
    ASSERT_EQ(moved.description(), Alert::CertificateRevoked);
}

TEST(AlertTest, InvalidAlertData) {
    std::vector<uint8_t> data = {1, 0, 22};
    ASSERT_THROW(Alert _(data), std::runtime_error);
}

TEST(AlertTest, ToStringAndSerialization) {
    Alert alert(Alert::InternalError, true);
    std::string str = alert.toString();
    std::vector<uint8_t> serialized = alert.serialize();

    Alert deserialized(serialized);
    ASSERT_EQ(alert.isFatal(), deserialized.isFatal());
    ASSERT_EQ(alert.description(), deserialized.description());
}

