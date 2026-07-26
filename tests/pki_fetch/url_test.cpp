#include <gtest/gtest.h>
#include <snet/pki_fetch/url.hpp>

using namespace snet::pki_fetch;

class UrlParserTest : public ::testing::Test
{
};

TEST_F(UrlParserTest, ParseHttpWithoutPort)
{
    auto res = UrlParser::parse("http://example.com/status");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "example.com");
    EXPECT_EQ(res->port, "80");
    EXPECT_EQ(res->path, "/status");
}

TEST_F(UrlParserTest, ParseHttpsWithoutPort)
{
    auto res = UrlParser::parse("https://example.com/check");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "example.com");
    EXPECT_EQ(res->port, "443");
    EXPECT_EQ(res->path, "/check");
}

TEST_F(UrlParserTest, ParseHttpWithPort)
{
    auto res = UrlParser::parse("http://example.com:8080/status");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "example.com");
    EXPECT_EQ(res->port, "8080");
    EXPECT_EQ(res->path, "/status");
}

TEST_F(UrlParserTest, ParseHttpsWithPort)
{
    auto res = UrlParser::parse("https://example.com:8443/ocsp");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "example.com");
    EXPECT_EQ(res->port, "8443");
    EXPECT_EQ(res->path, "/ocsp");
}

TEST_F(UrlParserTest, ParseUrlWithoutPath)
{
    auto res = UrlParser::parse("http://example.com");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "example.com");
    EXPECT_EQ(res->port, "80");
    EXPECT_EQ(res->path, "/");
}

TEST_F(UrlParserTest, ParseUrlWithRootPath)
{
    auto res = UrlParser::parse("https://example.com/");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "example.com");
    EXPECT_EQ(res->port, "443");
    EXPECT_EQ(res->path, "/");
}

TEST_F(UrlParserTest, ParseUrlWithComplexPath)
{
    auto res = UrlParser::parse("http://ca.com/v1/status/123");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "ca.com");
    EXPECT_EQ(res->port, "80");
    EXPECT_EQ(res->path, "/v1/status/123");
}

TEST_F(UrlParserTest, ParseUrlWithQueryParams)
{
    auto res = UrlParser::parse("https://example.com/status?serial=123&issuer=456");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "example.com");
    EXPECT_EQ(res->port, "443");
    EXPECT_EQ(res->path, "/status?serial=123&issuer=456");
}

TEST_F(UrlParserTest, ParseUrlWithSubdomain)
{
    auto res = UrlParser::parse("http://subdomain.example.com/status");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "subdomain.example.com");
    EXPECT_EQ(res->port, "80");
    EXPECT_EQ(res->path, "/status");
}

TEST_F(UrlParserTest, ParseIpv4Address)
{
    auto res = UrlParser::parse("http://192.168.1.1:8080/status");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "192.168.1.1");
    EXPECT_EQ(res->port, "8080");
    EXPECT_EQ(res->path, "/status");
}

TEST_F(UrlParserTest, ParseIpv6Address)
{
    auto res = UrlParser::parse("http://[::1]:8080/status");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "[::1]");
    EXPECT_EQ(res->port, "8080");
    EXPECT_EQ(res->path, "/status");
}

TEST_F(UrlParserTest, RejectUnsupportedScheme)
{
    auto res = UrlParser::parse("ftp://example.com/status");
    EXPECT_FALSE(res.has_value());
}

TEST_F(UrlParserTest, RejectMissingScheme)
{
    auto res = UrlParser::parse("example.com/status");
    EXPECT_FALSE(res.has_value());
}

TEST_F(UrlParserTest, RejectEmptyHost)
{
    auto res = UrlParser::parse("http:///status");
    EXPECT_FALSE(res.has_value());
}

TEST_F(UrlParserTest, RejectEmptyPort)
{
    auto res = UrlParser::parse("http://example.com:/status");
    EXPECT_FALSE(res.has_value());
}

TEST_F(UrlParserTest, RejectEmptyUrl)
{
    auto res = UrlParser::parse("");
    EXPECT_FALSE(res.has_value());
}

TEST_F(UrlParserTest, RejectOnlyScheme)
{
    auto res = UrlParser::parse("http://");
    EXPECT_FALSE(res.has_value());
}

TEST_F(UrlParserTest, RejectPortWithLetters)
{
    auto res = UrlParser::parse("http://example.com:abc/status");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->port, "abc");
}

TEST_F(UrlParserTest, HandleUrlWithMultipleColons)
{
    auto res = UrlParser::parse("http://example.com/path:with:colon");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "example.com");
    EXPECT_EQ(res->port, "80");
    EXPECT_EQ(res->path, "/path:with:colon");
}

TEST_F(UrlParserTest, HandleUrlWithPortAndNoPath)
{
    auto res = UrlParser::parse("https://example.com:443");
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->host, "example.com");
    EXPECT_EQ(res->port, "443");
    EXPECT_EQ(res->path, "/");
}