#include <gtest/gtest.h>

#include <fdpi/protocol/ssh.hpp>

#include <vector>

static std::vector<uint8_t> toBytes(const std::string& s) {
    return {s.begin(), s.end()};
}

TEST(SshDecoder, ParsesOpenSshBanner) {
    auto data = toBytes("SSH-2.0-OpenSSH_9.0\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSsh(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->protocolVersion, "2.0");
    EXPECT_EQ(result->softwareVersion, "OpenSSH_9.0");
    EXPECT_FALSE(result->comments.has_value());
    EXPECT_EQ(offset, data.size());
}

TEST(SshDecoder, ParsesDropbearBanner) {
    auto data = toBytes("SSH-2.0-dropbear_2022.83\n");
    size_t offset = 0;
    auto result = fdpi::decodeSsh(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->protocolVersion, "2.0");
    EXPECT_EQ(result->softwareVersion, "dropbear_2022.83");
    EXPECT_FALSE(result->comments.has_value());
    EXPECT_EQ(offset, data.size());
}

TEST(SshDecoder, ParsesVersionWithComments) {
    auto data = toBytes("SSH-2.0-OpenSSH_9.0 some comment\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSsh(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->protocolVersion, "2.0");
    EXPECT_EQ(result->softwareVersion, "OpenSSH_9.0");
    ASSERT_TRUE(result->comments.has_value());
    EXPECT_EQ(*result->comments, "some comment");
}

TEST(SshDecoder, ParsesSsh1Banner) {
    auto data = toBytes("SSH-1.99-OpenSSH_6.0p1\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSsh(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->protocolVersion, "1.99");
    EXPECT_EQ(result->softwareVersion, "OpenSSH_6.0p1");
    EXPECT_FALSE(result->comments.has_value());
}

TEST(SshDecoder, RejectsTruncated) {
    // No newline terminator
    auto data = toBytes("SSH-2.0-OpenSSH_9.0");
    size_t offset = 0;
    auto result = fdpi::decodeSsh(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(SshDecoder, RejectsInvalidPrefix) {
    auto data = toBytes("HTTP/1.1 200 OK\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSsh(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(SshDecoder, HandlesNonZeroOffset) {
    // 3 bytes padding + SSH banner
    std::string banner = "SSH-2.0-libssh_0.10.0\r\n";
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE};
    data.insert(data.end(), banner.begin(), banner.end());
    size_t offset = 3;
    auto result = fdpi::decodeSsh(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->protocolVersion, "2.0");
    EXPECT_EQ(result->softwareVersion, "libssh_0.10.0");
    EXPECT_EQ(offset, 3 + banner.size());
}
