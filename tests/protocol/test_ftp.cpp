#include <gtest/gtest.h>

#include <fdpi/protocol/ftp.hpp>

#include <vector>

static std::vector<uint8_t> toBytes(const std::string& s) {
    return {s.begin(), s.end()};
}

TEST(FtpDecoder, ParsesServerGreeting) {
    auto data = toBytes("220 Welcome to FTP server\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->replyCode, 220);
    EXPECT_EQ(result->replyText, "Welcome to FTP server");
    EXPECT_EQ(offset, 27u);
}

TEST(FtpDecoder, ParsesReplyCode) {
    auto data = toBytes("331 Please specify the password\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->replyCode, 331);
    EXPECT_EQ(result->replyText, "Please specify the password");
}

TEST(FtpDecoder, ParsesUserCommand) {
    auto data = toBytes("USER anonymous\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "USER");
    EXPECT_EQ(result->argument, "anonymous");
    EXPECT_EQ(result->replyCode, 0);
}

TEST(FtpDecoder, ParsesPassCommand) {
    auto data = toBytes("PASS secret123\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "PASS");
    EXPECT_EQ(result->argument, "secret123");
}

TEST(FtpDecoder, ParsesRetrCommand) {
    auto data = toBytes("RETR /pub/file.txt\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "RETR");
    EXPECT_EQ(result->argument, "/pub/file.txt");
}

TEST(FtpDecoder, ParsesQuitCommand) {
    auto data = toBytes("QUIT\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "QUIT");
    EXPECT_TRUE(result->argument.empty());
}

TEST(FtpDecoder, ParsesMultilineReply) {
    // Multiline reply uses dash after code
    auto data = toBytes("220-Welcome\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->replyCode, 220);
    EXPECT_EQ(result->replyText, "Welcome");
}

TEST(FtpDecoder, RejectsTruncated) {
    // No CRLF
    auto data = toBytes("USER test");
    size_t offset = 0;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(FtpDecoder, RejectsEmpty) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(FtpDecoder, HandlesNonZeroOffset) {
    // 5 bytes padding + "USER test\r\n"
    std::string s = "XXXXXUSER test\r\n";
    auto data = toBytes(s);
    size_t offset = 5;
    auto result = fdpi::decodeFtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "USER");
    EXPECT_EQ(result->argument, "test");
    EXPECT_EQ(offset, 16u);
}
