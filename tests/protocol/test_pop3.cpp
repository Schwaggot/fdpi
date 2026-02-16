#include <gtest/gtest.h>

#include <fdpi/protocol/pop3.hpp>

#include <vector>

static std::vector<uint8_t> toBytes(const std::string& s) {
    return {s.begin(), s.end()};
}

TEST(Pop3Decoder, ParsesOkResponse) {
    auto data = toBytes("+OK POP3 server ready\r\n");
    size_t offset = 0;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_TRUE(result->success);
    EXPECT_EQ(result->responseText, "POP3 server ready");
    EXPECT_EQ(offset, 23u);
}

TEST(Pop3Decoder, ParsesErrResponse) {
    auto data = toBytes("-ERR invalid password\r\n");
    size_t offset = 0;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_FALSE(result->success);
    EXPECT_EQ(result->responseText, "invalid password");
}

TEST(Pop3Decoder, ParsesUserCommand) {
    auto data = toBytes("USER alice\r\n");
    size_t offset = 0;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "USER");
    EXPECT_EQ(result->argument, "alice");
}

TEST(Pop3Decoder, ParsesPassCommand) {
    auto data = toBytes("PASS secret\r\n");
    size_t offset = 0;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "PASS");
    EXPECT_EQ(result->argument, "secret");
}

TEST(Pop3Decoder, ParsesStatCommand) {
    auto data = toBytes("STAT\r\n");
    size_t offset = 0;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "STAT");
    EXPECT_TRUE(result->argument.empty());
}

TEST(Pop3Decoder, ParsesRetrCommand) {
    auto data = toBytes("RETR 1\r\n");
    size_t offset = 0;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "RETR");
    EXPECT_EQ(result->argument, "1");
}

TEST(Pop3Decoder, ParsesQuitCommand) {
    auto data = toBytes("QUIT\r\n");
    size_t offset = 0;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "QUIT");
    EXPECT_TRUE(result->argument.empty());
}

TEST(Pop3Decoder, ExtractsResponseText) {
    auto data = toBytes("+OK 2 messages (320 octets)\r\n");
    size_t offset = 0;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_TRUE(result->success);
    EXPECT_EQ(result->responseText, "2 messages (320 octets)");
}

TEST(Pop3Decoder, RejectsTruncated) {
    auto data = toBytes("USER test");
    size_t offset = 0;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(Pop3Decoder, HandlesNonZeroOffset) {
    std::string s = "JUNK+OK ready\r\n";
    auto data = toBytes(s);
    size_t offset = 4;
    auto result = fdpi::decodePop3(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_TRUE(result->success);
    EXPECT_EQ(result->responseText, "ready");
    EXPECT_EQ(offset, 15u);
}
