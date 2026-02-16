#include <gtest/gtest.h>

#include <fdpi/protocol/smtp.hpp>

#include <vector>

static std::vector<uint8_t> toBytes(const std::string& s) {
    return {s.begin(), s.end()};
}

TEST(SmtpDecoder, ParsesServerGreeting) {
    auto data = toBytes("220 mail.example.com ESMTP Postfix\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->replyCode, 220);
    EXPECT_EQ(result->replyText, "mail.example.com ESMTP Postfix");
}

TEST(SmtpDecoder, ParsesEhloCommand) {
    auto data = toBytes("EHLO client.example.com\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "EHLO");
    EXPECT_EQ(result->argument, "client.example.com");
    EXPECT_EQ(result->replyCode, 0);
}

TEST(SmtpDecoder, ParsesMailFromCommand) {
    auto data = toBytes("MAIL FROM:<user@example.com>\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "MAIL");
    EXPECT_EQ(result->argument, "FROM:<user@example.com>");
}

TEST(SmtpDecoder, ParsesRcptToCommand) {
    auto data = toBytes("RCPT TO:<dest@example.com>\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "RCPT");
    EXPECT_EQ(result->argument, "TO:<dest@example.com>");
}

TEST(SmtpDecoder, ParsesDataCommand) {
    auto data = toBytes("DATA\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->command, "DATA");
    EXPECT_TRUE(result->argument.empty());
}

TEST(SmtpDecoder, ParsesReplyCode) {
    auto data = toBytes("354 End data with <CR><LF>.<CR><LF>\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->replyCode, 354);
}

TEST(SmtpDecoder, Parses250Response) {
    auto data = toBytes("250 OK\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->replyCode, 250);
    EXPECT_EQ(result->replyText, "OK");
}

TEST(SmtpDecoder, ParsesMultilineReply) {
    auto data = toBytes("250-mail.example.com Hello\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->replyCode, 250);
    EXPECT_EQ(result->replyText, "mail.example.com Hello");
}

TEST(SmtpDecoder, RejectsTruncated) {
    auto data = toBytes("EHLO example.com");
    size_t offset = 0;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(SmtpDecoder, HandlesNonZeroOffset) {
    std::string s = "XXX250 OK\r\n";
    auto data = toBytes(s);
    size_t offset = 3;
    auto result = fdpi::decodeSmtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->replyCode, 250);
    EXPECT_EQ(result->replyText, "OK");
    EXPECT_EQ(offset, 11u);
}
