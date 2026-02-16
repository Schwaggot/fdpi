#include <gtest/gtest.h>

#include <fdpi/protocol/imap.hpp>

#include <vector>

static std::vector<uint8_t> toBytes(const std::string& s) {
    return {s.begin(), s.end()};
}

TEST(ImapDecoder, ParsesServerGreeting) {
    auto data = toBytes("* OK IMAP4rev1 server ready\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->tag, "*");
    EXPECT_EQ(result->command, "OK");
    EXPECT_EQ(result->argument, "IMAP4rev1 server ready");
    EXPECT_EQ(offset, 29u);
}

TEST(ImapDecoder, ParsesUntaggedOk) {
    auto data = toBytes("* BYE server shutting down\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->tag, "*");
    EXPECT_EQ(result->command, "BYE");
    EXPECT_EQ(result->argument, "server shutting down");
}

TEST(ImapDecoder, ParsesLoginCommand) {
    auto data = toBytes("A001 LOGIN alice secret\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->tag, "A001");
    EXPECT_EQ(result->command, "LOGIN");
    EXPECT_EQ(result->argument, "alice secret");
}

TEST(ImapDecoder, ParsesSelectCommand) {
    auto data = toBytes("A002 SELECT INBOX\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->tag, "A002");
    EXPECT_EQ(result->command, "SELECT");
    EXPECT_EQ(result->argument, "INBOX");
}

TEST(ImapDecoder, ParsesTaggedOkResponse) {
    auto data = toBytes("A001 OK LOGIN completed\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->tag, "A001");
    EXPECT_EQ(result->statusCode, "OK");
    EXPECT_EQ(result->responseText, "LOGIN completed");
}

TEST(ImapDecoder, ParsesTaggedNoResponse) {
    auto data = toBytes("A001 NO LOGIN failed\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->tag, "A001");
    EXPECT_EQ(result->statusCode, "NO");
    EXPECT_EQ(result->responseText, "LOGIN failed");
}

TEST(ImapDecoder, ParsesFetchCommand) {
    auto data = toBytes("A003 FETCH 1 (FLAGS BODY[HEADER])\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->tag, "A003");
    EXPECT_EQ(result->command, "FETCH");
    EXPECT_EQ(result->argument, "1 (FLAGS BODY[HEADER])");
}

TEST(ImapDecoder, ParsesLogoutCommand) {
    auto data = toBytes("A004 LOGOUT\r\n");
    size_t offset = 0;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->tag, "A004");
    EXPECT_EQ(result->command, "LOGOUT");
    EXPECT_TRUE(result->argument.empty());
}

TEST(ImapDecoder, RejectsTruncated) {
    auto data = toBytes("A001 LOGIN user pass");
    size_t offset = 0;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(ImapDecoder, HandlesNonZeroOffset) {
    std::string s = "PAD* OK ready\r\n";
    auto data = toBytes(s);
    size_t offset = 3;
    auto result = fdpi::decodeImap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->tag, "*");
    EXPECT_EQ(result->command, "OK");
    EXPECT_EQ(result->argument, "ready");
    EXPECT_EQ(offset, 15u);
}
