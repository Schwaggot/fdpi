#include <gtest/gtest.h>

#include <fdpi/protocol/imf.hpp>

#include <vector>

TEST(ImfDecoder, ParsesBasicEmail) {
    std::string raw = "From: sender@example.com\r\n"
                      "To: recipient@example.com\r\n"
                      "Subject: Test Email\r\n"
                      "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"
                      "Message-ID: <12345@example.com>\r\n"
                      "Content-Type: text/plain\r\n"
                      "\r\n"
                      "Body text here";
    std::vector<uint8_t> data(raw.begin(), raw.end());
    size_t offset = 0;
    auto result = fdpi::decodeImf(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->from, "sender@example.com");
    EXPECT_EQ(result->to, "recipient@example.com");
    EXPECT_EQ(result->subject, "Test Email");
    EXPECT_EQ(result->date, "Mon, 1 Jan 2024 00:00:00 +0000");
    EXPECT_EQ(result->messageId, "<12345@example.com>");
    EXPECT_EQ(result->contentType, "text/plain");
    EXPECT_EQ(result->headers.size(), 6u);
}

TEST(ImfDecoder, ParsesContinuationLine) {
    std::string raw = "Subject: This is a very long\r\n"
                      " subject line\r\n"
                      "\r\n";
    std::vector<uint8_t> data(raw.begin(), raw.end());
    size_t offset = 0;
    auto result = fdpi::decodeImf(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->subject, "This is a very long subject line");
}

TEST(ImfDecoder, ParsesMinimalHeaders) {
    std::string raw = "From: test@test.com\r\n"
                      "\r\n";
    std::vector<uint8_t> data(raw.begin(), raw.end());
    size_t offset = 0;
    auto result = fdpi::decodeImf(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->from, "test@test.com");
    EXPECT_EQ(result->headers.size(), 1u);
}

TEST(ImfDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeImf(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(ImfDecoder, RejectsNoHeaders) {
    std::string raw = "\r\n";
    std::vector<uint8_t> data(raw.begin(), raw.end());
    size_t offset = 0;
    auto result = fdpi::decodeImf(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}
