#include <gtest/gtest.h>

#include <fdpi/protocol/eapol.hpp>

#include <vector>

TEST(EapolDecoder, ParsesEapolKey) {
    // EAPOL-Key: version=2, type=3 (Key), bodyLength=95
    std::vector<uint8_t> data = {
        0x02, // version
        0x03, // type (Key)
        0x00,
        0x5F, // body length = 95
    };
    // Append 95 bytes of key body
    data.resize(4 + 95, 0xAB);

    size_t offset = 0;
    auto result = fdpi::decodeEapol(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 2);
    EXPECT_EQ(result->type, 3);
    EXPECT_EQ(result->bodyLength, 95);
    EXPECT_EQ(result->body.size(), 95u);
    EXPECT_EQ(result->body[0], 0xAB);
    EXPECT_EQ(offset, 99u); // 4 header + 95 body
}

TEST(EapolDecoder, ParsesEapolStart) {
    // EAPOL-Start: version=1, type=1, bodyLength=0 (no body)
    std::vector<uint8_t> data = {
        0x01, // version
        0x01, // type (Start)
        0x00,
        0x00, // body length = 0
    };
    size_t offset = 0;
    auto result = fdpi::decodeEapol(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 1);
    EXPECT_EQ(result->type, 1);
    EXPECT_EQ(result->bodyLength, 0);
    EXPECT_TRUE(result->body.empty());
    EXPECT_EQ(offset, 4u);
}

TEST(EapolDecoder, TruncatedHeader) {
    // Only 3 bytes — not enough for 4-byte EAPOL header
    std::vector<uint8_t> data = {0x02, 0x03, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeEapol(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(EapolDecoder, BodyClampedToAvailable) {
    // bodyLength=100 but only 10 body bytes available
    std::vector<uint8_t> data = {
        0x02, // version
        0x03, // type (Key)
        0x00,
        0x64, // body length = 100
    };
    data.resize(4 + 10, 0xCD);

    size_t offset = 0;
    auto result = fdpi::decodeEapol(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->bodyLength, 100);
    EXPECT_EQ(result->body.size(), 10u); // clamped
    EXPECT_EQ(offset, 14u);
}

TEST(EapolDecoder, HandlesNonZeroOffset) {
    // 4 bytes padding + valid EAPOL
    std::vector<uint8_t> data = {
        0xDE, 0xAD, 0xBE, 0xEF, // padding
        0x01,                   // version
        0x02,                   // type (Logoff)
        0x00, 0x00,             // body length = 0
    };
    size_t offset = 4;
    auto result = fdpi::decodeEapol(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 1);
    EXPECT_EQ(result->type, 2);
    EXPECT_EQ(offset, 8u);
}
