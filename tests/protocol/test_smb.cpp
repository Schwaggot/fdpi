#include <gtest/gtest.h>

#include <fdpi/protocol/smb.hpp>

#include <vector>

TEST(SmbDecoder, ParsesSMB1Negotiate) {
    // SMB1 header: \xFF SMB + 28 bytes = 32 bytes minimum
    std::vector<uint8_t> data(32, 0);
    data[0] = 0xFF;
    data[1] = 'S';
    data[2] = 'M';
    data[3] = 'B';
    data[4] = 0x72; // command: Negotiate
    data[9] = 0x08; // flags

    size_t offset = 0;
    auto result = fdpi::decodeSmb(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 1);
    EXPECT_EQ(result->command, 0x72);
    EXPECT_EQ(result->flags, 0x08);
    EXPECT_EQ(offset, 32u);
}

TEST(SmbDecoder, ParsesSMB2Negotiate) {
    // SMB2 header: \xFE SMB + 60 bytes = 64 bytes minimum
    std::vector<uint8_t> data(64, 0);
    data[0] = 0xFE;
    data[1] = 'S';
    data[2] = 'M';
    data[3] = 'B';
    data[12] = 0x00; // command: Negotiate (0)

    size_t offset = 0;
    auto result = fdpi::decodeSmb(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 2);
    EXPECT_EQ(result->command, 0);
    EXPECT_EQ(offset, 64u);
}

TEST(SmbDecoder, RejectsBadMagic) {
    std::vector<uint8_t> data = {0x00, 'S', 'M', 'B', 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeSmb(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(SmbDecoder, RejectsTruncatedSMB1) {
    // SMB1 magic but only 20 bytes (need 32)
    std::vector<uint8_t> data(20, 0);
    data[0] = 0xFF;
    data[1] = 'S';
    data[2] = 'M';
    data[3] = 'B';

    size_t offset = 0;
    auto result = fdpi::decodeSmb(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(SmbDecoder, RejectsTruncatedSMB2) {
    // SMB2 magic but only 32 bytes (need 64)
    std::vector<uint8_t> data(32, 0);
    data[0] = 0xFE;
    data[1] = 'S';
    data[2] = 'M';
    data[3] = 'B';

    size_t offset = 0;
    auto result = fdpi::decodeSmb(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(SmbDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeSmb(data, offset);
    ASSERT_FALSE(result.has_value());
}
