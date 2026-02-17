#include <gtest/gtest.h>

#include <fdpi/protocol/homeplug.hpp>

#include <vector>

static std::vector<uint8_t> makeHomePlugPacket(const uint8_t version,
                                               const uint16_t mmType) {
    std::vector<uint8_t> pkt(5, 0);
    pkt[0] = version;
    pkt[1] = static_cast<uint8_t>(mmType & 0xFF);        // little-endian low
    pkt[2] = static_cast<uint8_t>((mmType >> 8) & 0xFF); // little-endian high
    pkt[3] = 0x00;                                       // fragmentation info
    pkt[4] = 0x00;
    return pkt;
}

TEST(HomePlugDecoder, ParsesBasicPacket) {
    auto data = makeHomePlugPacket(1, 0xA000);
    size_t offset = 0;
    auto result = fdpi::decodeHomeplug(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 1);
    EXPECT_EQ(result->type, 0xA000);
    EXPECT_EQ(offset, 5u);
}

TEST(HomePlugDecoder, ParsesVersion0) {
    auto data = makeHomePlugPacket(0, 0x0004);
    size_t offset = 0;
    auto result = fdpi::decodeHomeplug(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 0);
    EXPECT_EQ(result->type, 0x0004);
}

TEST(HomePlugDecoder, RejectsTruncated) {
    std::vector<uint8_t> data = {0x01, 0x00, 0x00, 0x00}; // Only 4 bytes
    size_t offset = 0;
    auto result = fdpi::decodeHomeplug(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(HomePlugDecoder, HandlesNonZeroOffset) {
    auto pkt = makeHomePlugPacket(2, 0x6050);
    std::vector<uint8_t> data(3, 0xBB); // 3 bytes padding
    data.insert(data.end(), pkt.begin(), pkt.end());
    size_t offset = 3;
    auto result = fdpi::decodeHomeplug(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 2);
    EXPECT_EQ(result->type, 0x6050);
    EXPECT_EQ(offset, 8u);
}
