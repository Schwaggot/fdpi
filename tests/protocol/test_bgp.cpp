#include <gtest/gtest.h>

#include <fdpi/protocol/bgp.hpp>

#include <vector>

// Helper: build a BGP message with 16-byte 0xFF marker
static std::vector<uint8_t> makeMarker() {
    return std::vector<uint8_t>(16, 0xFF);
}

TEST(BgpDecoder, ParsesOpenMessage) {
    auto data = makeMarker();
    // length = 29 (big-endian)
    data.push_back(0x00);
    data.push_back(29);
    // type = OPEN (1)
    data.push_back(0x01);
    // version = 4
    data.push_back(0x04);
    // myAS = 65001 (0xFDE9)
    data.push_back(0xFD);
    data.push_back(0xE9);
    // holdTime = 180 (0x00B4)
    data.push_back(0x00);
    data.push_back(0xB4);
    // bgpId = 10.0.0.1
    data.push_back(0x0A);
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x01);
    // optParmLen = 0
    data.push_back(0x00);

    size_t offset = 0;
    auto result = fdpi::decodeBgp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->length, 29);
    EXPECT_EQ(result->type, 1);
    ASSERT_TRUE(result->version.has_value());
    EXPECT_EQ(*result->version, 4);
    ASSERT_TRUE(result->myAs.has_value());
    EXPECT_EQ(*result->myAs, 65001);
    ASSERT_TRUE(result->holdTime.has_value());
    EXPECT_EQ(*result->holdTime, 180);
    ASSERT_TRUE(result->bgpId.has_value());
    EXPECT_EQ(*result->bgpId, fdpi::IPv4Address(0x0A000001));
    EXPECT_EQ(offset, 29u);
}

TEST(BgpDecoder, ParsesKeepalive) {
    auto data = makeMarker();
    // length = 19
    data.push_back(0x00);
    data.push_back(19);
    // type = KEEPALIVE (4)
    data.push_back(0x04);

    size_t offset = 0;
    auto result = fdpi::decodeBgp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->length, 19);
    EXPECT_EQ(result->type, 4);
    EXPECT_FALSE(result->version.has_value());
    EXPECT_FALSE(result->myAs.has_value());
    EXPECT_FALSE(result->holdTime.has_value());
    EXPECT_FALSE(result->bgpId.has_value());
    EXPECT_EQ(offset, 19u);
}

TEST(BgpDecoder, ParsesNotification) {
    auto data = makeMarker();
    // length = 21 (19 header + 2 error fields)
    data.push_back(0x00);
    data.push_back(21);
    // type = NOTIFICATION (3)
    data.push_back(0x03);
    // error code + subcode
    data.push_back(0x06);
    data.push_back(0x02);

    size_t offset = 0;
    auto result = fdpi::decodeBgp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 3);
    EXPECT_EQ(result->length, 21);
    EXPECT_FALSE(result->version.has_value());
    EXPECT_EQ(offset, 21u);
}

TEST(BgpDecoder, ExtractsAsNumber) {
    auto data = makeMarker();
    data.push_back(0x00);
    data.push_back(29);
    data.push_back(0x01); // OPEN
    data.push_back(0x04); // version
    // myAS = 64512 (0xFC00)
    data.push_back(0xFC);
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x5A); // holdTime = 90
    data.push_back(0xC0);
    data.push_back(0xA8);
    data.push_back(0x01);
    data.push_back(0x01); // bgpId = 192.168.1.1
    data.push_back(0x00); // optParmLen

    size_t offset = 0;
    auto result = fdpi::decodeBgp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->myAs.has_value());
    EXPECT_EQ(*result->myAs, 64512);
}

TEST(BgpDecoder, ExtractsBgpIdentifier) {
    auto data = makeMarker();
    data.push_back(0x00);
    data.push_back(29);
    data.push_back(0x01);
    data.push_back(0x04);
    data.push_back(0x00);
    data.push_back(0x01); // myAS = 1
    data.push_back(0x00);
    data.push_back(0xB4); // holdTime = 180
    // bgpId = 172.16.0.1
    data.push_back(0xAC);
    data.push_back(0x10);
    data.push_back(0x00);
    data.push_back(0x01);
    data.push_back(0x00);

    size_t offset = 0;
    auto result = fdpi::decodeBgp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->bgpId.has_value());
    EXPECT_EQ(*result->bgpId, fdpi::IPv4Address(0xAC100001));
}

TEST(BgpDecoder, ExtractsHoldTime) {
    auto data = makeMarker();
    data.push_back(0x00);
    data.push_back(29);
    data.push_back(0x01);
    data.push_back(0x04);
    data.push_back(0x00);
    data.push_back(0x01);
    // holdTime = 240 (0x00F0)
    data.push_back(0x00);
    data.push_back(0xF0);
    data.push_back(0x0A);
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x01);
    data.push_back(0x00);

    size_t offset = 0;
    auto result = fdpi::decodeBgp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->holdTime.has_value());
    EXPECT_EQ(*result->holdTime, 240);
}

TEST(BgpDecoder, RejectsTruncated) {
    // Only 18 bytes (need 19 minimum)
    auto data = makeMarker();
    data.push_back(0x00);
    data.push_back(19);

    size_t offset = 0;
    auto result = fdpi::decodeBgp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(BgpDecoder, RejectsInvalidMarker) {
    std::vector<uint8_t> data(16, 0xFF);
    data[8] = 0x00; // corrupt marker
    data.push_back(0x00);
    data.push_back(19);
    data.push_back(0x04);

    size_t offset = 0;
    auto result = fdpi::decodeBgp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}
