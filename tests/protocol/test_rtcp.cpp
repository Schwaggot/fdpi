#include <gtest/gtest.h>

#include <fdpi/protocol/rtcp.hpp>

#include <vector>

// Build an RTCP packet: V=2, padding, RC, PT, length, SSRC
static std::vector<uint8_t>
makeRtcpPacket(bool padding, uint8_t rc, uint8_t pt, uint16_t length, uint32_t ssrc) {
    size_t totalSize = (static_cast<size_t>(length) + 1) * 4;
    std::vector<uint8_t> pkt(totalSize, 0);
    pkt[0] = static_cast<uint8_t>((2 << 6) | (padding ? (1 << 5) : 0) | (rc & 0x1F));
    pkt[1] = pt;
    pkt[2] = static_cast<uint8_t>((length >> 8) & 0xFF);
    pkt[3] = static_cast<uint8_t>(length & 0xFF);
    pkt[4] = static_cast<uint8_t>((ssrc >> 24) & 0xFF);
    pkt[5] = static_cast<uint8_t>((ssrc >> 16) & 0xFF);
    pkt[6] = static_cast<uint8_t>((ssrc >> 8) & 0xFF);
    pkt[7] = static_cast<uint8_t>(ssrc & 0xFF);
    return pkt;
}

TEST(RtcpDecoder, ParsesSenderReport) {
    auto data = makeRtcpPacket(false, 0, 200, 6, 0x12345678);
    size_t offset = 0;
    auto result = fdpi::decodeRtcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 2);
    EXPECT_FALSE(result->padding);
    EXPECT_EQ(result->receptionReportCount, 0);
    EXPECT_EQ(result->packetType, 200);
    EXPECT_EQ(result->length, 6);
    EXPECT_EQ(result->ssrc, 0x12345678u);
}

TEST(RtcpDecoder, ParsesReceiverReport) {
    auto data = makeRtcpPacket(false, 1, 201, 1, 0xAABBCCDD);
    size_t offset = 0;
    auto result = fdpi::decodeRtcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->packetType, 201);
    EXPECT_EQ(result->receptionReportCount, 1);
    EXPECT_EQ(result->ssrc, 0xAABBCCDDu);
}

TEST(RtcpDecoder, ParsesWithPadding) {
    auto data = makeRtcpPacket(true, 0, 200, 1, 0);
    size_t offset = 0;
    auto result = fdpi::decodeRtcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->padding);
}

TEST(RtcpDecoder, ParsesBye) {
    auto data = makeRtcpPacket(false, 1, 203, 1, 0x11111111);
    size_t offset = 0;
    auto result = fdpi::decodeRtcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->packetType, 203);
}

TEST(RtcpDecoder, RejectsTruncated) {
    std::vector<uint8_t> data(7, 0); // 7 < 8
    size_t offset = 0;
    auto result = fdpi::decodeRtcp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(RtcpDecoder, HandlesNonZeroOffset) {
    auto pkt = makeRtcpPacket(false, 0, 200, 1, 0xDEADBEEF);
    std::vector<uint8_t> data(4, 0xEE);
    data.insert(data.end(), pkt.begin(), pkt.end());
    size_t offset = 4;
    auto result = fdpi::decodeRtcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ssrc, 0xDEADBEEFu);
}
