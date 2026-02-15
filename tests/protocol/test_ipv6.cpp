#include <gtest/gtest.h>
#include <fdpi/protocol/ipv6.hpp>
#include <vector>

TEST(IPv6Decoder, ParsesValidHeader) {
    // IPv6: version=6, trafficClass=0, flowLabel=0,
    //       payloadLength=20, nextHeader=6 (TCP), hopLimit=64
    //       src=::1, dst=::1
    std::vector<uint8_t> data = {
        0x60, 0x00, 0x00, 0x00, // version=6, TC=0, flowLabel=0
        0x00, 0x14,             // payloadLength=20
        0x06,                   // nextHeader=TCP
        0x40,                   // hopLimit=64
        // src: ::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // dst: ::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 6);
    EXPECT_EQ(result->trafficClass, 0);
    EXPECT_EQ(result->flowLabel, 0u);
    EXPECT_EQ(result->payloadLength, 20);
    EXPECT_EQ(result->nextHeader, 6);  // TCP
    EXPECT_EQ(result->hopLimit, 64);

    // Check src = ::1
    EXPECT_EQ(result->srcIp, fdpi::IPv6Address("::1"));
    EXPECT_EQ(result->dstIp, fdpi::IPv6Address("::1"));

    EXPECT_EQ(offset, 40u);
}

TEST(IPv6Decoder, ParsesTrafficClassAndFlowLabel) {
    // version=6, trafficClass=0xAB, flowLabel=0x12345
    // First 4 bytes: 6 | AB | 12345
    // Bits: 0110 AAAA BBBB CCCC CCCC CCCC CCCC CCCC
    //       0110 1010 1011 0001 0010 0011 0100 0101
    //       0x6A  0xB1  0x23  0x45
    std::vector<uint8_t> data = {
        0x6A, 0xB1, 0x23, 0x45, // version=6, TC=0xAB, flowLabel=0x12345
        0x00, 0x00,             // payloadLength=0
        0x3A,                   // nextHeader=ICMPv6
        0xFF,                   // hopLimit=255
        // src: fe80::1
        0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // dst: ff02::1
        0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 6);
    EXPECT_EQ(result->trafficClass, 0xAB);
    EXPECT_EQ(result->flowLabel, 0x12345u);
    EXPECT_EQ(result->nextHeader, 0x3A);  // ICMPv6
    EXPECT_EQ(result->hopLimit, 255);

    EXPECT_EQ(result->srcIp.bytes[0], 0xFE);
    EXPECT_EQ(result->srcIp.bytes[1], 0x80);
    EXPECT_EQ(result->srcIp.bytes[15], 0x01);

    EXPECT_EQ(result->dstIp.bytes[0], 0xFF);
    EXPECT_EQ(result->dstIp.bytes[1], 0x02);
}

TEST(IPv6Decoder, ParsesUDPNextHeader) {
    std::vector<uint8_t> data = {
        0x60, 0x00, 0x00, 0x00, // version=6
        0x00, 0x08,             // payloadLength=8
        0x11,                   // nextHeader=UDP (17)
        0x40,                   // hopLimit=64
        // src: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // dst: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->nextHeader, 17);  // UDP
    EXPECT_EQ(result->payloadLength, 8);
}

TEST(IPv6Decoder, RejectsTruncatedHeader) {
    // Only 39 bytes - need 40 for IPv6 header
    std::vector<uint8_t> data(39, 0);
    data[0] = 0x60;  // version 6
    size_t offset = 0;
    auto result = fdpi::decodeIPv6(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(IPv6Decoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeIPv6(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(IPv6Decoder, ParsesWithNonZeroOffset) {
    std::vector<uint8_t> data(44, 0);
    // 4 bytes padding + 40 bytes IPv6 header
    data[4] = 0x60;  // version 6
    data[11] = 0x40; // hopLimit=64

    size_t offset = 4;
    auto result = fdpi::decodeIPv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 6);
    EXPECT_EQ(result->hopLimit, 64);
    EXPECT_EQ(offset, 44u);
}

TEST(IPv6Decoder, ParsesZeroPayloadLength) {
    // Jumbogram: payloadLength=0
    std::vector<uint8_t> data = {
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x00,             // payloadLength=0
        0x06,                   // nextHeader=TCP
        0x01,                   // hopLimit=1
        // src/dst all zeros
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payloadLength, 0);
}
