#include <gtest/gtest.h>
#include <fdpi/protocol/ipv4.hpp>
#include <vector>

TEST(IPv4Decoder, ParsesValidHeader) {
    // IPv4: version=4, IHL=5, DSCP=0, ECN=0, totalLength=40,
    //       id=0x1234, flags=0x40 (DF), fragOffset=0, TTL=64,
    //       protocol=6 (TCP), checksum=0, src=192.168.1.1, dst=10.0.0.1
    std::vector<uint8_t> data = {
        0x45,                   // version=4, IHL=5
        0x00,                   // DSCP=0, ECN=0
        0x00, 0x28,             // totalLength=40
        0x12, 0x34,             // identification
        0x40, 0x00,             // flags=DF, fragmentOffset=0
        0x40,                   // TTL=64
        0x06,                   // protocol=TCP
        0x00, 0x00,             // checksum (0 for test)
        0xC0, 0xA8, 0x01, 0x01, // src: 192.168.1.1
        0x0A, 0x00, 0x00, 0x01  // dst: 10.0.0.1
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 4);
    EXPECT_EQ(result->ihl, 5);
    EXPECT_EQ(result->dscp, 0);
    EXPECT_EQ(result->ecn, 0);
    EXPECT_EQ(result->totalLength, 40);
    EXPECT_EQ(result->identification, 0x1234);
    EXPECT_EQ(result->flags, 0x02);  // DF bit set (bit 1 of 3-bit flags field)
    EXPECT_EQ(result->fragmentOffset, 0);
    EXPECT_EQ(result->ttl, 64);
    EXPECT_EQ(result->protocol, 6);  // TCP
    EXPECT_EQ(result->srcIp, fdpi::IPv4Address(0xC0A80101));
    EXPECT_EQ(result->dstIp, fdpi::IPv4Address(0x0A000001));
    EXPECT_TRUE(result->options.empty());
    EXPECT_EQ(offset, 20u);
}

TEST(IPv4Decoder, ParsesHeaderWithOptions) {
    // IPv4 with IHL=6 (24 bytes, 4 bytes of options)
    std::vector<uint8_t> data = {
        0x46,                   // version=4, IHL=6
        0x00,                   // DSCP=0, ECN=0
        0x00, 0x1C,             // totalLength=28
        0x00, 0x01,             // identification
        0x00, 0x00,             // flags=0, fragmentOffset=0
        0x40,                   // TTL=64
        0x11,                   // protocol=UDP
        0x00, 0x00,             // checksum
        0x7F, 0x00, 0x00, 0x01, // src: 127.0.0.1
        0x7F, 0x00, 0x00, 0x01, // dst: 127.0.0.1
        0x01, 0x01, 0x01, 0x00  // options: NOP, NOP, NOP, End
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ihl, 6);
    EXPECT_EQ(result->protocol, 17);  // UDP
    ASSERT_EQ(result->options.size(), 4u);
    EXPECT_EQ(result->options[0], 0x01);  // NOP
    EXPECT_EQ(offset, 24u);
}

TEST(IPv4Decoder, ParsesFragmentedPacket) {
    // More Fragments flag set, fragment offset = 0 (first fragment)
    std::vector<uint8_t> data = {
        0x45,                   // version=4, IHL=5
        0x00,                   // TOS
        0x00, 0x3C,             // totalLength=60
        0xAB, 0xCD,             // identification
        0x20, 0x00,             // flags=MF (0x2000), fragmentOffset=0
        0x40,                   // TTL=64
        0x06,                   // protocol=TCP
        0x00, 0x00,             // checksum
        0x0A, 0x00, 0x01, 0x01, // src: 10.0.1.1
        0x0A, 0x00, 0x02, 0x02  // dst: 10.0.2.2
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->identification, 0xABCD);
    EXPECT_EQ(result->flags, 0x01);  // MF bit set (bit 0 of flags)
    EXPECT_EQ(result->fragmentOffset, 0);
}

TEST(IPv4Decoder, ParsesNonZeroFragmentOffset) {
    // Fragment offset = 185 (185 * 8 = 1480 bytes)
    // flags_frag = 0x00B9 -> no flags, offset=185
    std::vector<uint8_t> data = {
        0x45,                   // version=4, IHL=5
        0x00,                   // TOS
        0x00, 0x28,             // totalLength=40
        0xAB, 0xCD,             // identification
        0x00, 0xB9,             // flags=0, fragmentOffset=185
        0x40,                   // TTL=64
        0x06,                   // protocol=TCP
        0x00, 0x00,             // checksum
        0x0A, 0x00, 0x01, 0x01, // src
        0x0A, 0x00, 0x02, 0x02  // dst
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->fragmentOffset, 185);
}

TEST(IPv4Decoder, RejectsTruncatedHeader) {
    // Only 19 bytes - need at least 20
    std::vector<uint8_t> data = {
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01,
        0x0A, 0x00, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(IPv4Decoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(IPv4Decoder, RejectsInvalidIHL) {
    // IHL=2 (less than minimum 5)
    std::vector<uint8_t> data = {
        0x42,                   // version=4, IHL=2 (invalid)
        0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01,
        0x0A, 0x00, 0x00, 0x01
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(IPv4Decoder, ParsesMinimumSizeHeader) {
    // IHL=5 (20 bytes), totalLength=20 (header only, no payload)
    std::vector<uint8_t> data = {
        0x45,                   // version=4, IHL=5
        0x00,                   // TOS
        0x00, 0x14,             // totalLength=20 (minimum)
        0x00, 0x00,             // identification
        0x00, 0x00,             // flags, fragment offset
        0x01,                   // TTL=1
        0x01,                   // protocol=ICMP
        0x00, 0x00,             // checksum
        0x00, 0x00, 0x00, 0x00, // src: 0.0.0.0
        0xFF, 0xFF, 0xFF, 0xFF  // dst: 255.255.255.255 (broadcast)
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->totalLength, 20);
    EXPECT_EQ(result->ttl, 1);
    EXPECT_EQ(result->protocol, 1);  // ICMP
    EXPECT_EQ(result->dstIp, fdpi::IPv4Address(0xFFFFFFFF));
}

TEST(IPv4Decoder, ParsesDSCPAndECN) {
    // TOS byte: DSCP=46 (EF, 101110), ECN=3 (CE, 11)
    // TOS = (46 << 2) | 3 = 0xBB
    std::vector<uint8_t> data = {
        0x45,                   // version=4, IHL=5
        0xBB,                   // DSCP=46, ECN=3
        0x00, 0x28,             // totalLength=40
        0x00, 0x01,             // identification
        0x00, 0x00,             // flags, fragment offset
        0x40,                   // TTL=64
        0x06,                   // protocol=TCP
        0x00, 0x00,             // checksum
        0xC0, 0xA8, 0x00, 0x01, // src
        0xC0, 0xA8, 0x00, 0x02  // dst
    };
    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->dscp, 46);
    EXPECT_EQ(result->ecn, 3);
}

TEST(IPv4Decoder, ParsesMaxOptionsHeader) {
    // IHL=15 (60 bytes, 40 bytes of options - maximum)
    std::vector<uint8_t> data(60, 0);
    data[0] = 0x4F;              // version=4, IHL=15
    data[2] = 0x00; data[3] = 0x3C;  // totalLength=60

    size_t offset = 0;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ihl, 15);
    EXPECT_EQ(result->options.size(), 40u);
    EXPECT_EQ(offset, 60u);
}

TEST(IPv4Decoder, ParsesWithNonZeroOffset) {
    std::vector<uint8_t> data = {
        0xDE, 0xAD,             // 2 bytes padding
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02
    };
    size_t offset = 2;
    auto result = fdpi::decodeIPv4(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 4);
    EXPECT_EQ(result->srcIp, fdpi::IPv4Address(0x0A000001));
    EXPECT_EQ(offset, 22u);
}

