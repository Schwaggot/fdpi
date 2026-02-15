#include <gtest/gtest.h>
#include <fdpi/protocol/icmp.hpp>
#include <vector>

// ---- ICMP (v4) Tests ----

TEST(IcmpDecoder, ParsesEchoRequest) {
    // ICMP Echo Request: type=8, code=0, checksum=0x1234, id=1, seq=1
    // restOfHeader = (id << 16) | seq = 0x00010001
    std::vector<uint8_t> data = {
        0x08,                   // type: Echo Request
        0x00,                   // code: 0
        0x12, 0x34,             // checksum
        0x00, 0x01, 0x00, 0x01  // restOfHeader: id=1, seq=1
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 8);
    EXPECT_EQ(result->code, 0);
    EXPECT_EQ(result->checksum, 0x1234);
    EXPECT_EQ(result->restOfHeader, 0x00010001u);
    EXPECT_EQ(offset, 8u);
}

TEST(IcmpDecoder, ParsesEchoReply) {
    // ICMP Echo Reply: type=0, code=0
    std::vector<uint8_t> data = {
        0x00,                   // type: Echo Reply
        0x00,                   // code: 0
        0x56, 0x78,             // checksum
        0x00, 0x01, 0x00, 0x02  // restOfHeader: id=1, seq=2
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 0);
    EXPECT_EQ(result->code, 0);
    EXPECT_EQ(result->restOfHeader, 0x00010002u);
}

TEST(IcmpDecoder, ParsesDestinationUnreachable) {
    // ICMP Destination Unreachable: type=3, code=1 (Host Unreachable)
    std::vector<uint8_t> data = {
        0x03,                   // type: Destination Unreachable
        0x01,                   // code: Host Unreachable
        0x00, 0x00,             // checksum
        0x00, 0x00, 0x00, 0x00  // unused (restOfHeader)
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 3);
    EXPECT_EQ(result->code, 1);
}

TEST(IcmpDecoder, ParsesTimeExceeded) {
    // ICMP Time Exceeded: type=11, code=0 (TTL expired)
    std::vector<uint8_t> data = {
        0x0B,                   // type: Time Exceeded
        0x00,                   // code: TTL expired in transit
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 11);
    EXPECT_EQ(result->code, 0);
}

TEST(IcmpDecoder, RejectsTruncatedPacket) {
    // Only 7 bytes - need 8
    std::vector<uint8_t> data = {
        0x08, 0x00, 0x12, 0x34, 0x00, 0x01, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(IcmpDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_FALSE(result.has_value());
}

// ---- ICMPv6 Tests ----

TEST(Icmpv6Decoder, ParsesEchoRequest) {
    // ICMPv6 Echo Request: type=128, code=0
    std::vector<uint8_t> data = {
        0x80,                   // type: ICMPv6 Echo Request (128)
        0x00,                   // code: 0
        0xAB, 0xCD,             // checksum
        0x00, 0x01, 0x00, 0x01  // id=1, seq=1
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 128);
    EXPECT_EQ(result->code, 0);
    EXPECT_EQ(result->checksum, 0xABCD);
    EXPECT_EQ(result->restOfHeader, 0x00010001u);
    EXPECT_EQ(offset, 8u);
}

TEST(Icmpv6Decoder, ParsesEchoReply) {
    // ICMPv6 Echo Reply: type=129, code=0
    std::vector<uint8_t> data = {
        0x81,                   // type: ICMPv6 Echo Reply (129)
        0x00,
        0x00, 0x00,
        0x00, 0x01, 0x00, 0x02
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 129);
}

TEST(Icmpv6Decoder, ParsesNeighborSolicitation) {
    // ICMPv6 Neighbor Solicitation: type=135
    std::vector<uint8_t> data = {
        0x87,                   // type: Neighbor Solicitation (135)
        0x00,                   // code: 0
        0x00, 0x00,             // checksum
        0x00, 0x00, 0x00, 0x00  // reserved
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 135);
}

TEST(Icmpv6Decoder, ParsesRouterAdvertisement) {
    // ICMPv6 Router Advertisement: type=134
    std::vector<uint8_t> data = {
        0x86,                   // type: Router Advertisement (134)
        0x00,
        0x00, 0x00,
        0x40, 0x00, 0x07, 0x08  // cur hop limit, flags, router lifetime
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 134);
}

TEST(Icmpv6Decoder, RejectsTruncatedPacket) {
    std::vector<uint8_t> data = {0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeIcmpv6(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(Icmpv6Decoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeIcmpv6(data, offset);
    ASSERT_FALSE(result.has_value());
}
