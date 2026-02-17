#include <gtest/gtest.h>

#include <fdpi/address.hpp>
#include <fdpi/protocol/icmp.hpp>

#include <vector>

// ---- ICMP (v4) Tests ----

TEST(IcmpDecoder, ParsesEchoRequest) {
    // ICMP Echo Request: type=8, code=0, checksum=0x1234, id=1, seq=1
    // restOfHeader = (id << 16) | seq = 0x00010001
    std::vector<uint8_t> data = {
        0x08,                  // type: Echo Request
        0x00,                  // code: 0
        0x12, 0x34,            // checksum
        0x00, 0x01, 0x00, 0x01 // restOfHeader: id=1, seq=1
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
        0x00,                  // type: Echo Reply
        0x00,                  // code: 0
        0x56, 0x78,            // checksum
        0x00, 0x01, 0x00, 0x02 // restOfHeader: id=1, seq=2
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
        0x03,                  // type: Destination Unreachable
        0x01,                  // code: Host Unreachable
        0x00, 0x00,            // checksum
        0x00, 0x00, 0x00, 0x00 // unused (restOfHeader)
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 3);
    EXPECT_EQ(result->code, 1);
}

TEST(IcmpDecoder, ParsesTimeExceeded) {
    // ICMP Time Exceeded: type=11, code=0 (TTL expired)
    std::vector<uint8_t> data = {0x0B, // type: Time Exceeded
                                 0x00, // code: TTL expired in transit
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 11);
    EXPECT_EQ(result->code, 0);
}

TEST(IcmpDecoder, RejectsTruncatedPacket) {
    // Only 7 bytes - need 8
    std::vector<uint8_t> data = {0x08, 0x00, 0x12, 0x34, 0x00, 0x01, 0x00};
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
        0x80,                  // type: ICMPv6 Echo Request (128)
        0x00,                  // code: 0
        0xAB, 0xCD,            // checksum
        0x00, 0x01, 0x00, 0x01 // id=1, seq=1
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
    std::vector<uint8_t> data = {0x81, // type: ICMPv6 Echo Reply (129)
                                 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02};
    size_t offset = 0;
    auto result = fdpi::decodeIcmpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 129);
}

TEST(Icmpv6Decoder, ParsesNeighborSolicitation) {
    // ICMPv6 Neighbor Solicitation: type=135
    std::vector<uint8_t> data = {
        0x87,                  // type: Neighbor Solicitation (135)
        0x00,                  // code: 0
        0x00, 0x00,            // checksum
        0x00, 0x00, 0x00, 0x00 // reserved
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 135);
}

TEST(Icmpv6Decoder, ParsesRouterAdvertisement) {
    // ICMPv6 Router Advertisement: type=134
    std::vector<uint8_t> data = {
        0x86,                                    // type: Router Advertisement (134)
        0x00, 0x00, 0x00, 0x40, 0x00, 0x07, 0x08 // cur hop limit, flags, router lifetime
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

// ---- Embedded header tests ----

TEST(IcmpDecoder, DestUnreachableWithEmbeddedIPv4UDP) {
    // ICMP Dest Unreachable (type=3, code=3) + embedded IPv4 (IHL=5) + UDP
    std::vector<uint8_t> data = {
        // ICMP header (8 bytes)
        0x03,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Embedded IPv4 header (20 bytes): version=4, IHL=5
        0x45,
        0x00,
        0x00,
        0x3C, // ver/ihl, dscp/ecn, total len
        0x12,
        0x34,
        0x00,
        0x00, // id, flags/frag
        0x40,
        0x11,
        0xAB,
        0xCD, // ttl, proto=17(UDP), checksum
        0xC0,
        0xA8,
        0x01,
        0x0A, // src: 192.168.1.10
        0xC0,
        0xA8,
        0x01,
        0x14, // dst: 192.168.1.20
        // Embedded UDP header (8 bytes)
        0x04,
        0xD2,
        0x00,
        0x50, // srcPort=1234, dstPort=80
        0x00,
        0x28,
        0x12,
        0x34, // length=40, checksum=0x1234
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 3);
    EXPECT_EQ(result->code, 3);
    ASSERT_TRUE(result->embedded.has_value());
    auto& emb = *result->embedded;
    EXPECT_EQ(emb.protocol, 17);
    EXPECT_EQ(emb.srcIp, fdpi::IPv4Address(std::string_view("192.168.1.10")));
    EXPECT_EQ(emb.dstIp, fdpi::IPv4Address(std::string_view("192.168.1.20")));
    EXPECT_EQ(emb.srcPort, 1234);
    EXPECT_EQ(emb.dstPort, 80);
    EXPECT_EQ(emb.udpLength, 40);
    EXPECT_EQ(emb.udpChecksum, 0x1234);
}

TEST(IcmpDecoder, TimeExceededWithEmbeddedIPv4TCP) {
    // ICMP Time Exceeded (type=11, code=0) + embedded IPv4 + TCP
    std::vector<uint8_t> data = {
        // ICMP header (8 bytes)
        0x0B,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Embedded IPv4 header (20 bytes): proto=6(TCP)
        0x45,
        0x00,
        0x00,
        0x28,
        0x00,
        0x01,
        0x00,
        0x00,
        0x40,
        0x06,
        0x00,
        0x00, // proto=6 (TCP)
        0x0A,
        0x00,
        0x00,
        0x01, // src: 10.0.0.1
        0x0A,
        0x00,
        0x00,
        0x02, // dst: 10.0.0.2
        // Embedded TCP header first 8 bytes (ports)
        0x1F,
        0x90,
        0x00,
        0x50, // srcPort=8080, dstPort=80
        0x00,
        0x00,
        0x00,
        0x01, // seq num (rest of 8 bytes)
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->embedded.has_value());
    auto& emb = *result->embedded;
    EXPECT_EQ(emb.protocol, 6);
    EXPECT_EQ(emb.srcPort, 8080);
    EXPECT_EQ(emb.dstPort, 80);
    // UDP-specific fields should be 0 for non-UDP
    EXPECT_EQ(emb.udpLength, 0);
    EXPECT_EQ(emb.udpChecksum, 0);
}

TEST(IcmpDecoder, EchoRequestHasNoEmbedded) {
    std::vector<uint8_t> data = {0x08, 0x00, 0x12, 0x34, 0x00, 0x01, 0x00, 0x01};
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->embedded.has_value());
}

TEST(IcmpDecoder, ErrorTypeTruncatedEmbeddedIsNullopt) {
    // Dest Unreachable but only 10 bytes of embedded data (need 28)
    std::vector<uint8_t> data = {
        // ICMP header
        0x03,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Truncated embedded data (10 bytes, not enough for IPv4+transport)
        0x45,
        0x00,
        0x00,
        0x3C,
        0x12,
        0x34,
        0x00,
        0x00,
        0x40,
        0x11,
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 3);
    // ICMP decoded OK, but embedded is not set due to truncation
    EXPECT_FALSE(result->embedded.has_value());
}

TEST(IcmpDecoder, EmbeddedIPv4WithOptions) {
    // Dest Unreachable + embedded IPv4 with IHL=6 (24-byte header) + UDP
    std::vector<uint8_t> data = {
        // ICMP header
        0x03,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Embedded IPv4 header (24 bytes): IHL=6
        0x46,
        0x00,
        0x00,
        0x40,
        0x12,
        0x34,
        0x00,
        0x00,
        0x40,
        0x11,
        0xAB,
        0xCD, // proto=17 (UDP)
        0xC0,
        0xA8,
        0x02,
        0x01, // src: 192.168.2.1
        0xC0,
        0xA8,
        0x02,
        0x02, // dst: 192.168.2.2
        0x00,
        0x00,
        0x00,
        0x00, // IP options (4 bytes padding)
        // Embedded UDP header (8 bytes) starts at offset 24
        0x13,
        0x88,
        0x01,
        0xBB, // srcPort=5000, dstPort=443
        0x00,
        0x20,
        0x56,
        0x78, // length=32, checksum=0x5678
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->embedded.has_value());
    auto& emb = *result->embedded;
    EXPECT_EQ(emb.protocol, 17);
    EXPECT_EQ(emb.srcIp, fdpi::IPv4Address(std::string_view("192.168.2.1")));
    EXPECT_EQ(emb.dstIp, fdpi::IPv4Address(std::string_view("192.168.2.2")));
    EXPECT_EQ(emb.srcPort, 5000);
    EXPECT_EQ(emb.dstPort, 443);
    EXPECT_EQ(emb.udpLength, 32);
    EXPECT_EQ(emb.udpChecksum, 0x5678);
}

TEST(Icmpv6Decoder, DestUnreachableWithEmbeddedIPv6UDP) {
    // ICMPv6 Dest Unreachable (type=1, code=4) + embedded IPv6 + UDP
    std::vector<uint8_t> data = {
        // ICMPv6 header (8 bytes)
        0x01,
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Embedded IPv6 header (40 bytes)
        0x60,
        0x00,
        0x00,
        0x00, // version=6, traffic class, flow label
        0x00,
        0x10,
        0x11,
        0x40, // payload len=16, next header=17(UDP), hop=64
        // src IPv6: 2001:db8::1
        0x20,
        0x01,
        0x0D,
        0xB8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        // dst IPv6: 2001:db8::2
        0x20,
        0x01,
        0x0D,
        0xB8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        // Embedded UDP header (8 bytes)
        0x04,
        0xD2,
        0x00,
        0x35, // srcPort=1234, dstPort=53
        0x00,
        0x10,
        0xAB,
        0xCD, // length=16, checksum=0xABCD
    };
    size_t offset = 0;
    auto result = fdpi::decodeIcmpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 1);
    ASSERT_TRUE(result->embedded.has_value());
    auto& emb = *result->embedded;
    EXPECT_EQ(emb.nextHeader, 17);
    EXPECT_EQ(emb.srcIp, fdpi::IPv6Address(std::string_view("2001:db8::1")));
    EXPECT_EQ(emb.dstIp, fdpi::IPv6Address(std::string_view("2001:db8::2")));
    EXPECT_EQ(emb.srcPort, 1234);
    EXPECT_EQ(emb.dstPort, 53);
    EXPECT_EQ(emb.udpLength, 16);
    EXPECT_EQ(emb.udpChecksum, 0xABCD);
}
