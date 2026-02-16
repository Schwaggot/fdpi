#include <gtest/gtest.h>

#include <fdpi/protocol/dhcp.hpp>

#include <cstring>
#include <vector>

// Build a minimal DHCP packet: 236-byte header + 4-byte magic cookie + options
static std::vector<uint8_t> makeDhcpPacket(uint8_t op,
                                           uint32_t xid,
                                           fdpi::IPv4Address ciaddr,
                                           fdpi::IPv4Address yiaddr,
                                           fdpi::IPv4Address siaddr,
                                           fdpi::IPv4Address giaddr,
                                           fdpi::MacAddress chaddr,
                                           const std::vector<uint8_t>& options) {
    std::vector<uint8_t> pkt(236, 0);
    pkt[0] = op;
    pkt[1] = 1; // htype: Ethernet
    pkt[2] = 6; // hlen: 6
    pkt[3] = 0; // hops

    // xid (big-endian)
    pkt[4] = static_cast<uint8_t>((xid >> 24) & 0xFF);
    pkt[5] = static_cast<uint8_t>((xid >> 16) & 0xFF);
    pkt[6] = static_cast<uint8_t>((xid >> 8) & 0xFF);
    pkt[7] = static_cast<uint8_t>(xid & 0xFF);

    // secs = 0, flags = 0 (bytes 8-11)

    // ciaddr at offset 12
    std::memcpy(&pkt[12], ciaddr.bytes.data(), 4);
    // yiaddr at offset 16
    std::memcpy(&pkt[16], yiaddr.bytes.data(), 4);
    // siaddr at offset 20
    std::memcpy(&pkt[20], siaddr.bytes.data(), 4);
    // giaddr at offset 24
    std::memcpy(&pkt[24], giaddr.bytes.data(), 4);
    // chaddr at offset 28 (16 bytes, only first 6 used for Ethernet)
    std::memcpy(&pkt[28], chaddr.bytes.data(), 6);

    // sname (64 bytes at 44) and file (128 bytes at 108) are zero

    // Magic cookie at offset 236
    pkt.push_back(0x63);
    pkt.push_back(0x82);
    pkt.push_back(0x53);
    pkt.push_back(0x63);

    // Options
    pkt.insert(pkt.end(), options.begin(), options.end());

    // End option
    pkt.push_back(0xFF);

    return pkt;
}

TEST(DhcpDecoder, ParsesDiscoverRequest) {
    fdpi::MacAddress mac(std::array<uint8_t, 6>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    // Option 53 (message type) = 1 (Discover)
    std::vector<uint8_t> opts = {53, 1, 1};
    auto data = makeDhcpPacket(1, 0x12345678, fdpi::IPv4Address(0), fdpi::IPv4Address(0),
                               fdpi::IPv4Address(0), fdpi::IPv4Address(0), mac, opts);
    size_t offset = 0;
    auto result = fdpi::decodeDhcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->op, 1);
    EXPECT_EQ(result->xid, 0x12345678u);
    EXPECT_TRUE(result->messageType.has_value());
    EXPECT_EQ(result->messageType.value(), 1); // Discover
}

TEST(DhcpDecoder, ParsesOfferReply) {
    fdpi::MacAddress mac(std::array<uint8_t, 6>{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF});
    // Option 53 = 2 (Offer)
    std::vector<uint8_t> opts = {53, 1, 2};
    auto data = makeDhcpPacket(2, 0xAABBCCDD, fdpi::IPv4Address(0),
                               fdpi::IPv4Address(0xC0A80164), // 192.168.1.100
                               fdpi::IPv4Address(0xC0A80101), // 192.168.1.1
                               fdpi::IPv4Address(0), mac, opts);
    size_t offset = 0;
    auto result = fdpi::decodeDhcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->op, 2);
    EXPECT_EQ(result->yiaddr, fdpi::IPv4Address(0xC0A80164));
    EXPECT_EQ(result->siaddr, fdpi::IPv4Address(0xC0A80101));
    EXPECT_TRUE(result->messageType.has_value());
    EXPECT_EQ(result->messageType.value(), 2); // Offer
}

TEST(DhcpDecoder, ExtractsMessageTypeOption) {
    fdpi::MacAddress mac{};
    // Option 53 = 3 (Request)
    std::vector<uint8_t> opts = {53, 1, 3};
    auto data = makeDhcpPacket(1, 0, fdpi::IPv4Address(0), fdpi::IPv4Address(0),
                               fdpi::IPv4Address(0), fdpi::IPv4Address(0), mac, opts);
    size_t offset = 0;
    auto result = fdpi::decodeDhcp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->messageType.has_value());
    EXPECT_EQ(result->messageType.value(), 3);
}

TEST(DhcpDecoder, ExtractsHostnameOption) {
    fdpi::MacAddress mac{};
    // Option 12 (hostname) = "myhost"
    std::vector<uint8_t> opts = {12, 6, 'm', 'y', 'h', 'o', 's', 't'};
    auto data = makeDhcpPacket(1, 0, fdpi::IPv4Address(0), fdpi::IPv4Address(0),
                               fdpi::IPv4Address(0), fdpi::IPv4Address(0), mac, opts);
    size_t offset = 0;
    auto result = fdpi::decodeDhcp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->hostname.has_value());
    EXPECT_EQ(result->hostname.value(), "myhost");
}

TEST(DhcpDecoder, ExtractsAddresses) {
    fdpi::MacAddress mac(std::array<uint8_t, 6>{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE});
    std::vector<uint8_t> opts = {53, 1, 5}; // ACK
    auto data = makeDhcpPacket(
        2, 0x11223344, fdpi::IPv4Address(0x0A000001), fdpi::IPv4Address(0x0A000002),
        fdpi::IPv4Address(0x0A000003), fdpi::IPv4Address(0x0A000004), mac, opts);
    size_t offset = 0;
    auto result = fdpi::decodeDhcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ciaddr, fdpi::IPv4Address(0x0A000001));
    EXPECT_EQ(result->yiaddr, fdpi::IPv4Address(0x0A000002));
    EXPECT_EQ(result->siaddr, fdpi::IPv4Address(0x0A000003));
    EXPECT_EQ(result->giaddr, fdpi::IPv4Address(0x0A000004));
    EXPECT_EQ(result->chaddr.bytes[0], 0xDE);
    EXPECT_EQ(result->chaddr.bytes[5], 0xFE);
}

TEST(DhcpDecoder, ParsesMultipleOptions) {
    fdpi::MacAddress mac{};
    // Option 53 = 1 (Discover), Option 12 = "test", Option 55 = [1,3,6]
    std::vector<uint8_t> opts = {
        53, 1, 1,                  // message type
        12, 4, 't', 'e', 's', 't', // hostname
        55, 3, 1,   3,   6         // parameter request list
    };
    auto data = makeDhcpPacket(1, 0, fdpi::IPv4Address(0), fdpi::IPv4Address(0),
                               fdpi::IPv4Address(0), fdpi::IPv4Address(0), mac, opts);
    size_t offset = 0;
    auto result = fdpi::decodeDhcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->messageType.has_value());
    EXPECT_EQ(result->messageType.value(), 1);
    EXPECT_TRUE(result->hostname.has_value());
    EXPECT_EQ(result->hostname.value(), "test");
    // Should have at least 3 options
    EXPECT_GE(result->options.size(), 3u);
}

TEST(DhcpDecoder, RejectsTruncated) {
    // Less than 240 bytes (236 header + 4 magic cookie)
    std::vector<uint8_t> data(235, 0);
    size_t offset = 0;
    auto result = fdpi::decodeDhcp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DhcpDecoder, RejectsInvalidMagicCookie) {
    // 236 bytes of header + wrong magic cookie
    std::vector<uint8_t> data(240, 0);
    data[236] = 0x00;
    data[237] = 0x00;
    data[238] = 0x00;
    data[239] = 0x00;
    size_t offset = 0;
    auto result = fdpi::decodeDhcp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}
