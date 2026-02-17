#include <gtest/gtest.h>

#include <fdpi/protocol/stun.hpp>

#include <cstring>
#include <vector>

// Build a minimal 20-byte STUN header
static std::vector<uint8_t> makeStunHeader(uint16_t type, uint16_t length) {
    std::vector<uint8_t> pkt(20, 0);
    pkt[0] = static_cast<uint8_t>((type >> 8) & 0xFF);
    pkt[1] = static_cast<uint8_t>(type & 0xFF);
    pkt[2] = static_cast<uint8_t>((length >> 8) & 0xFF);
    pkt[3] = static_cast<uint8_t>(length & 0xFF);
    // Magic cookie
    pkt[4] = 0x21;
    pkt[5] = 0x12;
    pkt[6] = 0xA4;
    pkt[7] = 0x42;
    // Transaction ID: 0x01..0x0C
    for (int i = 0; i < 12; ++i)
        pkt[8 + i] = static_cast<uint8_t>(i + 1);
    return pkt;
}

TEST(StunDecoder, ParsesBindingRequest) {
    auto data = makeStunHeader(0x0001, 0); // Binding Request, no attrs
    size_t offset = 0;
    auto result = fdpi::decodeStun(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 0x0001);
    EXPECT_EQ(result->length, 0);
    EXPECT_EQ(result->magicCookie, 0x2112A442u);
    EXPECT_TRUE(result->isRequest);
    EXPECT_FALSE(result->isIndication);
    EXPECT_EQ(offset, 20u);
}

TEST(StunDecoder, ParsesBindingResponse) {
    auto data = makeStunHeader(0x0101, 0); // Binding Success Response
    size_t offset = 0;
    auto result = fdpi::decodeStun(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 0x0101);
    EXPECT_FALSE(result->isRequest);
    EXPECT_FALSE(result->isIndication);
}

TEST(StunDecoder, ParsesXorMappedAddressIPv4) {
    // Build STUN with XOR-MAPPED-ADDRESS attribute
    auto data = makeStunHeader(0x0101, 12); // 12 bytes of attributes
    // XOR-MAPPED-ADDRESS: type=0x0020, length=8
    data.push_back(0x00);
    data.push_back(0x20); // attr type
    data.push_back(0x00);
    data.push_back(0x08); // attr length
    data.push_back(0x00); // reserved
    data.push_back(0x01); // family: IPv4
    // XOR'd port: port 12345 XOR 0x2112 = port ^ 0x2112
    uint16_t xport = 12345 ^ 0x2112;
    data.push_back(static_cast<uint8_t>((xport >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(xport & 0xFF));
    // XOR'd address: 192.168.1.100 XOR 0x2112A442
    uint32_t addr = (192u << 24) | (168u << 16) | (1u << 8) | 100u; // 0xC0A80164
    uint32_t xaddr = addr ^ 0x2112A442;
    data.push_back(static_cast<uint8_t>((xaddr >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((xaddr >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((xaddr >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(xaddr & 0xFF));

    size_t offset = 0;
    auto result = fdpi::decodeStun(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->mappedPort.has_value());
    EXPECT_EQ(*result->mappedPort, 12345);
    ASSERT_TRUE(result->mappedAddress.has_value());
    auto* v4 = std::get_if<fdpi::IPv4Address>(&*result->mappedAddress);
    ASSERT_NE(v4, nullptr);
    EXPECT_EQ(v4->toString(), "192.168.1.100");
}

TEST(StunDecoder, ParsesTransactionId) {
    auto data = makeStunHeader(0x0001, 0);
    size_t offset = 0;
    auto result = fdpi::decodeStun(data, offset);
    ASSERT_TRUE(result.has_value());
    for (int i = 0; i < 12; ++i) {
        EXPECT_EQ(result->transactionId[i], i + 1);
    }
}

TEST(StunDecoder, RejectsTruncated) {
    std::vector<uint8_t> data(19, 0); // 19 < 20
    size_t offset = 0;
    auto result = fdpi::decodeStun(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(StunDecoder, HandlesNonZeroOffset) {
    auto pkt = makeStunHeader(0x0001, 0);
    std::vector<uint8_t> data(8, 0xCC);
    data.insert(data.end(), pkt.begin(), pkt.end());
    size_t offset = 8;
    auto result = fdpi::decodeStun(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->magicCookie, 0x2112A442u);
    EXPECT_EQ(offset, 28u);
}
