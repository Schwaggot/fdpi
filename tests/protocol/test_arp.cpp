#include <gtest/gtest.h>
#include <fdpi/protocol/arp.hpp>
#include <vector>

TEST(ArpDecoder, ParsesValidRequest) {
    // ARP Request: who-has 10.0.0.2 tell 10.0.0.1
    std::vector<uint8_t> data = {
        0x00, 0x01,                            // hardwareType: Ethernet (1)
        0x08, 0x00,                            // protocolType: IPv4 (0x0800)
        0x06,                                  // hardwareSize: 6
        0x04,                                  // protocolSize: 4
        0x00, 0x01,                            // opcode: Request (1)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,   // senderMac
        0x0A, 0x00, 0x00, 0x01,                // senderIp: 10.0.0.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // targetMac: 00:00:00:00:00:00
        0x0A, 0x00, 0x00, 0x02                 // targetIp: 10.0.0.2
    };
    size_t offset = 0;
    auto result = fdpi::decodeArp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->hardwareType, 1);
    EXPECT_EQ(result->protocolType, 0x0800);
    EXPECT_EQ(result->hardwareSize, 6);
    EXPECT_EQ(result->protocolSize, 4);
    EXPECT_EQ(result->opcode, 1);  // Request
    EXPECT_EQ(result->senderMac.bytes[0], 0x00);
    EXPECT_EQ(result->senderMac.bytes[5], 0x55);
    EXPECT_EQ(result->senderIp, fdpi::IPv4Address(0x0A000001));
    EXPECT_EQ(result->targetMac.bytes[0], 0x00);
    EXPECT_EQ(result->targetIp, fdpi::IPv4Address(0x0A000002));
    EXPECT_EQ(offset, 28u);
}

TEST(ArpDecoder, ParsesValidReply) {
    // ARP Reply
    std::vector<uint8_t> data = {
        0x00, 0x01,                            // hardwareType: Ethernet
        0x08, 0x00,                            // protocolType: IPv4
        0x06,                                  // hardwareSize: 6
        0x04,                                  // protocolSize: 4
        0x00, 0x02,                            // opcode: Reply (2)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,   // senderMac
        0x0A, 0x00, 0x00, 0x02,                // senderIp: 10.0.0.2
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,   // targetMac
        0x0A, 0x00, 0x00, 0x01                 // targetIp: 10.0.0.1
    };
    size_t offset = 0;
    auto result = fdpi::decodeArp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 2);  // Reply
    EXPECT_EQ(result->senderMac.bytes[0], 0xAA);
    EXPECT_EQ(result->senderMac.bytes[5], 0xFF);
    EXPECT_EQ(result->senderIp, fdpi::IPv4Address(0x0A000002));
    EXPECT_EQ(result->targetMac.bytes[0], 0x00);
    EXPECT_EQ(result->targetMac.bytes[5], 0x55);
    EXPECT_EQ(result->targetIp, fdpi::IPv4Address(0x0A000001));
}

TEST(ArpDecoder, RejectsTruncatedPacket) {
    // ARP header is 28 bytes for Ethernet/IPv4, give only 27
    std::vector<uint8_t> data = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x0A, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0A, 0x00, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeArp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(ArpDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeArp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(ArpDecoder, ParsesWithNonZeroOffset) {
    // 2 bytes padding + 28 bytes ARP
    std::vector<uint8_t> data = {
        0xDE, 0xAD,                            // padding
        0x00, 0x01,                            // hardwareType
        0x08, 0x00,                            // protocolType
        0x06, 0x04,                            // hardware/protocol size
        0x00, 0x01,                            // opcode: Request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,   // senderMac
        0xC0, 0xA8, 0x01, 0x01,                // senderIp: 192.168.1.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // targetMac
        0xC0, 0xA8, 0x01, 0x02                 // targetIp: 192.168.1.2
    };
    size_t offset = 2;
    auto result = fdpi::decodeArp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->senderIp, fdpi::IPv4Address(0xC0A80101));
    EXPECT_EQ(result->targetIp, fdpi::IPv4Address(0xC0A80102));
    EXPECT_EQ(offset, 30u);
}

TEST(ArpDecoder, ParsesGratuitousArp) {
    // Gratuitous ARP: sender and target IP are the same
    std::vector<uint8_t> data = {
        0x00, 0x01,                            // hardwareType
        0x08, 0x00,                            // protocolType
        0x06, 0x04,                            // sizes
        0x00, 0x01,                            // opcode: Request
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,   // senderMac
        0xC0, 0xA8, 0x00, 0x01,                // senderIp
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // targetMac: broadcast
        0xC0, 0xA8, 0x00, 0x01                 // targetIp (same as sender)
    };
    size_t offset = 0;
    auto result = fdpi::decodeArp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->senderIp, result->targetIp);
}
