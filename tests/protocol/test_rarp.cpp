#include <gtest/gtest.h>

#include <fdpi/protocol/rarp.hpp>

#include <vector>

TEST(RarpDecoder, ParsesRarpRequest) {
    // RARP Request: opcode 3
    std::vector<uint8_t> data = {
        0x00, 0x01,                         // hardwareType: Ethernet (1)
        0x08, 0x00,                         // protocolType: IPv4 (0x0800)
        0x06,                               // hardwareSize: 6
        0x04,                               // protocolSize: 4
        0x00, 0x03,                         // opcode: RARP Request (3)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // senderMac
        0x00, 0x00, 0x00, 0x00,             // senderIp: 0.0.0.0
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // targetMac
        0x00, 0x00, 0x00, 0x00              // targetIp: 0.0.0.0
    };
    size_t offset = 0;
    auto result = fdpi::decodeRarp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 3);
    EXPECT_EQ(result->hardwareType, 1);
    EXPECT_EQ(result->protocolType, 0x0800);
    EXPECT_EQ(offset, 28u);
}

TEST(RarpDecoder, ParsesRarpReply) {
    // RARP Reply: opcode 4
    std::vector<uint8_t> data = {
        0x00, 0x01,                         // hardwareType: Ethernet
        0x08, 0x00,                         // protocolType: IPv4
        0x06,                               // hardwareSize: 6
        0x04,                               // protocolSize: 4
        0x00, 0x04,                         // opcode: RARP Reply (4)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // senderMac
        0x0A, 0x00, 0x00, 0x01,             // senderIp: 10.0.0.1
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // targetMac
        0xC0, 0xA8, 0x01, 0x64              // targetIp: 192.168.1.100
    };
    size_t offset = 0;
    auto result = fdpi::decodeRarp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 4);
    EXPECT_EQ(result->senderIp, fdpi::IPv4Address(0x0A000001));
    EXPECT_EQ(result->targetIp, fdpi::IPv4Address(0xC0A80164));
}

TEST(RarpDecoder, ExtractsAddresses) {
    std::vector<uint8_t> data = {
        0x00, 0x01,                         // hardwareType
        0x08, 0x00,                         // protocolType
        0x06, 0x04,                         // sizes
        0x00, 0x04,                         // opcode: Reply
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, // senderMac
        0xC0, 0xA8, 0x0A, 0x01,             // senderIp: 192.168.10.1
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // targetMac
        0xAC, 0x10, 0x00, 0x01              // targetIp: 172.16.0.1
    };
    size_t offset = 0;
    auto result = fdpi::decodeRarp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->senderMac.bytes[0], 0xDE);
    EXPECT_EQ(result->senderMac.bytes[5], 0xFE);
    EXPECT_EQ(result->senderIp, fdpi::IPv4Address(0xC0A80A01));
    EXPECT_EQ(result->targetMac.bytes[0], 0x01);
    EXPECT_EQ(result->targetMac.bytes[5], 0x06);
    EXPECT_EQ(result->targetIp, fdpi::IPv4Address(0xAC100001));
}

TEST(RarpDecoder, RejectsTruncatedPacket) {
    // RARP header is 28 bytes, give only 27
    std::vector<uint8_t> data = {0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x03, 0x00,
                                 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeRarp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(RarpDecoder, HandlesNonZeroOffset) {
    // 4 bytes padding + 28 bytes RARP
    std::vector<uint8_t> data = {
        0xDE, 0xAD, 0xBE, 0xEF,             // padding
        0x00, 0x01,                         // hardwareType
        0x08, 0x00,                         // protocolType
        0x06, 0x04,                         // sizes
        0x00, 0x03,                         // opcode: Request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // senderMac
        0xC0, 0xA8, 0x01, 0x01,             // senderIp: 192.168.1.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // targetMac
        0xC0, 0xA8, 0x01, 0x02              // targetIp: 192.168.1.2
    };
    size_t offset = 4;
    auto result = fdpi::decodeRarp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->senderIp, fdpi::IPv4Address(0xC0A80101));
    EXPECT_EQ(result->targetIp, fdpi::IPv4Address(0xC0A80102));
    EXPECT_EQ(offset, 32u);
}

TEST(RarpDecoder, ParsesNonEthernetHardwareType) {
    // htype = 6 (IEEE 802)
    std::vector<uint8_t> data = {
        0x00, 0x06,                         // hardwareType: IEEE 802 (6)
        0x08, 0x00,                         // protocolType: IPv4
        0x06,                               // hardwareSize: 6
        0x04,                               // protocolSize: 4
        0x00, 0x03,                         // opcode: RARP Request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // senderMac
        0x0A, 0x00, 0x00, 0x01,             // senderIp: 10.0.0.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // targetMac
        0x0A, 0x00, 0x00, 0x02              // targetIp: 10.0.0.2
    };
    size_t offset = 0;
    auto result = fdpi::decodeRarp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->hardwareType, 6);
    EXPECT_EQ(result->hardwareSize, 6);
    EXPECT_EQ(result->protocolSize, 4);
}
