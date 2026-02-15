#include <gtest/gtest.h>
#include <fdpi/protocol/tcp.hpp>
#include <vector>

TEST(TcpDecoder, ParsesSynPacket) {
    // TCP SYN: srcPort=12345, dstPort=80, seq=1000, ack=0,
    //          dataOffset=5 (20 bytes), flags=SYN (0x02), window=65535
    std::vector<uint8_t> data = {
        0x30, 0x39,             // srcPort: 12345
        0x00, 0x50,             // dstPort: 80
        0x00, 0x00, 0x03, 0xE8, // seqNum: 1000
        0x00, 0x00, 0x00, 0x00, // ackNum: 0
        0x50,                   // dataOffset=5, reserved=0
        0x02,                   // flags: SYN
        0xFF, 0xFF,             // window: 65535
        0x00, 0x00,             // checksum
        0x00, 0x00              // urgentPointer
    };
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->srcPort, 12345);
    EXPECT_EQ(result->dstPort, 80);
    EXPECT_EQ(result->seqNum, 1000u);
    EXPECT_EQ(result->ackNum, 0u);
    EXPECT_EQ(result->dataOffset, 5);
    EXPECT_TRUE(result->syn());
    EXPECT_FALSE(result->ack());
    EXPECT_FALSE(result->fin());
    EXPECT_FALSE(result->rst());
    EXPECT_FALSE(result->psh());
    EXPECT_EQ(result->window, 65535);
    EXPECT_TRUE(result->options.empty());
    EXPECT_EQ(offset, 20u);
}

TEST(TcpDecoder, ParsesSynAckPacket) {
    std::vector<uint8_t> data = {
        0x00, 0x50,             // srcPort: 80
        0x30, 0x39,             // dstPort: 12345
        0x00, 0x00, 0x07, 0xD0, // seqNum: 2000
        0x00, 0x00, 0x03, 0xE9, // ackNum: 1001
        0x50,                   // dataOffset=5
        0x12,                   // flags: SYN+ACK
        0x80, 0x00,             // window: 32768
        0x00, 0x00,             // checksum
        0x00, 0x00              // urgentPointer
    };
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->srcPort, 80);
    EXPECT_EQ(result->dstPort, 12345);
    EXPECT_EQ(result->seqNum, 2000u);
    EXPECT_EQ(result->ackNum, 1001u);
    EXPECT_TRUE(result->syn());
    EXPECT_TRUE(result->ack());
    EXPECT_FALSE(result->fin());
}

TEST(TcpDecoder, ParsesDataSegment) {
    // TCP with ACK+PSH flags
    std::vector<uint8_t> data = {
        0x00, 0x50,             // srcPort: 80
        0x30, 0x39,             // dstPort: 12345
        0x00, 0x00, 0x07, 0xD1, // seqNum: 2001
        0x00, 0x00, 0x03, 0xEA, // ackNum: 1002
        0x50,                   // dataOffset=5
        0x18,                   // flags: PSH+ACK
        0x40, 0x00,             // window
        0x00, 0x00,             // checksum
        0x00, 0x00              // urgentPointer
    };
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->psh());
    EXPECT_TRUE(result->ack());
    EXPECT_FALSE(result->syn());
}

TEST(TcpDecoder, ParsesWithOptions) {
    // TCP with dataOffset=8 (32 bytes, 12 bytes of options)
    // Common options: MSS (4 bytes), NOP, Window Scale (3 bytes), NOP, NOP, Timestamps (10 bytes)... but let's do 12 bytes
    std::vector<uint8_t> data = {
        0x30, 0x39,             // srcPort: 12345
        0x00, 0x50,             // dstPort: 80
        0x00, 0x00, 0x03, 0xE8, // seqNum
        0x00, 0x00, 0x00, 0x00, // ackNum
        0x80,                   // dataOffset=8 (32 bytes)
        0x02,                   // flags: SYN
        0xFF, 0xFF,             // window
        0x00, 0x00,             // checksum
        0x00, 0x00,             // urgentPointer
        // Options (12 bytes):
        0x02, 0x04, 0x05, 0xB4, // MSS: 1460
        0x01,                   // NOP
        0x03, 0x03, 0x06,       // Window Scale: 6
        0x01, 0x01, 0x01, 0x00  // NOP, NOP, NOP, End
    };
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->dataOffset, 8);
    EXPECT_EQ(result->options.size(), 12u);
    // Check MSS option starts with kind=2, length=4
    EXPECT_EQ(result->options[0], 0x02);
    EXPECT_EQ(result->options[1], 0x04);
    EXPECT_EQ(result->options[2], 0x05);
    EXPECT_EQ(result->options[3], 0xB4);
    EXPECT_EQ(offset, 32u);
}

TEST(TcpDecoder, ParsesFinPacket) {
    std::vector<uint8_t> data = {
        0x30, 0x39, 0x00, 0x50,
        0x00, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x08, 0x00,
        0x50,
        0x11,                   // flags: FIN+ACK
        0x40, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->fin());
    EXPECT_TRUE(result->ack());
    EXPECT_FALSE(result->rst());
}

TEST(TcpDecoder, ParsesRstPacket) {
    std::vector<uint8_t> data = {
        0x30, 0x39, 0x00, 0x50,
        0x00, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x50,
        0x04,                   // flags: RST
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->rst());
    EXPECT_FALSE(result->ack());
    EXPECT_FALSE(result->syn());
}

TEST(TcpDecoder, ParsesAllFlagAccessors) {
    // All flags set: FIN|SYN|RST|PSH|ACK|URG|ECE|CWR = 0xFF
    std::vector<uint8_t> data = {
        0x00, 0x50, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x50,
        0xFF,                   // all flags set
        0x40, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->fin());
    EXPECT_TRUE(result->syn());
    EXPECT_TRUE(result->rst());
    EXPECT_TRUE(result->psh());
    EXPECT_TRUE(result->ack());
    EXPECT_TRUE(result->urg());
    EXPECT_TRUE(result->ece());
    EXPECT_TRUE(result->cwr());
}

TEST(TcpDecoder, RejectsTruncatedHeader) {
    // Only 19 bytes - need at least 20
    std::vector<uint8_t> data = {
        0x30, 0x39, 0x00, 0x50,
        0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xFF, 0xFF,
        0x00, 0x00, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(TcpDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(TcpDecoder, ParsesHighPorts) {
    // Ephemeral port range
    std::vector<uint8_t> data = {
        0xC0, 0x00,             // srcPort: 49152
        0xFF, 0xFF,             // dstPort: 65535
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeTcp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->srcPort, 49152);
    EXPECT_EQ(result->dstPort, 65535);
}
