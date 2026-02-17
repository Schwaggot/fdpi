#include <gtest/gtest.h>

#include <fdpi/protocol/nbdgm.hpp>
#include <fdpi/protocol/nbns.hpp>

#include <vector>

TEST(NbdgmDecoder, ParsesDirectUniqueDatagram) {
    std::vector<uint8_t> data = {
        0x10,                   // messageType: Direct Unique
        0x02,                   // flags: first fragment
        0x00, 0x01,             // dgmId: 1
        0xC0, 0xA8, 0x01, 0x0A, // sourceIp: 192.168.1.10
        0x00, 0x8A,             // sourcePort: 138
        // dgmLength, packetOffset (4 bytes)
        0x00, 0x40, // dgmLength: 64
        0x00, 0x00, // packetOffset: 0
        // Source name: encoded "A" + padding
        0x20, 'E', 'B', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C',
        'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C',
        'A', 0x00,
        // Destination name: encoded "B" + padding
        0x20, 'E', 'C', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C',
        'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C',
        'A', 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeNbdgm(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageType, 0x10);
    EXPECT_EQ(result->flags, 0x02);
    EXPECT_EQ(result->dgmId, 1);
    EXPECT_EQ(result->sourceIp, fdpi::IPv4Address(std::string_view("192.168.1.10")));
    EXPECT_EQ(result->sourcePort, 138);
    EXPECT_EQ(result->dgmLength, 64);
    EXPECT_EQ(result->packetOffset, 0);
    EXPECT_FALSE(result->sourceName.empty());
    EXPECT_FALSE(result->destinationName.empty());
}

TEST(NbdgmDecoder, ParsesBroadcastDatagram) {
    std::vector<uint8_t> data = {
        0x12,                   // messageType: Broadcast
        0x02,                   // flags
        0x00, 0x02,             // dgmId: 2
        0x0A, 0x00, 0x00, 0x01, // sourceIp: 10.0.0.1
        0x00, 0x8A,             // sourcePort: 138
        0x00, 0x30,             // dgmLength: 48
        0x00, 0x00,             // packetOffset: 0
        // Short encoded names
        0x20, 'E', 'B', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C',
        'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C',
        'A', 0x00, 0x20, 'E', 'C', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C',
        'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C',
        'A', 'C', 'A', 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeNbdgm(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageType, 0x12);
    EXPECT_EQ(result->sourceIp, fdpi::IPv4Address(std::string_view("10.0.0.1")));
}

TEST(NbdgmDecoder, RejectsTruncatedPacket) {
    std::vector<uint8_t> data = {0x10, 0x02, 0x00, 0x01, 0xC0, 0xA8, 0x01};
    size_t offset = 0;
    auto result = fdpi::decodeNbdgm(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(NbdgmDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeNbdgm(data, offset);
    ASSERT_FALSE(result.has_value());
}
