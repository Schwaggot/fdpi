#include <gtest/gtest.h>
#include <fdpi/protocol/udp.hpp>
#include <vector>

TEST(UdpDecoder, ParsesValidHeader) {
    // UDP: srcPort=1234, dstPort=53, length=12, checksum=0
    std::vector<uint8_t> data = {
        0x04, 0xD2,  // srcPort: 1234
        0x00, 0x35,  // dstPort: 53 (DNS)
        0x00, 0x0C,  // length: 12
        0x00, 0x00   // checksum: 0
    };
    size_t offset = 0;
    auto result = fdpi::decodeUdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->srcPort, 1234);
    EXPECT_EQ(result->dstPort, 53);
    EXPECT_EQ(result->length, 12);
    EXPECT_EQ(result->checksum, 0);
    EXPECT_EQ(offset, 8u);
}

TEST(UdpDecoder, ParsesDNSPort) {
    std::vector<uint8_t> data = {
        0xC0, 0x00,  // srcPort: 49152
        0x00, 0x35,  // dstPort: 53
        0x00, 0x20,  // length: 32
        0xAB, 0xCD   // checksum
    };
    size_t offset = 0;
    auto result = fdpi::decodeUdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->dstPort, 53);
    EXPECT_EQ(result->checksum, 0xABCD);
}

TEST(UdpDecoder, ParsesMinimumLength) {
    // Minimum UDP length is 8 (header only, no payload)
    std::vector<uint8_t> data = {
        0x00, 0x01,  // srcPort: 1
        0x00, 0x01,  // dstPort: 1
        0x00, 0x08,  // length: 8 (minimum)
        0x00, 0x00   // checksum
    };
    size_t offset = 0;
    auto result = fdpi::decodeUdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->length, 8);
}

TEST(UdpDecoder, RejectsTruncatedHeader) {
    // Only 7 bytes - need 8
    std::vector<uint8_t> data = {
        0x04, 0xD2, 0x00, 0x35, 0x00, 0x0C, 0x00
    };
    size_t offset = 0;
    auto result = fdpi::decodeUdp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(UdpDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeUdp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(UdpDecoder, ParsesWithNonZeroOffset) {
    std::vector<uint8_t> data = {
        0xDE, 0xAD, 0xBE, 0xEF,  // 4 bytes padding
        0x00, 0x50,              // srcPort: 80
        0x01, 0xBB,              // dstPort: 443
        0x00, 0x10,              // length: 16
        0x12, 0x34               // checksum
    };
    size_t offset = 4;
    auto result = fdpi::decodeUdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->srcPort, 80);
    EXPECT_EQ(result->dstPort, 443);
    EXPECT_EQ(offset, 12u);
}

TEST(UdpDecoder, ParsesMaxPorts) {
    std::vector<uint8_t> data = {
        0xFF, 0xFF,  // srcPort: 65535
        0xFF, 0xFF,  // dstPort: 65535
        0xFF, 0xFF,  // length: 65535
        0xFF, 0xFF   // checksum: 65535
    };
    size_t offset = 0;
    auto result = fdpi::decodeUdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->srcPort, 65535);
    EXPECT_EQ(result->dstPort, 65535);
    EXPECT_EQ(result->length, 65535);
    EXPECT_EQ(result->checksum, 65535);
}
