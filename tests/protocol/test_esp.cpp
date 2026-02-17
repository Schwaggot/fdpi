#include <gtest/gtest.h>

#include <fdpi/protocol/esp.hpp>

#include <vector>

TEST(EspDecoder, ParsesBasicPacket) {
    std::vector<uint8_t> data = {
        0x00, 0x00, 0x10, 0x01, // SPI: 0x00001001
        0x00, 0x00, 0x00, 0x05  // Sequence Number: 5
    };
    size_t offset = 0;
    auto result = fdpi::decodeEsp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->spi, 0x00001001u);
    EXPECT_EQ(result->sequenceNumber, 5u);
    EXPECT_EQ(offset, 8u);
}

TEST(EspDecoder, ParsesLargeSPI) {
    std::vector<uint8_t> data = {
        0xDE, 0xAD, 0xBE, 0xEF, // SPI: 0xDEADBEEF
        0x00, 0x00, 0x00, 0x01  // Sequence Number: 1
    };
    size_t offset = 0;
    auto result = fdpi::decodeEsp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->spi, 0xDEADBEEFu);
    EXPECT_EQ(result->sequenceNumber, 1u);
}

TEST(EspDecoder, ParsesWithTrailingData) {
    std::vector<uint8_t> data = {
        0x00, 0x00, 0x00, 0x01, // SPI
        0x00, 0x00, 0x00, 0x02, // Sequence Number
        0xFF, 0xFF, 0xFF, 0xFF  // encrypted payload
    };
    size_t offset = 0;
    auto result = fdpi::decodeEsp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->spi, 1u);
    EXPECT_EQ(result->sequenceNumber, 2u);
    EXPECT_EQ(offset, 8u);
}

TEST(EspDecoder, RejectsTruncatedPacket) {
    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeEsp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(EspDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeEsp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(EspDecoder, ParsesWithOffset) {
    std::vector<uint8_t> data = {
        0xAA, 0xBB, 0xCC, 0xDD, // padding
        0x12, 0x34, 0x56, 0x78, // SPI: 0x12345678
        0xAB, 0xCD, 0xEF, 0x01  // Sequence Number: 0xABCDEF01
    };
    size_t offset = 4;
    auto result = fdpi::decodeEsp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->spi, 0x12345678u);
    EXPECT_EQ(result->sequenceNumber, 0xABCDEF01u);
    EXPECT_EQ(offset, 12u);
}
