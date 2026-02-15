#include <gtest/gtest.h>
#include <fdpi/protocol/quic.hpp>
#include <vector>

TEST(QuicDecoder, ParsesLongHeaderInitial) {
    // QUIC v1 Long Header Initial packet
    // First byte: 1 (long header) | 1 (fixed) | 00 (Initial) | 00 (reserved+PN len)
    // = 0b11000000 = 0xC0
    std::vector<uint8_t> data = {
        0xC0,                   // flags: long header, Initial
        0x00, 0x00, 0x00, 0x01, // version: 1
        0x08,                   // DCID length: 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  // DCID
        0x04,                   // SCID length: 4
        0xA1, 0xA2, 0xA3, 0xA4  // SCID
    };
    size_t offset = 0;
    auto result = fdpi::decodeQuic(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isLongHeader);
    EXPECT_EQ(result->version, 1);
    ASSERT_EQ(result->dcid.size(), 8u);
    EXPECT_EQ(result->dcid[0], 0x01);
    EXPECT_EQ(result->dcid[7], 0x08);
    ASSERT_EQ(result->scid.size(), 4u);
    EXPECT_EQ(result->scid[0], 0xA1);
    EXPECT_EQ(result->scid[3], 0xA4);
}

TEST(QuicDecoder, ParsesShortHeader) {
    // QUIC Short Header (1-RTT)
    // First byte: 0 (short header) | 1 (fixed) | ...
    // = 0b01000000 = 0x40
    // For short headers, DCID length is not in packet (known from connection)
    // We'll assume decoder reads available bytes as DCID
    std::vector<uint8_t> data = {
        0x40,                   // flags: short header
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  // DCID (assumed 8 bytes)
    };
    size_t offset = 0;
    auto result = fdpi::decodeQuic(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isLongHeader);
    // Short headers don't have SCID
    EXPECT_TRUE(result->scid.empty());
}

TEST(QuicDecoder, ParsesVersionNegotiation) {
    // Version Negotiation: version = 0
    std::vector<uint8_t> data = {
        0xC0,                   // flags: long header
        0x00, 0x00, 0x00, 0x00, // version: 0 (version negotiation)
        0x04,                   // DCID length
        0x01, 0x02, 0x03, 0x04, // DCID
        0x04,                   // SCID length
        0x05, 0x06, 0x07, 0x08  // SCID
    };
    size_t offset = 0;
    auto result = fdpi::decodeQuic(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isLongHeader);
    EXPECT_EQ(result->version, 0);  // version negotiation
}

TEST(QuicDecoder, ParsesHandshakePacket) {
    // Long Header Handshake: type bits = 10
    // First byte: 1 (long) | 1 (fixed) | 10 (Handshake) | 00
    // = 0b11100000 = 0xE0
    std::vector<uint8_t> data = {
        0xE0,                   // flags: long header, Handshake
        0x00, 0x00, 0x00, 0x01, // version: 1
        0x04,                   // DCID length
        0x01, 0x02, 0x03, 0x04,
        0x04,                   // SCID length
        0x05, 0x06, 0x07, 0x08
    };
    size_t offset = 0;
    auto result = fdpi::decodeQuic(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isLongHeader);
}

TEST(QuicDecoder, ParsesZeroLengthConnectionIds) {
    // Long header with zero-length connection IDs
    std::vector<uint8_t> data = {
        0xC0,                   // flags: long header, Initial
        0x00, 0x00, 0x00, 0x01, // version
        0x00,                   // DCID length: 0
        0x00                    // SCID length: 0
    };
    size_t offset = 0;
    auto result = fdpi::decodeQuic(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->dcid.empty());
    EXPECT_TRUE(result->scid.empty());
}

TEST(QuicDecoder, ParsesMaxLengthConnectionId) {
    // DCID length 20 (maximum per RFC 9000)
    std::vector<uint8_t> data = {
        0xC0,
        0x00, 0x00, 0x00, 0x01,
        0x14,  // DCID length: 20
    };
    // Add 20 bytes of DCID
    for (int i = 0; i < 20; ++i)
        data.push_back(static_cast<uint8_t>(i));
    data.push_back(0x00);  // SCID length: 0

    size_t offset = 0;
    auto result = fdpi::decodeQuic(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->dcid.size(), 20u);
    EXPECT_EQ(result->dcid[0], 0);
    EXPECT_EQ(result->dcid[19], 19);
}

TEST(QuicDecoder, RejectsTruncatedHeader) {
    // Only 4 bytes for long header - need at least version + cid lengths
    std::vector<uint8_t> data = {0xC0, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeQuic(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(QuicDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeQuic(data, offset);
    ASSERT_FALSE(result.has_value());
}
