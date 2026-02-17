#include <gtest/gtest.h>

#include <fdpi/protocol/gtp.hpp>

#include <vector>

TEST(GtpDecoder, ParsesGtpV1) {
    // GTPv1-U: version=1, PT=1, no ext/seq/npdu, message type=0xFF (T-PDU)
    // Flags: 001 1 0 0 0 0 = 0x30
    std::vector<uint8_t> data = {
        0x30,                  // version=1, PT=1, no optional fields
        0xFF,                  // message type: T-PDU
        0x00, 0x10,            // length: 16
        0x00, 0x00, 0x00, 0x01 // TEID: 1
    };
    size_t offset = 0;
    auto result = fdpi::decodeGtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 1);
    EXPECT_TRUE(result->protocolType);
    EXPECT_EQ(result->messageType, 0xFF);
    EXPECT_EQ(result->length, 16);
    EXPECT_EQ(result->teid, 1u);
    EXPECT_EQ(offset, 8u);
}

TEST(GtpDecoder, ParsesGtpV1WithExtension) {
    // GTPv1-U with sequence number flag set: version=1, PT=1, S=1
    // Flags: 001 1 0 0 1 0 = 0x32
    std::vector<uint8_t> data = {
        0x32,                   // version=1, PT=1, S=1
        0xFF,                   // message type: T-PDU
        0x00, 0x20,             // length: 32
        0x00, 0x00, 0x00, 0x0A, // TEID: 10
        0x00, 0x01,             // sequence number
        0x00,                   // N-PDU
        0x00                    // extension header type
    };
    size_t offset = 0;
    auto result = fdpi::decodeGtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 1);
    EXPECT_EQ(result->teid, 10u);
    EXPECT_EQ(offset, 12u); // 8 + 4 optional bytes
}

TEST(GtpDecoder, ParsesGtpV2) {
    // GTPv2-C: version=2, PT=1
    // Flags: 010 1 0 0 0 0 = 0x48
    std::vector<uint8_t> data = {
        0x48,                  // version=2, PT=0, no TEID flag is 0
        0x01,                  // message type: Echo Request
        0x00, 0x08,            // length: 8
        0x00, 0x00, 0x00, 0x00 // TEID: 0
    };
    size_t offset = 0;
    auto result = fdpi::decodeGtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 2);
    EXPECT_EQ(result->messageType, 1);
}

TEST(GtpDecoder, RejectsTruncatedPacket) {
    std::vector<uint8_t> data = {0x30, 0xFF, 0x00, 0x10, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeGtp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(GtpDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeGtp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(GtpDecoder, RejectsTruncatedOptionalFields) {
    // GTPv1 with sequence number flag but truncated optional fields
    std::vector<uint8_t> data = {
        0x32,                   // version=1, PT=1, S=1
        0xFF,                   // message type
        0x00, 0x20,             // length
        0x00, 0x00, 0x00, 0x01, // TEID
        0x00, 0x01              // only 2 bytes of optional (need 4)
    };
    size_t offset = 0;
    auto result = fdpi::decodeGtp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}
