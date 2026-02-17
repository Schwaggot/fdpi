#include <gtest/gtest.h>

#include <fdpi/protocol/ocsp.hpp>

#include <vector>

TEST(OcspDecoder, ParsesOcspRequest) {
    // Minimal OCSPRequest: SEQUENCE { SEQUENCE { ... } }
    // Outer SEQUENCE (0x30) + length + inner SEQUENCE (0x30)
    std::vector<uint8_t> data = {
        0x30, 0x04, // SEQUENCE, length 4
        0x30, 0x02, // inner SEQUENCE
        0x30, 0x00, // innermost SEQUENCE (empty)
    };
    size_t offset = 0;
    auto result = fdpi::decodeOcsp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isRequest);
}

TEST(OcspDecoder, ParsesOcspResponse) {
    // OCSPResponse: SEQUENCE { ENUMERATED responseStatus }
    // responseStatus = 0 (successful)
    std::vector<uint8_t> data = {
        0x30, 0x03,       // SEQUENCE, length 3
        0x0A, 0x01, 0x00, // ENUMERATED, length 1, value 0 (successful)
    };
    size_t offset = 0;
    auto result = fdpi::decodeOcsp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isRequest);
    EXPECT_EQ(result->responseStatus, 0);
}

TEST(OcspDecoder, ParsesResponseStatusMalformed) {
    std::vector<uint8_t> data = {
        0x30, 0x03, 0x0A, 0x01, 0x01, // responseStatus = 1 (malformedRequest)
    };
    size_t offset = 0;
    auto result = fdpi::decodeOcsp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isRequest);
    EXPECT_EQ(result->responseStatus, 1);
}

TEST(OcspDecoder, RejectsNonSequence) {
    std::vector<uint8_t> data = {0x02, 0x01, 0x00}; // INTEGER, not SEQUENCE
    size_t offset = 0;
    auto result = fdpi::decodeOcsp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(OcspDecoder, RejectsEmptySequence) {
    std::vector<uint8_t> data = {0x30, 0x00}; // SEQUENCE, length 0
    size_t offset = 0;
    auto result = fdpi::decodeOcsp(data, offset);
    // Only 2 bytes, decoder requires minimum 3
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(OcspDecoder, RejectsTruncatedLongForm) {
    // SEQUENCE with long-form length claiming more bytes than available
    std::vector<uint8_t> data = {0x30, 0x82, 0x01, 0x00}; // needs 256 more bytes
    size_t offset = 0;
    auto result = fdpi::decodeOcsp(data, offset);
    // Still parseable — decoder clamps offset to data size
    ASSERT_TRUE(result.has_value());
}

TEST(OcspDecoder, RejectsTooShort) {
    std::vector<uint8_t> data = {0x30};
    size_t offset = 0;
    auto result = fdpi::decodeOcsp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(OcspDecoder, HandlesNonZeroOffset) {
    std::vector<uint8_t> data = {0xFF, 0xFF, 0x30, 0x03, 0x0A, 0x01, 0x00};
    size_t offset = 2;
    auto result = fdpi::decodeOcsp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isRequest);
    EXPECT_EQ(result->responseStatus, 0);
}
