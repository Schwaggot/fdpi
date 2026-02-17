#include <gtest/gtest.h>

#include <fdpi/protocol/srvloc.hpp>

#include <vector>

TEST(SrvLocDecoder, ParsesSLPv2ServiceRequest) {
    // SLPv2 header (14 bytes min) + "en" language tag
    std::vector<uint8_t> data = {
        0x02,             // version: 2
        0x01,             // function-id: SrvRqst
        0x00, 0x00, 0x20, // length: 32 (3 bytes in v2)
        0x00, 0x00,       // flags
        0x00, 0x00, 0x00, // extension offset (3 bytes)
        0x00, 0x01,       // XID: 1
        0x00, 0x02,       // language tag length: 2
        'e',  'n'         // language tag: "en"
    };
    size_t offset = 0;
    auto result = fdpi::decodeSrvloc(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 2);
    EXPECT_EQ(result->functionId, 1);
    EXPECT_EQ(result->xid, 1);
    EXPECT_EQ(result->languageTag, "en");
}

TEST(SrvLocDecoder, ParsesSLPv2ServiceReply) {
    std::vector<uint8_t> data = {
        0x02,             // version: 2
        0x02,             // function-id: SrvRply
        0x00, 0x00, 0x1C, // length: 28
        0x00, 0x00,       // flags
        0x00, 0x00, 0x00, // extension offset
        0x00, 0x02,       // XID: 2
        0x00, 0x00        // language tag length: 0
    };
    size_t offset = 0;
    auto result = fdpi::decodeSrvloc(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 2);
    EXPECT_EQ(result->functionId, 2);
    EXPECT_EQ(result->xid, 2);
    EXPECT_TRUE(result->languageTag.empty());
}

TEST(SrvLocDecoder, RejectsTruncatedV2) {
    std::vector<uint8_t> data = {0x02, 0x01, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeSrvloc(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(SrvLocDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeSrvloc(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(SrvLocDecoder, RejectsUnsupportedVersion) {
    std::vector<uint8_t> data = {0x03, // version: 3 (unsupported)
                                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeSrvloc(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}
