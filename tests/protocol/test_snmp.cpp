#include <gtest/gtest.h>

#include <fdpi/protocol/snmp.hpp>

#include <vector>

TEST(SnmpDecoder, ParsesV1GetRequest) {
    // SNMP v1 GetRequest for OID 1.3.6.1.2.1
    std::vector<uint8_t> data = {
        0x30, 0x26,       // SEQUENCE len=38
        0x02, 0x01, 0x00, // INTEGER version=0 (v1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69,
        0x63,                                     // OCTET STRING "public"
        0xA0, 0x19,                               // GetRequest PDU len=25
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,       // requestId=1
        0x02, 0x01, 0x00,                         // errorStatus=0
        0x02, 0x01, 0x00,                         // errorIndex=0
        0x30, 0x0B,                               // varbind list
        0x30, 0x09,                               // varbind
        0x06, 0x05, 0x2B, 0x06, 0x01, 0x02, 0x01, // OID
        0x05, 0x00                                // NULL
    };
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 0);
    EXPECT_EQ(result->community, "public");
    ASSERT_TRUE(result->pduType.has_value());
    EXPECT_EQ(*result->pduType, fdpi::SnmpPduType::GetRequest);
    ASSERT_TRUE(result->requestId.has_value());
    EXPECT_EQ(*result->requestId, 1u);
    EXPECT_EQ(offset, data.size());
}

TEST(SnmpDecoder, ParsesV1GetResponse) {
    // SNMP v1 GetResponse
    std::vector<uint8_t> data = {
        0x30, 0x1C,       // SEQUENCE len=28
        0x02, 0x01, 0x00, // version=0 (v1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69,
        0x63,                               // "public"
        0xA2, 0x0F,                         // GetResponse PDU len=15
        0x02, 0x04, 0x00, 0x00, 0x00, 0x02, // requestId=2
        0x02, 0x01, 0x00,                   // errorStatus=0
        0x02, 0x01, 0x00,                   // errorIndex=0
        0x30, 0x01, 0x00                    // varbind list (minimal)
    };
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 0);
    ASSERT_TRUE(result->pduType.has_value());
    EXPECT_EQ(*result->pduType, fdpi::SnmpPduType::GetResponse);
    EXPECT_EQ(*result->requestId, 2u);
}

TEST(SnmpDecoder, ParsesV1Trap) {
    // SNMP v1 Trap
    std::vector<uint8_t> data = {
        0x30, 0x14,       // SEQUENCE len=20
        0x02, 0x01, 0x00, // version=0 (v1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69,
        0x63,                               // "public"
        0xA4, 0x07,                         // Trap PDU len=7
        0x02, 0x04, 0x00, 0x00, 0x00, 0x03, // requestId=3
        0x00                                // padding
    };
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->pduType.has_value());
    EXPECT_EQ(*result->pduType, fdpi::SnmpPduType::Trap);
}

TEST(SnmpDecoder, ParsesV2cGetBulk) {
    // SNMP v2c GetBulkRequest
    std::vector<uint8_t> data = {
        0x30, 0x1C,       // SEQUENCE
        0x02, 0x01, 0x01, // version=1 (v2c)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69,
        0x63,                               // "public"
        0xA5, 0x0F,                         // GetBulkRequest PDU
        0x02, 0x04, 0x00, 0x00, 0x00, 0x0A, // requestId=10
        0x02, 0x01, 0x00,                   // non-repeaters=0
        0x02, 0x01, 0x0A,                   // max-repetitions=10
        0x30, 0x01, 0x00                    // varbind list
    };
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 1);
    ASSERT_TRUE(result->pduType.has_value());
    EXPECT_EQ(*result->pduType, fdpi::SnmpPduType::GetBulkRequest);
    EXPECT_EQ(*result->requestId, 10u);
}

TEST(SnmpDecoder, ParsesV2cInform) {
    // SNMP v2c InformRequest
    std::vector<uint8_t> data = {
        0x30, 0x1C,       // SEQUENCE
        0x02, 0x01, 0x01, // version=1 (v2c)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69,
        0x63,                               // "public"
        0xA6, 0x0F,                         // InformRequest PDU
        0x02, 0x04, 0x00, 0x00, 0x00, 0x14, // requestId=20
        0x02, 0x01, 0x00,                   // errorStatus
        0x02, 0x01, 0x00,                   // errorIndex
        0x30, 0x01, 0x00                    // varbind list
    };
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 1);
    ASSERT_TRUE(result->pduType.has_value());
    EXPECT_EQ(*result->pduType, fdpi::SnmpPduType::InformRequest);
    EXPECT_EQ(*result->requestId, 20u);
}

TEST(SnmpDecoder, ParsesV3Message) {
    // SNMP v3 message - just check version extraction
    std::vector<uint8_t> data = {
        0x30, 0x0E,       // SEQUENCE len=14
        0x02, 0x01, 0x03, // version=3
        0x30, 0x09,       // msgSecurityParameters SEQUENCE
        0x02, 0x01, 0x01, // msgID
        0x02, 0x01, 0xFF, // msgMaxSize
        0x04, 0x01, 0x00  // msgFlags
    };
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 3);
    EXPECT_FALSE(result->community.has_value());
    EXPECT_FALSE(result->pduType.has_value());
    EXPECT_FALSE(result->requestId.has_value());
}

TEST(SnmpDecoder, ExtractsCommunityString) {
    // SNMP v2c with community "private"
    std::vector<uint8_t> data = {
        0x30, 0x1D,                                           // SEQUENCE
        0x02, 0x01, 0x01,                                     // version=1 (v2c)
        0x04, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, // "private"
        0xA0, 0x0F,                                           // GetRequest PDU
        0x02, 0x04, 0x00, 0x00, 0x00, 0x05,                   // requestId=5
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x01, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->community, "private");
}

TEST(SnmpDecoder, ExtractsRequestId) {
    // Large requestId = 0x12345678
    std::vector<uint8_t> data = {
        0x30, 0x1C,       // SEQUENCE
        0x02, 0x01, 0x00, // version=0 (v1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69,
        0x63,                               // "public"
        0xA0, 0x0F,                         // GetRequest PDU
        0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // requestId=0x12345678
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x01, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->requestId.has_value());
    EXPECT_EQ(*result->requestId, 0x12345678u);
}

TEST(SnmpDecoder, RejectsTruncated) {
    // Truncated: SEQUENCE says len=38 but only 3 bytes follow
    std::vector<uint8_t> data = {0x30, 0x26, 0x02, 0x01, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(SnmpDecoder, RejectsMalformedAsn1) {
    // Invalid: first byte is not SEQUENCE tag 0x30
    std::vector<uint8_t> data = {0x31, 0x06, 0x02, 0x01, 0x00, 0x04, 0x01, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeSnmp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}
