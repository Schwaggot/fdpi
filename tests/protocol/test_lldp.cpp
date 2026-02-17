#include <gtest/gtest.h>

#include <fdpi/protocol/lldp.hpp>

#include <vector>

// Helper to build a TLV: 7-bit type + 9-bit length, then value bytes
static void
appendTlv(std::vector<uint8_t>& buf, uint16_t type, const std::vector<uint8_t>& value) {
    uint16_t hdr = static_cast<uint16_t>((type << 9) | (value.size() & 0x01FF));
    buf.push_back(static_cast<uint8_t>((hdr >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(hdr & 0xFF));
    buf.insert(buf.end(), value.begin(), value.end());
}

static void appendEndTlv(std::vector<uint8_t>& buf) {
    buf.push_back(0x00);
    buf.push_back(0x00);
}

TEST(LldpDecoder, ParsesBasicLldp) {
    std::vector<uint8_t> data;
    // Chassis ID (type 1): subtype 4 (MAC) + "host1"
    std::vector<uint8_t> chassisVal = {0x04, 'h', 'o', 's', 't', '1'};
    appendTlv(data, 1, chassisVal);
    // Port ID (type 2): subtype 5 (ifName) + "eth0"
    std::vector<uint8_t> portVal = {0x05, 'e', 't', 'h', '0'};
    appendTlv(data, 2, portVal);
    // TTL (type 3): 120 seconds
    std::vector<uint8_t> ttlVal = {0x00, 120};
    appendTlv(data, 3, ttlVal);
    // End
    appendEndTlv(data);

    size_t offset = 0;
    auto result = fdpi::decodeLldp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->chassisId, "host1");
    EXPECT_EQ(result->portId, "eth0");
    EXPECT_EQ(result->ttl, 120);
    EXPECT_FALSE(result->systemName.has_value());
    EXPECT_FALSE(result->systemDescription.has_value());
}

TEST(LldpDecoder, ParsesOptionalTlvs) {
    std::vector<uint8_t> data;
    std::vector<uint8_t> chassisVal = {0x04, 'R', '1'};
    appendTlv(data, 1, chassisVal);
    std::vector<uint8_t> portVal = {0x05, 'p', '1'};
    appendTlv(data, 2, portVal);
    std::vector<uint8_t> ttlVal = {0x00, 60};
    appendTlv(data, 3, ttlVal);
    // System Name (type 5)
    std::string sysName = "MyRouter";
    std::vector<uint8_t> nameVal(sysName.begin(), sysName.end());
    appendTlv(data, 5, nameVal);
    // System Description (type 6)
    std::string sysDesc = "Linux router";
    std::vector<uint8_t> descVal(sysDesc.begin(), sysDesc.end());
    appendTlv(data, 6, descVal);
    appendEndTlv(data);

    size_t offset = 0;
    auto result = fdpi::decodeLldp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->chassisId, "R1");
    EXPECT_EQ(result->ttl, 60);
    ASSERT_TRUE(result->systemName.has_value());
    EXPECT_EQ(*result->systemName, "MyRouter");
    ASSERT_TRUE(result->systemDescription.has_value());
    EXPECT_EQ(*result->systemDescription, "Linux router");
}

TEST(LldpDecoder, StoresAllTlvs) {
    std::vector<uint8_t> data;
    std::vector<uint8_t> chassisVal = {0x04, 'A'};
    appendTlv(data, 1, chassisVal);
    std::vector<uint8_t> portVal = {0x05, 'B'};
    appendTlv(data, 2, portVal);
    std::vector<uint8_t> ttlVal = {0x00, 30};
    appendTlv(data, 3, ttlVal);
    appendEndTlv(data);

    size_t offset = 0;
    auto result = fdpi::decodeLldp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->tlvs.size(), 3u);
    EXPECT_EQ(result->tlvs[0].type, 1);
    EXPECT_EQ(result->tlvs[1].type, 2);
    EXPECT_EQ(result->tlvs[2].type, 3);
}

TEST(LldpDecoder, RejectsTruncated) {
    std::vector<uint8_t> data = {0x02}; // Only 1 byte
    size_t offset = 0;
    auto result = fdpi::decodeLldp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(LldpDecoder, HandlesNonZeroOffset) {
    std::vector<uint8_t> data(5, 0xAA); // 5 bytes padding
    std::vector<uint8_t> lldp;
    std::vector<uint8_t> chassisVal = {0x04, 'X'};
    appendTlv(lldp, 1, chassisVal);
    std::vector<uint8_t> portVal = {0x05, 'Y'};
    appendTlv(lldp, 2, portVal);
    std::vector<uint8_t> ttlVal = {0x00, 10};
    appendTlv(lldp, 3, ttlVal);
    appendEndTlv(lldp);
    data.insert(data.end(), lldp.begin(), lldp.end());

    size_t offset = 5;
    auto result = fdpi::decodeLldp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->chassisId, "X");
    EXPECT_EQ(result->portId, "Y");
    EXPECT_EQ(result->ttl, 10);
}
