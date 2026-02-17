#include <gtest/gtest.h>

#include <fdpi/protocol/igmp.hpp>

#include <vector>

TEST(IgmpDecoder, ParsesMembershipQuery) {
    // IGMP Membership Query: type=0x11, maxRespTime=100, group=0.0.0.0
    std::vector<uint8_t> data = {
        0x11,                  // type: Membership Query
        0x64,                  // maxRespTime: 100 (10 seconds)
        0x12, 0x34,            // checksum
        0x00, 0x00, 0x00, 0x00 // group: 0.0.0.0 (general query)
    };
    size_t offset = 0;
    auto result = fdpi::decodeIgmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 0x11);
    EXPECT_EQ(result->maxRespTime, 0x64);
    EXPECT_EQ(result->checksum, 0x1234);
    EXPECT_EQ(result->groupAddress, fdpi::IPv4Address(std::string_view("0.0.0.0")));
    EXPECT_EQ(offset, 8u);
}

TEST(IgmpDecoder, ParsesV2MembershipReport) {
    // IGMPv2 Membership Report: type=0x16, group=239.1.2.3
    std::vector<uint8_t> data = {
        0x16,                  // type: v2 Membership Report
        0x00,                  // maxRespTime: 0
        0xAB, 0xCD,            // checksum
        0xEF, 0x01, 0x02, 0x03 // group: 239.1.2.3
    };
    size_t offset = 0;
    auto result = fdpi::decodeIgmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 0x16);
    EXPECT_EQ(result->groupAddress, fdpi::IPv4Address(std::string_view("239.1.2.3")));
}

TEST(IgmpDecoder, ParsesLeaveGroup) {
    // IGMP Leave Group: type=0x17
    std::vector<uint8_t> data = {
        0x17,                  // type: Leave Group
        0x00,                  // maxRespTime
        0x00, 0x00,            // checksum
        0xE0, 0x00, 0x00, 0x01 // group: 224.0.0.1
    };
    size_t offset = 0;
    auto result = fdpi::decodeIgmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 0x17);
    EXPECT_EQ(result->groupAddress, fdpi::IPv4Address(std::string_view("224.0.0.1")));
}

TEST(IgmpDecoder, ParsesV3MembershipReport) {
    // IGMPv3 Membership Report: type=0x22
    std::vector<uint8_t> data = {
        0x22,                  // type: v3 Membership Report
        0x00,                  // reserved
        0x00, 0x00,            // checksum
        0x00, 0x00, 0x00, 0x00 // reserved
    };
    size_t offset = 0;
    auto result = fdpi::decodeIgmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 0x22);
}

TEST(IgmpDecoder, RejectsTruncatedPacket) {
    std::vector<uint8_t> data = {0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeIgmp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(IgmpDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeIgmp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(IgmpDecoder, ParsesWithOffset) {
    // 4 bytes padding + IGMP packet
    std::vector<uint8_t> data = {
        0xAA, 0xBB, 0xCC, 0xDD, // padding
        0x11,                   // type
        0x64,                   // maxRespTime
        0x12, 0x34,             // checksum
        0xE0, 0x00, 0x00, 0xFB  // group: 224.0.0.251
    };
    size_t offset = 4;
    auto result = fdpi::decodeIgmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, 0x11);
    EXPECT_EQ(result->groupAddress, fdpi::IPv4Address(std::string_view("224.0.0.251")));
    EXPECT_EQ(offset, 12u);
}
