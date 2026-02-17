#include <gtest/gtest.h>

#include <fdpi/protocol/dblansyncd.hpp>

#include <string>
#include <vector>

static std::vector<uint8_t> toBytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

TEST(DbLanSyncDiscDecoder, ParsesFullPayload) {
    auto data = toBytes(
        R"({"version": 2, "host_int": 123456789, "displayname": "MyPC", "port": 17500})");
    size_t offset = 0;
    auto result = fdpi::decodeDbLanSyncDisc(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->version.has_value());
    EXPECT_EQ(*result->version, 2u);
    ASSERT_TRUE(result->hostInt.has_value());
    EXPECT_EQ(*result->hostInt, 123456789u);
    ASSERT_TRUE(result->displayName.has_value());
    EXPECT_EQ(*result->displayName, "MyPC");
    ASSERT_TRUE(result->port.has_value());
    EXPECT_EQ(*result->port, 17500);
}

TEST(DbLanSyncDiscDecoder, ParsesPartialPayload) {
    auto data = toBytes(R"({"version": 1})");
    size_t offset = 0;
    auto result = fdpi::decodeDbLanSyncDisc(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->version.has_value());
    EXPECT_EQ(*result->version, 1u);
    EXPECT_FALSE(result->hostInt.has_value());
    EXPECT_FALSE(result->displayName.has_value());
    EXPECT_FALSE(result->port.has_value());
}

TEST(DbLanSyncDiscDecoder, RejectsNonJson) {
    auto data = toBytes("not json at all");
    size_t offset = 0;
    auto result = fdpi::decodeDbLanSyncDisc(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(DbLanSyncDiscDecoder, RejectsTruncated) {
    std::vector<uint8_t> data = {0x00};
    size_t offset = 0;
    auto result = fdpi::decodeDbLanSyncDisc(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(DbLanSyncDiscDecoder, HandlesNonZeroOffset) {
    std::vector<uint8_t> data = {0xAA, 0xBB};
    auto json = toBytes(R"({"version": 3, "port": 17500})");
    data.insert(data.end(), json.begin(), json.end());
    size_t offset = 2;
    auto result = fdpi::decodeDbLanSyncDisc(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->version.has_value());
    EXPECT_EQ(*result->version, 3u);
    ASSERT_TRUE(result->port.has_value());
    EXPECT_EQ(*result->port, 17500);
}
