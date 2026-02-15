#include <gtest/gtest.h>
#include <fdpi/protocol/gre.hpp>
#include <vector>

TEST(GreDecoder, ParsesBasicGre) {
    // Basic GRE: no checksum, no key, no sequence
    // Flags/version: 0x0000, Protocol: 0x0800 (IPv4)
    std::vector<uint8_t> data = {
        0x00, 0x00,  // flags: C=0, K=0, S=0, version=0
        0x08, 0x00   // protocol: IPv4
    };
    size_t offset = 0;
    auto result = fdpi::decodeGre(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->checksumPresent);
    EXPECT_FALSE(result->keyPresent);
    EXPECT_FALSE(result->seqPresent);
    EXPECT_EQ(result->protocolType, 0x0800);
    EXPECT_FALSE(result->checksum.has_value());
    EXPECT_FALSE(result->key.has_value());
    EXPECT_FALSE(result->sequenceNumber.has_value());
    EXPECT_EQ(offset, 4u);
}

TEST(GreDecoder, ParsesGreWithChecksum) {
    // GRE with checksum flag set
    // Flags: C=1 (bit 15) -> 0x8000
    std::vector<uint8_t> data = {
        0x80, 0x00,             // flags: C=1
        0x08, 0x00,             // protocol: IPv4
        0x12, 0x34, 0x00, 0x00  // checksum=0x1234, reserved=0
    };
    size_t offset = 0;
    auto result = fdpi::decodeGre(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->checksumPresent);
    EXPECT_TRUE(result->checksum.has_value());
    EXPECT_EQ(result->protocolType, 0x0800);
    EXPECT_EQ(offset, 8u);
}

TEST(GreDecoder, ParsesGreWithKey) {
    // GRE with key flag set
    // Flags: K=1 (bit 13) -> 0x2000
    std::vector<uint8_t> data = {
        0x20, 0x00,             // flags: K=1
        0x08, 0x00,             // protocol: IPv4
        0x00, 0x00, 0xAB, 0xCD  // key=0x0000ABCD
    };
    size_t offset = 0;
    auto result = fdpi::decodeGre(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->keyPresent);
    EXPECT_TRUE(result->key.has_value());
    EXPECT_EQ(result->key.value(), 0x0000ABCDu);
    EXPECT_EQ(offset, 8u);
}

TEST(GreDecoder, ParsesGreWithSequenceNumber) {
    // GRE with sequence number flag set
    // Flags: S=1 (bit 12) -> 0x1000
    std::vector<uint8_t> data = {
        0x10, 0x00,             // flags: S=1
        0x08, 0x00,             // protocol: IPv4
        0x00, 0x00, 0x00, 0x42  // sequence=66
    };
    size_t offset = 0;
    auto result = fdpi::decodeGre(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->seqPresent);
    EXPECT_TRUE(result->sequenceNumber.has_value());
    EXPECT_EQ(result->sequenceNumber.value(), 66u);
    EXPECT_EQ(offset, 8u);
}

TEST(GreDecoder, ParsesGreWithAllOptions) {
    // GRE with checksum + key + sequence
    // Flags: C=1, K=1, S=1 -> 0xB000
    std::vector<uint8_t> data = {
        0xB0, 0x00,             // flags: C=1, K=1, S=1
        0x86, 0xDD,             // protocol: IPv6
        0xAB, 0xCD, 0x00, 0x00, // checksum + reserved
        0x00, 0x01, 0x02, 0x03, // key
        0x00, 0x00, 0x00, 0x0A  // sequence=10
    };
    size_t offset = 0;
    auto result = fdpi::decodeGre(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->checksumPresent);
    EXPECT_TRUE(result->keyPresent);
    EXPECT_TRUE(result->seqPresent);
    EXPECT_EQ(result->protocolType, 0x86DD);
    EXPECT_TRUE(result->key.has_value());
    EXPECT_EQ(result->key.value(), 0x00010203u);
    EXPECT_TRUE(result->sequenceNumber.has_value());
    EXPECT_EQ(result->sequenceNumber.value(), 10u);
    EXPECT_EQ(offset, 16u);
}

TEST(GreDecoder, RejectsTruncatedBasicHeader) {
    // Only 3 bytes - need at least 4
    std::vector<uint8_t> data = {0x00, 0x00, 0x08};
    size_t offset = 0;
    auto result = fdpi::decodeGre(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(GreDecoder, RejectsTruncatedWithKey) {
    // Key flag set but only 4 bytes (basic header) - no room for key
    std::vector<uint8_t> data = {
        0x20, 0x00,  // flags: K=1
        0x08, 0x00   // protocol
        // missing key bytes
    };
    size_t offset = 0;
    auto result = fdpi::decodeGre(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(GreDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeGre(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(GreDecoder, ParsesGreEncapsulatingSelf) {
    // GRE encapsulating GRE (protocol 0x6558 = Transparent Ethernet Bridging)
    std::vector<uint8_t> data = {
        0x00, 0x00,  // flags: none
        0x65, 0x58   // protocol: Transparent Ethernet Bridging
    };
    size_t offset = 0;
    auto result = fdpi::decodeGre(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->protocolType, 0x6558);
}
