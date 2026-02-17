#include <gtest/gtest.h>

#include <fdpi/protocol/nbns.hpp>

#include <vector>

TEST(NbnsDecoder, ParsesNameQuery) {
    // NBNS query for "WORKGROUP" (NetBIOS encoded)
    // NetBIOS encoding of "WORKGROUP      \x00":
    // W=0x57: E(0x45) H(0x48), O=0x4F: E(0x45) P(0x50), etc.
    std::vector<uint8_t> data = {
        // Header (12 bytes)
        0x00, 0x01, // ID: 1
        0x01, 0x10, // Flags: query, broadcast
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: NetBIOS encoded name
        0x20, // label length: 32
        // "WORKGROUP       " padded to 16 bytes, each byte encoded as 2 chars
        // W(0x57)=EH, O(0x4F)=EP, R(0x52)=FC, K(0x4B)=FL,
        // G(0x47)=FH, R(0x52)=FC, O(0x4F)=EP, U(0x55)=FF,
        // P(0x50)=FA, ' '(0x20)=CA * 7
        'E', 'H', 'E', 'P', 'F', 'C', 'F', 'L', 'F', 'H', 'F', 'C', 'E', 'P', 'F', 'F',
        'F', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A',
        0x00,       // null terminator
        0x00, 0x20, // type: NB (0x0020)
        0x00, 0x01  // class: IN
    };
    size_t offset = 0;
    auto result = fdpi::decodeNbns(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->id, 1);
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->questions.size(), 1u);
    EXPECT_EQ(result->questions[0].type, 0x0020);
    EXPECT_EQ(result->questions[0].qclass, 1);
    // Name should be "WORKGROUP" with trailing spaces trimmed + suffix
    EXPECT_FALSE(result->questions[0].name.empty());
}

TEST(NbnsDecoder, ParsesResponse) {
    std::vector<uint8_t> data = {
        // Header
        0x00, 0x02, // ID: 2
        0x85, 0x00, // Flags: response, authoritative
        0x00, 0x00, // QDCOUNT: 0
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Answer RR: compressed name pointer
        0xC0, 0x0C, // name: pointer to offset 12 (doesn't exist here, will be empty)
        0x00, 0x20, // type: NB
        0x00, 0x01, // class: IN
        0x00, 0x00, 0x00, 0x3C, // TTL: 60
        0x00, 0x06,             // RDLENGTH: 6
        0x00, 0x00,             // flags
        0xC0, 0xA8, 0x01, 0x0A  // IP: 192.168.1.10
    };
    size_t offset = 0;
    auto result = fdpi::decodeNbns(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->id, 2);
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->answers.size(), 1u);
    EXPECT_EQ(result->answers[0].type, 0x0020);
    EXPECT_EQ(result->answers[0].ttl, 60u);
    EXPECT_EQ(result->answers[0].rdata.size(), 6u);
}

TEST(NbnsDecoder, RejectsTruncatedHeader) {
    std::vector<uint8_t> data = {0x00, 0x01, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeNbns(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(NbnsDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeNbns(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(NetbiosNameDecoder, DecodesSimpleName) {
    // NetBIOS encoding of "A" (0x41): 'E'(0x45) 'B'(0x42)
    // Padded with spaces (0x20): 'C'(0x43) 'A'(0x41)
    std::vector<uint8_t> data = {
        0x20, // label length: 32
        'E',  'B', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A',
        'C',  'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A', 'C', 'A',
        0x00 // null terminator
    };
    size_t offset = 0;
    auto name = fdpi::decodeNetbiosName(data, offset);
    EXPECT_FALSE(name.empty());
    // Should start with "A"
    EXPECT_EQ(name[0], 'A');
}
