#include <gtest/gtest.h>
#include <fdpi/protocol/mpls.hpp>
#include <vector>

TEST(MplsDecoder, ParsesSingleLabel) {
    // MPLS label entry: Label=1000 (0x3E8), TC=0, S=1 (bottom), TTL=64
    // Byte layout: [Label(20):TC(3):S(1):TTL(8)]
    // Label=1000 = 0x003E8 -> shifted left 12: 0x003E8 << 12
    // Binary: 00000000 00111110 1000 000 1 01000000
    // Hex: 0x00 0x3E 0x81 0x40
    uint32_t entry = (1000 << 12) | (0 << 9) | (1 << 8) | 64;
    std::vector<uint8_t> data = {
        static_cast<uint8_t>((entry >> 24) & 0xFF),
        static_cast<uint8_t>((entry >> 16) & 0xFF),
        static_cast<uint8_t>((entry >> 8) & 0xFF),
        static_cast<uint8_t>(entry & 0xFF),
    };
    size_t offset = 0;
    auto result = fdpi::decodeMpls(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->labelStack.size(), 1u);
    EXPECT_EQ(result->labelStack[0].label, 1000u);
    EXPECT_EQ(result->labelStack[0].tc, 0);
    EXPECT_TRUE(result->labelStack[0].bottomOfStack);
    EXPECT_EQ(result->labelStack[0].ttl, 64);
    EXPECT_EQ(offset, 4u);
}

TEST(MplsDecoder, ParsesStackedLabels) {
    // Two MPLS labels: outer (label=100, S=0) + inner (label=200, S=1)
    uint32_t outer = (100 << 12) | (0 << 9) | (0 << 8) | 255;  // S=0
    uint32_t inner = (200 << 12) | (3 << 9) | (1 << 8) | 128;  // S=1, TC=3

    std::vector<uint8_t> data = {
        static_cast<uint8_t>((outer >> 24) & 0xFF),
        static_cast<uint8_t>((outer >> 16) & 0xFF),
        static_cast<uint8_t>((outer >> 8) & 0xFF),
        static_cast<uint8_t>(outer & 0xFF),
        static_cast<uint8_t>((inner >> 24) & 0xFF),
        static_cast<uint8_t>((inner >> 16) & 0xFF),
        static_cast<uint8_t>((inner >> 8) & 0xFF),
        static_cast<uint8_t>(inner & 0xFF),
    };
    size_t offset = 0;
    auto result = fdpi::decodeMpls(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->labelStack.size(), 2u);

    EXPECT_EQ(result->labelStack[0].label, 100u);
    EXPECT_FALSE(result->labelStack[0].bottomOfStack);
    EXPECT_EQ(result->labelStack[0].ttl, 255);
    EXPECT_EQ(result->labelStack[0].tc, 0);

    EXPECT_EQ(result->labelStack[1].label, 200u);
    EXPECT_TRUE(result->labelStack[1].bottomOfStack);
    EXPECT_EQ(result->labelStack[1].ttl, 128);
    EXPECT_EQ(result->labelStack[1].tc, 3);

    EXPECT_EQ(offset, 8u);
}

TEST(MplsDecoder, ParsesThreeLabelStack) {
    // Three labels deep
    uint32_t l1 = (16 << 12) | (0 << 9) | (0 << 8) | 64;
    uint32_t l2 = (17 << 12) | (0 << 9) | (0 << 8) | 63;
    uint32_t l3 = (18 << 12) | (0 << 9) | (1 << 8) | 62;  // bottom

    std::vector<uint8_t> data;
    for (uint32_t entry : {l1, l2, l3}) {
        data.push_back(static_cast<uint8_t>((entry >> 24) & 0xFF));
        data.push_back(static_cast<uint8_t>((entry >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((entry >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>(entry & 0xFF));
    }

    size_t offset = 0;
    auto result = fdpi::decodeMpls(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->labelStack.size(), 3u);
    EXPECT_EQ(result->labelStack[0].label, 16u);
    EXPECT_EQ(result->labelStack[1].label, 17u);
    EXPECT_EQ(result->labelStack[2].label, 18u);
    EXPECT_TRUE(result->labelStack[2].bottomOfStack);
    EXPECT_EQ(offset, 12u);
}

TEST(MplsDecoder, RejectsTruncatedLabel) {
    // Only 3 bytes - needs 4
    std::vector<uint8_t> data = {0x00, 0x3E, 0x81};
    size_t offset = 0;
    auto result = fdpi::decodeMpls(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(MplsDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeMpls(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(MplsDecoder, ParsesSpecialLabels) {
    // Label 0 = IPv4 Explicit NULL, Label 2 = IPv6 Explicit NULL
    uint32_t entry = (0 << 12) | (0 << 9) | (1 << 8) | 1;  // label 0, bottom, TTL=1
    std::vector<uint8_t> data = {
        static_cast<uint8_t>((entry >> 24) & 0xFF),
        static_cast<uint8_t>((entry >> 16) & 0xFF),
        static_cast<uint8_t>((entry >> 8) & 0xFF),
        static_cast<uint8_t>(entry & 0xFF),
    };
    size_t offset = 0;
    auto result = fdpi::decodeMpls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->labelStack[0].label, 0u);
    EXPECT_EQ(result->labelStack[0].ttl, 1);
}
