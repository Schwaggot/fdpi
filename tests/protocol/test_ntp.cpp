#include <gtest/gtest.h>

#include <fdpi/protocol/ntp.hpp>

#include <vector>

// Helper to build a 48-byte NTP packet
static std::vector<uint8_t> makeNtpPacket(uint8_t li,
                                          uint8_t version,
                                          uint8_t mode,
                                          uint8_t stratum,
                                          int8_t poll,
                                          int8_t precision,
                                          uint32_t rootDelay,
                                          uint32_t rootDisp,
                                          uint32_t refId,
                                          uint64_t refTs,
                                          uint64_t origTs,
                                          uint64_t recvTs,
                                          uint64_t xmitTs) {
    std::vector<uint8_t> pkt(48, 0);
    pkt[0] = static_cast<uint8_t>((li << 6) | (version << 3) | mode);
    pkt[1] = stratum;
    pkt[2] = static_cast<uint8_t>(poll);
    pkt[3] = static_cast<uint8_t>(precision);

    auto put32 = [&](size_t off, uint32_t v) {
        pkt[off] = static_cast<uint8_t>((v >> 24) & 0xFF);
        pkt[off + 1] = static_cast<uint8_t>((v >> 16) & 0xFF);
        pkt[off + 2] = static_cast<uint8_t>((v >> 8) & 0xFF);
        pkt[off + 3] = static_cast<uint8_t>(v & 0xFF);
    };
    auto put64 = [&](size_t off, uint64_t v) {
        for (int i = 0; i < 8; ++i)
            pkt[off + i] = static_cast<uint8_t>((v >> (56 - 8 * i)) & 0xFF);
    };

    put32(4, rootDelay);
    put32(8, rootDisp);
    put32(12, refId);
    put64(16, refTs);
    put64(24, origTs);
    put64(32, recvTs);
    put64(40, xmitTs);
    return pkt;
}

TEST(NtpDecoder, ParsesNtpV4ClientRequest) {
    auto data = makeNtpPacket(0, 4, 3, // LI=0, version=4, mode=3 (client)
                              0, 0, -20, 0, 0, 0, 0, 0, 0, 0xDEADBEEF12345678ULL);
    size_t offset = 0;
    auto result = fdpi::decodeNtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->leapIndicator, 0);
    EXPECT_EQ(result->version, 4);
    EXPECT_EQ(result->mode, 3);
    EXPECT_EQ(result->stratum, 0);
    EXPECT_EQ(result->transmitTimestamp, 0xDEADBEEF12345678ULL);
    EXPECT_EQ(offset, 48u);
}

TEST(NtpDecoder, ParsesNtpV4ServerResponse) {
    auto data = makeNtpPacket(0, 4, 4, // LI=0, version=4, mode=4 (server)
                              2, 6, -21, 0x00000100, 0x00000200, 0x7F000001,
                              0xAAAABBBBCCCCDDDDULL, 0x1111222233334444ULL,
                              0x5555666677778888ULL, 0x9999AAAABBBBCCCCULL);
    size_t offset = 0;
    auto result = fdpi::decodeNtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 4);
    EXPECT_EQ(result->mode, 4);
    EXPECT_EQ(result->stratum, 2);
    EXPECT_EQ(result->poll, 6);
    EXPECT_EQ(result->precision, -21);
    EXPECT_EQ(result->rootDelay, 0x00000100u);
    EXPECT_EQ(result->rootDispersion, 0x00000200u);
    EXPECT_EQ(result->referenceId, 0x7F000001u);
}

TEST(NtpDecoder, ParsesNtpV3Packet) {
    auto data = makeNtpPacket(0, 3, 3,                     // LI=0, version=3, mode=3
                              1, 4, -18, 0, 0, 0x4C4F434C, // "LOCL"
                              0, 0, 0, 0);
    size_t offset = 0;
    auto result = fdpi::decodeNtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 3);
    EXPECT_EQ(result->referenceId, 0x4C4F434C);
}

TEST(NtpDecoder, ExtractsTimestamps) {
    uint64_t refTs = 0x0102030405060708ULL;
    uint64_t origTs = 0x1112131415161718ULL;
    uint64_t recvTs = 0x2122232425262728ULL;
    uint64_t xmitTs = 0x3132333435363738ULL;
    auto data = makeNtpPacket(0, 4, 4, 1, 0, 0, 0, 0, 0, refTs, origTs, recvTs, xmitTs);
    size_t offset = 0;
    auto result = fdpi::decodeNtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->referenceTimestamp, refTs);
    EXPECT_EQ(result->originTimestamp, origTs);
    EXPECT_EQ(result->receiveTimestamp, recvTs);
    EXPECT_EQ(result->transmitTimestamp, xmitTs);
}

TEST(NtpDecoder, ExtractsLeapIndicator) {
    // LI=3 (clock not synchronized)
    auto data = makeNtpPacket(3, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    size_t offset = 0;
    auto result = fdpi::decodeNtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->leapIndicator, 3);
}

TEST(NtpDecoder, RejectsTruncated) {
    std::vector<uint8_t> data(47, 0); // 47 < 48
    size_t offset = 0;
    auto result = fdpi::decodeNtp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(NtpDecoder, HandlesNonZeroOffset) {
    auto pkt = makeNtpPacket(0, 4, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    // Prepend 10 bytes of padding
    std::vector<uint8_t> data(10, 0xAA);
    data.insert(data.end(), pkt.begin(), pkt.end());
    size_t offset = 10;
    auto result = fdpi::decodeNtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 4);
    EXPECT_EQ(result->mode, 3);
    EXPECT_EQ(offset, 58u);
}

TEST(NtpDecoder, ParsesStratumField) {
    // Stratum 16 = unsynchronized
    auto data = makeNtpPacket(0, 4, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    size_t offset = 0;
    auto result = fdpi::decodeNtp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->stratum, 16);
}
