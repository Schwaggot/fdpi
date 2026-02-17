#include <gtest/gtest.h>

#include <fdpi/protocol/dtls.hpp>

#include <vector>

// Build a DTLS record header (13 bytes) + optional body
static std::vector<uint8_t> makeDtlsRecord(uint8_t contentType,
                                           uint16_t version,
                                           uint16_t epoch,
                                           uint64_t seqNum,
                                           const std::vector<uint8_t>& body = {}) {
    std::vector<uint8_t> pkt(13, 0);
    pkt[0] = contentType;
    pkt[1] = static_cast<uint8_t>((version >> 8) & 0xFF);
    pkt[2] = static_cast<uint8_t>(version & 0xFF);
    pkt[3] = static_cast<uint8_t>((epoch >> 8) & 0xFF);
    pkt[4] = static_cast<uint8_t>(epoch & 0xFF);
    // 48-bit sequence number
    pkt[5] = static_cast<uint8_t>((seqNum >> 40) & 0xFF);
    pkt[6] = static_cast<uint8_t>((seqNum >> 32) & 0xFF);
    pkt[7] = static_cast<uint8_t>((seqNum >> 24) & 0xFF);
    pkt[8] = static_cast<uint8_t>((seqNum >> 16) & 0xFF);
    pkt[9] = static_cast<uint8_t>((seqNum >> 8) & 0xFF);
    pkt[10] = static_cast<uint8_t>(seqNum & 0xFF);
    uint16_t len = static_cast<uint16_t>(body.size());
    pkt[11] = static_cast<uint8_t>((len >> 8) & 0xFF);
    pkt[12] = static_cast<uint8_t>(len & 0xFF);
    pkt.insert(pkt.end(), body.begin(), body.end());
    return pkt;
}

TEST(DtlsDecoder, ParsesDtls12ClientHello) {
    // Handshake (22) + DTLS 1.2 (0xFEFD) + epoch 0 + seq 0
    // Body: handshake type 1 (ClientHello)
    std::vector<uint8_t> body = {0x01, 0x00, 0x00, 0x05, 0x00, 0x00};
    auto data = makeDtlsRecord(22, 0xFEFD, 0, 0, body);
    size_t offset = 0;
    auto result = fdpi::decodeDtls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->contentType, 22);
    EXPECT_EQ(result->version, 0xFEFD);
    EXPECT_EQ(result->epoch, 0);
    EXPECT_EQ(result->sequenceNumber, 0u);
    ASSERT_TRUE(result->handshakeType.has_value());
    EXPECT_EQ(*result->handshakeType, 1); // ClientHello
}

TEST(DtlsDecoder, ParsesDtls10) {
    auto data = makeDtlsRecord(23, 0xFEFF, 1, 42); // AppData, DTLS 1.0
    size_t offset = 0;
    auto result = fdpi::decodeDtls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->contentType, 23);
    EXPECT_EQ(result->version, 0xFEFF);
    EXPECT_EQ(result->epoch, 1);
    EXPECT_EQ(result->sequenceNumber, 42u);
    EXPECT_FALSE(result->handshakeType.has_value());
}

TEST(DtlsDecoder, ParsesChangeCipherSpec) {
    std::vector<uint8_t> body = {0x01};
    auto data = makeDtlsRecord(20, 0xFEFD, 0, 5, body);
    size_t offset = 0;
    auto result = fdpi::decodeDtls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->contentType, 20);
    EXPECT_EQ(result->length, 1);
}

TEST(DtlsDecoder, ParsesSequenceNumber) {
    uint64_t seq = 0x0102030405ULL;
    auto data = makeDtlsRecord(23, 0xFEFD, 0, seq);
    size_t offset = 0;
    auto result = fdpi::decodeDtls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->sequenceNumber, seq);
}

TEST(DtlsDecoder, RejectsTruncated) {
    std::vector<uint8_t> data(12, 0); // 12 < 13
    size_t offset = 0;
    auto result = fdpi::decodeDtls(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DtlsDecoder, HandlesNonZeroOffset) {
    auto pkt = makeDtlsRecord(22, 0xFEFD, 0, 0);
    std::vector<uint8_t> data(6, 0xDD);
    data.insert(data.end(), pkt.begin(), pkt.end());
    size_t offset = 6;
    auto result = fdpi::decodeDtls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->contentType, 22);
    EXPECT_EQ(result->version, 0xFEFD);
}
