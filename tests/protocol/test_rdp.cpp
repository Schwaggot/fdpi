#include <gtest/gtest.h>

#include <fdpi/protocol/rdp.hpp>

#include <vector>

// Helper: build a TPKT + X.224 header for Connection Request (0xE0)
static std::vector<uint8_t> makeCR(uint16_t totalLen,
                                   const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> data;
    // TPKT: version=3, reserved=0, length
    data.push_back(0x03);
    data.push_back(0x00);
    data.push_back(static_cast<uint8_t>((totalLen >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(totalLen & 0xFF));
    // X.224: LI, type=0xE0 (CR), dstRef=0, srcRef=0, classOption=0
    uint8_t li = static_cast<uint8_t>(totalLen - 5); // LI = rest - 1
    data.push_back(li);
    data.push_back(0xE0);
    data.push_back(0x00);
    data.push_back(0x00); // dstRef
    data.push_back(0x00);
    data.push_back(0x00); // srcRef
    data.push_back(0x00); // classOption
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

// Helper: build a TPKT + X.224 header for Connection Confirm (0xD0)
static std::vector<uint8_t> makeCC(uint16_t totalLen,
                                   const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> data;
    data.push_back(0x03);
    data.push_back(0x00);
    data.push_back(static_cast<uint8_t>((totalLen >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(totalLen & 0xFF));
    uint8_t li = static_cast<uint8_t>(totalLen - 5);
    data.push_back(li);
    data.push_back(0xD0);
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x00);
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

TEST(RdpDecoder, ParsesConnectionRequest) {
    auto data = makeCR(11, {});
    size_t offset = 0;
    auto result = fdpi::decodeRdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->tpktVersion, 3);
    EXPECT_EQ(result->tpktLength, 11);
    EXPECT_EQ(result->x224Type, 0xE0);
    EXPECT_EQ(result->dstRef, 0);
    EXPECT_EQ(result->srcRef, 0);
    EXPECT_EQ(result->classOption, 0);
    EXPECT_FALSE(result->cookie.has_value());
    EXPECT_FALSE(result->requestedProtocols.has_value());
    EXPECT_EQ(offset, 11u);
}

TEST(RdpDecoder, ParsesConnectionConfirm) {
    auto data = makeCC(11, {});
    size_t offset = 0;
    auto result = fdpi::decodeRdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->tpktVersion, 3);
    EXPECT_EQ(result->x224Type, 0xD0);
    EXPECT_FALSE(result->selectedProtocol.has_value());
    EXPECT_EQ(offset, 11u);
}

TEST(RdpDecoder, ExtractsCookie) {
    std::string cookie = "Cookie: mstshash=admin\r\n";
    std::vector<uint8_t> payload(cookie.begin(), cookie.end());
    uint16_t totalLen = static_cast<uint16_t>(11 + payload.size());
    auto data = makeCR(totalLen, payload);

    size_t offset = 0;
    auto result = fdpi::decodeRdp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cookie.has_value());
    EXPECT_EQ(*result->cookie, cookie);
}

TEST(RdpDecoder, ExtractsRequestedProtocols) {
    // Negotiation Request: type=0x01, flags=0x00, length=0x0008,
    // requestedProtocols=0x00000003 (TLS + CredSSP)
    std::vector<uint8_t> payload = {0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00};
    uint16_t totalLen = static_cast<uint16_t>(11 + payload.size());
    auto data = makeCR(totalLen, payload);

    size_t offset = 0;
    auto result = fdpi::decodeRdp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->requestedProtocols.has_value());
    EXPECT_EQ(*result->requestedProtocols, 3u);
}

TEST(RdpDecoder, ExtractsSelectedProtocol) {
    // Negotiation Response: type=0x02, flags=0x00, length=0x0008,
    // selectedProtocol=0x00000002 (CredSSP)
    std::vector<uint8_t> payload = {0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00};
    uint16_t totalLen = static_cast<uint16_t>(11 + payload.size());
    auto data = makeCC(totalLen, payload);

    size_t offset = 0;
    auto result = fdpi::decodeRdp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->selectedProtocol.has_value());
    EXPECT_EQ(*result->selectedProtocol, 2u);
}

TEST(RdpDecoder, ParsesNegotiationRequest) {
    // Cookie followed by negotiation request
    std::string cookie = "Cookie: mstshash=test\r\n";
    std::vector<uint8_t> payload(cookie.begin(), cookie.end());
    // Append negotiation request
    std::vector<uint8_t> neg = {0x01, 0x00, 0x08, 0x00,
                                0x01, 0x00, 0x00, 0x00}; // TLS only
    payload.insert(payload.end(), neg.begin(), neg.end());
    uint16_t totalLen = static_cast<uint16_t>(11 + payload.size());
    auto data = makeCR(totalLen, payload);

    size_t offset = 0;
    auto result = fdpi::decodeRdp(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cookie.has_value());
    EXPECT_EQ(*result->cookie, cookie);
    ASSERT_TRUE(result->requestedProtocols.has_value());
    EXPECT_EQ(*result->requestedProtocols, 1u);
}

TEST(RdpDecoder, ParsesNegotiationResponse) {
    // Connection Confirm with negotiation response
    std::vector<uint8_t> payload = {0x02, 0x00, 0x08, 0x00,
                                    0x01, 0x00, 0x00, 0x00}; // TLS
    uint16_t totalLen = static_cast<uint16_t>(11 + payload.size());
    auto data = makeCC(totalLen, payload);

    size_t offset = 0;
    auto result = fdpi::decodeRdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->x224Type, 0xD0);
    ASSERT_TRUE(result->selectedProtocol.has_value());
    EXPECT_EQ(*result->selectedProtocol, 1u);
}

TEST(RdpDecoder, RejectsTruncated) {
    // Only 10 bytes (need at least 11)
    std::vector<uint8_t> data = {0x03, 0x00, 0x00, 0x0B, 0x06,
                                 0xE0, 0x00, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeRdp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(RdpDecoder, RejectsInvalidTpktVersion) {
    // Version = 4 instead of 3
    std::vector<uint8_t> data = {0x04, 0x00, 0x00, 0x0B, 0x06, 0xE0,
                                 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeRdp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(RdpDecoder, HandlesNonZeroOffset) {
    // 2 bytes padding + valid CR
    std::vector<uint8_t> padding = {0xDE, 0xAD};
    auto cr = makeCR(11, {});
    padding.insert(padding.end(), cr.begin(), cr.end());

    size_t offset = 2;
    auto result = fdpi::decodeRdp(padding, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->tpktVersion, 3);
    EXPECT_EQ(result->x224Type, 0xE0);
    EXPECT_EQ(offset, 13u);
}
