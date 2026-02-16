#include <gtest/gtest.h>

#include <fdpi/protocol/dhcpv6.hpp>

#include <vector>

// Build a DHCPv6 packet: 1 byte msgType + 3 bytes txnId + options
static std::vector<uint8_t>
makeDhcpv6Packet(uint8_t msgType, uint32_t txnId, const std::vector<uint8_t>& options) {
    std::vector<uint8_t> pkt;
    pkt.push_back(msgType);
    // 24-bit transaction ID (big-endian)
    pkt.push_back(static_cast<uint8_t>((txnId >> 16) & 0xFF));
    pkt.push_back(static_cast<uint8_t>((txnId >> 8) & 0xFF));
    pkt.push_back(static_cast<uint8_t>(txnId & 0xFF));
    pkt.insert(pkt.end(), options.begin(), options.end());
    return pkt;
}

// Build a TLV option: 2-byte type + 2-byte length + data
static std::vector<uint8_t> makeOption(uint16_t type, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> opt;
    opt.push_back(static_cast<uint8_t>((type >> 8) & 0xFF));
    opt.push_back(static_cast<uint8_t>(type & 0xFF));
    auto len = static_cast<uint16_t>(data.size());
    opt.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    opt.push_back(static_cast<uint8_t>(len & 0xFF));
    opt.insert(opt.end(), data.begin(), data.end());
    return opt;
}

TEST(Dhcpv6Decoder, ParsesSolicit) {
    auto data = makeDhcpv6Packet(1, 0x123456, {});
    size_t offset = 0;
    auto result = fdpi::decodeDhcpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageType, 1); // Solicit
    EXPECT_EQ(result->transactionId, 0x123456u);
    EXPECT_EQ(offset, 4u);
}

TEST(Dhcpv6Decoder, ParsesAdvertise) {
    auto data = makeDhcpv6Packet(2, 0xABCDEF, {});
    size_t offset = 0;
    auto result = fdpi::decodeDhcpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageType, 2); // Advertise
    EXPECT_EQ(result->transactionId, 0xABCDEFu);
}

TEST(Dhcpv6Decoder, ExtractsTransactionId) {
    auto data = makeDhcpv6Packet(3, 0x000001, {});
    size_t offset = 0;
    auto result = fdpi::decodeDhcpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->transactionId, 1u);
}

TEST(Dhcpv6Decoder, ParsesOptions) {
    // Option 1 (Client Identifier) with some data
    auto opt1 = makeOption(1, {0x00, 0x01, 0x00, 0x01});
    // Option 6 (Option Request) with requested options
    auto opt2 = makeOption(6, {0x00, 0x17, 0x00, 0x18});
    std::vector<uint8_t> opts;
    opts.insert(opts.end(), opt1.begin(), opt1.end());
    opts.insert(opts.end(), opt2.begin(), opt2.end());

    auto data = makeDhcpv6Packet(1, 0x112233, opts);
    size_t offset = 0;
    auto result = fdpi::decodeDhcpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->options.size(), 2u);
    EXPECT_EQ(result->options[0].code, 1);
    EXPECT_EQ(result->options[1].code, 6);
}

TEST(Dhcpv6Decoder, ExtractsClientFqdn) {
    // Option 39 (Client FQDN): flags byte + FQDN data
    // Simple encoding: flags=0, then "host.example.com"
    std::vector<uint8_t> fqdnData = {0x00}; // flags
    std::string fqdn = "host.example.com";
    fqdnData.insert(fqdnData.end(), fqdn.begin(), fqdn.end());
    auto opt = makeOption(39, fqdnData);

    auto data = makeDhcpv6Packet(1, 0x445566, opt);
    size_t offset = 0;
    auto result = fdpi::decodeDhcpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->clientFqdn.has_value());
    EXPECT_EQ(result->clientFqdn.value(), "host.example.com");
}

TEST(Dhcpv6Decoder, RejectsTruncated) {
    // Less than 4 bytes
    std::vector<uint8_t> data = {0x01, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeDhcpv6(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(Dhcpv6Decoder, RejectsInvalidMessageType) {
    // Message type 0 is invalid
    auto data = makeDhcpv6Packet(0, 0x000000, {});
    size_t offset = 0;
    auto result = fdpi::decodeDhcpv6(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}

TEST(Dhcpv6Decoder, HandlesNonZeroOffset) {
    auto pkt = makeDhcpv6Packet(1, 0xFEDCBA, {});
    // Prepend 8 bytes of padding
    std::vector<uint8_t> data(8, 0xBB);
    data.insert(data.end(), pkt.begin(), pkt.end());
    size_t offset = 8;
    auto result = fdpi::decodeDhcpv6(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageType, 1);
    EXPECT_EQ(result->transactionId, 0xFEDCBAu);
    EXPECT_EQ(offset, 12u);
}
