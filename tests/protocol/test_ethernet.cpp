#include <gtest/gtest.h>
#include <fdpi/protocol/ethernet.hpp>
#include <vector>

// ---- Ethernet Header Tests ----

TEST(EthernetDecoder, ParsesValidFrame) {
    // Ethernet: dst=ff:ff:ff:ff:ff:ff, src=00:11:22:33:44:55, type=0x0800 (IPv4)
    std::vector<uint8_t> data = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src MAC
        0x08, 0x00                             // EtherType: IPv4
    };
    size_t offset = 0;
    auto result = fdpi::decodeEthernet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_EQ(result->dst.bytes[0], 0xff);
    EXPECT_EQ(result->dst.bytes[5], 0xff);
    EXPECT_EQ(result->src.bytes[0], 0x00);
    EXPECT_EQ(result->src.bytes[1], 0x11);
    EXPECT_EQ(result->src.bytes[2], 0x22);
    EXPECT_EQ(result->src.bytes[3], 0x33);
    EXPECT_EQ(result->src.bytes[4], 0x44);
    EXPECT_EQ(result->src.bytes[5], 0x55);
    EXPECT_EQ(offset, 14u);
}

TEST(EthernetDecoder, ParsesIPv6EtherType) {
    std::vector<uint8_t> data = {
        0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,  // dst MAC
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  // src MAC
        0x86, 0xdd                             // EtherType: IPv6
    };
    size_t offset = 0;
    auto result = fdpi::decodeEthernet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x86DD);
    EXPECT_EQ(offset, 14u);
}

TEST(EthernetDecoder, ParsesARPEtherType) {
    std::vector<uint8_t> data = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // dst MAC (broadcast)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // src MAC
        0x08, 0x06                             // EtherType: ARP
    };
    size_t offset = 0;
    auto result = fdpi::decodeEthernet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0806);
}

TEST(EthernetDecoder, RejectsTruncatedFrame) {
    // Only 13 bytes - one short of minimum Ethernet header
    std::vector<uint8_t> data = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08
    };
    size_t offset = 0;
    auto result = fdpi::decodeEthernet(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(EthernetDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeEthernet(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(EthernetDecoder, ParsesWithNonZeroOffset) {
    // 2 bytes padding + 14 bytes ethernet header
    std::vector<uint8_t> data = {
        0x00, 0x00,                            // padding
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // dst MAC
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // src MAC
        0x08, 0x00                             // EtherType: IPv4
    };
    size_t offset = 2;
    auto result = fdpi::decodeEthernet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->dst.bytes[0], 0xaa);
    EXPECT_EQ(result->src.bytes[0], 0x11);
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_EQ(offset, 16u);
}

TEST(EthernetDecoder, ParsesMinimumValidFrame) {
    // Exactly 14 bytes - minimum Ethernet header
    std::vector<uint8_t> data = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // dst MAC (all zeros)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // src MAC (all zeros)
        0x00, 0x00                             // EtherType: 0
    };
    size_t offset = 0;
    auto result = fdpi::decodeEthernet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0000);
    EXPECT_EQ(offset, 14u);
}

TEST(EthernetDecoder, ParsesMPLSEtherType) {
    std::vector<uint8_t> data = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x88, 0x47                             // EtherType: MPLS unicast
    };
    size_t offset = 0;
    auto result = fdpi::decodeEthernet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x8847);
}

// ---- VLAN Tag Tests ----

TEST(VlanDecoder, ParsesValidVlanTag) {
    // VLAN TCI: priority=5 (101), DEI=0, VID=100 (0x064)
    // TCI = (5 << 13) | (0 << 12) | 100 = 0xA064
    // Inner EtherType: 0x0800 (IPv4)
    std::vector<uint8_t> data = {
        0xA0, 0x64,  // TCI
        0x08, 0x00   // inner EtherType
    };
    size_t offset = 0;
    auto result = fdpi::decodeVlan(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->tci, 0xA064);
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_EQ(result->vlanId(), 100);
    EXPECT_EQ(result->priority(), 5);
    EXPECT_EQ(offset, 4u);
}

TEST(VlanDecoder, ParsesVlanIdZero) {
    // VID = 0 (priority-tagged frame)
    std::vector<uint8_t> data = {
        0x00, 0x00,  // TCI: priority=0, DEI=0, VID=0
        0x86, 0xdd   // inner EtherType: IPv6
    };
    size_t offset = 0;
    auto result = fdpi::decodeVlan(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->vlanId(), 0);
    EXPECT_EQ(result->priority(), 0);
    EXPECT_EQ(result->etherType, 0x86DD);
}

TEST(VlanDecoder, ParsesMaxVlanId) {
    // VID = 4095 (0xFFF), priority = 7
    // TCI = (7 << 13) | 4095 = 0xFFFF
    std::vector<uint8_t> data = {
        0xFF, 0xFF,  // TCI: max values
        0x08, 0x00   // inner EtherType
    };
    size_t offset = 0;
    auto result = fdpi::decodeVlan(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->vlanId(), 4095);
    EXPECT_EQ(result->priority(), 7);
}

TEST(VlanDecoder, RejectsTruncatedVlan) {
    // Only 3 bytes - needs 4
    std::vector<uint8_t> data = {0xA0, 0x64, 0x08};
    size_t offset = 0;
    auto result = fdpi::decodeVlan(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(VlanDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeVlan(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(EthernetDecoder, ParsesVlanTaggedFrame) {
    // Full Ethernet + VLAN: dst, src, 0x8100 (VLAN), TCI, inner EtherType
    std::vector<uint8_t> data = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src MAC
        0x81, 0x00,                            // EtherType: 802.1Q VLAN
        0x00, 0x0A,                            // TCI: VID=10
        0x08, 0x00                             // inner EtherType: IPv4
    };
    size_t offset = 0;
    auto ethResult = fdpi::decodeEthernet(data, offset);
    ASSERT_TRUE(ethResult.has_value());
    EXPECT_EQ(ethResult->etherType, 0x8100);
    EXPECT_EQ(offset, 14u);

    // Now decode the VLAN tag
    auto vlanResult = fdpi::decodeVlan(data, offset);
    ASSERT_TRUE(vlanResult.has_value());
    EXPECT_EQ(vlanResult->vlanId(), 10);
    EXPECT_EQ(vlanResult->etherType, 0x0800);
    EXPECT_EQ(offset, 18u);
}

TEST(EthernetDecoder, ParsesQinQDoubleVlan) {
    // Ethernet + outer VLAN (0x88a8) + inner VLAN (0x8100)
    std::vector<uint8_t> data = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src MAC
        0x88, 0xa8,                            // EtherType: 802.1ad (QinQ)
        0x00, 0x64,                            // Outer TCI: VID=100
        0x81, 0x00,                            // Inner 802.1Q tag
        0x00, 0x0A,                            // Inner TCI: VID=10
        0x08, 0x00                             // innermost EtherType: IPv4
    };
    size_t offset = 0;
    auto ethResult = fdpi::decodeEthernet(data, offset);
    ASSERT_TRUE(ethResult.has_value());
    EXPECT_EQ(ethResult->etherType, 0x88A8);
    EXPECT_EQ(offset, 14u);

    // Decode outer VLAN
    auto outerVlan = fdpi::decodeVlan(data, offset);
    ASSERT_TRUE(outerVlan.has_value());
    EXPECT_EQ(outerVlan->vlanId(), 100);
    EXPECT_EQ(outerVlan->etherType, 0x8100);
    EXPECT_EQ(offset, 18u);

    // Decode inner VLAN
    auto innerVlan = fdpi::decodeVlan(data, offset);
    ASSERT_TRUE(innerVlan.has_value());
    EXPECT_EQ(innerVlan->vlanId(), 10);
    EXPECT_EQ(innerVlan->etherType, 0x0800);
    EXPECT_EQ(offset, 22u);
}
