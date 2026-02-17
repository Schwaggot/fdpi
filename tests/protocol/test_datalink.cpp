#include <fdpi/datalink.hpp>
#include <fdpi/decoder.hpp>
#include <gtest/gtest.h>

#include <cstring>
#include <vector>

// ---- DLT_NULL (BSD Loopback) Tests ----

TEST(DataLink, NullIPv4) {
    // 4-byte native-endian AF_INET (2)
    uint32_t af = 2;
    std::vector<uint8_t> data(4);
    std::memcpy(data.data(), &af, 4);

    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_NULL, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_FALSE(result->hasMacs);
    EXPECT_EQ(offset, 4u);
}

TEST(DataLink, NullIPv6LinuxAF) {
    uint32_t af = 10; // AF_INET6 on Linux
    std::vector<uint8_t> data(4);
    std::memcpy(data.data(), &af, 4);

    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_NULL, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x86DD);
}

TEST(DataLink, NullIPv6MacOSAF) {
    uint32_t af = 30; // AF_INET6 on macOS
    std::vector<uint8_t> data(4);
    std::memcpy(data.data(), &af, 4);

    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_NULL, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x86DD);
}

TEST(DataLink, NullTruncated) {
    std::vector<uint8_t> data = {0x02, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_NULL, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DataLink, NullUnsupportedAF) {
    uint32_t af = 99; // Unknown AF
    std::vector<uint8_t> data(4);
    std::memcpy(data.data(), &af, 4);

    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_NULL, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::UnsupportedProtocol);
}

// ---- DLT_EN10MB (Ethernet) Tests ----

TEST(DataLink, EthernetIPv4) {
    std::vector<uint8_t> data = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x00                          // EtherType: IPv4
    };
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_EN10MB, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_TRUE(result->hasMacs);
    EXPECT_EQ(result->dstMac.bytes[0], 0xff);
    EXPECT_EQ(result->srcMac.bytes[1], 0x11);
    EXPECT_EQ(offset, 14u);
}

TEST(DataLink, EthernetTruncated) {
    std::vector<uint8_t> data = {0xff, 0xff, 0xff};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_EN10MB, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

// ---- DLT_RAW (Raw IP) Tests ----

TEST(DataLink, RawIPv4) {
    // IPv4 packet starts with version nibble 4
    std::vector<uint8_t> data = {0x45, 0x00, 0x00, 0x28};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_RAW, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_FALSE(result->hasMacs);
    EXPECT_EQ(offset, 0u); // No L2 header consumed
}

TEST(DataLink, RawIPv6) {
    // IPv6 packet starts with version nibble 6
    std::vector<uint8_t> data = {0x60, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_RAW, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x86DD);
    EXPECT_EQ(offset, 0u);
}

TEST(DataLink, RawEmpty) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_RAW, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DataLink, RawUnsupportedVersion) {
    std::vector<uint8_t> data = {0x30}; // Version nibble = 3
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_RAW, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::UnsupportedProtocol);
}

// ---- DLT_PPP Tests ----

TEST(DataLink, PppIPv4WithAddrCtrl) {
    // 0xFF 0x03 (addr/ctrl) + 0x0021 (IPv4)
    std::vector<uint8_t> data = {0xFF, 0x03, 0x00, 0x21};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_PPP, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_FALSE(result->hasMacs);
    EXPECT_EQ(offset, 4u);
}

TEST(DataLink, PppIPv6WithAddrCtrl) {
    std::vector<uint8_t> data = {0xFF, 0x03, 0x00, 0x57};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_PPP, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x86DD);
    EXPECT_EQ(offset, 4u);
}

TEST(DataLink, PppIPv4WithoutAddrCtrl) {
    // No addr/ctrl, 2-byte protocol 0x0021
    std::vector<uint8_t> data = {0x00, 0x21};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_PPP, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_EQ(offset, 2u);
}

TEST(DataLink, PppSingleByteProtocol) {
    // Single-byte protocol: 0x21 (odd low bit, IPv4)
    std::vector<uint8_t> data = {0x21};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_PPP, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_EQ(offset, 1u);
}

TEST(DataLink, PppTruncated) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_PPP, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DataLink, PppAddrCtrlTruncated) {
    // 0xFF 0x03 addr/ctrl but no protocol byte following
    std::vector<uint8_t> data = {0xFF, 0x03};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_PPP, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DataLink, PppUnsupportedProtocol) {
    std::vector<uint8_t> data = {0xFF, 0x03, 0x00, 0x2B}; // Unknown protocol
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_PPP, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::UnsupportedProtocol);
}

// ---- DLT_LINUX_SLL (Linux Cooked v1) Tests ----

TEST(DataLink, LinuxSllIPv4WithMac) {
    // 16-byte SLL header
    // pkt_type=0, ARPHRD=1, addr_len=6, addr=00:11:22:33:44:55+00:00, proto=0x0800
    std::vector<uint8_t> data = {
        0x00, 0x00,                         // packet type (host)
        0x00, 0x01,                         // ARPHRD_ETHER
        0x00, 0x06,                         // address length
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // address (6 bytes used)
        0x00, 0x00,                         // padding
        0x08, 0x00                          // protocol: IPv4
    };
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_LINUX_SLL, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_TRUE(result->hasMacs);
    EXPECT_EQ(result->srcMac.bytes[1], 0x11);
    EXPECT_EQ(offset, 16u);
}

TEST(DataLink, LinuxSllTruncated) {
    std::vector<uint8_t> data(15, 0);
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_LINUX_SLL, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

// ---- DLT_LINUX_SLL2 (Linux Cooked v2) Tests ----

TEST(DataLink, LinuxSll2IPv6WithMac) {
    // 20-byte SLL2 header
    // proto=0x86DD, reserved, ifindex, ARPHRD=1, pkt_type=0, addr_len=6, addr
    std::vector<uint8_t> data = {
        0x86, 0xDD,                         // protocol: IPv6
        0x00, 0x00,                         // reserved
        0x00, 0x00, 0x00, 0x01,             // interface index
        0x00, 0x01,                         // ARPHRD_ETHER
        0x00,                               // packet type
        0x06,                               // address length
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // address (6 bytes)
        0x00, 0x00                          // padding
    };
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_LINUX_SLL2, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x86DD);
    EXPECT_TRUE(result->hasMacs);
    EXPECT_EQ(result->srcMac.bytes[0], 0xAA);
    EXPECT_EQ(result->srcMac.bytes[5], 0xFF);
    EXPECT_EQ(offset, 20u);
}

TEST(DataLink, LinuxSll2Truncated) {
    std::vector<uint8_t> data(19, 0);
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_LINUX_SLL2, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

// ---- DLT_IEEE802_5 (Token Ring) Tests ----

TEST(DataLink, TokenRingValid) {
    // AC(1) + FC(1) + dst(6) + src(6) + LLC/SNAP(8) = 22 bytes
    // No source routing (bit 7 of src[0] clear)
    std::vector<uint8_t> data = {
        0x10,                               // AC
        0x40,                               // FC (LLC frame)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst MAC
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // src MAC (bit 7 clear)
        // LLC/SNAP: DSAP=0xAA, SSAP=0xAA, Ctrl=0x03, OUI=0, EtherType=0x0800
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_5, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_TRUE(result->hasMacs);
    EXPECT_EQ(result->dstMac.bytes[0], 0x01);
    EXPECT_EQ(result->srcMac.bytes[0], 0x0A);
    EXPECT_EQ(offset, 22u);
}

TEST(DataLink, TokenRingWithSourceRouting) {
    // src MAC bit 7 set → source routing present
    // Routing info: length=6 (2-byte routing control + 4 bytes route)
    std::vector<uint8_t> data = {
        0x10,                               // AC
        0x40,                               // FC
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst MAC
        0x8A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // src MAC (bit 7 set)
        // Source routing: 0x06 in bits 0-4 of first byte = length 6
        0x06, 0x30, 0x00, 0x01, 0x00, 0x02, // routing info (6 bytes)
        // LLC/SNAP
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_5, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x86DD);
    EXPECT_TRUE(result->hasMacs);
    // Source routing bit should be cleared in returned MAC
    EXPECT_EQ(result->srcMac.bytes[0], 0x0A);
    EXPECT_EQ(offset, 28u);
}

TEST(DataLink, TokenRingTruncated) {
    std::vector<uint8_t> data(13, 0);
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_5, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

// ---- DLT_FDDI Tests ----

TEST(DataLink, FddiValid) {
    // FC(1) + dst(6) + src(6) + LLC/SNAP(8) = 21 bytes
    std::vector<uint8_t> data = {0x50,                               // FC (LLC frame)
                                 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst MAC
                                 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // src MAC
                                 // LLC/SNAP
                                 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_FDDI, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_TRUE(result->hasMacs);
    EXPECT_EQ(result->dstMac.bytes[0], 0x01);
    EXPECT_EQ(result->srcMac.bytes[0], 0x0A);
    EXPECT_EQ(offset, 21u);
}

TEST(DataLink, FddiTruncated) {
    std::vector<uint8_t> data(12, 0);
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_FDDI, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DataLink, FddiBadLlcSnap) {
    // Valid FDDI header but invalid LLC (not 0xAA/0xAA/0x03)
    std::vector<uint8_t> data = {
        0x50, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00 // Bad LLC
    };
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_FDDI, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::UnsupportedProtocol);
}

// ---- DLT_IEEE802_11 (WiFi) Tests ----

TEST(DataLink, WifiDataFrameIBSS) {
    // Data frame, type=2 subtype=0, ToDS=0 FromDS=0 (IBSS)
    // Frame control: type=2(data) => bits[3:2]=10, subtype=0 => bits[7:4]=0000
    // FC byte 0 = 0b00001000 = 0x08 (Protocol=0, Type=2, Subtype=0)
    // FC byte 1 = 0x00 (no ToDS, no FromDS)
    std::vector<uint8_t> data = {0x08, 0x00, // Frame control (data frame)
                                 0x00, 0x00, // Duration
                                 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, // addr1 (DA)
                                 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, // addr2 (SA)
                                 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, // addr3 (BSSID)
                                 0x00, 0x00,                         // Sequence control
                                 // LLC/SNAP
                                 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_TRUE(result->hasMacs);
    // IBSS: DA=addr1, SA=addr2
    EXPECT_EQ(result->dstMac.bytes[0], 0xA1);
    EXPECT_EQ(result->srcMac.bytes[0], 0xB1);
    EXPECT_EQ(offset, 32u); // 24 header + 8 LLC/SNAP
}

TEST(DataLink, WifiDataFrameFromAP) {
    // FromDS=1, ToDS=0: DA=addr1, SA=addr3
    // FC byte 1 = 0x02 (FromDS set)
    std::vector<uint8_t> data = {0x08, 0x02, // Frame control (data, FromDS)
                                 0x00, 0x00, // Duration
                                 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, // addr1 (DA)
                                 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, // addr2 (BSSID)
                                 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, // addr3 (SA)
                                 0x00, 0x00,                         // Sequence control
                                 // LLC/SNAP
                                 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x86DD);
    EXPECT_EQ(result->dstMac.bytes[0], 0xA1);
    EXPECT_EQ(result->srcMac.bytes[0], 0xC1); // SA from addr3
}

TEST(DataLink, WifiManagementFrame) {
    // Management frame (type=0): should succeed with etherType=0
    // FC byte 0 = 0x00 (type=0 management, subtype=0)
    std::vector<uint8_t> data(32, 0);
    data[0] = 0x00; // Management frame
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0);
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->type, 0); // Management
}

TEST(DataLink, WifiTruncated) {
    std::vector<uint8_t> data(23, 0);
    data[0] = 0x08; // Data frame
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DataLink, WifiQoSDataFrame) {
    // QoS data frame: subtype=8 => bits[7:4]=1000
    // FC byte 0 = 0b10001000 = 0x88 (Type=2, Subtype=8)
    // ToDS=0, FromDS=0 (IBSS)
    // Header = 24 + 2(QoS) = 26 bytes, then LLC/SNAP
    std::vector<uint8_t> data = {0x88, 0x00, // Frame control (QoS data)
                                 0x00, 0x00, // Duration
                                 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, // addr1
                                 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, // addr2
                                 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, // addr3
                                 0x00, 0x00,                         // Sequence control
                                 0x00, 0x00,                         // QoS control
                                 // LLC/SNAP
                                 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_EQ(offset, 34u); // 26 header + 8 LLC/SNAP
}

// ---- DLT_IEEE802_11_RADIOTAP Tests ----

TEST(DataLink, RadiotapDataFrame) {
    // Radiotap header: version=0, pad=0, length=8 (LE), present=0
    // Followed by a standard 802.11 data frame (IBSS) + LLC/SNAP
    std::vector<uint8_t> data = {            // Radiotap header (8 bytes)
                                 0x00,       // version
                                 0x00,       // pad
                                 0x08, 0x00, // length (LE) = 8
                                 0x00, 0x00, 0x00,
                                 0x00,       // present flags
                                             // 802.11 data frame (IBSS, 24 bytes)
                                 0x08, 0x00, // Frame control (data frame)
                                 0x00, 0x00, // Duration
                                 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, // addr1 (DA)
                                 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, // addr2 (SA)
                                 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, // addr3 (BSSID)
                                 0x00, 0x00,                         // Sequence control
                                                                     // LLC/SNAP (8 bytes)
                                 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
    size_t offset = 0;
    auto result =
        fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11_RADIOTAP, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    EXPECT_TRUE(result->hasMacs);
    EXPECT_EQ(result->dstMac.bytes[0], 0xA1);
    EXPECT_EQ(result->srcMac.bytes[0], 0xB1);
    EXPECT_EQ(offset, 40u); // 8 radiotap + 24 wifi + 8 LLC/SNAP
}

TEST(DataLink, RadiotapLargeHeader) {
    // Radiotap with length=16 (some extra fields) followed by 802.11 data frame
    std::vector<uint8_t> data(48, 0);
    data[2] = 0x10; // radiotap length = 16 (LE)
    // 802.11 data frame starts at offset 16
    data[16] = 0x08; // Frame control: data frame
    // addr1 (DA) at offset 20
    for (int i = 0; i < 6; i++)
        data[20 + i] = static_cast<uint8_t>(0xD0 + i);
    // addr2 (SA) at offset 26
    for (int i = 0; i < 6; i++)
        data[26 + i] = static_cast<uint8_t>(0xE0 + i);
    // addr3 (BSSID) at offset 32
    for (int i = 0; i < 6; i++)
        data[32 + i] = static_cast<uint8_t>(0xF0 + i);
    // LLC/SNAP at offset 40
    data[40] = 0xAA;
    data[41] = 0xAA;
    data[42] = 0x03;
    data[46] = 0x86;
    data[47] = 0xDD; // IPv6

    size_t offset = 0;
    auto result =
        fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11_RADIOTAP, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x86DD);
    EXPECT_EQ(offset, 48u); // 16 radiotap + 24 wifi + 8 LLC/SNAP
}

TEST(DataLink, RadiotapTruncatedHeader) {
    // Only 4 bytes — not enough for minimum radiotap (8)
    std::vector<uint8_t> data = {0x00, 0x00, 0x08, 0x00};
    size_t offset = 0;
    auto result =
        fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11_RADIOTAP, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DataLink, RadiotapLengthExceedsData) {
    // Radiotap header says length=100 but we only have 20 bytes
    std::vector<uint8_t> data(20, 0);
    data[2] = 100;
    data[3] = 0; // length = 100
    size_t offset = 0;
    auto result =
        fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11_RADIOTAP, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DataLink, RadiotapManagementFrame) {
    // Radiotap + management frame → success with etherType=0
    std::vector<uint8_t> data(40, 0);
    data[2] = 0x08; // radiotap length = 8
    data[8] = 0x00; // Frame control: management frame (type=0)
    size_t offset = 0;
    auto result =
        fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11_RADIOTAP, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0);
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->type, 0); // Management
}

// ---- toString Tests ----

TEST(DataLink, ToStringKnownTypes) {
    EXPECT_EQ(fdpi::toString(fdpi::DataLinkType::DLT_NULL), "DLT_NULL");
    EXPECT_EQ(fdpi::toString(fdpi::DataLinkType::DLT_EN10MB), "DLT_EN10MB");
    EXPECT_EQ(fdpi::toString(fdpi::DataLinkType::DLT_RAW), "DLT_RAW");
    EXPECT_EQ(fdpi::toString(fdpi::DataLinkType::DLT_LINUX_SLL), "DLT_LINUX_SLL");
    EXPECT_EQ(fdpi::toString(fdpi::DataLinkType::DLT_LINUX_SLL2), "DLT_LINUX_SLL2");
    EXPECT_EQ(fdpi::toString(fdpi::DataLinkType::DLT_IEEE802_11), "DLT_IEEE802_11");
    EXPECT_EQ(fdpi::toString(fdpi::DataLinkType::DLT_IEEE802_11_RADIOTAP),
              "DLT_IEEE802_11_RADIOTAP");
}

// ---- UnsupportedDataLink Error ----

TEST(DataLink, UnsupportedDltValue) {
    std::vector<uint8_t> data(100, 0);
    size_t offset = 0;
    auto result =
        fdpi::resolveDataLink(static_cast<fdpi::DataLinkType>(999), data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::UnsupportedDataLink);
}

// ---- Decoder Integration: DLT_RAW through PacketDecoder ----

TEST(DataLink, DecoderRawIPv4) {
    // Minimal IPv4 header (20 bytes) with proto=253 (experimental, no L4 decode)
    std::vector<uint8_t> data = {
        0x45, 0x00, 0x00, 0x14, // ver=4, IHL=5, TOS=0, len=20
        0x00, 0x01, 0x00, 0x00, // ID=1, flags=0, frag=0
        0x40, 0xFD, 0x00, 0x00, // TTL=64, proto=253(experimental), checksum=0
        0xC0, 0xA8, 0x01, 0x01, // src=192.168.1.1
        0xC0, 0xA8, 0x01, 0x02, // dst=192.168.1.2
    };

    fdpi::PacketDecoderConfig config;
    config.enableProtocolDetection = false;
    fdpi::PacketDecoder decoder(config);

    auto result = decoder.decode(data, {}, fdpi::DataLinkType::DLT_RAW);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->dlt, fdpi::DataLinkType::DLT_RAW);
    EXPECT_FALSE(result->ethernet.has_value()); // No Ethernet for raw IP
    auto* ipv4 = std::get_if<fdpi::IPv4>(&result->layer3);
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(ipv4->srcIp, fdpi::IPv4Address("192.168.1.1"));
    EXPECT_EQ(ipv4->dstIp, fdpi::IPv4Address("192.168.1.2"));
}

TEST(DataLink, DecoderDefaultIsEthernet) {
    // Verify backward compatibility: default DLT is Ethernet
    std::vector<uint8_t> data = {
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff, // dst MAC
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55, // src MAC
        0x08,
        0x06, // EtherType: ARP
        // Minimal ARP
        0x00,
        0x01,
        0x08,
        0x00,
        0x06,
        0x04,
        0x00,
        0x01,
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0xC0,
        0xA8,
        0x01,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xC0,
        0xA8,
        0x01,
        0x02,
    };

    fdpi::PacketDecoderConfig config;
    config.enableProtocolDetection = false;
    fdpi::PacketDecoder decoder(config);

    // Call without DLT parameter — should default to Ethernet
    auto result = decoder.decode(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->dlt, fdpi::DataLinkType::DLT_EN10MB);
    EXPECT_TRUE(result->ethernet.has_value());
}
