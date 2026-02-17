#include <gtest/gtest.h>

#include <fdpi/datalink.hpp>

#include <vector>

// --- Management Frames ---

TEST(WifiDecoder, BeaconFrame) {
    // Management frame type=0, subtype=8 (Beacon)
    // FC byte 0 = 0b10000000 = 0x80 (Type=0, Subtype=8)
    // FC byte 1 = 0x00
    // 24-byte header: FC(2) + Dur(2) + addr1(6) + addr2(6) + addr3(6) + seq(2)
    std::vector<uint8_t> data = {0x80, 0x00, // Frame control (beacon)
                                 0x00, 0x00, // Duration
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, // addr1 (DA = broadcast)
                                 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, // addr2 (SA)
                                 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, // addr3 (BSSID)
                                 0x10, 0x00,                         // Sequence control
                                 // Beacon body (payload)
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0);
    EXPECT_TRUE(result->hasMacs);
    EXPECT_EQ(result->dstMac.bytes[0], 0xFF); // broadcast
    EXPECT_EQ(result->srcMac.bytes[5], 0x01);
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->type, 0);    // Management
    EXPECT_EQ(result->wifi->subtype, 8); // Beacon
    EXPECT_TRUE(result->wifi->addr2.has_value());
    EXPECT_TRUE(result->wifi->addr3.has_value());
    EXPECT_EQ(offset, 24u);
}

TEST(WifiDecoder, AuthenticationFrame) {
    // Management frame type=0, subtype=11 (Authentication)
    // FC byte 0 = 0b10110000 = 0xB0
    std::vector<uint8_t> data = {0xB0, 0x00, // Frame control (auth)
                                 0x3A, 0x01, // Duration
                                 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // addr1
                                 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // addr2
                                 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // addr3
                                 0x20, 0x00,                         // Sequence control
                                 // Auth body
                                 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->type, 0);     // Management
    EXPECT_EQ(result->wifi->subtype, 11); // Authentication
    EXPECT_EQ(offset, 24u);
}

// --- Data Frames ---

TEST(WifiDecoder, DataFrameWithLlcSnap) {
    // Data frame IBSS: type=2, subtype=0
    // FC byte 0 = 0x08 (type=2, subtype=0)
    std::vector<uint8_t> data = {0x08, 0x00, // Frame control (data)
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
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->type, 2);
    EXPECT_EQ(result->wifi->subtype, 0);
    EXPECT_EQ(offset, 32u); // 24 header + 8 LLC/SNAP
}

TEST(WifiDecoder, QoSDataFrame) {
    // QoS data frame: subtype=8 => FC byte 0 = 0x88
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
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->subtype, 8);
    EXPECT_EQ(offset, 34u); // 26 header + 8 LLC/SNAP
}

// --- Radiotap + Beacon ---

TEST(WifiDecoder, RadiotapBeacon) {
    // Radiotap header (8 bytes) + Beacon management frame (24 bytes)
    std::vector<uint8_t> data = {
        // Radiotap header
        0x00, // version
        0x00, // pad
        0x08,
        0x00, // length (LE) = 8
        0x00,
        0x00,
        0x00,
        0x00, // present flags
        // 802.11 Beacon
        0x80,
        0x00, // Frame control (beacon)
        0x00,
        0x00, // Duration
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF, // addr1
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0x01, // addr2
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0x01, // addr3
        0x30,
        0x00, // Sequence control
    };
    size_t offset = 0;
    auto result =
        fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11_RADIOTAP, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0);
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->type, 0);
    EXPECT_EQ(result->wifi->subtype, 8);
    EXPECT_EQ(offset, 32u); // 8 radiotap + 24 management
}

// --- Control Frames ---

TEST(WifiDecoder, AckFrame) {
    // Control frame type=1, subtype=13 (ACK)
    // FC byte 0: type=1 (bits 3:2 = 01), subtype=13 (bits 7:4 = 1101)
    // FC byte 0 = 0b11010100 = 0xD4
    // ACK: only addr1 (10 bytes min)
    std::vector<uint8_t> data = {
        0xD4, 0x00,                         // Frame control (ACK)
        0x00, 0x00,                         // Duration
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // addr1 (RA)
    };
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0);
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->type, 1);     // Control
    EXPECT_EQ(result->wifi->subtype, 13); // ACK
    EXPECT_FALSE(result->wifi->addr2.has_value());
    EXPECT_EQ(offset, 10u);
}

TEST(WifiDecoder, RtsFrame) {
    // Control frame type=1, subtype=11 (RTS)
    // FC byte 0 = 0b10110100 = 0xB4
    // RTS: addr1 + addr2 (16 bytes min)
    std::vector<uint8_t> data = {
        0xB4, 0x00,                         // Frame control (RTS)
        0x00, 0x00,                         // Duration
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // addr1 (RA)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // addr2 (TA)
    };
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0);
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->type, 1);     // Control
    EXPECT_EQ(result->wifi->subtype, 11); // RTS
    ASSERT_TRUE(result->wifi->addr2.has_value());
    EXPECT_EQ(result->wifi->addr2->bytes[0], 0xAA);
    EXPECT_EQ(offset, 16u);
}

// --- WDS (4-address) ---

TEST(WifiDecoder, WdsFrame) {
    // Data frame with ToDS=1 FromDS=1 (WDS, 4 addresses)
    // FC byte 0 = 0x08 (data, subtype=0)
    // FC byte 1 = 0x03 (ToDS=1, FromDS=1)
    // Header: FC(2) + Dur(2) + addr1(6) + addr2(6) + addr3(6) + seq(2) + addr4(6) = 30
    std::vector<uint8_t> data = {0x08, 0x03, // Frame control (data, WDS)
                                 0x00, 0x00, // Duration
                                 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, // addr1 (RA)
                                 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, // addr2 (TA)
                                 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, // addr3 (DA)
                                 0x00, 0x00,                         // Sequence control
                                 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, // addr4 (SA)
                                 // LLC/SNAP
                                 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0x0800);
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_TRUE(result->wifi->toDS);
    EXPECT_TRUE(result->wifi->fromDS);
    ASSERT_TRUE(result->wifi->addr4.has_value());
    EXPECT_EQ(result->wifi->addr4->bytes[0], 0xD1);
    // WDS: DA=addr3, SA=addr4
    EXPECT_EQ(result->dstMac.bytes[0], 0xC1);
    EXPECT_EQ(result->srcMac.bytes[0], 0xD1);
    EXPECT_EQ(offset, 38u); // 30 header + 8 LLC/SNAP
}

// --- Error cases ---

TEST(WifiDecoder, TruncatedFrame) {
    // Only 9 bytes — not enough for minimum 10-byte control frame
    std::vector<uint8_t> data = {0xD4, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44};
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(WifiDecoder, TruncatedManagementFrame) {
    // Management frame but only 23 bytes (need 24)
    std::vector<uint8_t> data(23, 0);
    data[0] = 0x80; // Beacon
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

// --- Flags ---

TEST(WifiDecoder, ProtectedAndRetryFlags) {
    // Beacon with Protected Frame and Retry flags set
    // FC byte 1: Protected=bit 6 (0x40), Retry=bit 3 (0x08) => 0x48
    std::vector<uint8_t> data = {
        0x80, 0x48,                         // Frame control
        0x00, 0x00,                         // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // addr1
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, // addr2
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, // addr3
        0x00, 0x00,                         // Sequence control
    };
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_TRUE(result->wifi->protectedFrame);
    EXPECT_TRUE(result->wifi->retry);
}

// --- Null Data Frame ---

TEST(WifiDecoder, NullDataFrame) {
    // Data frame subtype=4 (Null): no payload, no LLC/SNAP
    // FC byte 0 = 0b01001000 = 0x48 (type=2, subtype=4)
    std::vector<uint8_t> data = {
        0x48, 0x00,                         // Frame control (null data)
        0x00, 0x00,                         // Duration
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, // addr1
        0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, // addr2
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, // addr3
        0x00, 0x00,                         // Sequence control
    };
    size_t offset = 0;
    auto result = fdpi::resolveDataLink(fdpi::DataLinkType::DLT_IEEE802_11, data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->etherType, 0);
    ASSERT_TRUE(result->wifi.has_value());
    EXPECT_EQ(result->wifi->type, 2);
    EXPECT_EQ(result->wifi->subtype, 4);
    EXPECT_EQ(offset, 24u);
}
