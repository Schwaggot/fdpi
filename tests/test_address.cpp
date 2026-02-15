#include <gtest/gtest.h>
#include <fdpi/address.hpp>
#include <stdexcept>

// === IPv4Address ===

TEST(IPv4Address, DefaultConstruction) {
    fdpi::IPv4Address addr;
    EXPECT_EQ(addr.bytes, (std::array<uint8_t, 4>{0, 0, 0, 0}));
}

TEST(IPv4Address, FromUint32) {
    fdpi::IPv4Address addr(0xC0A80101);
    EXPECT_EQ(addr.bytes[0], 192);
    EXPECT_EQ(addr.bytes[1], 168);
    EXPECT_EQ(addr.bytes[2], 1);
    EXPECT_EQ(addr.bytes[3], 1);
}

TEST(IPv4Address, FromUint32Zero) {
    fdpi::IPv4Address addr(0x00000000);
    EXPECT_EQ(addr.bytes, (std::array<uint8_t, 4>{0, 0, 0, 0}));
}

TEST(IPv4Address, FromUint32Max) {
    fdpi::IPv4Address addr(0xFFFFFFFF);
    EXPECT_EQ(addr.bytes, (std::array<uint8_t, 4>{255, 255, 255, 255}));
}

TEST(IPv4Address, FromString) {
    fdpi::IPv4Address addr("192.168.1.1");
    EXPECT_EQ(addr, fdpi::IPv4Address(0xC0A80101));
}

TEST(IPv4Address, FromStringZero) {
    fdpi::IPv4Address addr("0.0.0.0");
    EXPECT_EQ(addr, fdpi::IPv4Address(0x00000000));
}

TEST(IPv4Address, FromStringMax) {
    fdpi::IPv4Address addr("255.255.255.255");
    EXPECT_EQ(addr, fdpi::IPv4Address(0xFFFFFFFF));
}

TEST(IPv4Address, FromStringLoopback) {
    fdpi::IPv4Address addr("127.0.0.1");
    EXPECT_EQ(addr.bytes[0], 127);
    EXPECT_EQ(addr.bytes[1], 0);
    EXPECT_EQ(addr.bytes[2], 0);
    EXPECT_EQ(addr.bytes[3], 1);
}

TEST(IPv4Address, FromStringTenNet) {
    fdpi::IPv4Address addr("10.0.0.1");
    EXPECT_EQ(addr, fdpi::IPv4Address(0x0A000001));
}

TEST(IPv4Address, FromStringInvalidTooFewOctets) {
    EXPECT_THROW(fdpi::IPv4Address("10.0.1"), std::invalid_argument);
}

TEST(IPv4Address, FromStringInvalidTooManyOctets) {
    EXPECT_THROW(fdpi::IPv4Address("10.0.0.1.2"), std::invalid_argument);
}

TEST(IPv4Address, FromStringInvalidOctetRange) {
    EXPECT_THROW(fdpi::IPv4Address("256.0.0.1"), std::invalid_argument);
}

TEST(IPv4Address, FromStringInvalidEmpty) {
    EXPECT_THROW(fdpi::IPv4Address(""), std::invalid_argument);
}

TEST(IPv4Address, FromStringInvalidGarbage) {
    EXPECT_THROW(fdpi::IPv4Address("abc.def.ghi.jkl"), std::invalid_argument);
}

TEST(IPv4Address, ToUint32) {
    EXPECT_EQ(fdpi::IPv4Address(0xC0A80101).toUint32(), 0xC0A80101u);
    EXPECT_EQ(fdpi::IPv4Address(0x00000000).toUint32(), 0u);
    EXPECT_EQ(fdpi::IPv4Address(0xFFFFFFFF).toUint32(), 0xFFFFFFFFu);
}

TEST(IPv4Address, Uint32RoundTrip) {
    for (uint32_t val : {0u, 1u, 0x7F000001u, 0xC0A80101u, 0xFFFFFFFFu}) {
        EXPECT_EQ(fdpi::IPv4Address(val).toUint32(), val);
    }
}

TEST(IPv4Address, StringToUint32) {
    EXPECT_EQ(fdpi::IPv4Address("192.168.1.1").toUint32(), 0xC0A80101u);
    EXPECT_EQ(fdpi::IPv4Address("10.0.0.1").toUint32(), 0x0A000001u);
    EXPECT_EQ(fdpi::IPv4Address("0.0.0.0").toUint32(), 0u);
}

TEST(IPv4Address, StringAndUint32Agree) {
    EXPECT_EQ(fdpi::IPv4Address("10.0.0.1"), fdpi::IPv4Address(0x0A000001));
    EXPECT_EQ(fdpi::IPv4Address("192.168.0.1"), fdpi::IPv4Address(0xC0A80001));
    EXPECT_EQ(fdpi::IPv4Address("172.16.0.1"), fdpi::IPv4Address(0xAC100001));
}

// === IPv6Address ===

TEST(IPv6Address, DefaultConstruction) {
    fdpi::IPv6Address addr;
    std::array<uint8_t, 16> zero{};
    EXPECT_EQ(addr.bytes, zero);
}

TEST(IPv6Address, FromHiLo) {
    fdpi::IPv6Address addr(0x0000000000000000, 0x0000000000000001);
    // ::1
    std::array<uint8_t, 16> expected{};
    expected[15] = 1;
    EXPECT_EQ(addr.bytes, expected);
}

TEST(IPv6Address, FromHiLoFull) {
    fdpi::IPv6Address addr(0x2001'0DB8'0000'0000, 0x0000'0000'0000'0001);
    EXPECT_EQ(addr.bytes[0], 0x20);
    EXPECT_EQ(addr.bytes[1], 0x01);
    EXPECT_EQ(addr.bytes[2], 0x0D);
    EXPECT_EQ(addr.bytes[3], 0xB8);
    EXPECT_EQ(addr.bytes[15], 0x01);
}

TEST(IPv6Address, FromStringLoopback) {
    fdpi::IPv6Address addr("::1");
    fdpi::IPv6Address expected(0, 1);
    EXPECT_EQ(addr, expected);
}

TEST(IPv6Address, FromStringAllZeros) {
    fdpi::IPv6Address addr("::");
    fdpi::IPv6Address expected(0, 0);
    EXPECT_EQ(addr, expected);
}

TEST(IPv6Address, FromStringFull) {
    fdpi::IPv6Address addr("2001:0db8:0000:0000:0000:0000:0000:0001");
    fdpi::IPv6Address expected(0x2001'0DB8'0000'0000, 0x0000'0000'0000'0001);
    EXPECT_EQ(addr, expected);
}

TEST(IPv6Address, FromStringAbbreviated) {
    fdpi::IPv6Address addr("2001:db8::1");
    fdpi::IPv6Address expected(0x2001'0DB8'0000'0000, 0x0000'0000'0000'0001);
    EXPECT_EQ(addr, expected);
}

TEST(IPv6Address, FromStringLinkLocal) {
    fdpi::IPv6Address addr("fe80::1");
    EXPECT_EQ(addr.bytes[0], 0xFE);
    EXPECT_EQ(addr.bytes[1], 0x80);
    EXPECT_EQ(addr.bytes[15], 0x01);
    // Middle bytes should be zero
    for (int i = 2; i < 15; ++i) {
        EXPECT_EQ(addr.bytes[i], 0) << "byte " << i;
    }
}

TEST(IPv6Address, FromStringDoubleColonMiddle) {
    fdpi::IPv6Address addr("2001:db8::ff00:42:8329");
    EXPECT_EQ(addr.bytes[0], 0x20);
    EXPECT_EQ(addr.bytes[1], 0x01);
    EXPECT_EQ(addr.bytes[2], 0x0D);
    EXPECT_EQ(addr.bytes[3], 0xB8);
    EXPECT_EQ(addr.bytes[10], 0xFF);
    EXPECT_EQ(addr.bytes[11], 0x00);
    EXPECT_EQ(addr.bytes[12], 0x00);
    EXPECT_EQ(addr.bytes[13], 0x42);
    EXPECT_EQ(addr.bytes[14], 0x83);
    EXPECT_EQ(addr.bytes[15], 0x29);
}

TEST(IPv6Address, FromStringNoAbbreviation) {
    fdpi::IPv6Address addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    for (auto b : addr.bytes) {
        EXPECT_EQ(b, 0xFF);
    }
}

TEST(IPv6Address, FromStringInvalidTooManyGroups) {
    EXPECT_THROW(fdpi::IPv6Address("1:2:3:4:5:6:7:8:9"), std::invalid_argument);
}

TEST(IPv6Address, FromStringInvalidTooFewGroups) {
    EXPECT_THROW(fdpi::IPv6Address("1:2:3"), std::invalid_argument);
}

TEST(IPv6Address, FromStringInvalidBadHex) {
    EXPECT_THROW(fdpi::IPv6Address("gggg::1"), std::invalid_argument);
}

TEST(IPv6Address, HiGetter) {
    fdpi::IPv6Address addr(0x2001'0DB8'0000'0000, 0x0000'0000'0000'0001);
    EXPECT_EQ(addr.hi(), 0x2001'0DB8'0000'0000u);
}

TEST(IPv6Address, LoGetter) {
    fdpi::IPv6Address addr(0x2001'0DB8'0000'0000, 0x0000'0000'0000'0001);
    EXPECT_EQ(addr.lo(), 0x0000'0000'0000'0001u);
}

TEST(IPv6Address, HiLoRoundTrip) {
    uint64_t h = 0xFEDCBA9876543210;
    uint64_t l = 0x0123456789ABCDEF;
    fdpi::IPv6Address addr(h, l);
    EXPECT_EQ(addr.hi(), h);
    EXPECT_EQ(addr.lo(), l);
}

TEST(IPv6Address, HiLoFromString) {
    fdpi::IPv6Address addr("2001:db8::1");
    EXPECT_EQ(addr.hi(), 0x2001'0DB8'0000'0000u);
    EXPECT_EQ(addr.lo(), 0x0000'0000'0000'0001u);
}

TEST(IPv6Address, HiLoZero) {
    fdpi::IPv6Address addr("::");
    EXPECT_EQ(addr.hi(), 0u);
    EXPECT_EQ(addr.lo(), 0u);
}

TEST(IPv6Address, HiLoAndStringAgree) {
    EXPECT_EQ(fdpi::IPv6Address("::1"), fdpi::IPv6Address(0, 1));
    EXPECT_EQ(fdpi::IPv6Address("::"), fdpi::IPv6Address(0, 0));
    EXPECT_EQ(fdpi::IPv6Address("::ffff"), fdpi::IPv6Address(0, 0xFFFF));
}

// === MacAddress ===

TEST(MacAddress, DefaultConstruction) {
    fdpi::MacAddress addr;
    EXPECT_EQ(addr.bytes, (std::array<uint8_t, 6>{0, 0, 0, 0, 0, 0}));
}

TEST(MacAddress, FromStringColon) {
    fdpi::MacAddress addr("00:11:22:33:44:55");
    EXPECT_EQ(addr.bytes[0], 0x00);
    EXPECT_EQ(addr.bytes[1], 0x11);
    EXPECT_EQ(addr.bytes[2], 0x22);
    EXPECT_EQ(addr.bytes[3], 0x33);
    EXPECT_EQ(addr.bytes[4], 0x44);
    EXPECT_EQ(addr.bytes[5], 0x55);
}

TEST(MacAddress, FromStringDash) {
    fdpi::MacAddress addr("AA-BB-CC-DD-EE-FF");
    EXPECT_EQ(addr.bytes[0], 0xAA);
    EXPECT_EQ(addr.bytes[1], 0xBB);
    EXPECT_EQ(addr.bytes[2], 0xCC);
    EXPECT_EQ(addr.bytes[3], 0xDD);
    EXPECT_EQ(addr.bytes[4], 0xEE);
    EXPECT_EQ(addr.bytes[5], 0xFF);
}

TEST(MacAddress, FromStringBroadcast) {
    fdpi::MacAddress addr("FF:FF:FF:FF:FF:FF");
    for (auto b : addr.bytes) {
        EXPECT_EQ(b, 0xFF);
    }
}

TEST(MacAddress, FromStringLowercase) {
    fdpi::MacAddress addr("aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(addr.bytes[0], 0xAA);
    EXPECT_EQ(addr.bytes[5], 0xFF);
}

TEST(MacAddress, FromStringInvalidTooShort) {
    EXPECT_THROW(fdpi::MacAddress("00:11:22"), std::invalid_argument);
}

TEST(MacAddress, FromStringInvalidBadSeparator) {
    EXPECT_THROW(fdpi::MacAddress("00.11.22.33.44.55"), std::invalid_argument);
}

TEST(MacAddress, FromStringInvalidEmpty) {
    EXPECT_THROW(fdpi::MacAddress(""), std::invalid_argument);
}

TEST(MacAddress, FromStringInvalidBadHex) {
    EXPECT_THROW(fdpi::MacAddress("GG:HH:II:JJ:KK:LL"), std::invalid_argument);
}

TEST(MacAddress, ColonAndDashAgree) {
    fdpi::MacAddress colon("AA:BB:CC:DD:EE:FF");
    fdpi::MacAddress dash("AA-BB-CC-DD-EE-FF");
    EXPECT_EQ(colon, dash);
}

// === toString ===

TEST(IPv4Address, ToString) {
    EXPECT_EQ(fdpi::IPv4Address(0xC0A80101).toString(), "192.168.1.1");
    EXPECT_EQ(fdpi::IPv4Address(0x0A000001).toString(), "10.0.0.1");
    EXPECT_EQ(fdpi::IPv4Address(0x7F000001).toString(), "127.0.0.1");
    EXPECT_EQ(fdpi::IPv4Address(0xFFFFFFFF).toString(), "255.255.255.255");
    EXPECT_EQ(fdpi::IPv4Address(0x00000000).toString(), "0.0.0.0");
}

TEST(IPv4Address, ToStringFromString) {
    EXPECT_EQ(fdpi::IPv4Address("10.0.0.1").toString(), "10.0.0.1");
    EXPECT_EQ(fdpi::IPv4Address("192.168.0.1").toString(), "192.168.0.1");
}

TEST(IPv6Address, ToStringLoopback) {
    EXPECT_EQ(fdpi::IPv6Address("::1").toString(), "::1");
}

TEST(IPv6Address, ToStringAllZeros) {
    EXPECT_EQ(fdpi::IPv6Address("::").toString(), "::");
}

TEST(IPv6Address, ToStringFull) {
    fdpi::IPv6Address addr("2001:db8::1");
    EXPECT_EQ(addr.toString(), "2001:db8::1");
}

TEST(IPv6Address, ToStringNoCompression) {
    fdpi::IPv6Address addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    EXPECT_EQ(addr.toString(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

TEST(IPv6Address, ToStringLinkLocal) {
    EXPECT_EQ(fdpi::IPv6Address("fe80::1").toString(), "fe80::1");
}

TEST(MacAddress, ToString) {
    EXPECT_EQ(fdpi::MacAddress("00:11:22:33:44:55").toString(), "00:11:22:33:44:55");
    EXPECT_EQ(fdpi::MacAddress("AA-BB-CC-DD-EE-FF").toString(), "aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(fdpi::MacAddress("FF:FF:FF:FF:FF:FF").toString(), "ff:ff:ff:ff:ff:ff");
}
