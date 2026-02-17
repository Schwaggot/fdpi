#include <gtest/gtest.h>

#include <fdpi/decoder.hpp>

#include <chrono>
#include <cstdint>
#include <vector>

namespace {

// Minimal struct: only required fields
struct MinimalSource {
    const uint8_t* data;
    std::size_t captureLength;
};

// Full struct: all optional fields
struct FullSource {
    const uint8_t* data;
    std::size_t captureLength;
    uint64_t timestampSeconds;
    uint64_t timestampMicroseconds;
    uint16_t dataLinkType;
};

// Struct with only seconds (no microseconds)
struct SecondsOnlySource {
    const uint8_t* data;
    std::size_t captureLength;
    uint64_t timestampSeconds;
};

// Not a PacketSource: missing captureLength
struct BadSource {
    const uint8_t* data;
};

// Not a PacketSource: data is wrong type
struct WrongTypeSource {
    int data;
    std::size_t captureLength;
};

// Build a minimal valid Ethernet + IPv4 + TCP packet
std::vector<uint8_t> buildMinimalPacket() {
    return {
        // Ethernet header (14 bytes)
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF, // dst
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55, // src
        0x08,
        0x00, // EtherType: IPv4

        // IPv4 header (20 bytes)
        0x45,
        0x00,
        0x00,
        0x28, // version/IHL, DSCP, total length (40)
        0x00,
        0x01,
        0x00,
        0x00, // identification, flags, fragment offset
        0x40,
        0x06,
        0x00,
        0x00, // TTL, protocol (TCP), checksum
        0xC0,
        0xA8,
        0x01,
        0x01, // src IP: 192.168.1.1
        0x0A,
        0x00,
        0x00,
        0x01, // dst IP: 10.0.0.1

        // TCP header (20 bytes)
        0x30,
        0x39,
        0x00,
        0x50, // src port: 12345, dst port: 80
        0x00,
        0x00,
        0x00,
        0x01, // seq num
        0x00,
        0x00,
        0x00,
        0x00, // ack num
        0x50,
        0x02,
        0x20,
        0x00, // data offset, SYN flag, window
        0x00,
        0x00,
        0x00,
        0x00, // checksum, urgent pointer
    };
}

} // anonymous namespace

// Static assertions for concept satisfaction
static_assert(fdpi::PacketSource<MinimalSource>);
static_assert(fdpi::PacketSource<FullSource>);
static_assert(fdpi::PacketSource<SecondsOnlySource>);
static_assert(!fdpi::PacketSource<BadSource>);
static_assert(!fdpi::PacketSource<WrongTypeSource>);
static_assert(!fdpi::PacketSource<int>);

TEST(PacketSource, DecodeWithMinimalSource) {
    fdpi::PacketDecoder decoder;
    auto pktData = buildMinimalPacket();

    MinimalSource src{pktData.data(), pktData.size()};
    auto result = decoder.decode(src);
    ASSERT_TRUE(result.has_value());

    // Default timestamp when none provided
    EXPECT_EQ(result->timestamp, fdpi::Timestamp{});
}

TEST(PacketSource, DecodeWithFullSource) {
    fdpi::PacketDecoder decoder;
    auto pktData = buildMinimalPacket();

    FullSource src{
        pktData.data(),
        pktData.size(),
        1700000000, // seconds
        500000,     // microseconds
        1,          // DLT_EN10MB
    };

    auto result = decoder.decode(src);
    ASSERT_TRUE(result.has_value());

    // Verify timestamp combines seconds + microseconds
    auto expectedTs = fdpi::Timestamp{std::chrono::seconds{1700000000}} +
                      std::chrono::microseconds{500000};
    EXPECT_EQ(result->timestamp, expectedTs);
}

TEST(PacketSource, TimestampCombinesSecondsAndMicroseconds) {
    fdpi::PacketDecoder decoder;
    auto pktData = buildMinimalPacket();

    FullSource src{pktData.data(), pktData.size(), 100, 250000, 1};
    auto result = decoder.decode(src);
    ASSERT_TRUE(result.has_value());

    auto expected =
        fdpi::Timestamp{std::chrono::seconds{100}} + std::chrono::microseconds{250000};
    EXPECT_EQ(result->timestamp, expected);
}

TEST(PacketSource, SecondsOnlyTimestamp) {
    fdpi::PacketDecoder decoder;
    auto pktData = buildMinimalPacket();

    SecondsOnlySource src{pktData.data(), pktData.size(), 1700000000};
    auto result = decoder.decode(src);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->timestamp, fdpi::Timestamp{std::chrono::seconds{1700000000}});
}

TEST(PacketSource, EquivalenceWithManualDecode) {
    fdpi::PacketDecoder decoder1;
    fdpi::PacketDecoder decoder2;
    auto pktData = buildMinimalPacket();

    auto ts = fdpi::Timestamp{std::chrono::seconds{42}};

    // Manual decode
    auto manual = decoder1.decode(std::span<const uint8_t>{pktData}, ts,
                                  fdpi::DataLinkType::DLT_EN10MB);

    // Template decode
    FullSource src{pktData.data(), pktData.size(), 42, 0, 1};
    auto templated = decoder2.decode(src);

    ASSERT_TRUE(manual.has_value());
    ASSERT_TRUE(templated.has_value());

    EXPECT_EQ(manual->timestamp, templated->timestamp);
    EXPECT_EQ(manual->dlt, templated->dlt);
}
