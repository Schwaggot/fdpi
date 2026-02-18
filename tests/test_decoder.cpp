#include <gtest/gtest.h>

#include <fdpi/decoder.hpp>
#include <fdpi/protocol/pop3.hpp>

#include <chrono>
#include <string>
#include <vector>

// Build a complete Ethernet + IPv4 + TCP packet
static std::vector<uint8_t> buildTcpPacket(uint32_t srcIp,
                                           uint32_t dstIp,
                                           uint16_t srcPort,
                                           uint16_t dstPort,
                                           uint8_t tcpFlags = 0x02 // SYN
) {
    std::vector<uint8_t> packet;

    // Ethernet header (14 bytes)
    // dst MAC
    packet.insert(packet.end(), {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    // src MAC
    packet.insert(packet.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    // EtherType: IPv4
    packet.push_back(0x08);
    packet.push_back(0x00);

    // IPv4 header (20 bytes)
    packet.push_back(0x45);      // version=4, IHL=5
    packet.push_back(0x00);      // TOS
    uint16_t totalLen = 20 + 20; // IP header + TCP header
    packet.push_back(static_cast<uint8_t>(totalLen >> 8));
    packet.push_back(static_cast<uint8_t>(totalLen & 0xFF));
    packet.push_back(0x00);
    packet.push_back(0x01); // identification
    packet.push_back(0x40);
    packet.push_back(0x00); // flags=DF, frag=0
    packet.push_back(0x40); // TTL=64
    packet.push_back(0x06); // protocol=TCP
    packet.push_back(0x00);
    packet.push_back(0x00); // checksum
    packet.push_back(static_cast<uint8_t>((srcIp >> 24) & 0xFF));
    packet.push_back(static_cast<uint8_t>((srcIp >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((srcIp >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(srcIp & 0xFF));
    packet.push_back(static_cast<uint8_t>((dstIp >> 24) & 0xFF));
    packet.push_back(static_cast<uint8_t>((dstIp >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((dstIp >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(dstIp & 0xFF));

    // TCP header (20 bytes)
    packet.push_back(static_cast<uint8_t>(srcPort >> 8));
    packet.push_back(static_cast<uint8_t>(srcPort & 0xFF));
    packet.push_back(static_cast<uint8_t>(dstPort >> 8));
    packet.push_back(static_cast<uint8_t>(dstPort & 0xFF));
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x03);
    packet.push_back(0xE8); // seq=1000
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00); // ack=0
    packet.push_back(0x50); // dataOffset=5
    packet.push_back(tcpFlags);
    packet.push_back(0xFF);
    packet.push_back(0xFF); // window
    packet.push_back(0x00);
    packet.push_back(0x00); // checksum
    packet.push_back(0x00);
    packet.push_back(0x00); // urgent

    return packet;
}

// Build Ethernet + IPv4 + UDP + DNS query packet
static std::vector<uint8_t> buildDnsQueryPacket(const std::string& domain) {
    std::vector<uint8_t> packet;

    // Ethernet header
    packet.insert(packet.end(), {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    packet.insert(packet.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    packet.push_back(0x08);
    packet.push_back(0x00);

    // Build DNS payload first so we know sizes
    std::vector<uint8_t> dns;
    dns.push_back(0x12);
    dns.push_back(0x34); // ID
    dns.push_back(0x01);
    dns.push_back(0x00); // standard query, RD=1
    dns.push_back(0x00);
    dns.push_back(0x01); // QDCOUNT=1
    dns.push_back(0x00);
    dns.push_back(0x00); // ANCOUNT=0
    dns.push_back(0x00);
    dns.push_back(0x00); // NSCOUNT=0
    dns.push_back(0x00);
    dns.push_back(0x00); // ARCOUNT=0

    // Domain name in wire format
    size_t pos = 0;
    while (pos < domain.size()) {
        auto dot = domain.find('.', pos);
        if (dot == std::string::npos)
            dot = domain.size();
        dns.push_back(static_cast<uint8_t>(dot - pos));
        for (size_t i = pos; i < dot; ++i)
            dns.push_back(static_cast<uint8_t>(domain[i]));
        pos = dot + 1;
    }
    dns.push_back(0x00); // root
    dns.push_back(0x00);
    dns.push_back(0x01); // type A
    dns.push_back(0x00);
    dns.push_back(0x01); // class IN

    uint16_t udpLen = static_cast<uint16_t>(8 + dns.size());
    uint16_t ipTotalLen = static_cast<uint16_t>(20 + udpLen);

    // IPv4 header
    packet.push_back(0x45);
    packet.push_back(0x00);
    packet.push_back(static_cast<uint8_t>(ipTotalLen >> 8));
    packet.push_back(static_cast<uint8_t>(ipTotalLen & 0xFF));
    packet.push_back(0x00);
    packet.push_back(0x02); // id
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x40);
    packet.push_back(0x11); // TTL=64, proto=UDP
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.insert(packet.end(), {0x0A, 0x00, 0x00, 0x01}); // src
    packet.insert(packet.end(), {0x08, 0x08, 0x08, 0x08}); // dst: 8.8.8.8

    // UDP header
    packet.push_back(0xC0);
    packet.push_back(0x00); // srcPort=49152
    packet.push_back(0x00);
    packet.push_back(0x35); // dstPort=53
    packet.push_back(static_cast<uint8_t>(udpLen >> 8));
    packet.push_back(static_cast<uint8_t>(udpLen & 0xFF));
    packet.push_back(0x00);
    packet.push_back(0x00); // checksum

    // DNS payload
    packet.insert(packet.end(), dns.begin(), dns.end());

    return packet;
}

// ---- PacketDecoder Tests ----

TEST(PacketDecoder, DefaultConstruction) {
    fdpi::PacketDecoder decoder;
    EXPECT_EQ(decoder.flows().size(), 0u);
}

TEST(PacketDecoder, ConfiguredConstruction) {
    fdpi::PacketDecoder::Config config;
    config.enableDefragmentation = false;
    config.enableTcpReassembly = false;
    config.enableProtocolDetection = false;
    fdpi::PacketDecoder decoder(config);
    EXPECT_EQ(decoder.flows().size(), 0u);
}

TEST(PacketDecoder, DecodesEthernetIPv4TcpPacket) {
    fdpi::PacketDecoder decoder;
    auto pktData = buildTcpPacket(0xC0A80101, 0x0A000001, 12345, 80, 0x02);

    auto result = decoder.decode(pktData);
    ASSERT_TRUE(result.has_value());

    const auto& pkt = result.value();

    // Ethernet
    ASSERT_TRUE(pkt.ethernet.has_value());
    EXPECT_EQ(pkt.ethernet->etherType, 0x0800);

    // IPv4
    auto* ipv4 = std::get_if<fdpi::IPv4>(&pkt.layer3);
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(ipv4->version, 4);
    EXPECT_EQ(ipv4->srcIp, fdpi::IPv4Address(0xC0A80101));
    EXPECT_EQ(ipv4->dstIp, fdpi::IPv4Address(0x0A000001));
    EXPECT_EQ(ipv4->protocol, 6);

    // TCP
    auto* tcp = std::get_if<fdpi::TCP>(&pkt.layer4);
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(tcp->srcPort, 12345);
    EXPECT_EQ(tcp->dstPort, 80);
    EXPECT_TRUE(tcp->syn());
}

TEST(PacketDecoder, DecodesUdpDnsPacket) {
    fdpi::PacketDecoder decoder;
    auto pktData = buildDnsQueryPacket("example.com");

    auto result = decoder.decode(pktData);
    ASSERT_TRUE(result.has_value());

    const auto& pkt = result.value();

    // Ethernet
    ASSERT_TRUE(pkt.ethernet.has_value());
    EXPECT_EQ(pkt.ethernet->etherType, 0x0800);

    // IPv4
    auto* ipv4 = std::get_if<fdpi::IPv4>(&pkt.layer3);
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(ipv4->protocol, 17); // UDP

    // UDP
    auto* udp = std::get_if<fdpi::UDP>(&pkt.layer4);
    ASSERT_NE(udp, nullptr);
    EXPECT_EQ(udp->dstPort, 53);
}

TEST(PacketDecoder, RejectsEmptyPacket) {
    fdpi::PacketDecoder decoder;
    std::vector<uint8_t> empty;

    auto result = decoder.decode(empty);
    ASSERT_FALSE(result.has_value());
}

TEST(PacketDecoder, RejectsTruncatedPacket) {
    fdpi::PacketDecoder decoder;
    // Only 10 bytes - not enough for Ethernet header
    std::vector<uint8_t> data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0x00, 0x11, 0x22, 0x33};

    auto result = decoder.decode(data);
    ASSERT_FALSE(result.has_value());
}

TEST(PacketDecoder, UpdatesFlowTable) {
    fdpi::PacketDecoder decoder;
    auto pktData = buildTcpPacket(0xC0A80101, 0x0A000001, 12345, 80);

    decoder.decode(pktData);
    EXPECT_EQ(decoder.flows().size(), 1u);

    // Second packet to same flow
    decoder.decode(pktData);
    EXPECT_EQ(decoder.flows().size(), 1u);
}

TEST(PacketDecoder, TracksMultipleFlows) {
    fdpi::PacketDecoder decoder;

    auto pkt1 = buildTcpPacket(0xC0A80101, 0x0A000001, 12345, 80);
    auto pkt2 = buildTcpPacket(0xC0A80102, 0x0A000002, 54321, 443);

    decoder.decode(pkt1);
    decoder.decode(pkt2);
    EXPECT_EQ(decoder.flows().size(), 2u);
}

TEST(PacketDecoder, SetsTimestamp) {
    fdpi::PacketDecoder decoder;
    auto pktData = buildTcpPacket(0xC0A80101, 0x0A000001, 12345, 80);

    auto result =
        decoder.decode(pktData, fdpi::Timestamp{std::chrono::microseconds{42000}});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->timestamp, fdpi::Timestamp{std::chrono::microseconds{42000}});
}

TEST(PacketDecoder, DecodesARPPacket) {
    // Ethernet + ARP
    std::vector<uint8_t> data = {
        // Ethernet header
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst: broadcast
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
        0x08, 0x06,                         // EtherType: ARP
        // ARP
        0x00, 0x01,                         // hardware type: Ethernet
        0x08, 0x00,                         // protocol type: IPv4
        0x06, 0x04,                         // sizes
        0x00, 0x01,                         // opcode: Request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender MAC
        0xC0, 0xA8, 0x01, 0x01,             // sender IP: 192.168.1.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC
        0xC0, 0xA8, 0x01, 0x02              // target IP: 192.168.1.2
    };

    fdpi::PacketDecoder decoder;
    auto result = decoder.decode(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(result->ethernet.has_value());
    EXPECT_EQ(result->ethernet->etherType, 0x0806);

    auto* arp = std::get_if<fdpi::ARP>(&result->layer3);
    ASSERT_NE(arp, nullptr);
    EXPECT_EQ(arp->opcode, 1);
    EXPECT_EQ(arp->senderIp, fdpi::IPv4Address(0xC0A80101));
}

TEST(PacketDecoder, DecodesIPv6Packet) {
    std::vector<uint8_t> data = {
        // Ethernet header
        0x33, 0x33, 0x00, 0x00, 0x00, 0x01, // dst: IPv6 multicast
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
        0x86, 0xDD,                         // EtherType: IPv6
        // IPv6 header (40 bytes)
        0x60, 0x00, 0x00, 0x00, // version=6
        0x00, 0x14,             // payload length = 20
        0x06,                   // next header: TCP
        0x40,                   // hop limit: 64
        // src: ::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01,
        // dst: ::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01,
        // TCP header (20 bytes)
        0x30, 0x39,             // srcPort: 12345
        0x00, 0x50,             // dstPort: 80
        0x00, 0x00, 0x03, 0xE8, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02,             // dataOffset=5, SYN
        0xFF, 0xFF,             // window
        0x00, 0x00,             // checksum
        0x00, 0x00              // urgent
    };

    fdpi::PacketDecoder decoder;
    auto result = decoder.decode(data);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->ethernet->etherType, 0x86DD);

    auto* ipv6 = std::get_if<fdpi::IPv6>(&result->layer3);
    ASSERT_NE(ipv6, nullptr);
    EXPECT_EQ(ipv6->version, 6);
    EXPECT_EQ(ipv6->nextHeader, 6);

    auto* tcp = std::get_if<fdpi::TCP>(&result->layer4);
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(tcp->srcPort, 12345);
    EXPECT_EQ(tcp->dstPort, 80);
}

// Build an IPv4 ICMP fragment packet.
// fragmentOffset is in 8-byte units; moreFragments sets the MF flag.
static std::vector<uint8_t> buildIcmpFragmentPacket(uint16_t fragmentOffset,
                                                    bool moreFragments,
                                                    uint8_t payloadByte = 0x61) {
    std::vector<uint8_t> packet;

    // Ethernet header (14 bytes)
    packet.insert(packet.end(), {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    packet.insert(packet.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    packet.push_back(0x08);
    packet.push_back(0x00); // IPv4

    // IPv4 header (20 bytes)
    packet.push_back(0x45);     // version=4, IHL=5
    packet.push_back(0x00);     // TOS
    uint16_t totalLen = 20 + 8; // IP + 8 bytes payload
    packet.push_back(static_cast<uint8_t>(totalLen >> 8));
    packet.push_back(static_cast<uint8_t>(totalLen & 0xFF));
    packet.push_back(0x00);
    packet.push_back(0x42); // identification
    // flags + fragment offset
    uint16_t flagsAndOffset = fragmentOffset & 0x1FFF;
    if (moreFragments)
        flagsAndOffset |= 0x2000;
    packet.push_back(static_cast<uint8_t>(flagsAndOffset >> 8));
    packet.push_back(static_cast<uint8_t>(flagsAndOffset & 0xFF));
    packet.push_back(0x40); // TTL=64
    packet.push_back(0x01); // protocol=ICMP
    packet.push_back(0x00);
    packet.push_back(0x00);                                // checksum
    packet.insert(packet.end(), {0xC0, 0xA8, 0x01, 0x01}); // src
    packet.insert(packet.end(), {0x0A, 0x00, 0x00, 0x01}); // dst

    // Payload (8 bytes)
    for (int i = 0; i < 8; ++i) {
        packet.push_back(static_cast<uint8_t>(payloadByte + i));
    }

    return packet;
}

TEST(PacketDecoder, IPv4FirstFragmentDecodesL4) {
    // First fragment (offset=0, MF=1): payload starts at ICMP header
    auto data = buildIcmpFragmentPacket(0, true);
    // Patch payload to be a valid ICMP echo request header:
    // type=8, code=0, checksum=0x0000, id=0x0001, seq=0x0002
    size_t icmpStart = 14 + 20; // eth + ipv4
    data[icmpStart + 0] = 8;    // type
    data[icmpStart + 1] = 0;    // code
    data[icmpStart + 2] = 0x00; // checksum hi
    data[icmpStart + 3] = 0x00; // checksum lo
    data[icmpStart + 4] = 0x00; // rest of header
    data[icmpStart + 5] = 0x01;
    data[icmpStart + 6] = 0x00;
    data[icmpStart + 7] = 0x02;

    // Disable defragmentation so the fragment isn't buffered
    fdpi::PacketDecoder::Config cfg;
    cfg.enableDefragmentation = false;
    fdpi::PacketDecoder decoder(cfg);
    auto result = decoder.decode(data);
    ASSERT_TRUE(result.has_value());

    auto* icmp = std::get_if<fdpi::ICMP>(&result->layer4);
    ASSERT_NE(icmp, nullptr) << "First fragment should decode ICMP";
    EXPECT_EQ(icmp->type, 8);
    EXPECT_EQ(icmp->code, 0);
}

TEST(PacketDecoder, IPv4NonFirstFragmentSkipsL4) {
    // Non-first fragment (offset=185, MF=1): payload is NOT an L4 header
    auto data = buildIcmpFragmentPacket(185, true);

    // Disable defragmentation so the fragment isn't buffered
    fdpi::PacketDecoder::Config cfg;
    cfg.enableDefragmentation = false;
    fdpi::PacketDecoder decoder(cfg);
    auto result = decoder.decode(data);
    ASSERT_TRUE(result.has_value());

    // layer4 should be monostate — no L4 decoding
    EXPECT_TRUE(std::holds_alternative<std::monostate>(result->layer4))
        << "Non-first fragment must not decode L4";
    // IPv4 layer should still be present
    auto* ipv4 = std::get_if<fdpi::IPv4>(&result->layer3);
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(ipv4->fragmentOffset, 185);
    EXPECT_FALSE(result->payload.empty());
}

// Build Ethernet + IPv6 + Fragment Header + payload
static std::vector<uint8_t>
buildIPv6FragmentPacket(uint8_t realNextHeader,
                        uint16_t fragOffset,
                        bool moreFragments,
                        const std::vector<uint8_t>& innerPayload) {
    std::vector<uint8_t> packet;

    // Ethernet header
    packet.insert(packet.end(), {0x33, 0x33, 0x00, 0x00, 0x00, 0x01});
    packet.insert(packet.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    packet.push_back(0x86);
    packet.push_back(0xDD); // IPv6

    // IPv6 header (40 bytes)
    packet.push_back(0x60);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00); // version=6, TC=0, FL=0
    uint16_t payloadLen = static_cast<uint16_t>(8 + innerPayload.size());
    packet.push_back(static_cast<uint8_t>(payloadLen >> 8));
    packet.push_back(static_cast<uint8_t>(payloadLen & 0xFF));
    packet.push_back(44);   // nextHeader = Fragment (44)
    packet.push_back(0x40); // hopLimit = 64
    // src: 2001:db8::1
    packet.insert(packet.end(), {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    // dst: 2001:db8::2
    packet.insert(packet.end(), {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});

    // Fragment extension header (8 bytes)
    packet.push_back(realNextHeader); // Next Header (real protocol)
    packet.push_back(0x00);           // Reserved
    uint16_t fragField = static_cast<uint16_t>(fragOffset << 3);
    if (moreFragments)
        fragField |= 0x01;
    packet.push_back(static_cast<uint8_t>(fragField >> 8));
    packet.push_back(static_cast<uint8_t>(fragField & 0xFF));
    // Identification (4 bytes)
    packet.insert(packet.end(), {0x00, 0x00, 0x12, 0x34});

    // Inner payload
    packet.insert(packet.end(), innerPayload.begin(), innerPayload.end());

    return packet;
}

TEST(PacketDecoder, IPv6FragmentFirstFragmentSkipsL4) {
    // First fragment (offset=0, MF=1): L4 should NOT be decoded
    // (matches tshark behavior with reassembly off)
    std::vector<uint8_t> udpHeader = {0x30, 0x39, // srcPort: 12345
                                      0x00, 0x35, // dstPort: 53
                                      0x00, 0x10, // length: 16
                                      0x00, 0x00, // checksum
                                      // 8 bytes dummy payload
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto data = buildIPv6FragmentPacket(17, 0, true, udpHeader);

    fdpi::PacketDecoder decoder;
    auto result = decoder.decode(data);
    ASSERT_TRUE(result.has_value());

    auto* ipv6 = std::get_if<fdpi::IPv6>(&result->layer3);
    ASSERT_NE(ipv6, nullptr);
    EXPECT_EQ(ipv6->nextHeader, 44); // raw header still says Fragment

    // L4 should be monostate — fragments don't get L4 decoded
    EXPECT_TRUE(std::holds_alternative<std::monostate>(result->layer4))
        << "First IPv6 fragment should skip L4 decode";
    // Payload should contain the fragment data
    EXPECT_FALSE(result->payload.empty());
}

TEST(PacketDecoder, IPv6AtomicFragmentDecodesL4) {
    // Atomic fragment (offset=0, MF=0): L4 should be decoded
    std::vector<uint8_t> udpHeader = {0x30, 0x39, // srcPort: 12345
                                      0x00, 0x35, // dstPort: 53
                                      0x00, 0x10, // length: 16
                                      0x00, 0x00, // checksum
                                      // 8 bytes dummy payload
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto data = buildIPv6FragmentPacket(17, 0, false, udpHeader);

    fdpi::PacketDecoder decoder;
    auto result = decoder.decode(data);
    ASSERT_TRUE(result.has_value());

    auto* udp = std::get_if<fdpi::UDP>(&result->layer4);
    ASSERT_NE(udp, nullptr) << "Atomic fragment should decode UDP";
    EXPECT_EQ(udp->srcPort, 12345);
    EXPECT_EQ(udp->dstPort, 53);
}

TEST(PacketDecoder, IPv6FragmentNonFirstFragmentSkipsL4) {
    // Non-first fragment (offset=185, MF=0): payload is not an L4 header
    std::vector<uint8_t> payload(16, 0x61); // arbitrary data
    auto data = buildIPv6FragmentPacket(17, 185, false, payload);

    fdpi::PacketDecoder decoder;
    auto result = decoder.decode(data);
    ASSERT_TRUE(result.has_value());

    auto* ipv6 = std::get_if<fdpi::IPv6>(&result->layer3);
    ASSERT_NE(ipv6, nullptr);

    EXPECT_TRUE(std::holds_alternative<std::monostate>(result->layer4))
        << "Non-first IPv6 fragment must not decode L4";
    EXPECT_FALSE(result->payload.empty());
}

// Build Ethernet + IPv4(proto=GRE) + GRE + inner IPv4 + inner TCP
static std::vector<uint8_t> buildGreIpv4TcpPacket() {
    std::vector<uint8_t> packet;

    // Ethernet header (14 bytes)
    packet.insert(packet.end(), {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); // dst
    packet.insert(packet.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}); // src
    packet.push_back(0x08);
    packet.push_back(0x00); // IPv4

    // Outer IPv4 header (20 bytes) — proto=47 (GRE)
    packet.push_back(0x45);
    packet.push_back(0x00);
    // totalLength: 20(outer IP) + 4(GRE) + 20(inner IP) + 20(inner TCP) = 64
    packet.push_back(0x00);
    packet.push_back(0x40);
    packet.push_back(0x00);
    packet.push_back(0x01); // id
    packet.push_back(0x40);
    packet.push_back(0x00); // DF
    packet.push_back(0x40); // TTL=64
    packet.push_back(47);   // proto=GRE
    packet.push_back(0x00);
    packet.push_back(0x00);                                // checksum
    packet.insert(packet.end(), {0x0A, 0x00, 0x00, 0x01}); // src: 10.0.0.1
    packet.insert(packet.end(), {0x0A, 0x00, 0x00, 0x02}); // dst: 10.0.0.2

    // GRE header (4 bytes): no flags, protocol=IPv4
    packet.push_back(0x00);
    packet.push_back(0x00); // flags
    packet.push_back(0x08);
    packet.push_back(0x00); // protocol: IPv4

    // Inner IPv4 header (20 bytes) — proto=TCP
    packet.push_back(0x45);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x28); // totalLength=40 (20 IP + 20 TCP)
    packet.push_back(0x00);
    packet.push_back(0x02); // id
    packet.push_back(0x40);
    packet.push_back(0x00); // DF
    packet.push_back(0x40); // TTL=64
    packet.push_back(0x06); // proto=TCP
    packet.push_back(0x00);
    packet.push_back(0x00);                                // checksum
    packet.insert(packet.end(), {0xC0, 0xA8, 0x01, 0x01}); // src: 192.168.1.1
    packet.insert(packet.end(), {0xC0, 0xA8, 0x01, 0x02}); // dst: 192.168.1.2

    // Inner TCP header (20 bytes)
    packet.push_back(0x30);
    packet.push_back(0x39); // srcPort: 12345
    packet.push_back(0x00);
    packet.push_back(0x50); // dstPort: 80
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x03);
    packet.push_back(0xE8); // seq=1000
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00); // ack=0
    packet.push_back(0x50); // dataOffset=5
    packet.push_back(0x02); // SYN
    packet.push_back(0xFF);
    packet.push_back(0xFF); // window
    packet.push_back(0x00);
    packet.push_back(0x00); // checksum
    packet.push_back(0x00);
    packet.push_back(0x00); // urgent

    return packet;
}

TEST(PacketDecoder, GreIPv4InnerDecode) {
    auto data = buildGreIpv4TcpPacket();

    fdpi::PacketDecoder::Config cfg;
    cfg.enableDefragmentation = false;
    fdpi::PacketDecoder decoder(cfg);
    auto result = decoder.decode(data);
    ASSERT_TRUE(result.has_value());

    // layer3 should be the inner IPv4 (192.168.1.1 → 192.168.1.2)
    auto* ipv4 = std::get_if<fdpi::IPv4>(&result->layer3);
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(ipv4->srcIp, fdpi::IPv4Address(0xC0A80101));
    EXPECT_EQ(ipv4->dstIp, fdpi::IPv4Address(0xC0A80102));
    EXPECT_EQ(ipv4->protocol, 6); // TCP

    // layer4 should be the inner TCP
    auto* tcp = std::get_if<fdpi::TCP>(&result->layer4);
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(tcp->srcPort, 12345);
    EXPECT_EQ(tcp->dstPort, 80);
    EXPECT_TRUE(tcp->syn());
}

TEST(PacketDecoder, GreUnknownProtocol) {
    std::vector<uint8_t> packet;

    // Ethernet header
    packet.insert(packet.end(), {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    packet.insert(packet.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    packet.push_back(0x08);
    packet.push_back(0x00); // IPv4

    // Outer IPv4 (proto=GRE)
    packet.push_back(0x45);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x20); // totalLength=32 (20 IP + 4 GRE + 8 payload)
    packet.push_back(0x00);
    packet.push_back(0x01);
    packet.push_back(0x40);
    packet.push_back(0x00);
    packet.push_back(0x40);
    packet.push_back(47); // GRE
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.insert(packet.end(), {0x0A, 0x00, 0x00, 0x01});
    packet.insert(packet.end(), {0x0A, 0x00, 0x00, 0x02});

    // GRE header: unsupported protocol 0x6558 (Transparent Ethernet Bridging)
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x65);
    packet.push_back(0x58);

    // Some inner payload
    packet.insert(packet.end(), {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44});

    fdpi::PacketDecoder::Config cfg;
    cfg.enableDefragmentation = false;
    fdpi::PacketDecoder decoder(cfg);
    auto result = decoder.decode(packet);
    ASSERT_TRUE(result.has_value());

    // layer4 should be monostate — GRE with unsupported inner protocol
    EXPECT_TRUE(std::holds_alternative<std::monostate>(result->layer4));
    // Payload should contain the remaining bytes after GRE header
    EXPECT_FALSE(result->payload.empty());
    EXPECT_EQ(result->payload.size(), 8u);
}

TEST(PacketDecoder, VxlanInnerDecode) {
    std::vector<uint8_t> packet;

    // Outer Ethernet header (14 bytes)
    packet.insert(packet.end(), {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}); // dst
    packet.insert(packet.end(), {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}); // src
    packet.push_back(0x08);
    packet.push_back(0x00); // IPv4

    // Outer IPv4 header (20 bytes) — proto=UDP
    // totalLength: 20(IP) + 8(UDP) + 8(VxLAN) + 14(inner Eth) + 20(inner IP) + 20(inner
    // TCP) = 90
    packet.push_back(0x45);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x5A); // totalLength=90
    packet.push_back(0x00);
    packet.push_back(0x01);
    packet.push_back(0x40);
    packet.push_back(0x00);
    packet.push_back(0x40);
    packet.push_back(0x11); // UDP
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.insert(packet.end(), {0x0A, 0x00, 0x00, 0x01}); // src: 10.0.0.1
    packet.insert(packet.end(), {0x0A, 0x00, 0x00, 0x02}); // dst: 10.0.0.2

    // Outer UDP header (8 bytes) — dstPort=4789
    packet.push_back(0xFF);
    packet.push_back(0xE0); // srcPort: 65504
    packet.push_back(0x12);
    packet.push_back(0xB5); // dstPort: 4789
    packet.push_back(0x00);
    packet.push_back(0x46); // length: 70 (8 + 8 + 14 + 20 + 20)
    packet.push_back(0x00);
    packet.push_back(0x00); // checksum

    // VxLAN header (8 bytes): flags=0x08, VNI=100
    packet.push_back(0x08);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x64); // VNI=100
    packet.push_back(0x00);

    // Inner Ethernet header (14 bytes)
    packet.insert(packet.end(), {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}); // dst
    packet.insert(packet.end(), {0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}); // src
    packet.push_back(0x08);
    packet.push_back(0x00); // IPv4

    // Inner IPv4 header (20 bytes) — proto=TCP
    packet.push_back(0x45);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x28); // totalLength=40
    packet.push_back(0x00);
    packet.push_back(0x02);
    packet.push_back(0x40);
    packet.push_back(0x00);
    packet.push_back(0x40);
    packet.push_back(0x06); // TCP
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.insert(packet.end(), {0xC0, 0xA8, 0x01, 0x0A}); // src: 192.168.1.10
    packet.insert(packet.end(), {0xC0, 0xA8, 0x01, 0x0B}); // dst: 192.168.1.11

    // Inner TCP header (20 bytes)
    packet.push_back(0xC0);
    packet.push_back(0x00); // srcPort: 49152
    packet.push_back(0x01);
    packet.push_back(0xBB); // dstPort: 443
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x10);
    packet.push_back(0x00); // seq
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00); // ack
    packet.push_back(0x50); // dataOffset=5
    packet.push_back(0x02); // SYN
    packet.push_back(0xFF);
    packet.push_back(0xFF); // window
    packet.push_back(0x00);
    packet.push_back(0x00); // checksum
    packet.push_back(0x00);
    packet.push_back(0x00); // urgent

    fdpi::PacketDecoder::Config cfg;
    cfg.enableDefragmentation = false;
    fdpi::PacketDecoder decoder(cfg);
    auto result = decoder.decode(packet);
    ASSERT_TRUE(result.has_value());

    // layer3 should be the inner IPv4 (192.168.1.10 → 192.168.1.11)
    auto* ipv4 = std::get_if<fdpi::IPv4>(&result->layer3);
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(ipv4->srcIp, fdpi::IPv4Address(0xC0A8010A));
    EXPECT_EQ(ipv4->dstIp, fdpi::IPv4Address(0xC0A8010B));
    EXPECT_EQ(ipv4->protocol, 6); // TCP

    // layer4 should be the inner TCP
    auto* tcp = std::get_if<fdpi::TCP>(&result->layer4);
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(tcp->srcPort, 49152);
    EXPECT_EQ(tcp->dstPort, 443);
    EXPECT_TRUE(tcp->syn());
}

// Build Ethernet + IPv4 + TCP + payload
static std::vector<uint8_t> buildTcpPacketWithPayload(uint32_t srcIp,
                                                      uint32_t dstIp,
                                                      uint16_t srcPort,
                                                      uint16_t dstPort,
                                                      const std::string& payload,
                                                      uint32_t seqNum = 1000,
                                                      uint8_t tcpFlags = 0x18 // PSH|ACK
) {
    std::vector<uint8_t> packet;

    // Ethernet header (14 bytes)
    packet.insert(packet.end(), {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    packet.insert(packet.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    packet.push_back(0x08);
    packet.push_back(0x00);

    // IPv4 header (20 bytes)
    packet.push_back(0x45);
    packet.push_back(0x00);
    uint16_t totalLen = static_cast<uint16_t>(20 + 20 + payload.size());
    packet.push_back(static_cast<uint8_t>(totalLen >> 8));
    packet.push_back(static_cast<uint8_t>(totalLen & 0xFF));
    packet.push_back(0x00);
    packet.push_back(0x01);
    packet.push_back(0x40);
    packet.push_back(0x00);
    packet.push_back(0x40);
    packet.push_back(0x06); // TCP
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(static_cast<uint8_t>((srcIp >> 24) & 0xFF));
    packet.push_back(static_cast<uint8_t>((srcIp >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((srcIp >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(srcIp & 0xFF));
    packet.push_back(static_cast<uint8_t>((dstIp >> 24) & 0xFF));
    packet.push_back(static_cast<uint8_t>((dstIp >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((dstIp >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(dstIp & 0xFF));

    // TCP header (20 bytes)
    packet.push_back(static_cast<uint8_t>(srcPort >> 8));
    packet.push_back(static_cast<uint8_t>(srcPort & 0xFF));
    packet.push_back(static_cast<uint8_t>(dstPort >> 8));
    packet.push_back(static_cast<uint8_t>(dstPort & 0xFF));
    packet.push_back(static_cast<uint8_t>((seqNum >> 24) & 0xFF));
    packet.push_back(static_cast<uint8_t>((seqNum >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((seqNum >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(seqNum & 0xFF));
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x50);
    packet.push_back(tcpFlags);
    packet.push_back(0xFF);
    packet.push_back(0xFF);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);

    // Payload
    for (char c : payload) {
        packet.push_back(static_cast<uint8_t>(c));
    }

    return packet;
}

// POP3 addresses: server=10.0.0.1:110, client=192.168.1.1:50000
constexpr uint32_t kPop3Server = 0x0A000001;
constexpr uint32_t kPop3Client = 0xC0A80101;
constexpr uint16_t kPop3ServerPort = 110;
constexpr uint16_t kPop3ClientPort = 50000;

TEST(PacketDecoder, Pop3RetrMultilineSkipsDataPackets) {
    fdpi::PacketDecoder decoder;

    // Track sequence numbers per direction
    uint32_t serverSeq = 1000;
    uint32_t clientSeq = 1000;

    // Server greeting (establishes server→client detection)
    std::string greetStr = "+OK POP3 server ready\r\n";
    auto greeting = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                              kPop3ClientPort, greetStr, serverSeq);
    serverSeq += static_cast<uint32_t>(greetStr.size());
    auto r1 = decoder.decode(greeting);
    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(std::holds_alternative<fdpi::POP3>(r1->layer7));

    // USER command (establishes client→server detection)
    std::string userStr = "USER test\r\n";
    auto user = buildTcpPacketWithPayload(kPop3Client, kPop3Server, kPop3ClientPort,
                                          kPop3ServerPort, userStr, clientSeq);
    clientSeq += static_cast<uint32_t>(userStr.size());
    decoder.decode(user);
    std::string okUserStr = "+OK\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                             kPop3ClientPort, okUserStr, serverSeq));
    serverSeq += static_cast<uint32_t>(okUserStr.size());

    // Client: RETR 1
    std::string retrStr = "RETR 1\r\n";
    auto retr = buildTcpPacketWithPayload(kPop3Client, kPop3Server, kPop3ClientPort,
                                          kPop3ServerPort, retrStr, clientSeq);
    clientSeq += static_cast<uint32_t>(retrStr.size());
    auto r2 = decoder.decode(retr);
    ASSERT_TRUE(r2.has_value());
    auto* cmd = std::get_if<fdpi::POP3>(&r2->layer7);
    ASSERT_NE(cmd, nullptr);
    EXPECT_EQ(cmd->command, "RETR");

    // Server: +OK (enters data mode)
    std::string okRetrStr = "+OK 1234 octets\r\n";
    auto ok = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                        kPop3ClientPort, okRetrStr, serverSeq);
    serverSeq += static_cast<uint32_t>(okRetrStr.size());
    auto r3 = decoder.decode(ok);
    ASSERT_TRUE(r3.has_value());
    ASSERT_TRUE(std::holds_alternative<fdpi::POP3>(r3->layer7));

    // Data packet — should be suppressed (monostate)
    std::string dataStr = "From: user@example.com\r\nSubject: Test\r\n";
    auto data = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                          kPop3ClientPort, dataStr, serverSeq);
    serverSeq += static_cast<uint32_t>(dataStr.size());
    auto r4 = decoder.decode(data);
    ASSERT_TRUE(r4.has_value());
    EXPECT_TRUE(std::holds_alternative<std::monostate>(r4->layer7));

    // Terminator
    std::string termStr = ".\r\n";
    auto term = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                          kPop3ClientPort, termStr, serverSeq);
    serverSeq += static_cast<uint32_t>(termStr.size());
    auto r5 = decoder.decode(term);
    ASSERT_TRUE(r5.has_value());
    EXPECT_TRUE(std::holds_alternative<std::monostate>(r5->layer7));

    // After terminator, QUIT should decode normally
    std::string quitStr = "QUIT\r\n";
    auto quit = buildTcpPacketWithPayload(kPop3Client, kPop3Server, kPop3ClientPort,
                                          kPop3ServerPort, quitStr, clientSeq);
    clientSeq += static_cast<uint32_t>(quitStr.size());
    auto r6 = decoder.decode(quit);
    ASSERT_TRUE(r6.has_value());
    auto* quitCmd = std::get_if<fdpi::POP3>(&r6->layer7);
    ASSERT_NE(quitCmd, nullptr);
    EXPECT_EQ(quitCmd->command, "QUIT");
}

TEST(PacketDecoder, Pop3RetrErrDoesNotEnterDataMode) {
    fdpi::PacketDecoder decoder;

    uint32_t serverSeq = 1000;
    uint32_t clientSeq = 1000;

    // Server greeting
    std::string s1 = "+OK POP3 server ready\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                             kPop3ClientPort, s1, serverSeq));
    serverSeq += static_cast<uint32_t>(s1.size());
    // USER command (establishes client→server detection)
    std::string s2 = "USER test\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Client, kPop3Server, kPop3ClientPort,
                                             kPop3ServerPort, s2, clientSeq));
    clientSeq += static_cast<uint32_t>(s2.size());
    std::string s3 = "+OK\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                             kPop3ClientPort, s3, serverSeq));
    serverSeq += static_cast<uint32_t>(s3.size());

    // Client: RETR 999
    std::string s4 = "RETR 999\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Client, kPop3Server, kPop3ClientPort,
                                             kPop3ServerPort, s4, clientSeq));
    clientSeq += static_cast<uint32_t>(s4.size());

    // Server: -ERR (should NOT enter data mode)
    std::string s5 = "-ERR no such message\r\n";
    auto err = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                         kPop3ClientPort, s5, serverSeq);
    serverSeq += static_cast<uint32_t>(s5.size());
    auto r = decoder.decode(err);
    ASSERT_TRUE(r.has_value());
    auto* resp = std::get_if<fdpi::POP3>(&r->layer7);
    ASSERT_NE(resp, nullptr);
    EXPECT_FALSE(resp->success);

    // Next server packet should still decode as POP3
    std::string s6 = "+OK 0 messages\r\n";
    auto next = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                          kPop3ClientPort, s6, serverSeq);
    serverSeq += static_cast<uint32_t>(s6.size());
    auto r2 = decoder.decode(next);
    ASSERT_TRUE(r2.has_value());
    EXPECT_TRUE(std::holds_alternative<fdpi::POP3>(r2->layer7));
}

TEST(PacketDecoder, Pop3ListNoArgMultiline) {
    fdpi::PacketDecoder decoder;

    uint32_t serverSeq = 1000;
    uint32_t clientSeq = 1000;

    // Server greeting + USER to establish both flow directions
    std::string s1 = "+OK POP3 server ready\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                             kPop3ClientPort, s1, serverSeq));
    serverSeq += static_cast<uint32_t>(s1.size());
    std::string s2 = "USER test\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Client, kPop3Server, kPop3ClientPort,
                                             kPop3ServerPort, s2, clientSeq));
    clientSeq += static_cast<uint32_t>(s2.size());
    std::string s3 = "+OK\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                             kPop3ClientPort, s3, serverSeq));
    serverSeq += static_cast<uint32_t>(s3.size());

    // Client: LIST (no argument — multi-line)
    std::string s4 = "LIST\r\n";
    auto list = buildTcpPacketWithPayload(kPop3Client, kPop3Server, kPop3ClientPort,
                                          kPop3ServerPort, s4, clientSeq);
    clientSeq += static_cast<uint32_t>(s4.size());
    auto r = decoder.decode(list);
    ASSERT_TRUE(r.has_value());
    auto* cmd = std::get_if<fdpi::POP3>(&r->layer7);
    ASSERT_NE(cmd, nullptr);
    EXPECT_EQ(cmd->command, "LIST");

    // Server: +OK
    std::string s5 = "+OK\r\n";
    auto ok = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                        kPop3ClientPort, s5, serverSeq);
    serverSeq += static_cast<uint32_t>(s5.size());
    decoder.decode(ok);

    // Data line — suppressed
    std::string s6 = "1 1234\r\n2 5678\r\n.\r\n";
    auto data = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                          kPop3ClientPort, s6, serverSeq);
    serverSeq += static_cast<uint32_t>(s6.size());
    auto r2 = decoder.decode(data);
    ASSERT_TRUE(r2.has_value());
    EXPECT_TRUE(std::holds_alternative<std::monostate>(r2->layer7));
}

TEST(PacketDecoder, Pop3ListWithArgSingleLine) {
    fdpi::PacketDecoder decoder;

    uint32_t serverSeq = 1000;
    uint32_t clientSeq = 1000;

    // Server greeting + USER to establish both flow directions
    std::string s1 = "+OK POP3 server ready\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                             kPop3ClientPort, s1, serverSeq));
    serverSeq += static_cast<uint32_t>(s1.size());
    std::string s2 = "USER test\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Client, kPop3Server, kPop3ClientPort,
                                             kPop3ServerPort, s2, clientSeq));
    clientSeq += static_cast<uint32_t>(s2.size());
    std::string s3 = "+OK\r\n";
    decoder.decode(buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                             kPop3ClientPort, s3, serverSeq));
    serverSeq += static_cast<uint32_t>(s3.size());

    // Client: LIST 1 (with argument — single-line response)
    std::string s4 = "LIST 1\r\n";
    auto list = buildTcpPacketWithPayload(kPop3Client, kPop3Server, kPop3ClientPort,
                                          kPop3ServerPort, s4, clientSeq);
    clientSeq += static_cast<uint32_t>(s4.size());
    auto r = decoder.decode(list);
    ASSERT_TRUE(r.has_value());
    auto* cmd = std::get_if<fdpi::POP3>(&r->layer7);
    ASSERT_NE(cmd, nullptr);
    EXPECT_EQ(cmd->command, "LIST");

    // Server: +OK 1 1234 (should NOT enter data mode)
    std::string s5 = "+OK 1 1234\r\n";
    auto ok = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                        kPop3ClientPort, s5, serverSeq);
    serverSeq += static_cast<uint32_t>(s5.size());
    auto r2 = decoder.decode(ok);
    ASSERT_TRUE(r2.has_value());
    auto* resp = std::get_if<fdpi::POP3>(&r2->layer7);
    ASSERT_NE(resp, nullptr);
    EXPECT_TRUE(resp->success);

    // Next server packet should still decode as POP3 (not suppressed)
    std::string s6 = "+OK bye\r\n";
    auto next = buildTcpPacketWithPayload(kPop3Server, kPop3Client, kPop3ServerPort,
                                          kPop3ClientPort, s6, serverSeq);
    serverSeq += static_cast<uint32_t>(s6.size());
    auto r3 = decoder.decode(next);
    ASSERT_TRUE(r3.has_value());
    EXPECT_TRUE(std::holds_alternative<fdpi::POP3>(r3->layer7));
}

// === Stream Reassembly Tests ===

TEST(PacketDecoder, StreamReassembly_HttpSplitAcrossSegments) {
    fdpi::PacketDecoder decoder;

    // HTTP GET request split across two TCP segments.
    // First segment: "GET / HT" (no \r\n, HTTP parser will fail)
    // Second segment: "TP/1.1\r\nHost: example.com\r\n\r\n"
    uint32_t seq = 1000;
    std::string part1 = "GET / HT";
    auto seg1 = buildTcpPacketWithPayload(0xC0A80101, 0x0A000001, 50000, 80, part1, seq);
    seq += static_cast<uint32_t>(part1.size());

    auto r1 = decoder.decode(seg1);
    ASSERT_TRUE(r1.has_value());
    // First segment: incomplete HTTP, should be monostate
    EXPECT_TRUE(std::holds_alternative<std::monostate>(r1->layer7))
        << "Incomplete HTTP segment should not decode L7";

    std::string part2 = "TP/1.1\r\nHost: example.com\r\n\r\n";
    auto seg2 = buildTcpPacketWithPayload(0xC0A80101, 0x0A000001, 50000, 80, part2, seq);
    seq += static_cast<uint32_t>(part2.size());

    auto r2 = decoder.decode(seg2);
    ASSERT_TRUE(r2.has_value());
    // Second segment completes the HTTP request
    auto* http = std::get_if<fdpi::HTTP>(&r2->layer7);
    ASSERT_NE(http, nullptr) << "Completing segment should decode HTTP";
    EXPECT_TRUE(http->isRequest);
    EXPECT_EQ(http->method, "GET");
    EXPECT_EQ(http->uri, "/");
}

TEST(PacketDecoder, StreamReassembly_CompleteHttpInSingleSegment) {
    fdpi::PacketDecoder decoder;

    // Complete HTTP request in a single TCP segment — should decode as before
    std::string request = "GET /index.html HTTP/1.1\r\nHost: test.com\r\n\r\n";
    auto pkt =
        buildTcpPacketWithPayload(0xC0A80101, 0x0A000001, 50000, 80, request, 1000);

    auto r = decoder.decode(pkt);
    ASSERT_TRUE(r.has_value());
    auto* http = std::get_if<fdpi::HTTP>(&r->layer7);
    ASSERT_NE(http, nullptr) << "Complete HTTP in single segment should decode";
    EXPECT_TRUE(http->isRequest);
    EXPECT_EQ(http->method, "GET");
    EXPECT_EQ(http->uri, "/index.html");
}

TEST(PacketDecoder, StreamReassembly_UdpUnaffected) {
    fdpi::PacketDecoder decoder;

    // DNS over UDP — should decode on the single packet (unchanged behavior)
    auto pkt = buildDnsQueryPacket("example.com");
    auto r = decoder.decode(pkt);
    ASSERT_TRUE(r.has_value());
    auto* dns = std::get_if<fdpi::DNS>(&r->layer7);
    ASSERT_NE(dns, nullptr) << "UDP DNS should decode on single packet";
    EXPECT_FALSE(dns->questions.empty());
    EXPECT_EQ(dns->questions[0].name, "example.com");
}

TEST(PacketDecoder, StreamReassembly_DisabledFallsBackToPerPacket) {
    // With enableTcpReassembly=false, TCP HTTP in one segment should
    // still decode via the per-packet path
    fdpi::PacketDecoder::Config cfg;
    cfg.enableTcpReassembly = false;
    fdpi::PacketDecoder decoder(cfg);

    std::string request = "GET /test HTTP/1.1\r\nHost: test.com\r\n\r\n";
    auto pkt =
        buildTcpPacketWithPayload(0xC0A80101, 0x0A000001, 50000, 80, request, 1000);

    auto r = decoder.decode(pkt);
    ASSERT_TRUE(r.has_value());
    auto* http = std::get_if<fdpi::HTTP>(&r->layer7);
    ASSERT_NE(http, nullptr)
        << "With reassembly disabled, per-packet HTTP should still work";
    EXPECT_TRUE(http->isRequest);
    EXPECT_EQ(http->method, "GET");
}

TEST(PacketDecoder, StreamReassembly_TlsSplitAcrossSegments) {
    fdpi::PacketDecoder decoder;

    // Build a minimal TLS ClientHello and split it across two segments.
    // TLS record: content_type=22 (Handshake), version=0x0301, length
    // Handshake: type=1 (ClientHello), length, version, random (32 bytes),
    // session_id_len=0, cipher_suites_len=2, cipher, compression_len=1,
    // comp=0

    std::vector<uint8_t> clientHello;
    // Handshake header: type=1 (ClientHello)
    clientHello.push_back(0x01);
    // Handshake length (3 bytes) — placeholder, fill after
    clientHello.push_back(0x00);
    clientHello.push_back(0x00);
    clientHello.push_back(0x00); // will fill in

    // ClientHello body:
    // Version: TLS 1.2 (0x0303)
    clientHello.push_back(0x03);
    clientHello.push_back(0x03);
    // Random (32 bytes)
    for (int i = 0; i < 32; ++i)
        clientHello.push_back(static_cast<uint8_t>(i));
    // Session ID length: 0
    clientHello.push_back(0x00);
    // Cipher suites length: 2
    clientHello.push_back(0x00);
    clientHello.push_back(0x02);
    // One cipher suite: TLS_AES_128_GCM_SHA256 (0x1301)
    clientHello.push_back(0x13);
    clientHello.push_back(0x01);
    // Compression methods length: 1
    clientHello.push_back(0x01);
    // Compression method: null
    clientHello.push_back(0x00);
    // Extensions length: 0
    clientHello.push_back(0x00);
    clientHello.push_back(0x00);

    // Fix handshake length
    uint32_t hsBodyLen = static_cast<uint32_t>(clientHello.size() - 4);
    clientHello[1] = static_cast<uint8_t>((hsBodyLen >> 16) & 0xFF);
    clientHello[2] = static_cast<uint8_t>((hsBodyLen >> 8) & 0xFF);
    clientHello[3] = static_cast<uint8_t>(hsBodyLen & 0xFF);

    // TLS record header
    std::vector<uint8_t> tlsRecord;
    tlsRecord.push_back(0x16); // content_type = Handshake
    tlsRecord.push_back(0x03);
    tlsRecord.push_back(0x01); // version = TLS 1.0
    uint16_t recordLen = static_cast<uint16_t>(clientHello.size());
    tlsRecord.push_back(static_cast<uint8_t>(recordLen >> 8));
    tlsRecord.push_back(static_cast<uint8_t>(recordLen & 0xFF));
    tlsRecord.insert(tlsRecord.end(), clientHello.begin(), clientHello.end());

    // Split into two parts — first part is just the TLS record header (5 bytes)
    std::string strPart1(tlsRecord.begin(), tlsRecord.begin() + 5);
    std::string strPart2(tlsRecord.begin() + 5, tlsRecord.end());

    uint32_t seq = 1000;

    auto seg1 =
        buildTcpPacketWithPayload(0xC0A80101, 0x0A000001, 50000, 443, strPart1, seq);
    seq += static_cast<uint32_t>(strPart1.size());

    auto r1 = decoder.decode(seg1);
    ASSERT_TRUE(r1.has_value());
    // First segment: incomplete TLS record, should be monostate
    EXPECT_TRUE(std::holds_alternative<std::monostate>(r1->layer7))
        << "Incomplete TLS segment should not decode L7";

    auto seg2 =
        buildTcpPacketWithPayload(0xC0A80101, 0x0A000001, 50000, 443, strPart2, seq);

    auto r2 = decoder.decode(seg2);
    ASSERT_TRUE(r2.has_value());
    // Second segment completes the TLS ClientHello
    auto* tls = std::get_if<fdpi::TLS>(&r2->layer7);
    ASSERT_NE(tls, nullptr) << "Completing segment should decode TLS";
    EXPECT_EQ(tls->contentType, 22); // Handshake
}
