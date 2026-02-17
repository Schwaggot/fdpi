#include <fdpi/decoder.hpp>
#include <gtest/gtest.h>
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

    auto result = decoder.decode(pktData, 1000);
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

    auto result = decoder.decode(pktData, 2000);
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

    decoder.decode(pktData, 1000);
    EXPECT_EQ(decoder.flows().size(), 1u);

    // Second packet to same flow
    decoder.decode(pktData, 2000);
    EXPECT_EQ(decoder.flows().size(), 1u);
}

TEST(PacketDecoder, TracksMultipleFlows) {
    fdpi::PacketDecoder decoder;

    auto pkt1 = buildTcpPacket(0xC0A80101, 0x0A000001, 12345, 80);
    auto pkt2 = buildTcpPacket(0xC0A80102, 0x0A000002, 54321, 443);

    decoder.decode(pkt1, 1000);
    decoder.decode(pkt2, 2000);
    EXPECT_EQ(decoder.flows().size(), 2u);
}

TEST(PacketDecoder, SetsTimestamp) {
    fdpi::PacketDecoder decoder;
    auto pktData = buildTcpPacket(0xC0A80101, 0x0A000001, 12345, 80);

    auto result = decoder.decode(pktData, 42000);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->timestamp, 42000u);
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

TEST(PacketDecoder, IPv6FragmentFirstFragmentDecodesL4) {
    // Build a UDP header as inner payload (first fragment, offset=0, MF=1)
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

    auto* udp = std::get_if<fdpi::UDP>(&result->layer4);
    ASSERT_NE(udp, nullptr) << "First IPv6 fragment should decode UDP";
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
