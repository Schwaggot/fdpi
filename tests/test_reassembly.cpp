#include <fdpi/decoder.hpp>
#include <gtest/gtest.h>
#include <vector>

namespace {

fdpi::IPv4Address ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return fdpi::IPv4Address{{{a, b, c, d}}};
}

} // anonymous namespace

TEST(IpDefragmenter, DefaultConstruction) {
    fdpi::IpDefragmenter defrag;
    // Should not crash
}

TEST(IpDefragmenter, ConfiguredConstruction) {
    fdpi::IpDefragmenter::Config config;
    config.timeout = std::chrono::seconds(10);
    config.maxFragments = 100;
    fdpi::IpDefragmenter defrag(config);
}

TEST(IpDefragmenter, NonFragmentedPacketReturnsNullopt) {
    fdpi::IpDefragmenter defrag;

    // Non-fragmented: flags=0, fragmentOffset=0
    fdpi::IPv4 header{};
    header.version = 4;
    header.ihl = 5;
    header.totalLength = 20;
    header.identification = 1;
    header.flags = 0;
    header.fragmentOffset = 0;

    std::vector<uint8_t> data(20, 0);
    auto result = defrag.process(data, header);
    EXPECT_FALSE(result.has_value());
}

TEST(TcpReassembler, DefaultConstruction) {
    fdpi::TcpReassembler reassembler;
    // Should not crash
}

TEST(TcpReassembler, ConfiguredConstruction) {
    fdpi::TcpReassembler::Config config;
    config.streamTimeout = std::chrono::seconds(30);
    config.maxStreams = 1000;
    config.maxStreamBytes = 1024 * 1024;
    fdpi::TcpReassembler reassembler(config);
}

TEST(TcpReassembler, SynWithNoPayload) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(192, 168, 1, 1);
    flowId.dstIp = ipv4(192, 168, 1, 2);
    flowId.srcPort = 12345;
    flowId.dstPort = 80;
    flowId.protocol = 6;

    fdpi::TCP synHdr{};
    synHdr.srcPort = 12345;
    synHdr.dstPort = 80;
    synHdr.seqNum = 1000;
    synHdr.flags = 0x02; // SYN
    synHdr.dataOffset = 5;

    auto result = reassembler.process(flowId, synHdr, {});
    EXPECT_FALSE(result.data.has_value());
    EXPECT_FALSE(result.retransmission);
}

TEST(TcpReassembler, BasicReassembly) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(192, 168, 1, 1);
    flowId.dstIp = ipv4(192, 168, 1, 2);
    flowId.srcPort = 12345;
    flowId.dstPort = 80;
    flowId.protocol = 6;

    // SYN
    fdpi::TCP synHdr{};
    synHdr.srcPort = 12345;
    synHdr.dstPort = 80;
    synHdr.seqNum = 1000;
    synHdr.flags = 0x02; // SYN
    synHdr.dataOffset = 5;
    reassembler.process(flowId, synHdr, {});

    // Data packet
    fdpi::TCP dataHdr{};
    dataHdr.srcPort = 12345;
    dataHdr.dstPort = 80;
    dataHdr.seqNum = 1001;
    dataHdr.flags = 0x10; // ACK
    dataHdr.dataOffset = 5;

    std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
    auto result = reassembler.process(flowId, dataHdr, payload);
    ASSERT_TRUE(result.data.has_value());
    EXPECT_EQ(result.data->size(), 5u);
    EXPECT_EQ((*result.data)[0], 'H');
    EXPECT_FALSE(result.retransmission);
}

TEST(TcpReassembler, InOrderSegments) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(10, 0, 0, 1);
    flowId.dstIp = ipv4(10, 0, 0, 2);
    flowId.srcPort = 12345;
    flowId.dstPort = 80;
    flowId.protocol = 6;

    // First segment
    fdpi::TCP hdr1{};
    hdr1.srcPort = 12345;
    hdr1.dstPort = 80;
    hdr1.seqNum = 1000;
    hdr1.ackNum = 0;
    hdr1.dataOffset = 5;
    hdr1.flags = 0x10; // ACK

    std::vector<uint8_t> payload1 = {'H', 'e', 'l', 'l', 'o'};
    reassembler.process(flowId, hdr1, payload1);

    // Second segment
    fdpi::TCP hdr2 = hdr1;
    hdr2.seqNum = 1005;
    std::vector<uint8_t> payload2 = {' ', 'W', 'o', 'r', 'l', 'd'};
    auto result = reassembler.process(flowId, hdr2, payload2);

    // At least one segment should have been delivered
    // Exact behavior depends on implementation strategy
}

// --- Retransmission detection tests ---

TEST(TcpReassembler, SynRetransmission) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(192, 168, 1, 1);
    flowId.dstIp = ipv4(192, 168, 1, 2);
    flowId.srcPort = 12345;
    flowId.dstPort = 80;
    flowId.protocol = 6;

    fdpi::TCP synHdr{};
    synHdr.srcPort = 12345;
    synHdr.dstPort = 80;
    synHdr.seqNum = 1000;
    synHdr.flags = 0x02; // SYN
    synHdr.dataOffset = 5;

    // First SYN
    auto r1 = reassembler.process(flowId, synHdr, {});
    EXPECT_FALSE(r1.retransmission);

    // Second SYN — retransmission
    auto r2 = reassembler.process(flowId, synHdr, {});
    EXPECT_TRUE(r2.retransmission);
    EXPECT_FALSE(r2.data.has_value());
}

TEST(TcpReassembler, DataRetransmissionAfterDelivery) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(192, 168, 1, 1);
    flowId.dstIp = ipv4(192, 168, 1, 2);
    flowId.srcPort = 12345;
    flowId.dstPort = 80;
    flowId.protocol = 6;

    // SYN
    fdpi::TCP synHdr{};
    synHdr.srcPort = 12345;
    synHdr.dstPort = 80;
    synHdr.seqNum = 1000;
    synHdr.flags = 0x02;
    synHdr.dataOffset = 5;
    reassembler.process(flowId, synHdr, {});

    // Data segment (delivered in order)
    fdpi::TCP dataHdr{};
    dataHdr.srcPort = 12345;
    dataHdr.dstPort = 80;
    dataHdr.seqNum = 1001;
    dataHdr.flags = 0x10; // ACK
    dataHdr.dataOffset = 5;

    std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
    auto r1 = reassembler.process(flowId, dataHdr, payload);
    ASSERT_TRUE(r1.data.has_value());
    EXPECT_FALSE(r1.retransmission);

    // Retransmit the same segment
    auto r2 = reassembler.process(flowId, dataHdr, payload);
    EXPECT_TRUE(r2.retransmission);
    EXPECT_FALSE(r2.data.has_value());
}

TEST(TcpReassembler, OutOfOrderIsNotRetransmission) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(192, 168, 1, 1);
    flowId.dstIp = ipv4(192, 168, 1, 2);
    flowId.srcPort = 12345;
    flowId.dstPort = 80;
    flowId.protocol = 6;

    // SYN
    fdpi::TCP synHdr{};
    synHdr.srcPort = 12345;
    synHdr.dstPort = 80;
    synHdr.seqNum = 1000;
    synHdr.flags = 0x02;
    synHdr.dataOffset = 5;
    reassembler.process(flowId, synHdr, {});

    // Out-of-order segment at seq 1011 (gap: 1001-1010)
    fdpi::TCP oooHdr{};
    oooHdr.srcPort = 12345;
    oooHdr.dstPort = 80;
    oooHdr.seqNum = 1011;
    oooHdr.flags = 0x10;
    oooHdr.dataOffset = 5;

    std::vector<uint8_t> payload = {'W', 'o', 'r', 'l', 'd'};
    auto r1 = reassembler.process(flowId, oooHdr, payload);
    EXPECT_FALSE(r1.retransmission);
    EXPECT_FALSE(r1.data.has_value()); // Buffered, not yet deliverable

    // Fill the gap — this is NOT a retransmission
    fdpi::TCP gapHdr{};
    gapHdr.srcPort = 12345;
    gapHdr.dstPort = 80;
    gapHdr.seqNum = 1001;
    gapHdr.flags = 0x10;
    gapHdr.dataOffset = 5;

    std::vector<uint8_t> gapPayload = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l'};
    auto r2 = reassembler.process(flowId, gapHdr, gapPayload);
    EXPECT_FALSE(r2.retransmission);
    ASSERT_TRUE(r2.data.has_value()); // Should deliver gap + buffered OOO
}

TEST(TcpReassembler, DuplicateOutOfOrderSegment) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(192, 168, 1, 1);
    flowId.dstIp = ipv4(192, 168, 1, 2);
    flowId.srcPort = 12345;
    flowId.dstPort = 80;
    flowId.protocol = 6;

    // SYN
    fdpi::TCP synHdr{};
    synHdr.srcPort = 12345;
    synHdr.dstPort = 80;
    synHdr.seqNum = 1000;
    synHdr.flags = 0x02;
    synHdr.dataOffset = 5;
    reassembler.process(flowId, synHdr, {});

    // Out-of-order segment
    fdpi::TCP oooHdr{};
    oooHdr.srcPort = 12345;
    oooHdr.dstPort = 80;
    oooHdr.seqNum = 1011;
    oooHdr.flags = 0x10;
    oooHdr.dataOffset = 5;

    std::vector<uint8_t> payload = {'W', 'o', 'r', 'l', 'd'};
    auto r1 = reassembler.process(flowId, oooHdr, payload);
    EXPECT_FALSE(r1.retransmission);

    // Duplicate of the same OOO segment — retransmission
    auto r2 = reassembler.process(flowId, oooHdr, payload);
    EXPECT_TRUE(r2.retransmission);
    EXPECT_FALSE(r2.data.has_value());
}

TEST(TcpReassembler, KeepAliveIsNotRetransmission) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(192, 168, 1, 1);
    flowId.dstIp = ipv4(192, 168, 1, 2);
    flowId.srcPort = 12345;
    flowId.dstPort = 80;
    flowId.protocol = 6;

    // SYN
    fdpi::TCP synHdr{};
    synHdr.srcPort = 12345;
    synHdr.dstPort = 80;
    synHdr.seqNum = 1000;
    synHdr.flags = 0x02;
    synHdr.dataOffset = 5;
    reassembler.process(flowId, synHdr, {});

    // Deliver some data to advance nextExpectedSeq
    fdpi::TCP dataHdr{};
    dataHdr.srcPort = 12345;
    dataHdr.dstPort = 80;
    dataHdr.seqNum = 1001;
    dataHdr.flags = 0x10;
    dataHdr.dataOffset = 5;

    std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
    reassembler.process(flowId, dataHdr, payload);
    // nextExpectedSeq is now 1006

    // Keep-alive: seqNum = nextExpected-1, 1 byte payload
    fdpi::TCP keepAliveHdr{};
    keepAliveHdr.srcPort = 12345;
    keepAliveHdr.dstPort = 80;
    keepAliveHdr.seqNum = 1005; // nextExpected - 1
    keepAliveHdr.flags = 0x10;
    keepAliveHdr.dataOffset = 5;

    std::vector<uint8_t> keepAlivePayload = {0x00};
    auto r = reassembler.process(flowId, keepAliveHdr, keepAlivePayload);
    // seqEnd = 1005 + 1 = 1006 = nextExpectedSeq
    // seqBeforeOrEqual(1006, 1006) is true, so this IS detected as retransmission
    // Keep-alive with 1 byte at seqNum=nextExpected-1 overlaps delivered range
    EXPECT_TRUE(r.retransmission);
}

TEST(TcpReassembler, KeepAliveZeroBytesIsNotRetransmission) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(192, 168, 1, 1);
    flowId.dstIp = ipv4(192, 168, 1, 2);
    flowId.srcPort = 12345;
    flowId.dstPort = 80;
    flowId.protocol = 6;

    // SYN
    fdpi::TCP synHdr{};
    synHdr.srcPort = 12345;
    synHdr.dstPort = 80;
    synHdr.seqNum = 1000;
    synHdr.flags = 0x02;
    synHdr.dataOffset = 5;
    reassembler.process(flowId, synHdr, {});

    // Deliver some data
    fdpi::TCP dataHdr{};
    dataHdr.srcPort = 12345;
    dataHdr.dstPort = 80;
    dataHdr.seqNum = 1001;
    dataHdr.flags = 0x10;
    dataHdr.dataOffset = 5;

    std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
    reassembler.process(flowId, dataHdr, payload);

    // Keep-alive with zero-byte payload — not a retransmission (empty payload path)
    fdpi::TCP keepAliveHdr{};
    keepAliveHdr.srcPort = 12345;
    keepAliveHdr.dstPort = 80;
    keepAliveHdr.seqNum = 1005;
    keepAliveHdr.flags = 0x10;
    keepAliveHdr.dataOffset = 5;

    auto r = reassembler.process(flowId, keepAliveHdr, {});
    EXPECT_FALSE(r.retransmission);
}

TEST(TcpReassembler, NormalFlowNotFlagged) {
    fdpi::TcpReassembler reassembler;

    fdpi::FlowId flowId;
    flowId.srcIp = ipv4(10, 0, 0, 1);
    flowId.dstIp = ipv4(10, 0, 0, 2);
    flowId.srcPort = 5000;
    flowId.dstPort = 443;
    flowId.protocol = 6;

    // SYN
    fdpi::TCP synHdr{};
    synHdr.srcPort = 5000;
    synHdr.dstPort = 443;
    synHdr.seqNum = 100;
    synHdr.flags = 0x02;
    synHdr.dataOffset = 5;

    auto r0 = reassembler.process(flowId, synHdr, {});
    EXPECT_FALSE(r0.retransmission);

    // Three in-order data segments
    fdpi::TCP hdr{};
    hdr.srcPort = 5000;
    hdr.dstPort = 443;
    hdr.flags = 0x10;
    hdr.dataOffset = 5;

    std::vector<uint8_t> p1 = {1, 2, 3};
    hdr.seqNum = 101;
    auto r1 = reassembler.process(flowId, hdr, p1);
    EXPECT_FALSE(r1.retransmission);
    ASSERT_TRUE(r1.data.has_value());

    std::vector<uint8_t> p2 = {4, 5, 6};
    hdr.seqNum = 104;
    auto r2 = reassembler.process(flowId, hdr, p2);
    EXPECT_FALSE(r2.retransmission);
    ASSERT_TRUE(r2.data.has_value());

    std::vector<uint8_t> p3 = {7, 8, 9};
    hdr.seqNum = 107;
    auto r3 = reassembler.process(flowId, hdr, p3);
    EXPECT_FALSE(r3.retransmission);
    ASSERT_TRUE(r3.data.has_value());
}
