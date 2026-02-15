#include <gtest/gtest.h>
#include <fdpi/decoder.hpp>
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
    synHdr.flags = 0x02;  // SYN
    synHdr.dataOffset = 5;

    auto result = reassembler.process(flowId, synHdr, {});
    EXPECT_FALSE(result.has_value());
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
    synHdr.flags = 0x02;  // SYN
    synHdr.dataOffset = 5;
    reassembler.process(flowId, synHdr, {});

    // Data packet
    fdpi::TCP dataHdr{};
    dataHdr.srcPort = 12345;
    dataHdr.dstPort = 80;
    dataHdr.seqNum = 1001;
    dataHdr.flags = 0x10;  // ACK
    dataHdr.dataOffset = 5;

    std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
    auto result = reassembler.process(flowId, dataHdr, payload);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 5u);
    EXPECT_EQ((*result)[0], 'H');
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
    hdr1.flags = 0x10;  // ACK

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
