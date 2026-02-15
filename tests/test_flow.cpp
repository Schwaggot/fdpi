#include <gtest/gtest.h>
#include <fdpi/flow_table.hpp>
#include <fdpi/packet.hpp>
#include <unordered_set>

namespace {

fdpi::IPv4Address ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return fdpi::IPv4Address{{{a, b, c, d}}};
}

} // anonymous namespace

TEST(FlowId, EqualityForIdenticalFlows) {
    fdpi::FlowId a;
    a.srcIp = ipv4(10, 0, 0, 1);
    a.dstIp = ipv4(10, 0, 0, 2);
    a.srcPort = 12345;
    a.dstPort = 80;
    a.protocol = 6;

    fdpi::FlowId b = a;
    EXPECT_EQ(a, b);
}

TEST(FlowId, InequalityForDifferentFlows) {
    fdpi::FlowId a;
    a.srcIp = ipv4(10, 0, 0, 1);
    a.dstIp = ipv4(10, 0, 0, 2);
    a.srcPort = 12345;
    a.dstPort = 80;
    a.protocol = 6;

    fdpi::FlowId b = a;
    b.dstPort = 443;
    EXPECT_NE(a, b);
}

TEST(FlowId, InequalityForDifferentProtocols) {
    fdpi::FlowId a;
    a.srcIp = ipv4(10, 0, 0, 1);
    a.dstIp = ipv4(10, 0, 0, 2);
    a.srcPort = 12345;
    a.dstPort = 80;
    a.protocol = 6;  // TCP

    fdpi::FlowId b = a;
    b.protocol = 17;  // UDP
    EXPECT_NE(a, b);
}

TEST(FlowIdHash, ConsistentHashing) {
    fdpi::FlowId id;
    id.srcIp = ipv4(10, 0, 0, 1);
    id.dstIp = ipv4(10, 0, 0, 2);
    id.srcPort = 12345;
    id.dstPort = 80;
    id.protocol = 6;

    fdpi::FlowIdHash hasher;
    auto h1 = hasher(id);
    auto h2 = hasher(id);
    EXPECT_EQ(h1, h2);
}

TEST(FlowIdHash, DifferentFlowsGetDifferentHashes) {
    fdpi::FlowIdHash hasher;

    fdpi::FlowId a;
    a.srcIp = ipv4(10, 0, 0, 1);
    a.dstIp = ipv4(10, 0, 0, 2);
    a.srcPort = 12345;
    a.dstPort = 80;
    a.protocol = 6;

    fdpi::FlowId b;
    b.srcIp = ipv4(10, 0, 0, 3);
    b.dstIp = ipv4(10, 0, 0, 4);
    b.srcPort = 54321;
    b.dstPort = 443;
    b.protocol = 6;

    EXPECT_NE(hasher(a), hasher(b));
}

TEST(FlowIdHash, UsableInUnorderedSet) {
    std::unordered_set<fdpi::FlowId, fdpi::FlowIdHash> flowSet;

    fdpi::FlowId id1;
    id1.srcIp = ipv4(10, 0, 0, 1);
    id1.dstIp = ipv4(10, 0, 0, 2);
    id1.srcPort = 12345;
    id1.dstPort = 80;
    id1.protocol = 6;

    fdpi::FlowId id2;
    id2.srcIp = ipv4(10, 0, 0, 3);
    id2.dstIp = ipv4(10, 0, 0, 4);
    id2.srcPort = 54321;
    id2.dstPort = 443;
    id2.protocol = 6;

    flowSet.insert(id1);
    flowSet.insert(id2);
    flowSet.insert(id1);  // duplicate

    EXPECT_EQ(flowSet.size(), 2u);
    EXPECT_TRUE(flowSet.count(id1) > 0);
    EXPECT_TRUE(flowSet.count(id2) > 0);
}

TEST(FlowTable, DefaultConstructionSucceeds) {
    fdpi::FlowTable table;
    EXPECT_EQ(table.size(), 0u);
}

TEST(FlowTable, ConfiguredConstruction) {
    fdpi::FlowTable::Config config;
    config.flowTimeout = std::chrono::seconds(30);
    config.maxFlows = 100;
    fdpi::FlowTable table(config);
    EXPECT_EQ(table.size(), 0u);
}

TEST(FlowTable, LookupNonexistentFlow) {
    fdpi::FlowTable table;

    fdpi::FlowId id;
    id.srcIp = ipv4(10, 0, 0, 1);
    id.dstIp = ipv4(10, 0, 0, 2);
    id.srcPort = 12345;
    id.dstPort = 80;
    id.protocol = 6;

    auto result = table.lookup(id);
    EXPECT_FALSE(result.has_value());
}

TEST(FlowTable, InsertAndLookup) {
    fdpi::FlowTable table;

    fdpi::Packet pkt;
    pkt.flowId.srcIp = ipv4(10, 0, 0, 1);
    pkt.flowId.dstIp = ipv4(10, 0, 0, 2);
    pkt.flowId.srcPort = 12345;
    pkt.flowId.dstPort = 80;
    pkt.flowId.protocol = 6;
    pkt.timestamp = 1000;

    table.update(pkt);
    EXPECT_EQ(table.size(), 1u);

    auto result = table.lookup(pkt.flowId);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->packetCount, 1u);
}

TEST(FlowTable, UpdateIncrementsCounters) {
    fdpi::FlowTable table;

    fdpi::Packet pkt;
    pkt.flowId.srcIp = ipv4(10, 0, 0, 1);
    pkt.flowId.dstIp = ipv4(10, 0, 0, 2);
    pkt.flowId.srcPort = 12345;
    pkt.flowId.dstPort = 80;
    pkt.flowId.protocol = 6;
    pkt.timestamp = 1000;

    table.update(pkt);
    pkt.timestamp = 2000;
    table.update(pkt);
    pkt.timestamp = 3000;
    table.update(pkt);

    auto result = table.lookup(pkt.flowId);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->packetCount, 3u);
    EXPECT_EQ(result->firstSeen, 1000u);
    EXPECT_EQ(result->lastSeen, 3000u);
}

TEST(FlowTable, MultipleDistinctFlows) {
    fdpi::FlowTable table;

    fdpi::Packet pkt1;
    pkt1.flowId.srcIp = ipv4(10, 0, 0, 1);
    pkt1.flowId.dstIp = ipv4(10, 0, 0, 2);
    pkt1.flowId.srcPort = 12345;
    pkt1.flowId.dstPort = 80;
    pkt1.flowId.protocol = 6;

    fdpi::Packet pkt2;
    pkt2.flowId.srcIp = ipv4(10, 0, 0, 3);
    pkt2.flowId.dstIp = ipv4(10, 0, 0, 4);
    pkt2.flowId.srcPort = 54321;
    pkt2.flowId.dstPort = 443;
    pkt2.flowId.protocol = 6;

    table.update(pkt1);
    table.update(pkt2);
    EXPECT_EQ(table.size(), 2u);
}

TEST(FlowTable, ForEachVisitsAllFlows) {
    fdpi::FlowTable table;

    for (uint16_t i = 0; i < 5; ++i) {
        fdpi::Packet pkt;
        pkt.flowId.srcIp = ipv4(10, 0, 0, 1);
        pkt.flowId.dstIp = ipv4(10, 0, 0, 2);
        pkt.flowId.srcPort = static_cast<uint16_t>(10000 + i);
        pkt.flowId.dstPort = 80;
        pkt.flowId.protocol = 6;
        table.update(pkt);
    }

    size_t count = 0;
    table.forEach([&count](const fdpi::FlowMetadata&) { ++count; });
    EXPECT_EQ(count, 5u);
}

TEST(FlowMetadata, InitialState) {
    fdpi::FlowMetadata meta;
    EXPECT_EQ(meta.firstSeen, 0u);
    EXPECT_EQ(meta.lastSeen, 0u);
    EXPECT_EQ(meta.packetCount, 0u);
    EXPECT_EQ(meta.byteCount, 0u);
    EXPECT_FALSE(meta.detectedProtocol.has_value());
}
