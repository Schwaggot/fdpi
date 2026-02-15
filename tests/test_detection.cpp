#include <gtest/gtest.h>
#include <fdpi/decoder.hpp>
#include <fdpi/packet.hpp>
#include <vector>

// Helper to build a minimal packet with transport layer info for detection
static fdpi::Packet makePacket(uint8_t protocol, uint16_t srcPort, uint16_t dstPort) {
    fdpi::Packet pkt;
    pkt.flowId.srcIp = fdpi::IPv4Address{{{10, 0, 0, 1}}};
    pkt.flowId.dstIp = fdpi::IPv4Address{{{10, 0, 0, 2}}};
    pkt.flowId.srcPort = srcPort;
    pkt.flowId.dstPort = dstPort;
    pkt.flowId.protocol = protocol;

    if (protocol == 6) {
        fdpi::TCP tcp;
        tcp.srcPort = srcPort;
        tcp.dstPort = dstPort;
        tcp.flags = 0x18;  // PSH+ACK
        pkt.layer4 = tcp;
    } else if (protocol == 17) {
        fdpi::UDP udp;
        udp.srcPort = srcPort;
        udp.dstPort = dstPort;
        pkt.layer4 = udp;
    }
    return pkt;
}

TEST(ProtocolDetection, DetectsDNSOnPort53) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(17, 49152, 53);  // UDP to port 53

    // DNS query payload (minimal)
    std::vector<uint8_t> payload = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a',
        'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
        0x00, 0x00, 0x01, 0x00, 0x01
    };

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::DNS);
}

TEST(ProtocolDetection, DetectsHTTPOnPort80) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 80);  // TCP to port 80

    std::string httpReq = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    std::vector<uint8_t> payload(httpReq.begin(), httpReq.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::HTTP);
}

TEST(ProtocolDetection, DetectsTLSOnPort443) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 443);  // TCP to port 443

    // TLS ClientHello start
    std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x05,  // TLS record header
        0x01, 0x00, 0x00, 0x01, 0x03   // Handshake header start
    };

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::TLS);
}

TEST(ProtocolDetection, DetectsQUICOnUDP443) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(17, 49152, 443);  // UDP to port 443

    // QUIC Initial packet (long header)
    std::vector<uint8_t> payload = {
        0xC0,                          // long header, Initial
        0x00, 0x00, 0x00, 0x01,       // version 1
        0x08,                          // DCID length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x00                           // SCID length: 0
    };

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::QUIC);
}

TEST(ProtocolDetection, DetectsHTTPOnNonStandardPort) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 8080);  // TCP to port 8080

    std::string httpReq = "POST /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
    std::vector<uint8_t> payload(httpReq.begin(), httpReq.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::HTTP);
}

TEST(ProtocolDetection, ReturnsUnknownForEmptyPayload) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 80);

    std::vector<uint8_t> payload;
    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::Unknown);
}

TEST(ProtocolDetection, ReturnsUnknownForUnrecognizedProtocol) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 9999);

    // Random binary payload
    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::Unknown);
}

TEST(ProtocolDetection, DetectsDNSOnTCP) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 53);  // TCP to port 53

    // DNS over TCP has 2-byte length prefix
    std::vector<uint8_t> payload = {
        0x00, 0x1D,  // length prefix
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a',
        'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
        0x00, 0x00, 0x01, 0x00, 0x01
    };

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::DNS);
}

TEST(ProtocolDetectionEngine, DefaultConstruction) {
    fdpi::ProtocolDetectionEngine engine;
    // Should not crash
}
