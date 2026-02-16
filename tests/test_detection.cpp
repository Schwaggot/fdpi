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
        tcp.flags = 0x18; // PSH+ACK
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
    auto pkt = makePacket(17, 49152, 53); // UDP to port 53

    // DNS query payload (minimal)
    std::vector<uint8_t> payload = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
                                    'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
                                    0x00, 0x00, 0x01, 0x00, 0x01};

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::DNS);
}

TEST(ProtocolDetection, DetectsHTTPOnPort80) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 80); // TCP to port 80

    std::string httpReq = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    std::vector<uint8_t> payload(httpReq.begin(), httpReq.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::HTTP);
}

TEST(ProtocolDetection, DetectsTLSOnPort443) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 443); // TCP to port 443

    // TLS ClientHello start
    std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x05, // TLS record header
        0x01, 0x00, 0x00, 0x01, 0x03  // Handshake header start
    };

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::TLS);
}

TEST(ProtocolDetection, DetectsQUICOnUDP443) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(17, 49152, 443); // UDP to port 443

    // QUIC Initial packet (long header)
    std::vector<uint8_t> payload = {
        0xC0,                   // long header, Initial
        0x00, 0x00, 0x00, 0x01, // version 1
        0x08,                   // DCID length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x00 // SCID length: 0
    };

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::QUIC);
}

TEST(ProtocolDetection, DetectsHTTPOnNonStandardPort) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 8080); // TCP to port 8080

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
    auto pkt = makePacket(6, 49152, 53); // TCP to port 53

    // DNS over TCP has 2-byte length prefix
    std::vector<uint8_t> payload = {0x00, 0x1D, // length prefix
                                    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
                                    'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
                                    0x00, 0x00, 0x01, 0x00, 0x01};

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::DNS);
}

TEST(ProtocolDetection, DetectsFTPOnPort21) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 21, 49152); // TCP from port 21

    std::string greeting = "220 ProFTPD Server\r\n";
    std::vector<uint8_t> payload(greeting.begin(), greeting.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::FTP);
}

TEST(ProtocolDetection, DetectsSSHOnPort22) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 22, 49152); // TCP from port 22

    std::string banner = "SSH-2.0-OpenSSH_9.0\r\n";
    std::vector<uint8_t> payload(banner.begin(), banner.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::SSH);
}

TEST(ProtocolDetection, DetectsSMTPOnPort25) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 25, 49152); // TCP from port 25

    std::string greeting = "220 mail.example.com ESMTP\r\n";
    std::vector<uint8_t> payload(greeting.begin(), greeting.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::SMTP);
}

TEST(ProtocolDetection, DetectsPOP3OnPort110) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 110, 49152); // TCP from port 110

    std::string greeting = "+OK POP3 server ready\r\n";
    std::vector<uint8_t> payload(greeting.begin(), greeting.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::POP3);
}

TEST(ProtocolDetection, DetectsIMAPOnPort143) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 143, 49152); // TCP from port 143

    std::string greeting = "* OK IMAP4rev1 Service Ready\r\n";
    std::vector<uint8_t> payload(greeting.begin(), greeting.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::IMAP);
}

TEST(ProtocolDetection, DetectsBGPOnPort179) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 179); // TCP to port 179

    // BGP KEEPALIVE: 16 bytes 0xFF marker + length(19) + type(4)
    std::vector<uint8_t> payload = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0x00, 0x13, 0x04};

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::BGP);
}

TEST(ProtocolDetection, DetectsLDAPOnPort389) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 389); // TCP to port 389

    // LDAP BindRequest: SEQUENCE tag
    std::vector<uint8_t> payload = {0x30, 0x16, 0x02, 0x01, 0x01, 0x60, 0x11, 0x02,
                                    0x01, 0x03, 0x04, 0x08, 'c',  'n',  '=',  'a',
                                    'd',  'm',  'i',  'n',  0x80, 0x02, 'p',  'w'};

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::LDAP);
}

TEST(ProtocolDetection, DetectsNTPOnPort123) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(17, 49152, 123); // UDP to port 123

    // NTP v4 client request: LI=0, VN=4, Mode=3
    std::vector<uint8_t> payload(48, 0);
    payload[0] = 0x23; // LI=0, VN=4, Mode=3

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::NTP);
}

TEST(ProtocolDetection, DetectsDHCPOnPort67) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(17, 49152, 67); // UDP to port 67

    // DHCP: 236-byte header + magic cookie
    std::vector<uint8_t> payload(240, 0);
    payload[0] = 1; // BOOTREQUEST
    // Magic cookie at offset 236
    payload[236] = 0x63;
    payload[237] = 0x82;
    payload[238] = 0x53;
    payload[239] = 0x63;

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::DHCP);
}

TEST(ProtocolDetection, DetectsDHCPv6OnPort547) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(17, 49152, 547); // UDP to port 547

    // DHCPv6 Solicit: msgType=1, txnId=0x123456
    std::vector<uint8_t> payload = {0x01, 0x12, 0x34, 0x56};

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::DHCPv6);
}

TEST(ProtocolDetection, DetectsSNMPOnPort161) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(17, 49152, 161); // UDP to port 161

    // SNMP v1 GetRequest: ASN.1 SEQUENCE
    std::vector<uint8_t> payload = {0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06,
                                    'p',  'u',  'b',  'l',  'i',  'c',  0xA0,
                                    0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01};

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::SNMP);
}

TEST(ProtocolDetection, DetectsRDPOnPort3389) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 3389); // TCP to port 3389

    // TPKT header: version 3 + reserved + length
    std::vector<uint8_t> payload = {0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
                                    0x00, 0x03, 0x00, 0x00, 0x00};

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::RDP);
}

TEST(ProtocolDetection, DetectsSSHPortless) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 9999); // TCP non-standard port

    std::string banner = "SSH-2.0-OpenSSH_9.0\r\n";
    std::vector<uint8_t> payload(banner.begin(), banner.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::SSH);
}

TEST(ProtocolDetection, DetectsBGPPortless) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 49152, 9999); // TCP non-standard port

    // BGP OPEN with valid marker and type 1
    std::vector<uint8_t> payload = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x1D, 0x01, // type 1 = OPEN
        0x04, 0x00, 0x01, 0x00, 0xB4, 0x0A, 0x00, 0x00, 0x01, 0x00};

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::BGP);
}

TEST(ProtocolDetection, DetectsSMTPOnPort587) {
    fdpi::ProtocolDetectionEngine engine;
    auto pkt = makePacket(6, 587, 49152); // TCP from port 587

    std::string greeting = "220 smtp.example.com ESMTP\r\n";
    std::vector<uint8_t> payload(greeting.begin(), greeting.end());

    auto result = engine.detect(pkt, payload);
    EXPECT_EQ(result, fdpi::AppProtocol::SMTP);
}

TEST(ProtocolDetectionEngine, DefaultConstruction) {
    fdpi::ProtocolDetectionEngine engine;
    // Should not crash
}
