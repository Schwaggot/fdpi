#include <fdpi/decoder.hpp>
#include <fdpi/packet.hpp>

#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace fdpi {

struct ProtocolDetectionEngine::Impl {
    struct FlowDetectionState {
        size_t packetsSeen{0};
        AppProtocol result{AppProtocol::Unknown};
        bool decided{false};
    };

    std::mutex mutex;
    std::unordered_map<FlowId, FlowDetectionState, FlowIdHash> flowStates;
    std::unordered_set<uint16_t> tftpPorts; // ephemeral ports from TFTP flows

    AppProtocol detectSingle(const Packet& packet,
                             const std::span<const uint8_t> payload) const {
        // Port-based hints first
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;

        if (auto* tcp = std::get_if<TCP>(&packet.layer4)) {
            srcPort = tcp->srcPort;
            dstPort = tcp->dstPort;
        } else if (auto* udp = std::get_if<UDP>(&packet.layer4)) {
            srcPort = udp->srcPort;
            dstPort = udp->dstPort;
        }

        // mDNS: UDP port 5353
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 5353 || dstPort == 5353) {
                if (payload.size() >= 12) {
                    return AppProtocol::MDNS;
                }
            }
        }

        // LLMNR: UDP port 5355
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 5355 || dstPort == 5355) {
                if (payload.size() >= 12) {
                    return AppProtocol::LLMNR;
                }
            }
        }

        // DNS: port 53
        if (srcPort == 53 || dstPort == 53) {
            if (payload.size() >= 12) {
                return AppProtocol::DNS;
            }
        }

        // HTTP: ports 80, 8080 or payload-based detection
        if (srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080) {
            if (payload.size() >= 4) {
                // Check for HTTP methods or "HTTP/" response
                const std::string_view sv(
                    reinterpret_cast<const char*>(payload.data()),
                    std::min(payload.size(), static_cast<size_t>(16)));
                if (sv.starts_with("GET ") || sv.starts_with("POST ") ||
                    sv.starts_with("PUT ") || sv.starts_with("DELETE ") ||
                    sv.starts_with("HEAD ") || sv.starts_with("HTTP/")) {
                    return AppProtocol::HTTP;
                }
            }
        }

        // RFC 5764 / RFC 7983 demultiplexing for UDP:
        // Byte 0 range determines protocol on multiplexed flows.
        //   0-3:     STUN
        //   20-63:   DTLS
        //   128-191: RTP/RTCP
        if (std::holds_alternative<UDP>(packet.layer4) && !payload.empty()) {
            uint8_t firstByte = payload[0];

            // STUN range (0-3): magic cookie 0x2112A442 at offset 4
            if ((firstByte & 0xC0) == 0x00 && payload.size() >= 20) {
                if (payload[4] == 0x21 && payload[5] == 0x12 && payload[6] == 0xA4 &&
                    payload[7] == 0x42) {
                    return AppProtocol::STUN;
                }
            }

            // DTLS range (20-63): content type + DTLS version
            if (firstByte >= 20 && firstByte <= 63 && payload.size() >= 13) {
                uint16_t ver = static_cast<uint16_t>((payload[1] << 8) | payload[2]);
                if (ver == 0xFEFD || ver == 0xFEFF || ver == 0xFEFC) {
                    return AppProtocol::DTLS;
                }
            }

            // RTP/RTCP range (128-191): version=2, PT 200-211 → RTCP
            if (firstByte >= 128 && firstByte <= 191 && payload.size() >= 8) {
                uint8_t pt = payload[1];
                if (pt >= 200 && pt <= 211) {
                    return AppProtocol::RTCP;
                }
            }
        }

        // QUIC: UDP port 443 with QUIC long header bit
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if ((srcPort == 443 || dstPort == 443) && payload.size() >= 1) {
                if (payload[0] & 0x80) {
                    return AppProtocol::QUIC;
                }
            }
        }

        // TLS: TCP port 443 or content type check
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 443 || dstPort == 443) {
                if (payload.size() >= 5) {
                    const uint8_t contentType = payload[0];
                    if (contentType >= 20 && contentType <= 23) {
                        return AppProtocol::TLS;
                    }
                }
            }
        }

        // FTP: TCP port 21
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 21 || dstPort == 21) {
                if (payload.size() >= 4) {
                    // FTP response: 3-digit code + space or hyphen (RFC 959)
                    if (payload[0] >= '1' && payload[0] <= '5' && payload[1] >= '0' &&
                        payload[1] <= '9' && payload[2] >= '0' && payload[2] <= '9' &&
                        (payload[3] == ' ' || payload[3] == '-')) {
                        return AppProtocol::FTP;
                    }
                    // FTP commands
                    const std::string_view sv(
                        reinterpret_cast<const char*>(payload.data()),
                        std::min(payload.size(), static_cast<size_t>(16)));
                    if (sv.starts_with("USER ") || sv.starts_with("PASS ") ||
                        sv.starts_with("QUIT") || sv.starts_with("SYST") ||
                        sv.starts_with("FEAT") || sv.starts_with("CWD ") ||
                        sv.starts_with("PWD") || sv.starts_with("TYPE ") ||
                        sv.starts_with("PASV") || sv.starts_with("PORT ") ||
                        sv.starts_with("LIST") || sv.starts_with("RETR ") ||
                        sv.starts_with("STOR ") || sv.starts_with("DELE ") ||
                        sv.starts_with("SIZE ") || sv.starts_with("NOOP") ||
                        sv.starts_with("noop") || sv.starts_with("MKD ") ||
                        sv.starts_with("RMD ") || sv.starts_with("EPSV") ||
                        sv.starts_with("EPRT")) {
                        return AppProtocol::FTP;
                    }
                }
            }
        }

        // SSH: TCP port 22
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 22 || dstPort == 22) {
                if (payload.size() >= 4) {
                    const std::string_view sv(
                        reinterpret_cast<const char*>(payload.data()),
                        std::min(payload.size(), static_cast<size_t>(8)));
                    if (sv.starts_with("SSH-")) {
                        return AppProtocol::SSH;
                    }
                }
            }
        }

        // Telnet: TCP port 23
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 23 || dstPort == 23) {
                if (payload.size() >= 1) {
                    return AppProtocol::Telnet;
                }
            }
        }

        // SMTP: TCP ports 25, 587
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 25 || dstPort == 25 || srcPort == 587 || dstPort == 587) {
                if (payload.size() >= 4) {
                    const std::string_view sv(
                        reinterpret_cast<const char*>(payload.data()),
                        std::min(payload.size(), static_cast<size_t>(16)));
                    if (sv.starts_with("220 ") || sv.starts_with("EHLO ") ||
                        sv.starts_with("HELO ") || sv.starts_with("MAIL ") ||
                        sv.starts_with("250 ")) {
                        return AppProtocol::SMTP;
                    }
                }
            }
        }

        // POP3: TCP port 110
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 110 || dstPort == 110) {
                if (payload.size() >= 3) {
                    const std::string_view sv(
                        reinterpret_cast<const char*>(payload.data()),
                        std::min(payload.size(), static_cast<size_t>(16)));
                    if (sv.starts_with("+OK") || sv.starts_with("-ERR") ||
                        sv.starts_with("USER") || sv.starts_with("PASS")) {
                        return AppProtocol::POP3;
                    }
                }
            }
        }

        // IMAP: TCP port 143
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 143 || dstPort == 143) {
                if (payload.size() >= 4) {
                    const std::string_view sv(
                        reinterpret_cast<const char*>(payload.data()),
                        std::min(payload.size(), static_cast<size_t>(16)));
                    if (sv.starts_with("* OK") || sv.starts_with("* BYE") ||
                        sv.starts_with("* NO")) {
                        return AppProtocol::IMAP;
                    }
                }
            }
        }

        // BGP: TCP port 179
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 179 || dstPort == 179) {
                if (payload.size() >= 19) {
                    // Check for 16-byte all-0xFF marker
                    bool validMarker = true;
                    for (size_t i = 0; i < 16; ++i) {
                        if (payload[i] != 0xFF) {
                            validMarker = false;
                            break;
                        }
                    }
                    if (validMarker) {
                        return AppProtocol::BGP;
                    }
                }
            }
        }

        // RDP: TCP port 3389
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 3389 || dstPort == 3389) {
                if (payload.size() >= 7) {
                    // TPKT header: version 3 + reserved 0
                    if (payload[0] == 0x03 && payload[1] == 0x00) {
                        return AppProtocol::RDP;
                    }
                }
            }
        }

        // LDAP: TCP port 389
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 389 || dstPort == 389) {
                if (payload.size() >= 2) {
                    // ASN.1 SEQUENCE tag
                    if (payload[0] == 0x30) {
                        return AppProtocol::LDAP;
                    }
                }
            }
        }

        // SSDP: UDP port 1900
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 1900 || dstPort == 1900) {
                if (payload.size() >= 4) {
                    const std::string_view sv(
                        reinterpret_cast<const char*>(payload.data()),
                        std::min(payload.size(), static_cast<size_t>(16)));
                    if (sv.starts_with("M-SEARCH") || sv.starts_with("NOTIFY") ||
                        sv.starts_with("HTTP/")) {
                        return AppProtocol::SSDP;
                    }
                }
            }
        }

        // SrvLoc: UDP/TCP port 427
        if (srcPort == 427 || dstPort == 427) {
            if (payload.size() >= 5) {
                uint8_t ver = payload[0];
                if (ver == 1 || ver == 2) {
                    return AppProtocol::SrvLoc;
                }
            }
        }

        // NBNS: UDP port 137
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 137 || dstPort == 137) {
                if (payload.size() >= 12) {
                    return AppProtocol::NBNS;
                }
            }
        }

        // NBDGM: UDP port 138
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 138 || dstPort == 138) {
                if (payload.size() >= 10) {
                    return AppProtocol::NBDGM;
                }
            }
        }

        // SMB: TCP ports 139/445
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 445 || dstPort == 445) {
                if (payload.size() >= 4) {
                    // Check for SMB1 or SMB2/3 magic
                    if ((payload[0] == 0xFF || payload[0] == 0xFE) && payload[1] == 'S' &&
                        payload[2] == 'M' && payload[3] == 'B') {
                        return AppProtocol::SMB;
                    }
                }
            }
            if (srcPort == 139 || dstPort == 139) {
                // Skip 4-byte NBT session header
                if (payload.size() >= 8) {
                    if ((payload[4] == 0xFF || payload[4] == 0xFE) && payload[5] == 'S' &&
                        payload[6] == 'M' && payload[7] == 'B') {
                        return AppProtocol::SMB;
                    }
                }
            }
        }

        // RTMP: TCP port 1935
        if (std::holds_alternative<TCP>(packet.layer4)) {
            if (srcPort == 1935 || dstPort == 1935) {
                if (payload.size() >= 1) {
                    return AppProtocol::RTMP;
                }
            }
        }

        // Dropbox LAN Sync: UDP port 17500 + JSON payload
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 17500 || dstPort == 17500) {
                if (payload.size() >= 2 && payload[0] == '{') {
                    return AppProtocol::DbLanSyncDisc;
                }
            }
        }

        // NTP: UDP port 123
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 123 || dstPort == 123) {
                if (payload.size() >= 48) {
                    uint8_t version = (payload[0] >> 3) & 0x07;
                    uint8_t mode = payload[0] & 0x07;
                    if ((version == 3 || version == 4) && mode >= 1 && mode <= 5) {
                        return AppProtocol::NTP;
                    }
                }
            }
        }

        // DHCP: UDP ports 67/68
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68) {
                if (payload.size() >= 240) {
                    // Check DHCP magic cookie at offset 236
                    if (payload[236] == 0x63 && payload[237] == 0x82 &&
                        payload[238] == 0x53 && payload[239] == 0x63) {
                        return AppProtocol::DHCP;
                    }
                }
            }
        }

        // DHCPv6: UDP ports 546/547
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 546 || dstPort == 546 || srcPort == 547 || dstPort == 547) {
                if (payload.size() >= 4) {
                    uint8_t msgType = payload[0];
                    if (msgType >= 1 && msgType <= 13) {
                        return AppProtocol::DHCPv6;
                    }
                }
            }
        }

        // TFTP: UDP port 69
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 69 || dstPort == 69) {
                if (payload.size() >= 4) {
                    const uint16_t opcode = (payload[0] << 8) | payload[1];
                    if (opcode >= 1 && opcode <= 5) {
                        return AppProtocol::TFTP;
                    }
                }
            }
        }

        // SNMP: UDP ports 161/162
        if (std::holds_alternative<UDP>(packet.layer4)) {
            if (srcPort == 161 || dstPort == 161 || srcPort == 162 || dstPort == 162) {
                if (payload.size() >= 2) {
                    // ASN.1 SEQUENCE tag
                    if (payload[0] == 0x30) {
                        return AppProtocol::SNMP;
                    }
                }
            }
        }

        // Payload-based detection (no port hints)
        if (payload.size() >= 5) {
            const uint8_t ct = payload[0];
            if (ct >= 20 && ct <= 23) {
                const uint16_t ver =
                    static_cast<uint16_t>((payload[1] << 8) | payload[2]);
                if (ver == 0x0301 || ver == 0x0303 || ver == 0x0302 || ver == 0x0300) {
                    return AppProtocol::TLS;
                }
            }
        }

        if (payload.size() >= 4) {
            const std::string_view sv(reinterpret_cast<const char*>(payload.data()),
                                      std::min(payload.size(), static_cast<size_t>(16)));
            if (sv.starts_with("GET ") || sv.starts_with("POST ") ||
                sv.starts_with("PUT ") || sv.starts_with("DELETE ") ||
                sv.starts_with("HEAD ") || sv.starts_with("OPTIONS ") ||
                sv.starts_with("PATCH ") || sv.starts_with("HTTP/")) {
                return AppProtocol::HTTP;
            }
        }

        // QUIC on non-standard ports: UDP + long header bit + valid QUIC version
        if (std::holds_alternative<UDP>(packet.layer4) && payload.size() >= 5) {
            if ((payload[0] & 0x80) != 0) {
                // Check for known QUIC versions at bytes 1-4
                const uint32_t ver = (static_cast<uint32_t>(payload[1]) << 24) |
                                     (static_cast<uint32_t>(payload[2]) << 16) |
                                     (static_cast<uint32_t>(payload[3]) << 8) |
                                     static_cast<uint32_t>(payload[4]);
                // QUIC v1 = 0x00000001, QUIC v2 = 0x6b3343cf
                if (ver == 0x00000001 || ver == 0x6b3343cf || ver == 0xff000000) {
                    return AppProtocol::QUIC;
                }
            }
        }

        // SSH portless detection
        if (payload.size() >= 4) {
            const std::string_view sv(reinterpret_cast<const char*>(payload.data()),
                                      std::min(payload.size(), static_cast<size_t>(8)));
            if (sv.starts_with("SSH-")) {
                return AppProtocol::SSH;
            }
        }

        // BGP portless detection: 16 bytes of 0xFF + valid type 1-5
        if (payload.size() >= 19) {
            bool validMarker = true;
            for (size_t i = 0; i < 16; ++i) {
                if (payload[i] != 0xFF) {
                    validMarker = false;
                    break;
                }
            }
            if (validMarker) {
                uint8_t bgpType = payload[18];
                if (bgpType >= 1 && bgpType <= 5) {
                    return AppProtocol::BGP;
                }
            }
        }

        return AppProtocol::Unknown;
    }
};

ProtocolDetectionEngine::ProtocolDetectionEngine() : mImpl(std::make_unique<Impl>()) {}
ProtocolDetectionEngine::~ProtocolDetectionEngine() = default;

AppProtocol ProtocolDetectionEngine::detect(const Packet& packet,
                                            std::span<const uint8_t> payload) const {
    return mImpl->detectSingle(packet, payload);
}

AppProtocol ProtocolDetectionEngine::detectFlow(const FlowId& flowId,
                                                const Packet& packet,
                                                const std::span<const uint8_t> payload,
                                                const size_t maxPackets) {
    std::lock_guard lock(mImpl->mutex);

    auto& state = mImpl->flowStates[flowId];
    if (state.decided) {
        // For WebRTC-multiplexed protocols (RFC 5764), re-detect per
        // packet because STUN, DTLS and RTCP share the same 5-tuple.
        if (state.result == AppProtocol::STUN || state.result == AppProtocol::DTLS ||
            state.result == AppProtocol::RTCP) {
            return mImpl->detectSingle(packet, payload);
        }
        return state.result;
    }

    state.packetsSeen++;

    auto detected = mImpl->detectSingle(packet, payload);

    // TFTP conversation tracking: detect DATA/ACK/ERROR on ephemeral ports
    if (detected == AppProtocol::Unknown && std::holds_alternative<UDP>(packet.layer4)) {
        if (mImpl->tftpPorts.contains(flowId.srcPort) ||
            mImpl->tftpPorts.contains(flowId.dstPort)) {
            if (payload.size() >= 4) {
                uint16_t opcode = static_cast<uint16_t>((payload[0] << 8) | payload[1]);
                if (opcode >= 1 && opcode <= 5) {
                    detected = AppProtocol::TFTP;
                }
            }
        }
    }

    // When TFTP is detected, track both ports for conversation following
    if (detected == AppProtocol::TFTP) {
        if (flowId.srcPort != 69) {
            mImpl->tftpPorts.insert(flowId.srcPort);
        }
        if (flowId.dstPort != 69) {
            mImpl->tftpPorts.insert(flowId.dstPort);
        }
    }

    if (detected != AppProtocol::Unknown) {
        state.result = detected;
        state.decided = true;
        return detected;
    }

    if (state.packetsSeen >= maxPackets) {
        state.decided = true;
    }

    return state.result;
}

} // namespace fdpi
