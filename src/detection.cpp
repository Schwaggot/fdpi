#include <fdpi/decoder.hpp>
#include <fdpi/packet.hpp>
#include <mutex>
#include <unordered_map>

namespace fdpi {

struct ProtocolDetectionEngine::Impl {
    struct FlowDetectionState {
        size_t packetsSeen{0};
        AppProtocol result{AppProtocol::Unknown};
        bool decided{false};
    };

    std::mutex mutex;
    std::unordered_map<FlowId, FlowDetectionState, FlowIdHash> flowStates;

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
                    const std::string_view sv(
                        reinterpret_cast<const char*>(payload.data()),
                        std::min(payload.size(), static_cast<size_t>(16)));
                    if (sv.starts_with("220 ") || sv.starts_with("USER ") ||
                        sv.starts_with("PASS ") || sv.starts_with("QUIT") ||
                        sv.starts_with("SYST") || sv.starts_with("FEAT")) {
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
        return state.result;
    }

    state.packetsSeen++;

    const auto detected = mImpl->detectSingle(packet, payload);
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
