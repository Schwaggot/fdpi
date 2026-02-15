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
