#include <fdpi/datalink.hpp>
#include <fdpi/decoder.hpp>

namespace fdpi {

namespace {

// EtherType constants
constexpr uint16_t kEtherTypeIPv4 = 0x0800;
constexpr uint16_t kEtherTypeIPv6 = 0x86DD;
constexpr uint16_t kEtherTypeARP = 0x0806;
constexpr uint16_t kEtherTypeRARP = 0x8035;
constexpr uint16_t kEtherTypeVLAN = 0x8100;
constexpr uint16_t kEtherTypeQinQ = 0x88A8;
constexpr uint16_t kEtherTypeMPLS = 0x8847;

// IP protocol constants
constexpr uint8_t kProtoICMP = 1;
constexpr uint8_t kProtoTCP = 6;
constexpr uint8_t kProtoUDP = 17;
constexpr uint8_t kProtoGRE = 47;
constexpr uint8_t kProtoIPv6Frag = 44;
constexpr uint8_t kProtoICMPv6 = 58;

FlowId buildFlowId(const Packet& pkt) {
    FlowId id{};

    // Extract IPs from L3
    if (auto* v4 = std::get_if<IPv4>(&pkt.layer3)) {
        id.srcIp = v4->srcIp;
        id.dstIp = v4->dstIp;
        id.protocol = v4->protocol;
    } else if (auto* v6 = std::get_if<IPv6>(&pkt.layer3)) {
        id.srcIp = v6->srcIp;
        id.dstIp = v6->dstIp;
        id.protocol = v6->nextHeader;
    }

    // Extract ports from L4
    if (auto* tcp = std::get_if<TCP>(&pkt.layer4)) {
        id.srcPort = tcp->srcPort;
        id.dstPort = tcp->dstPort;
    } else if (auto* udp = std::get_if<UDP>(&pkt.layer4)) {
        id.srcPort = udp->srcPort;
        id.dstPort = udp->dstPort;
    }

    return id;
}

} // anonymous namespace

struct PacketDecoder::Impl {
    Config config;
    FlowTable flowTable;
    IpDefragmenter defragmenter;
    TcpReassembler reassembler;
    ProtocolDetectionEngine detector;

    explicit Impl(const Config& cfg)
        : config(cfg),
          flowTable(cfg.flowTableConfig),
          defragmenter(cfg.defragConfig),
          reassembler(cfg.reassemblyConfig) {}
};

PacketDecoder::PacketDecoder(Config config) : mImpl(std::make_unique<Impl>(config)) {}

PacketDecoder::~PacketDecoder() = default;

std::expected<Packet, Error> PacketDecoder::decode(std::span<const uint8_t> data,
                                                   uint64_t timestamp,
                                                   DataLinkType dlt) const {
    if (data.empty()) {
        return std::unexpected(Error::BufferTooSmall);
    }

    Packet pkt{};
    pkt.timestamp = timestamp;
    pkt.dlt = dlt;
    pkt.captureLength = static_cast<uint32_t>(data.size());
    pkt.wireLength = static_cast<uint32_t>(data.size());

    size_t offset = 0;
    uint16_t etherType = 0;

    if (dlt == DataLinkType::DLT_EN10MB) {
        // === L2: Ethernet fast path (exact original behavior) ===
        auto ethResult = decodeEthernet(data, offset);
        if (!ethResult) {
            return std::unexpected(ethResult.error());
        }
        pkt.ethernet = *ethResult;
        etherType = ethResult->etherType;

        // Handle VLAN tags
        while (etherType == kEtherTypeVLAN || etherType == kEtherTypeQinQ) {
            auto vlanResult = decodeVlan(data, offset);
            if (!vlanResult) {
                return std::unexpected(vlanResult.error());
            }
            pkt.vlan = *vlanResult;
            etherType = vlanResult->etherType;
        }
    } else {
        // === L2: Generic DLT dispatch ===
        auto linkResult = resolveDataLink(dlt, data, offset);
        if (!linkResult) {
            return std::unexpected(linkResult.error());
        }
        etherType = linkResult->etherType;

        if (linkResult->hasMacs) {
            Ethernet eth{};
            eth.dst = linkResult->dstMac;
            eth.src = linkResult->srcMac;
            eth.etherType = linkResult->etherType;
            pkt.ethernet = eth;
        }

        // Linux SLL captures may carry VLAN tags
        if (dlt == DataLinkType::DLT_LINUX_SLL || dlt == DataLinkType::DLT_LINUX_SLL2) {
            while (etherType == kEtherTypeVLAN || etherType == kEtherTypeQinQ) {
                auto vlanResult = decodeVlan(data, offset);
                if (!vlanResult) {
                    return std::unexpected(vlanResult.error());
                }
                pkt.vlan = *vlanResult;
                etherType = vlanResult->etherType;
            }
        }
    }

    // Handle MPLS
    if (etherType == kEtherTypeMPLS) {
        auto mplsResult = decodeMpls(data, offset);
        if (!mplsResult) {
            return std::unexpected(mplsResult.error());
        }
        // After MPLS, inspect the first nibble to determine if it's IPv4 or IPv6
        if (offset < data.size()) {
            uint8_t firstNibble = (data[offset] >> 4) & 0x0F;
            if (firstNibble == 4) {
                etherType = kEtherTypeIPv4;
            } else if (firstNibble == 6) {
                etherType = kEtherTypeIPv6;
            } else {
                // Cannot determine inner protocol
                pkt.payload.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                   data.end());
                pkt.flowId = buildFlowId(pkt);
                return pkt;
            }
        }
    }

    // === L3: Network layer ===
    uint8_t l4Protocol = 0;

    if (etherType == kEtherTypeIPv4) {
        auto ipResult = decodeIPv4(data, offset);
        if (!ipResult) {
            return std::unexpected(ipResult.error());
        }
        pkt.layer3 = *ipResult;
        l4Protocol = ipResult->protocol;

        // IP defragmentation
        if (mImpl->config.enableDefragmentation) {
            if (ipResult->fragmentOffset > 0 || (ipResult->flags & 0x01)) {
                auto reassembled = mImpl->defragmenter.process(
                    data.subspan(offset - static_cast<size_t>(ipResult->ihl) * 4),
                    *ipResult);
                if (!reassembled) {
                    // Fragment buffered, not yet complete
                    pkt.flowId = buildFlowId(pkt);
                    return pkt;
                }
                // Use reassembled data for L4+ decoding
                // For now, continue with original data
            }
        }

        // Non-first fragments: payload doesn't start at an L4 header boundary
        if (ipResult->fragmentOffset > 0) {
            pkt.payload.assign(data.begin() + static_cast<ptrdiff_t>(offset), data.end());
            pkt.flowId = buildFlowId(pkt);
            return pkt;
        }
    } else if (etherType == kEtherTypeIPv6) {
        auto ipResult = decodeIPv6(data, offset);
        if (!ipResult) {
            return std::unexpected(ipResult.error());
        }
        pkt.layer3 = *ipResult;
        l4Protocol = ipResult->nextHeader;

        // Parse IPv6 Fragment extension header (RFC 8200 §4.5)
        if (l4Protocol == kProtoIPv6Frag) {
            constexpr size_t kFragHdrSize = 8;
            if (data.size() < offset + kFragHdrSize) {
                pkt.flowId = buildFlowId(pkt);
                return pkt;
            }
            const uint8_t* fptr = data.data() + offset;
            l4Protocol = fptr[0]; // real next header
            uint16_t fragOffsetField = static_cast<uint16_t>((fptr[2] << 8) | fptr[3]);
            uint16_t fragOffset = fragOffsetField >> 3; // top 13 bits
            offset += kFragHdrSize;

            if (fragOffset > 0) {
                pkt.payload.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                   data.end());
                pkt.flowId = buildFlowId(pkt);
                return pkt;
            }
            // First fragment or unfragmented: continue to L4 with real protocol
        }
    } else if (etherType == kEtherTypeARP) {
        auto arpResult = decodeArp(data, offset);
        if (!arpResult) {
            return std::unexpected(arpResult.error());
        }
        pkt.layer3 = *arpResult;
        pkt.flowId = buildFlowId(pkt);
        return pkt; // ARP has no L4
    } else if (etherType == kEtherTypeRARP) {
        auto rarpResult = decodeRarp(data, offset);
        if (!rarpResult) {
            return std::unexpected(rarpResult.error());
        }
        pkt.layer3 = *rarpResult;
        pkt.flowId = buildFlowId(pkt);
        return pkt; // RARP has no L4
    } else {
        // Unsupported L3 protocol — store remaining as payload
        pkt.payload.assign(data.begin() + static_cast<ptrdiff_t>(offset), data.end());
        pkt.flowId = buildFlowId(pkt);
        return pkt;
    }

    // === L3.5: GRE tunnel ===
    if (l4Protocol == kProtoGRE) {
        auto greResult = decodeGre(data, offset);
        if (!greResult) {
            return std::unexpected(greResult.error());
        }
        if (greResult->protocolType == kEtherTypeIPv4) {
            auto ipResult = decodeIPv4(data, offset);
            if (!ipResult) {
                return std::unexpected(ipResult.error());
            }
            pkt.layer3 = *ipResult;
            l4Protocol = ipResult->protocol;
        } else if (greResult->protocolType == kEtherTypeIPv6) {
            auto ipResult = decodeIPv6(data, offset);
            if (!ipResult) {
                return std::unexpected(ipResult.error());
            }
            pkt.layer3 = *ipResult;
            l4Protocol = ipResult->nextHeader;
        } else {
            // Unknown inner protocol — store as payload
            pkt.payload.assign(data.begin() + static_cast<ptrdiff_t>(offset), data.end());
            pkt.flowId = buildFlowId(pkt);
            return pkt;
        }
        // Fall through to L4 decode with inner protocol
    }

    // === L4: Transport layer ===
    if (l4Protocol == kProtoTCP) {
        auto tcpResult = decodeTcp(data, offset);
        if (!tcpResult) {
            return std::unexpected(tcpResult.error());
        }
        pkt.layer4 = *tcpResult;
    } else if (l4Protocol == kProtoUDP) {
        auto udpResult = decodeUdp(data, offset);
        if (!udpResult) {
            return std::unexpected(udpResult.error());
        }
        pkt.layer4 = *udpResult;
    } else if (l4Protocol == kProtoICMP) {
        auto icmpResult = decodeIcmp(data, offset);
        if (!icmpResult) {
            return std::unexpected(icmpResult.error());
        }
        pkt.layer4 = *icmpResult;
    } else if (l4Protocol == kProtoICMPv6) {
        auto icmpResult = decodeIcmpv6(data, offset);
        if (!icmpResult) {
            return std::unexpected(icmpResult.error());
        }
        pkt.layer4 = *icmpResult;
    }

    // === Tunnel: VxLAN (UDP:4789) ===
    constexpr uint16_t kVxlanPort = 4789;
    constexpr size_t kVxlanHdrSize = 8;
    if (auto* udp = std::get_if<UDP>(&pkt.layer4);
        udp && udp->dstPort == kVxlanPort && offset + kVxlanHdrSize < data.size()) {
        offset += kVxlanHdrSize; // skip VxLAN header (flags + VNI)

        // Decode inner Ethernet
        auto innerEth = decodeEthernet(data, offset);
        if (innerEth) {
            uint16_t innerEtherType = innerEth->etherType;

            // Handle inner VLAN
            if (innerEtherType == kEtherTypeVLAN || innerEtherType == kEtherTypeQinQ) {
                if (auto vlan = decodeVlan(data, offset)) {
                    innerEtherType = vlan->etherType;
                }
            }

            // Decode inner L3
            uint8_t innerL4Proto = 0;
            if (innerEtherType == kEtherTypeIPv4) {
                if (auto ip = decodeIPv4(data, offset)) {
                    pkt.layer3 = *ip;
                    innerL4Proto = ip->protocol;
                }
            } else if (innerEtherType == kEtherTypeIPv6) {
                if (auto ip = decodeIPv6(data, offset)) {
                    pkt.layer3 = *ip;
                    innerL4Proto = ip->nextHeader;
                }
            }

            // Decode inner L4
            if (innerL4Proto == kProtoTCP) {
                if (auto r = decodeTcp(data, offset))
                    pkt.layer4 = *r;
            } else if (innerL4Proto == kProtoUDP) {
                if (auto r = decodeUdp(data, offset))
                    pkt.layer4 = *r;
            } else if (innerL4Proto == kProtoICMP) {
                if (auto r = decodeIcmp(data, offset))
                    pkt.layer4 = *r;
            } else if (innerL4Proto == kProtoICMPv6) {
                if (auto r = decodeIcmpv6(data, offset))
                    pkt.layer4 = *r;
            }
        }
    }

    // Remaining data is payload
    if (offset < data.size()) {
        pkt.payload.assign(data.begin() + static_cast<ptrdiff_t>(offset), data.end());
    }

    // Build flow ID
    pkt.flowId = buildFlowId(pkt);

    // === Flow tracking ===
    mImpl->flowTable.update(pkt);

    // === Protocol detection ===
    if (mImpl->config.enableProtocolDetection && !pkt.payload.empty()) {
        auto detected = mImpl->detector.detectFlow(pkt.flowId, pkt, pkt.payload);

        // === L7: Application layer decoding ===
        if (detected != AppProtocol::Unknown) {
            size_t l7Offset = 0;
            std::span<const uint8_t> payloadSpan(pkt.payload);

            switch (detected) {
            case AppProtocol::DNS: {
                // DNS over TCP has a 2-byte length prefix (RFC 1035 §4.2.2)
                if (std::holds_alternative<TCP>(pkt.layer4)) {
                    if (payloadSpan.size() < 2)
                        break;
                    l7Offset = 2;
                }
                if (auto result = decodeDns(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::HTTP: {
                if (auto result = decodeHttp(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::TLS: {
                if (auto result = decodeTls(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::QUIC: {
                if (auto result = decodeQuic(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::FTP: {
                if (auto result = decodeFtp(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::SSH: {
                if (auto result = decodeSsh(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::DHCP: {
                if (auto result = decodeDhcp(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::DHCPv6: {
                if (auto result = decodeDhcpv6(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::SMTP: {
                if (auto result = decodeSmtp(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::POP3: {
                if (auto result = decodePop3(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::IMAP: {
                if (auto result = decodeImap(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::SNMP: {
                if (auto result = decodeSnmp(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::RDP: {
                if (auto result = decodeRdp(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::BGP: {
                if (auto result = decodeBgp(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::NTP: {
                if (auto result = decodeNtp(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            case AppProtocol::LDAP: {
                if (auto result = decodeLdap(payloadSpan, l7Offset)) {
                    pkt.layer7 = std::move(*result);
                }
                break;
            }
            default:
                break;
            }

            // Update flow metadata with detected protocol
            // (already updated via flowTable.update above, but detection is new)
        }
    }

    // TCP reassembly (optional)
    if (mImpl->config.enableTcpReassembly) {
        if (auto* tcpHdr = std::get_if<TCP>(&pkt.layer4)) {
            if (!pkt.payload.empty()) {
                mImpl->reassembler.process(pkt.flowId, *tcpHdr, pkt.payload);
            }
        }
    }

    return pkt;
}

const FlowTable& PacketDecoder::flows() const {
    return mImpl->flowTable;
}

FlowTable& PacketDecoder::flows() {
    return mImpl->flowTable;
}

} // namespace fdpi
