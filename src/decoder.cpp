#include <fdpi/datalink.hpp>
#include <fdpi/decoder.hpp>
#include <fdpi/protocol/gtp.hpp>

#include <string_view>
#include <unordered_map>

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
constexpr uint16_t kEtherTypeEAPOL = 0x888E;
constexpr uint16_t kEtherTypeLLDP = 0x88CC;
constexpr uint16_t kEtherTypeHomePlug = 0x88E1;

// IP protocol constants
constexpr uint8_t kProtoICMP = 1;
constexpr uint8_t kProtoTCP = 6;
constexpr uint8_t kProtoUDP = 17;
constexpr uint8_t kProtoGRE = 47;
constexpr uint8_t kProtoIPv6Frag = 44;
constexpr uint8_t kProtoIGMP = 2;
constexpr uint8_t kProtoESP = 50;
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

FlowId reverseFlowId(const FlowId& id) {
    FlowId rev;
    rev.srcIp = id.dstIp;
    rev.dstIp = id.srcIp;
    rev.srcPort = id.dstPort;
    rev.dstPort = id.srcPort;
    rev.protocol = id.protocol;
    return rev;
}

} // anonymous namespace

struct Pop3FlowState {
    bool pendingMultiline = false;
    bool inDataMode = false;
};

struct L7StreamState {
    std::vector<uint8_t> buffer;
    AppProtocol detected{AppProtocol::Unknown};
    bool detectionDone{false};
};

struct PacketDecoder::Impl {
    Config config;
    FlowTable flowTable;
    IpDefragmenter defragmenter;
    TcpReassembler reassembler;
    ProtocolDetectionEngine detector;
    std::unordered_map<FlowId, Pop3FlowState, FlowIdHash> pop3States;
    std::unordered_map<FlowId, L7StreamState, FlowIdHash> l7Streams;

    explicit Impl(const Config& cfg)
        : config(cfg),
          flowTable(cfg.flowTableConfig),
          defragmenter(cfg.defragConfig),
          reassembler(cfg.reassemblyConfig) {}

    bool decodeL7(Packet& pkt,
                  AppProtocol detected,
                  std::span<const uint8_t> data,
                  size_t& offset);
};

// Attempts to decode L7 protocol from the given data span.
// Returns true if pkt.layer7 was populated.
bool PacketDecoder::Impl::decodeL7(Packet& pkt,
                                   AppProtocol detected,
                                   std::span<const uint8_t> data,
                                   size_t& offset) {
    switch (detected) {
    case AppProtocol::DNS: {
        // DNS over TCP has a 2-byte length prefix (RFC 1035 §4.2.2)
        if (std::holds_alternative<TCP>(pkt.layer4)) {
            if (data.size() < 2)
                return false;
            offset = 2;
        }
        if (auto result = decodeDns(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::HTTP: {
        if (auto result = decodeHttp(data, offset)) {
            // Check for OCSP sub-protocol via Content-Type header
            for (const auto& [key, val] : result->headers) {
                if ((key == "Content-Type" || key == "content-type") &&
                    val.find("application/ocsp") != std::string::npos) {
                    if (offset < data.size()) {
                        size_t ocspOff = offset;
                        if (auto ocsp = decodeOcsp(data, ocspOff)) {
                            result->ocspPayload = std::move(*ocsp);
                        }
                    }
                    break;
                }
            }
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::TLS: {
        if (auto result = decodeTls(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::QUIC: {
        if (auto result = decodeQuic(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::FTP: {
        if (auto result = decodeFtp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::SSH: {
        if (auto result = decodeSsh(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::DHCP: {
        if (auto result = decodeDhcp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::DHCPv6: {
        if (auto result = decodeDhcpv6(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::SMTP: {
        if (auto result = decodeSmtp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::POP3: {
        auto& state = pop3States[pkt.flowId];

        if (state.inDataMode) {
            std::string_view sv(reinterpret_cast<const char*>(data.data()), data.size());
            if (sv.starts_with(".\r\n") ||
                sv.find("\r\n.\r\n") != std::string_view::npos) {
                state.inDataMode = false;
            }
            return false;
        }

        auto result = decodePop3(data, offset);
        if (!result)
            return false;
        pkt.layer7 = std::move(*result);

        auto& pop3 = std::get<POP3>(pkt.layer7);
        if (!pop3.isResponse) {
            bool multiline = (pop3.command == "RETR" || pop3.command == "TOP") ||
                             ((pop3.command == "LIST" || pop3.command == "UIDL") &&
                              pop3.argument.empty());
            if (multiline) {
                auto rev = reverseFlowId(pkt.flowId);
                pop3States[rev].pendingMultiline = true;
            }
        } else if (state.pendingMultiline) {
            state.pendingMultiline = false;
            if (pop3.success) {
                state.inDataMode = true;
            }
        }
        return true;
    }
    case AppProtocol::IMAP: {
        if (auto result = decodeImap(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::SNMP: {
        if (auto result = decodeSnmp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::RDP: {
        if (auto result = decodeRdp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::BGP: {
        if (auto result = decodeBgp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::NTP: {
        if (auto result = decodeNtp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::LDAP: {
        if (auto result = decodeLdap(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::MDNS:
    case AppProtocol::LLMNR: {
        if (auto result = decodeDns(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::SSDP: {
        if (auto result = decodeSsdp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::SrvLoc: {
        if (auto result = decodeSrvloc(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::NBNS: {
        if (auto result = decodeNbns(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::NBDGM: {
        if (auto result = decodeNbdgm(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::SMB: {
        // TCP:139 (NetBIOS Session): skip 4-byte NBT session header
        if (std::holds_alternative<TCP>(pkt.layer4)) {
            auto* tcp = std::get_if<TCP>(&pkt.layer4);
            if (tcp && (tcp->srcPort == 139 || tcp->dstPort == 139)) {
                if (data.size() >= 4) {
                    offset = 4;
                }
            }
        }
        if (auto result = decodeSmb(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::RTMP: {
        if (auto result = decodeRtmp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::IMF: {
        if (auto result = decodeImf(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::STUN: {
        if (auto result = decodeStun(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::Telnet: {
        if (auto result = decodeTelnet(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::TFTP: {
        if (auto result = decodeTftp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::DTLS: {
        if (auto result = decodeDtls(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::RTCP: {
        if (auto result = decodeRtcp(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    case AppProtocol::DbLanSyncDisc: {
        if (auto result = decodeDbLanSyncDisc(data, offset)) {
            pkt.layer7 = std::move(*result);
            return true;
        }
        return false;
    }
    default:
        return false;
    }
}

PacketDecoder::PacketDecoder(Config config) : mImpl(std::make_unique<Impl>(config)) {}

PacketDecoder::~PacketDecoder() = default;

std::expected<Packet, Error> PacketDecoder::decode(std::span<const uint8_t> data,
                                                   Timestamp timestamp,
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

        if (linkResult->wifi) {
            pkt.wifi = *linkResult->wifi;
        }

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
    } else if (etherType == kEtherTypeEAPOL) {
        auto eapolResult = decodeEapol(data, offset);
        if (!eapolResult) {
            return std::unexpected(eapolResult.error());
        }
        pkt.layer3 = *eapolResult;
        pkt.flowId = buildFlowId(pkt);
        return pkt; // EAPOL has no L4
    } else if (etherType == kEtherTypeLLDP) {
        auto lldpResult = decodeLldp(data, offset);
        if (!lldpResult) {
            return std::unexpected(lldpResult.error());
        }
        pkt.layer3 = *lldpResult;
        pkt.flowId = buildFlowId(pkt);
        return pkt; // LLDP has no L4
    } else if (etherType == kEtherTypeHomePlug) {
        auto hpResult = decodeHomeplug(data, offset);
        if (!hpResult) {
            return std::unexpected(hpResult.error());
        }
        pkt.layer3 = *hpResult;
        pkt.flowId = buildFlowId(pkt);
        return pkt; // HomePlug has no L4
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
    } else if (l4Protocol == kProtoIGMP) {
        auto igmpResult = decodeIgmp(data, offset);
        if (!igmpResult) {
            return std::unexpected(igmpResult.error());
        }
        pkt.layer4 = *igmpResult;
    } else if (l4Protocol == kProtoESP) {
        auto espResult = decodeEsp(data, offset);
        if (!espResult) {
            return std::unexpected(espResult.error());
        }
        pkt.layer4 = *espResult;
        // ESP payload is encrypted — store as payload and return
        if (offset < data.size()) {
            pkt.payload.assign(data.begin() + static_cast<ptrdiff_t>(offset), data.end());
        }
        pkt.flowId = buildFlowId(pkt);
        mImpl->flowTable.update(pkt);
        return pkt;
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

    // === Tunnel: GTP-U (UDP:2152) ===
    constexpr uint16_t kGtpPort = 2152;
    if (auto* udp = std::get_if<UDP>(&pkt.layer4);
        udp && udp->dstPort == kGtpPort && offset < data.size()) {
        auto gtpResult = decodeGtp(data, offset);
        if (gtpResult) {
            // Decode inner IP
            if (offset < data.size()) {
                uint8_t firstNibble = (data[offset] >> 4) & 0x0F;
                uint8_t innerL4Proto = 0;
                if (firstNibble == 4) {
                    if (auto ip = decodeIPv4(data, offset)) {
                        pkt.layer3 = *ip;
                        innerL4Proto = ip->protocol;
                    }
                } else if (firstNibble == 6) {
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
    }

    // Remaining data is payload
    if (offset < data.size()) {
        pkt.payload.assign(data.begin() + static_cast<ptrdiff_t>(offset), data.end());
    }

    // Build flow ID
    pkt.flowId = buildFlowId(pkt);

    // === Flow tracking ===
    mImpl->flowTable.update(pkt);

    // === Protocol detection + L7 decoding ===
    if (mImpl->config.enableProtocolDetection && !pkt.payload.empty()) {
        auto* tcpHdr = std::get_if<TCP>(&pkt.layer4);

        if (tcpHdr && mImpl->config.enableTcpReassembly) {
            // --- TCP stream-first path ---
            // 1. Feed segment to reassembler
            auto reassembled =
                mImpl->reassembler.process(pkt.flowId, *tcpHdr, pkt.payload);

            if (reassembled && !reassembled->empty()) {
                auto& stream = mImpl->l7Streams[pkt.flowId];

                // Buffer size check
                if (stream.buffer.size() + reassembled->size() >
                    mImpl->config.maxL7StreamBytes) {
                    mImpl->l7Streams.erase(pkt.flowId);
                } else {
                    // Append reassembled data to stream buffer
                    stream.buffer.insert(stream.buffer.end(), reassembled->begin(),
                                         reassembled->end());

                    // Detect protocol if not yet decided
                    if (!stream.detectionDone) {
                        auto detected =
                            mImpl->detector.detectFlow(pkt.flowId, pkt, stream.buffer);
                        if (detected != AppProtocol::Unknown) {
                            stream.detected = detected;
                            stream.detectionDone = true;
                        }
                    }

                    // Attempt L7 decode if protocol is known
                    if (stream.detected != AppProtocol::Unknown) {
                        size_t l7Offset = 0;
                        std::span<const uint8_t> bufSpan(stream.buffer);
                        if (mImpl->decodeL7(pkt, stream.detected, bufSpan, l7Offset)) {
                            // Consume decoded bytes from buffer
                            stream.buffer.erase(stream.buffer.begin(),
                                                stream.buffer.begin() +
                                                    static_cast<ptrdiff_t>(l7Offset));
                        }
                    }
                }
            }

            // FIN/RST cleanup
            if (tcpHdr->fin() || tcpHdr->rst()) {
                mImpl->l7Streams.erase(pkt.flowId);
            }
        } else {
            // --- Non-TCP / reassembly-disabled path (unchanged) ---
            auto detected = mImpl->detector.detectFlow(pkt.flowId, pkt, pkt.payload);
            if (detected != AppProtocol::Unknown) {
                size_t l7Offset = 0;
                std::span<const uint8_t> payloadSpan(pkt.payload);
                mImpl->decodeL7(pkt, detected, payloadSpan, l7Offset);
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
