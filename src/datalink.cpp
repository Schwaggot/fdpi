#include <fdpi/datalink.hpp>
#include <fdpi/protocol/ethernet.hpp>

#include <cstring>

namespace fdpi {

namespace {

// EtherType constants
constexpr uint16_t kEtherTypeIPv4 = 0x0800;
constexpr uint16_t kEtherTypeIPv6 = 0x86DD;

// BSD address families for DLT_NULL
constexpr uint32_t kAF_INET = 2;
constexpr uint32_t kAF_INET6_LINUX = 10;
constexpr uint32_t kAF_INET6_OPENBSD = 24;
constexpr uint32_t kAF_INET6_FREEBSD = 28;
constexpr uint32_t kAF_INET6_MACOS = 30;

// PPP protocol numbers
constexpr uint16_t kPPP_IPv4 = 0x0021;
constexpr uint16_t kPPP_IPv6 = 0x0057;

uint16_t read16BE(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t read32Native(const uint8_t* p) {
    uint32_t val;
    std::memcpy(&val, p, 4);
    return val;
}

MacAddress readMac(const uint8_t* p) {
    return MacAddress(std::array<uint8_t, 6>{p[0], p[1], p[2], p[3], p[4], p[5]});
}

// Shared LLC/SNAP decoder for Token Ring, FDDI, and WiFi
// Expects: DSAP(1) SSAP(1) Ctrl(1) OUI(3) EtherType(2) = 8 bytes
std::expected<uint16_t, Error> decodeLlcSnap(std::span<const uint8_t> data,
                                             size_t& offset) {
    constexpr size_t kLlcSnapSize = 8;
    if (data.size() < offset + kLlcSnapSize) {
        return std::unexpected(Error::TruncatedHeader);
    }
    const uint8_t* p = data.data() + offset;
    // Verify LLC header: DSAP=0xAA, SSAP=0xAA, Ctrl=0x03
    if (p[0] != 0xAA || p[1] != 0xAA || p[2] != 0x03) {
        return std::unexpected(Error::UnsupportedProtocol);
    }
    // OUI at p[3..5], EtherType at p[6..7]
    uint16_t etherType = read16BE(p + 6);
    offset += kLlcSnapSize;
    return etherType;
}

uint32_t byteSwap32(uint32_t val) {
    return ((val & 0xFF000000) >> 24) | ((val & 0x00FF0000) >> 8) |
           ((val & 0x0000FF00) << 8) | ((val & 0x000000FF) << 24);
}

// --- DLT_NULL: BSD loopback ---
std::expected<LinkLayerResult, Error> decodeBsdNull(std::span<const uint8_t> data,
                                                    size_t& offset) {
    constexpr size_t kHeaderSize = 4;
    if (data.size() < offset + kHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }
    uint32_t af = read32Native(data.data() + offset);
    offset += kHeaderSize;

    // DLT_NULL stores AF in host byte order of the capturing machine.
    // If the value exceeds 255, the pcap was captured on a machine with
    // different endianness — byte-swap to recover the original AF value.
    if (af > 0xFF) {
        af = byteSwap32(af);
    }

    LinkLayerResult result{};
    if (af == kAF_INET) {
        result.etherType = kEtherTypeIPv4;
    } else if (af == kAF_INET6_LINUX || af == kAF_INET6_OPENBSD ||
               af == kAF_INET6_FREEBSD || af == kAF_INET6_MACOS) {
        result.etherType = kEtherTypeIPv6;
    } else {
        return std::unexpected(Error::UnsupportedProtocol);
    }
    return result;
}

// --- DLT_EN10MB: Ethernet (delegates to existing decoder) ---
std::expected<LinkLayerResult, Error> decodeEthernetDlt(std::span<const uint8_t> data,
                                                        size_t& offset) {
    auto ethResult = decodeEthernet(data, offset);
    if (!ethResult) {
        return std::unexpected(ethResult.error());
    }
    LinkLayerResult result{};
    result.etherType = ethResult->etherType;
    result.hasMacs = true;
    result.srcMac = ethResult->src;
    result.dstMac = ethResult->dst;
    return result;
}

// --- DLT_RAW: Raw IP (no L2 header) ---
std::expected<LinkLayerResult, Error> decodeRawIp(std::span<const uint8_t> data,
                                                  size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }
    uint8_t firstNibble = (data[offset] >> 4) & 0x0F;
    LinkLayerResult result{};
    if (firstNibble == 4) {
        result.etherType = kEtherTypeIPv4;
    } else if (firstNibble == 6) {
        result.etherType = kEtherTypeIPv6;
    } else {
        return std::unexpected(Error::UnsupportedProtocol);
    }
    // No offset advancement — raw IP has no L2 header
    return result;
}

// --- DLT_PPP ---
std::expected<LinkLayerResult, Error> decodePpp(std::span<const uint8_t> data,
                                                size_t& offset) {
    if (data.size() <= offset) {
        return std::unexpected(Error::TruncatedHeader);
    }
    const uint8_t* p = data.data() + offset;

    // Check for Address/Control bytes (0xFF, 0x03) — optional in some PPP
    size_t hdrStart = 0;
    if (data.size() >= offset + 2 && p[0] == 0xFF && p[1] == 0x03) {
        hdrStart = 2;
        if (data.size() < offset + hdrStart + 1) {
            return std::unexpected(Error::TruncatedHeader);
        }
    }

    // Protocol field: 1 or 2 bytes
    uint16_t protocol;
    if (p[hdrStart] & 0x01) {
        // Single-byte protocol (odd value in low bit)
        protocol = p[hdrStart];
        offset += hdrStart + 1;
    } else {
        if (data.size() < offset + hdrStart + 2) {
            return std::unexpected(Error::TruncatedHeader);
        }
        protocol = read16BE(p + hdrStart);
        offset += hdrStart + 2;
    }

    LinkLayerResult result{};
    if (protocol == kPPP_IPv4) {
        result.etherType = kEtherTypeIPv4;
    } else if (protocol == kPPP_IPv6) {
        result.etherType = kEtherTypeIPv6;
    } else {
        return std::unexpected(Error::UnsupportedProtocol);
    }
    return result;
}

// --- DLT_LINUX_SLL: Linux cooked capture v1 ---
std::expected<LinkLayerResult, Error> decodeLinuxSll(std::span<const uint8_t> data,
                                                     size_t& offset) {
    constexpr size_t kSllHeaderSize = 16;
    if (data.size() < offset + kSllHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }
    const uint8_t* p = data.data() + offset;
    // Offsets: 0-1=packet_type, 2-3=ARPHRD, 4-5=addr_len, 6-13=address, 14-15=protocol
    uint16_t addrLen = read16BE(p + 4);
    uint16_t protocol = read16BE(p + 14);

    LinkLayerResult result{};
    result.etherType = protocol;
    if (addrLen >= 6) {
        result.hasMacs = true;
        result.srcMac = readMac(p + 6);
        // No dst MAC in SLL
    }
    offset += kSllHeaderSize;
    return result;
}

// --- DLT_LINUX_SLL2: Linux cooked capture v2 ---
std::expected<LinkLayerResult, Error> decodeLinuxSll2(std::span<const uint8_t> data,
                                                      size_t& offset) {
    constexpr size_t kSll2HeaderSize = 20;
    if (data.size() < offset + kSll2HeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }
    const uint8_t* p = data.data() + offset;
    // Offsets: 0-1=protocol, 2-3=reserved, 4-7=ifindex, 8-9=ARPHRD,
    //          10=pkt_type, 11=addr_len, 12-19=address
    uint16_t protocol = read16BE(p);
    uint8_t addrLen = p[11];

    LinkLayerResult result{};
    result.etherType = protocol;
    if (addrLen >= 6) {
        result.hasMacs = true;
        result.srcMac = readMac(p + 12);
    }
    offset += kSll2HeaderSize;
    return result;
}

// --- DLT_IEEE802_5: Token Ring ---
std::expected<LinkLayerResult, Error> decodeTokenRing(std::span<const uint8_t> data,
                                                      size_t& offset) {
    // AC(1) + FC(1) + dst(6) + src(6) = 14 bytes minimum
    constexpr size_t kMinHeaderSize = 14;
    if (data.size() < offset + kMinHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }
    const uint8_t* p = data.data() + offset;

    LinkLayerResult result{};
    result.hasMacs = true;
    result.dstMac = readMac(p + 2);
    // Source MAC: bit 7 of first byte indicates source routing
    std::array<uint8_t, 6> srcBytes = {p[8], p[9], p[10], p[11], p[12], p[13]};
    bool hasSourceRouting = (srcBytes[0] & 0x80) != 0;
    srcBytes[0] &= 0x7F; // Clear source routing bit for actual MAC
    result.srcMac = MacAddress(srcBytes);
    offset += kMinHeaderSize;

    // Skip source routing if present
    if (hasSourceRouting) {
        if (data.size() < offset + 2) {
            return std::unexpected(Error::TruncatedHeader);
        }
        uint16_t routingLen = data[offset] & 0x1F;
        if (routingLen < 2 || data.size() < offset + routingLen) {
            return std::unexpected(Error::TruncatedHeader);
        }
        offset += routingLen;
    }

    // Decode LLC/SNAP
    auto snapResult = decodeLlcSnap(data, offset);
    if (!snapResult) {
        return std::unexpected(snapResult.error());
    }
    result.etherType = *snapResult;
    return result;
}

// --- DLT_FDDI ---
std::expected<LinkLayerResult, Error> decodeFddi(std::span<const uint8_t> data,
                                                 size_t& offset) {
    // FC(1) + dst(6) + src(6) = 13 bytes minimum
    constexpr size_t kMinHeaderSize = 13;
    if (data.size() < offset + kMinHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }
    const uint8_t* p = data.data() + offset;

    LinkLayerResult result{};
    result.hasMacs = true;
    result.dstMac = readMac(p + 1);
    result.srcMac = readMac(p + 7);
    offset += kMinHeaderSize;

    // Decode LLC/SNAP
    auto snapResult = decodeLlcSnap(data, offset);
    if (!snapResult) {
        return std::unexpected(snapResult.error());
    }
    result.etherType = *snapResult;
    return result;
}

// --- DLT_IEEE802_11: WiFi ---
std::expected<LinkLayerResult, Error> decodeWifi(std::span<const uint8_t> data,
                                                 size_t& offset) {
    // Minimum: frame control(2) + duration(2) + addr1(6) + addr2(6) + addr3(6) + seq(2) =
    // 24
    constexpr size_t kMinHeaderSize = 24;
    if (data.size() < offset + kMinHeaderSize) {
        return std::unexpected(Error::TruncatedHeader);
    }
    const uint8_t* p = data.data() + offset;
    uint16_t frameControl = static_cast<uint16_t>(p[0] | (p[1] << 8));

    // Frame type (bits 2-3), subtype (bits 4-7)
    uint8_t frameType = (frameControl >> 2) & 0x03;
    if (frameType != 2) {
        // Only data frames supported
        return std::unexpected(Error::UnsupportedProtocol);
    }

    bool toDS = (frameControl & 0x0100) != 0;
    bool fromDS = (frameControl & 0x0200) != 0;

    size_t hdrSize = kMinHeaderSize;
    // 4-address header when both ToDS and FromDS are set (WDS)
    if (toDS && fromDS) {
        hdrSize = 30;
    }

    // QoS data frames (subtype bit 3 set) have 2 extra bytes
    uint8_t subtype = (frameControl >> 4) & 0x0F;
    if (subtype & 0x08) {
        hdrSize += 2;
    }

    if (data.size() < offset + hdrSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    // Extract MACs based on ToDS/FromDS flags
    // addr1 @ +4, addr2 @ +10, addr3 @ +16, addr4 @ +24 (if present)
    LinkLayerResult result{};
    result.hasMacs = true;
    if (!toDS && !fromDS) {
        // IBSS: DA=addr1, SA=addr2
        result.dstMac = readMac(p + 4);
        result.srcMac = readMac(p + 10);
    } else if (!toDS && fromDS) {
        // From AP: DA=addr1, SA=addr3
        result.dstMac = readMac(p + 4);
        result.srcMac = readMac(p + 16);
    } else if (toDS && !fromDS) {
        // To AP: DA=addr3, SA=addr2
        result.dstMac = readMac(p + 16);
        result.srcMac = readMac(p + 10);
    } else {
        // WDS: DA=addr3, SA=addr4
        result.dstMac = readMac(p + 16);
        result.srcMac = readMac(p + 24);
    }

    offset += hdrSize;

    // Decode LLC/SNAP following the 802.11 header
    auto snapResult = decodeLlcSnap(data, offset);
    if (!snapResult) {
        return std::unexpected(snapResult.error());
    }
    result.etherType = *snapResult;
    return result;
}

// --- DLT_IEEE802_11_RADIOTAP: Radiotap + WiFi ---
std::expected<LinkLayerResult, Error> decodeRadiotap(std::span<const uint8_t> data,
                                                     size_t& offset) {
    // Radiotap header: version(1) + pad(1) + length(2 LE) + present(4+)
    constexpr size_t kMinRadiotapSize = 8;
    if (data.size() < offset + kMinRadiotapSize) {
        return std::unexpected(Error::TruncatedHeader);
    }
    const uint8_t* p = data.data() + offset;
    // Length is at bytes 2-3 in little-endian
    uint16_t radiotapLen = static_cast<uint16_t>(p[2] | (p[3] << 8));
    if (radiotapLen < kMinRadiotapSize || data.size() < offset + radiotapLen) {
        return std::unexpected(Error::TruncatedHeader);
    }
    offset += radiotapLen;
    // Delegate to standard 802.11 decoder
    return decodeWifi(data, offset);
}

} // anonymous namespace

std::expected<LinkLayerResult, Error>
resolveDataLink(DataLinkType dlt, std::span<const uint8_t> data, size_t& offset) {
    switch (dlt) {
    case DataLinkType::DLT_NULL:
        return decodeBsdNull(data, offset);
    case DataLinkType::DLT_EN10MB:
        return decodeEthernetDlt(data, offset);
    case DataLinkType::DLT_RAW:
        return decodeRawIp(data, offset);
    case DataLinkType::DLT_PPP:
        return decodePpp(data, offset);
    case DataLinkType::DLT_LINUX_SLL:
        return decodeLinuxSll(data, offset);
    case DataLinkType::DLT_LINUX_SLL2:
        return decodeLinuxSll2(data, offset);
    case DataLinkType::DLT_IEEE802_5:
        return decodeTokenRing(data, offset);
    case DataLinkType::DLT_FDDI:
        return decodeFddi(data, offset);
    case DataLinkType::DLT_IEEE802_11:
        return decodeWifi(data, offset);
    case DataLinkType::DLT_IEEE802_11_RADIOTAP:
        return decodeRadiotap(data, offset);
    }
    return std::unexpected(Error::UnsupportedDataLink);
}

} // namespace fdpi
