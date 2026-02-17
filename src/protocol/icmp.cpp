#include <fdpi/protocol/icmp.hpp>

#include <algorithm>

namespace fdpi {

namespace {

bool isIcmpErrorType(const uint8_t type) {
    return type == 3 || type == 4 || type == 5 || type == 11 || type == 12;
}

bool isIcmpv6ErrorType(const uint8_t type) {
    return type == 1 || type == 2 || type == 3 || type == 4;
}

} // namespace

std::expected<ICMP, Error> decodeIcmp(const std::span<const uint8_t> data,
                                      size_t& offset) {
    constexpr size_t kIcmpMinSize = 8;

    if (data.size() < offset + kIcmpMinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    ICMP hdr{};
    hdr.type = ptr[0];
    hdr.code = ptr[1];
    hdr.checksum = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.restOfHeader =
        (static_cast<uint32_t>(ptr[4]) << 24) | (static_cast<uint32_t>(ptr[5]) << 16) |
        (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);

    offset += kIcmpMinSize;

    // Parse embedded IPv4 header + transport for error messages
    if (isIcmpErrorType(hdr.type)) {
        const size_t remaining = data.size() - offset;
        // Need at least 20 bytes for IPv4 header
        if (remaining >= 20) {
            const uint8_t* emb = data.data() + offset;
            const uint8_t version = (emb[0] >> 4) & 0x0F;
            const uint8_t ihl = emb[0] & 0x0F;
            if (version == 4 && ihl >= 5) {
                const size_t ipHdrLen = static_cast<size_t>(ihl) * 4;
                // Need IP header + 8 bytes of transport
                if (remaining >= ipHdrLen + 8) {
                    IcmpEmbeddedInfo info{};
                    info.protocol = emb[9];
                    info.srcIp = IPv4Address(
                        std::array<uint8_t, 4>{emb[12], emb[13], emb[14], emb[15]});
                    info.dstIp = IPv4Address(
                        std::array<uint8_t, 4>{emb[16], emb[17], emb[18], emb[19]});

                    const uint8_t* transport = emb + ipHdrLen;
                    info.srcPort =
                        static_cast<uint16_t>((transport[0] << 8) | transport[1]);
                    info.dstPort =
                        static_cast<uint16_t>((transport[2] << 8) | transport[3]);

                    if (info.protocol == 17) { // UDP
                        info.udpLength =
                            static_cast<uint16_t>((transport[4] << 8) | transport[5]);
                        info.udpChecksum =
                            static_cast<uint16_t>((transport[6] << 8) | transport[7]);
                    }

                    hdr.embedded = info;
                }
            }
        }
    }

    return hdr;
}

std::expected<ICMPv6, Error> decodeIcmpv6(const std::span<const uint8_t> data,
                                          size_t& offset) {
    constexpr size_t kIcmpv6MinSize = 8;

    if (data.size() < offset + kIcmpv6MinSize) {
        return std::unexpected(Error::TruncatedHeader);
    }

    const uint8_t* ptr = data.data() + offset;

    ICMPv6 hdr{};
    hdr.type = ptr[0];
    hdr.code = ptr[1];
    hdr.checksum = static_cast<uint16_t>((ptr[2] << 8) | ptr[3]);
    hdr.restOfHeader =
        (static_cast<uint32_t>(ptr[4]) << 24) | (static_cast<uint32_t>(ptr[5]) << 16) |
        (static_cast<uint32_t>(ptr[6]) << 8) | static_cast<uint32_t>(ptr[7]);

    offset += kIcmpv6MinSize;

    // Parse embedded IPv6 header + transport for error messages
    if (isIcmpv6ErrorType(hdr.type)) {
        constexpr size_t kIPv6HdrLen = 40;
        const size_t remaining = data.size() - offset;
        // Need 40-byte IPv6 header + 8 bytes of transport
        if (remaining >= kIPv6HdrLen + 8) {
            const uint8_t* emb = data.data() + offset;
            const uint8_t version = (emb[0] >> 4) & 0x0F;
            if (version == 6) {
                Icmpv6EmbeddedInfo info{};
                info.nextHeader = emb[6];

                std::array<uint8_t, 16> srcBytes{};
                std::copy_n(emb + 8, 16, srcBytes.begin());
                info.srcIp = IPv6Address(srcBytes);

                std::array<uint8_t, 16> dstBytes{};
                std::copy_n(emb + 24, 16, dstBytes.begin());
                info.dstIp = IPv6Address(dstBytes);

                const uint8_t* transport = emb + kIPv6HdrLen;
                info.srcPort = static_cast<uint16_t>((transport[0] << 8) | transport[1]);
                info.dstPort = static_cast<uint16_t>((transport[2] << 8) | transport[3]);

                if (info.nextHeader == 17) { // UDP
                    info.udpLength =
                        static_cast<uint16_t>((transport[4] << 8) | transport[5]);
                    info.udpChecksum =
                        static_cast<uint16_t>((transport[6] << 8) | transport[7]);
                }

                hdr.embedded = info;
            }
        }
    }

    return hdr;
}

} // namespace fdpi
