#ifndef FDPI_PROTOCOL_ICMP_HPP
#define FDPI_PROTOCOL_ICMP_HPP

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace fdpi {

struct IcmpEmbeddedInfo {
    uint8_t protocol;
    IPv4Address srcIp;
    IPv4Address dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t udpLength;
    uint16_t udpChecksum;
};

struct Icmpv6EmbeddedInfo {
    uint8_t nextHeader;
    IPv6Address srcIp;
    IPv6Address dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t udpLength;
    uint16_t udpChecksum;
};

struct ICMP {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t restOfHeader;
    std::optional<IcmpEmbeddedInfo> embedded;
};

struct ICMPv6 {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t restOfHeader;
    std::optional<Icmpv6EmbeddedInfo> embedded;
};

std::expected<ICMP, Error> decodeIcmp(std::span<const uint8_t> data, size_t& offset);
std::expected<ICMPv6, Error> decodeIcmpv6(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_ICMP_HPP
