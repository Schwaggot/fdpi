#ifndef FDPI_PROTOCOL_IPV6_HPP
#define FDPI_PROTOCOL_IPV6_HPP

#include <cstdint>
#include <expected>
#include <span>

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

namespace fdpi {

struct IPv6 {
    uint8_t  version;
    uint8_t  trafficClass;
    uint32_t flowLabel;
    uint16_t payloadLength;
    uint8_t  nextHeader;
    uint8_t  hopLimit;
    IPv6Address srcIp;
    IPv6Address dstIp;
};

std::expected<IPv6, Error> decodeIPv6(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_IPV6_HPP
