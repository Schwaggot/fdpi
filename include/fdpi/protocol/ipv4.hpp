#ifndef FDPI_PROTOCOL_IPV4_HPP
#define FDPI_PROTOCOL_IPV4_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

namespace fdpi {

struct IPv4 {
    uint8_t  version;
    uint8_t  ihl;
    uint8_t  dscp;
    uint8_t  ecn;
    uint16_t totalLength;
    uint16_t identification;
    uint8_t  flags;
    uint16_t fragmentOffset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    IPv4Address srcIp;
    IPv4Address dstIp;
    std::vector<uint8_t> options;
};

std::expected<IPv4, Error> decodeIPv4(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_IPV4_HPP
