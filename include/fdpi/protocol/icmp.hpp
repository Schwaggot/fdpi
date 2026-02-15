#ifndef FDPI_PROTOCOL_ICMP_HPP
#define FDPI_PROTOCOL_ICMP_HPP

#include <cstdint>
#include <expected>
#include <span>

#include <fdpi/error.hpp>

namespace fdpi {

struct ICMP {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t restOfHeader;
};

struct ICMPv6 {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t restOfHeader;
};

std::expected<ICMP, Error> decodeIcmp(std::span<const uint8_t> data, size_t& offset);
std::expected<ICMPv6, Error> decodeIcmpv6(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_ICMP_HPP
