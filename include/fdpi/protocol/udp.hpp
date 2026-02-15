#ifndef FDPI_PROTOCOL_UDP_HPP
#define FDPI_PROTOCOL_UDP_HPP

#include <cstdint>
#include <expected>
#include <span>

#include <fdpi/error.hpp>

namespace fdpi {

struct UDP {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
};

std::expected<UDP, Error> decodeUdp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_UDP_HPP
