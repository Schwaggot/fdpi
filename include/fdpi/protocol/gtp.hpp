#ifndef FDPI_PROTOCOL_GTP_HPP
#define FDPI_PROTOCOL_GTP_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>

namespace fdpi {

struct GTP {
    uint8_t version;   // 3 bits (v1=1, v2=2)
    bool protocolType; // 1=GTP, 0=GTP'
    uint8_t messageType;
    uint16_t length;
    uint32_t teid; // Tunnel Endpoint Identifier
};

std::expected<GTP, Error> decodeGtp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_GTP_HPP
