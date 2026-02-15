#ifndef FDPI_PROTOCOL_QUIC_HPP
#define FDPI_PROTOCOL_QUIC_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include <fdpi/error.hpp>

namespace fdpi {

struct QUIC {
    bool     isLongHeader;
    uint8_t  version;
    std::vector<uint8_t> dcid;
    std::vector<uint8_t> scid;
    uint8_t  packetType;
};

std::expected<QUIC, Error> decodeQuic(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_QUIC_HPP
