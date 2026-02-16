#ifndef FDPI_PROTOCOL_BGP_HPP
#define FDPI_PROTOCOL_BGP_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <span>

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

namespace fdpi {

struct BGP {
    uint16_t length;
    uint8_t type; // 1=OPEN,2=UPDATE,3=NOTIFICATION,4=KEEPALIVE
    std::optional<uint8_t> version;
    std::optional<uint16_t> myAs;
    std::optional<uint16_t> holdTime;
    std::optional<IPv4Address> bgpId;
};

std::expected<BGP, Error> decodeBgp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_BGP_HPP
