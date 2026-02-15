#ifndef FDPI_PROTOCOL_ETHERNET_HPP
#define FDPI_PROTOCOL_ETHERNET_HPP

#include <cstdint>
#include <expected>
#include <span>

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

namespace fdpi {

struct Ethernet {
    MacAddress dst;
    MacAddress src;
    uint16_t   etherType;
};

struct VlanTag {
    uint16_t tci;
    uint16_t etherType;

    uint16_t vlanId() const { return tci & 0x0FFF; }
    uint8_t  priority() const { return static_cast<uint8_t>((tci >> 13) & 0x07); }
};

std::expected<Ethernet, Error> decodeEthernet(std::span<const uint8_t> data, size_t& offset);
std::expected<VlanTag, Error> decodeVlan(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_ETHERNET_HPP
