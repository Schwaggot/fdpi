#ifndef FDPI_PROTOCOL_ARP_HPP
#define FDPI_PROTOCOL_ARP_HPP

#include <cstdint>
#include <expected>
#include <span>

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

namespace fdpi {

struct ARP {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t  hardwareSize;
    uint8_t  protocolSize;
    uint16_t opcode;
    MacAddress  senderMac;
    IPv4Address senderIp;
    MacAddress  targetMac;
    IPv4Address targetIp;
};

std::expected<ARP, Error> decodeArp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_ARP_HPP
