#ifndef FDPI_PROTOCOL_RARP_HPP
#define FDPI_PROTOCOL_RARP_HPP

#include <cstdint>
#include <expected>
#include <span>

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

namespace fdpi {

struct RARP {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardwareSize;
    uint8_t protocolSize;
    uint16_t opcode; // 3=Request, 4=Reply
    MacAddress senderMac;
    IPv4Address senderIp;
    MacAddress targetMac;
    IPv4Address targetIp;
};

std::expected<RARP, Error> decodeRarp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_RARP_HPP
