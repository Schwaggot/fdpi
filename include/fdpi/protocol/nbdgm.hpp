#ifndef FDPI_PROTOCOL_NBDGM_HPP
#define FDPI_PROTOCOL_NBDGM_HPP

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace fdpi {

struct NBDGM {
    uint8_t messageType; // 0x10=Direct Unique, 0x11=Direct Group, 0x12=Broadcast
    uint8_t flags;
    uint16_t dgmId;
    IPv4Address sourceIp;
    uint16_t sourcePort;
    uint16_t dgmLength;
    uint16_t packetOffset;
    std::string sourceName;
    std::string destinationName;
};

std::expected<NBDGM, Error> decodeNbdgm(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_NBDGM_HPP
