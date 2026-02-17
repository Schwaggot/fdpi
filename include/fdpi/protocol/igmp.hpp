#ifndef FDPI_PROTOCOL_IGMP_HPP
#define FDPI_PROTOCOL_IGMP_HPP

#include <fdpi/address.hpp>
#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>

namespace fdpi {

struct IGMP {
    uint8_t type;        // 0x11=Query, 0x16=v2 Report, 0x17=Leave, 0x22=v3 Report
    uint8_t maxRespTime; // in 1/10 seconds
    uint16_t checksum;
    IPv4Address groupAddress;
};

std::expected<IGMP, Error> decodeIgmp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_IGMP_HPP
