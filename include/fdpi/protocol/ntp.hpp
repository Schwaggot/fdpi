#ifndef FDPI_PROTOCOL_NTP_HPP
#define FDPI_PROTOCOL_NTP_HPP

#include <cstdint>
#include <expected>
#include <span>

#include <fdpi/error.hpp>

namespace fdpi {

struct NTP {
    uint8_t leapIndicator; // 2 bits
    uint8_t version;       // 3 bits (3 or 4)
    uint8_t mode;          // 3 bits (client=3, server=4)
    uint8_t stratum;
    int8_t poll;
    int8_t precision;
    uint32_t rootDelay;
    uint32_t rootDispersion;
    uint32_t referenceId;
    uint64_t referenceTimestamp;
    uint64_t originTimestamp;
    uint64_t receiveTimestamp;
    uint64_t transmitTimestamp;
};

std::expected<NTP, Error> decodeNtp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_NTP_HPP
