#ifndef FDPI_PROTOCOL_RTCP_HPP
#define FDPI_PROTOCOL_RTCP_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>

namespace fdpi {

struct RTCP {
    uint8_t version{2};
    bool padding{false};
    uint8_t receptionReportCount{0};
    uint8_t packetType{0}; // 200=SR, 201=RR, 202=SDES, 203=BYE, 204=APP
    uint16_t length{0};    // in 32-bit words minus one
    uint32_t ssrc{0};
};

std::expected<RTCP, Error> decodeRtcp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_RTCP_HPP
