#ifndef FDPI_PROTOCOL_RTMP_HPP
#define FDPI_PROTOCOL_RTMP_HPP

#include <fdpi/error.hpp>

#include <cstdint>
#include <expected>
#include <span>

namespace fdpi {

struct RTMP {
    bool isHandshake{false};
    uint8_t handshakeType{0}; // 0=C0/S0, 1=C1/S1, 2=C2/S2
    uint8_t chunkType{0};     // fmt (0-3)
    uint32_t chunkStreamId{0};
    uint32_t timestamp{0};
    uint32_t messageLength{0};
    uint8_t messageTypeId{0}; // 1=SetChunkSize, 20=Command(AMF0)
    uint32_t messageStreamId{0};
};

std::expected<RTMP, Error> decodeRtmp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_RTMP_HPP
