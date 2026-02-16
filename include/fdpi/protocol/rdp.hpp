#ifndef FDPI_PROTOCOL_RDP_HPP
#define FDPI_PROTOCOL_RDP_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

#include <fdpi/error.hpp>

namespace fdpi {

struct RDP {
    uint8_t tpktVersion; // should be 3
    uint16_t tpktLength;
    uint8_t x224Type; // 0xE0=CR, 0xD0=CC
    uint16_t dstRef;
    uint16_t srcRef;
    uint8_t classOption;
    std::optional<uint32_t> requestedProtocols;
    std::optional<uint32_t> selectedProtocol;
    std::optional<std::string> cookie;
};

std::expected<RDP, Error> decodeRdp(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_RDP_HPP
