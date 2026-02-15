#ifndef FDPI_PROTOCOL_GRE_HPP
#define FDPI_PROTOCOL_GRE_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <span>

#include <fdpi/error.hpp>

namespace fdpi {

struct GRE {
    bool     checksumPresent;
    bool     keyPresent;
    bool     seqPresent;
    uint16_t protocolType;
    std::optional<uint32_t> checksum;
    std::optional<uint32_t> key;
    std::optional<uint32_t> sequenceNumber;
};

std::expected<GRE, Error> decodeGre(std::span<const uint8_t> data, size_t& offset);

} // namespace fdpi

#endif // FDPI_PROTOCOL_GRE_HPP
